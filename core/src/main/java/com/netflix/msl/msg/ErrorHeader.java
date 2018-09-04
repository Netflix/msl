/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.netflix.msl.msg;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

/**
 * <p>The error data is represented as
 * {@code
 * errordata = {
 *   "#mandatory" : [ "messageid", "errorcode" ],
 *   "timestamp" : "int64(0,2^53^)",
 *   "messageid" : "int64(0,2^53^)",
 *   "errorcode" : "int32(0,-)",
 *   "internalcode" : "int32(0,-)",
 *   "errormsg" : "string",
 *   "usermsg" : "string",
 * }} where:
 * <ul>
 * <li>{@code timestamp} is the sender time when the header is created in seconds since the UNIX epoch</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code errorcode} is the error code</li>
 * <li>{@code internalcode} is an service-specific error code</li>
 * <li>{@code errormsg} is a developer-consumable error message</li>
 * <li>{@code usermsg} is a user-consumable localized error message</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ErrorHeader extends Header {
    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    // Message error data.
    /** Key timestamp. */
    private static final String KEY_TIMESTAMP = "timestamp";
    /** Key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** Key error code. */
    private static final String KEY_ERROR_CODE = "errorcode";
    /** Key internal code. */
    private static final String KEY_INTERNAL_CODE = "internalcode";
    /** Key error message. */
    private static final String KEY_ERROR_MESSAGE = "errormsg";
    /** Key user message. */
    private static final String KEY_USER_MESSAGE = "usermsg";
    
    /**
     * <p>Construct a new error header with the provided error data.</p>
     * 
     * @param ctx MSL context.
     * @param entityAuthData the entity authentication data.
     * @param messageId the message ID.
     * @param errorCode the error code.
     * @param internalCode the internal code. Negative to indicate no code.
     * @param errorMsg the error message. May be null.
     * @param userMsg the user message. May be null.
     * @throws MslMessageException if no entity authentication data is
     *         provided.
     */
    public ErrorHeader(final MslContext ctx, final EntityAuthenticationData entityAuthData, final long messageId, final ResponseCode errorCode, final int internalCode, final String errorMsg, final String userMsg) throws MslMessageException {
        // Message ID must be within range.
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is out of range.");
        
        // Message entity must be provided.
        if (entityAuthData == null)
            throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);
        
        this.ctx = ctx;
        this.entityAuthData = entityAuthData;
        this.timestamp = ctx.getTime() / MILLISECONDS_PER_SECOND;
        this.messageId = messageId;
        this.errorCode = errorCode;
        this.internalCode = (internalCode >= 0) ? internalCode : -1;
        this.errorMsg = errorMsg;
        this.userMsg = userMsg;
        
        // Construct the error data.
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        errordata = encoder.createObject();
        errordata.put(KEY_TIMESTAMP, this.timestamp);
        errordata.put(KEY_MESSAGE_ID, this.messageId);
        errordata.put(KEY_ERROR_CODE, this.errorCode.intValue());
        if (this.internalCode > 0) errordata.put(KEY_INTERNAL_CODE, this.internalCode);
        if (this.errorMsg != null) errordata.put(KEY_ERROR_MESSAGE, this.errorMsg);
        if (this.userMsg != null) errordata.put(KEY_USER_MESSAGE, this.userMsg);
    }
    
    /**
     * <p>Construct a new error header from the provided MSL object.</p>
     * 
     * @param ctx MSL context.
     * @param errordataBytes error data MSL encoding.
     * @param entityAuthData the entity authentication data.
     * @param signature the header signature.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header.
     * @throws MslEntityAuthException if the entity authentication data is not
     *         supported or erroneous.
     * @throws MslMessageException if there is no entity authentication data
     *         (null), the error data is missing or invalid, the message ID is
     *         negative, or the internal code is negative.
     */
    protected ErrorHeader(final MslContext ctx, final byte[] errordataBytes, final EntityAuthenticationData entityAuthData, final byte[] signature) throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslMessageException {
        this.ctx = ctx;
        
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        
        final byte[] plaintext;
        try {
            // Validate the entity authentication data.
            this.entityAuthData = entityAuthData;
            if (entityAuthData == null)
                throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);
        
            // Grab the entity crypto context.
            final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
            final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
            if (factory == null)
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
            final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, entityAuthData);
            
            // Verify and decrypt the error data.
            if (!cryptoContext.verify(errordataBytes, signature, encoder))
                throw new MslCryptoException(MslError.MESSAGE_VERIFICATION_FAILED).setEntityAuthenticationData(entityAuthData);
            plaintext = cryptoContext.decrypt(errordataBytes, encoder);
        } catch (final MslCryptoException e) {
            e.setEntityAuthenticationData(entityAuthData);
            throw e;
        } catch (final MslEntityAuthException e) {
            e.setEntityAuthenticationData(entityAuthData);
            throw e;
        }
        
        try {
            errordata = encoder.parseObject(plaintext);
            messageId = errordata.getLong(KEY_MESSAGE_ID);
            if (this.messageId < 0 || this.messageId > MslConstants.MAX_LONG_VALUE)
                throw new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE, "errordata " + errordata).setEntityAuthenticationData(entityAuthData);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "errordata " + Base64.encode(plaintext), e).setEntityAuthenticationData(entityAuthData);
        }
        
        try {
            timestamp = (errordata.has(KEY_TIMESTAMP)) ? errordata.getLong(KEY_TIMESTAMP) : null;
            
            // If we do not recognize the error code then default to fail.
            ResponseCode code = ResponseCode.FAIL;
            try {
                code = ResponseCode.valueOf(errordata.getInt(KEY_ERROR_CODE));
            } catch (final IllegalArgumentException e) {
                code = ResponseCode.FAIL;
            }
            errorCode = code;
            
            if (errordata.has(KEY_INTERNAL_CODE)) {
                internalCode = errordata.getInt(KEY_INTERNAL_CODE);
                if (this.internalCode < 0)
                    throw new MslMessageException(MslError.INTERNAL_CODE_NEGATIVE, "errordata " + errordata).setEntityAuthenticationData(entityAuthData).setMessageId(messageId);
            } else {
                internalCode = -1;
            }
            errorMsg = errordata.optString(KEY_ERROR_MESSAGE, null);
            userMsg = errordata.optString(KEY_USER_MESSAGE, null);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "errordata " + errordata, e).setEntityAuthenticationData(entityAuthData).setMessageId(messageId);
        }
    }
    
    /**
     * Returns the entity authentication data.
     * 
     * @return the entity authentication data.
     */
    public EntityAuthenticationData getEntityAuthenticationData() {
        return entityAuthData;
    }
    
    /**
     * @return the timestamp. May be null.
     */
    public Date getTimestamp() {
        return (timestamp != null) ? new Date(timestamp * MILLISECONDS_PER_SECOND) : null;
    }
    
    /**
     * @return the message ID.
     */
    public long getMessageId() {
        return messageId;
    }
    
    /**
     * Returns the error code. If the parsed error code is not recognized then
     * this returns {@code ResponseCode#FAIL}.
     * 
     * @return the error code.
     */
    public ResponseCode getErrorCode() {
        return errorCode;
    }
    
    /**
     * @return the internal code or -1 if none provided.
     */
    public int getInternalCode() {
        return internalCode;
    }
    
    /**
     * @return the error message. May be null.
     */
    public String getErrorMessage() {
        return errorMsg;
    }
    
    /**
     * @return the user message. May be null.
     */
    public String getUserMessage() {
        return userMsg;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        // Return any cached encoding.
        if (encodings.containsKey(format))
            return encodings.get(format);
        
        // Create the crypto context.
        final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
        final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
        if (factory == null)
            throw new MslEncoderException("No entity authentication factory found for entity.");
        final ICryptoContext cryptoContext;
        try {
            cryptoContext = factory.getCryptoContext(ctx, entityAuthData);
        } catch (final MslEntityAuthException e) {
            throw new MslEncoderException("Error creating the entity crypto context.", e);
        } catch (final MslCryptoException e) {
            throw new MslEncoderException("Error creating the entity crypto context.", e);
        }

        // Encrypt and sign the error data.
        final byte[] plaintext = encoder.encodeObject(errordata, format);
        final byte[] ciphertext;
        try {
            ciphertext = cryptoContext.encrypt(plaintext, encoder, format);
        } catch (final MslCryptoException e) {
            throw new MslEncoderException("Error encrypting the error data.", e);
        }
        final byte[] signature;
        try {
            signature = cryptoContext.sign(ciphertext, encoder, format, this);
        } catch (final MslCryptoException e) {
            throw new MslEncoderException("Error signing the error data.", e);
        }
        
        // Create the encoding.
        final MslObject header = encoder.createObject();
        header.put(Header.KEY_ENTITY_AUTHENTICATION_DATA, entityAuthData);
        header.put(Header.KEY_ERRORDATA, ciphertext);
        header.put(Header.KEY_SIGNATURE, signature);
        final byte[] encoding = encoder.encodeObject(header, format);
        
        // Cache and return the encoding.
        encodings.put(format, encoding);
        return encoding;
        
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof ErrorHeader)) return false;
        final ErrorHeader that = (ErrorHeader)obj;
        return entityAuthData.equals(that.entityAuthData) &&
            (timestamp != null && timestamp.equals(that.timestamp) ||
             timestamp == null && that.timestamp == null) &&
            messageId == that.messageId &&
            errorCode == that.errorCode &&
            internalCode == that.internalCode &&
            (errorMsg == that.errorMsg || (errorMsg != null && errorMsg.equals(that.errorMsg))) &&
            (userMsg == that.userMsg || (userMsg != null && userMsg.equals(that.userMsg)));
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return entityAuthData.hashCode() ^
            ((timestamp != null) ? timestamp.hashCode() : 0) ^
            Long.valueOf(messageId).hashCode() ^
            errorCode.hashCode() ^
            Integer.valueOf(internalCode).hashCode() ^
            ((errorMsg != null) ? errorMsg.hashCode() : 0) ^
            ((userMsg != null) ? userMsg.hashCode() : 0);
    }

    /** MSL context. */
    protected final MslContext ctx;
    
    /** Entity authentication data. */
    protected final EntityAuthenticationData entityAuthData;
    /** Error data. */
    protected final MslObject errordata;
    
    /** Timestamp in seconds since the epoch. */
    private final Long timestamp;
    /** Message ID. */
    private final long messageId;
    /** Error code. */
    private final ResponseCode errorCode;
    /** Internal code. */
    private final int internalCode;
    /** Error message. */
    private final String errorMsg;
    /** User message. */
    private final String userMsg;
    
    /** Cached encodings. */
    protected final Map<MslEncoderFormat,byte[]> encodings = new HashMap<MslEncoderFormat,byte[]>();
}
