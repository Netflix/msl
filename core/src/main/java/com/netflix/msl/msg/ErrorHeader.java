/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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

import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;

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
import com.netflix.msl.util.MslContext;

/**
 * <p>The error data is represented as
 * {@code
 * errordata = {
 *   "#mandatory" : [ "messageid", "errorcode" ],
 *   "recipient" : "string",
 *   "timestamp" : "int64(0,2^53^)",
 *   "messageid" : "int64(0,2^53^)",
 *   "errorcode" : "int32(0,-)",
 *   "internalcode" : "int32(0,-)",
 *   "errormsg" : "string",
 *   "usermsg" : "string",
 * }} where:
 * <ul>
 * <li>{@code recipient} is the intended recipient's entity identity</li>
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
    /** JSON key recipient. */
    private static final String KEY_RECIPIENT = "recipient";
    /** JSON key timestamp. */
    private static final String KEY_TIMESTAMP = "timestamp";
    /** JSON key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** JSON key error code. */
    private static final String KEY_ERROR_CODE = "errorcode";
    /** JSON key internal code. */
    private static final String KEY_INTERNAL_CODE = "internalcode";
    /** JSON key error message. */
    private static final String KEY_ERROR_MESSAGE = "errormsg";
    /** JSON key user message. */
    private static final String KEY_USER_MESSAGE = "usermsg";
    
    /**
     * <p>Construct a new error header with the provided error data.</p>
     * 
     * <p>Headers are encrypted and signed using the crypto context appropriate
     * for the entity authentication scheme.</p>
     * 
     * @param ctx MSL context.
     * @param entityAuthData the entity authentication data.
     * @param recipient the intended recipient's entity identity. May be null.
     * @param messageId the message ID.
     * @param errorCode the error code.
     * @param internalCode the internal code. Negative to indicate no code.
     * @param errorMsg the error message. May be null.
     * @param userMsg the user message. May be null.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if no entity authentication data is
     *         provided.
     */
    public ErrorHeader(final MslContext ctx, final EntityAuthenticationData entityAuthData, final String recipient, final long messageId, final ResponseCode errorCode, final int internalCode, final String errorMsg, final String userMsg) throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslMessageException {
        this.entityAuthData = entityAuthData;
        this.recipient = recipient;
        this.timestamp = ctx.getTime() / MILLISECONDS_PER_SECOND;
        this.messageId = messageId;
        this.errorCode = errorCode;
        this.internalCode = (internalCode >= 0) ? internalCode : -1;
        this.errorMsg = errorMsg;
        this.userMsg = userMsg;
        
        // Message ID must be within range.
        if (this.messageId < 0 || this.messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + this.messageId + " is out of range.");
        
        // Message entity must be provided.
        if (entityAuthData == null)
            throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);
        
        // Construct the JSON.
        final JSONObject errorJO = new JSONObject();
        try {
            if (this.recipient != null) errorJO.put(KEY_RECIPIENT, this.recipient);
            errorJO.put(KEY_TIMESTAMP, this.timestamp);
            errorJO.put(KEY_MESSAGE_ID, this.messageId);
            errorJO.put(KEY_ERROR_CODE, this.errorCode.intValue());
            if (this.internalCode > 0) errorJO.put(KEY_INTERNAL_CODE, this.internalCode);
            if (this.errorMsg != null) errorJO.put(KEY_ERROR_MESSAGE, this.errorMsg);
            if (this.userMsg != null) errorJO.put(KEY_USER_MESSAGE, this.userMsg);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "errordata", e).setEntityAuthenticationData(entityAuthData).setMessageId(messageId);
        }

        try {
            // Create the crypto context.
            final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
            final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
            if (factory == null)
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
            final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, entityAuthData);
        
            // Encrypt and sign the error data.
            final byte[] plaintext = errorJO.toString().getBytes(MslConstants.DEFAULT_CHARSET);
            this.errordata = cryptoContext.encrypt(plaintext);
            this.signature = cryptoContext.sign(this.errordata);
        } catch (final MslCryptoException e) {
            e.setEntityAuthenticationData(entityAuthData);
            e.setMessageId(messageId);
            throw e;
        } catch (final MslEntityAuthException e) {
            e.setEntityAuthenticationData(entityAuthData);
            e.setMessageId(messageId);
            throw e;
        }
    }
    
    /**
     * <p>Construct a new error header from the provided JSON object.</p>
     * 
     * <p>Headers are encrypted and signed using the crypto context appropriate
     * for the entity authentication scheme.</p>
     * 
     * @param ctx MSL context.
     * @param errordata error data JSON representation.
     * @param entityAuthData the entity authentication data.
     * @param signature the header signature.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header.
     * @throws MslEntityAuthException if the entity authentication data is not
     *         supported or erroneous.
     * @throws MslMessageException if there is no entity authentication data
     *         (null), the error data is missing or invalid, the message ID is
     *         negative, or the internal code is negative.
     */
    protected ErrorHeader(final MslContext ctx, final String errordata, final EntityAuthenticationData entityAuthData, final byte[] signature) throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslMessageException {
        final byte[] plaintext;
        try {
            this.entityAuthData = entityAuthData;
            this.signature = signature;
            if (entityAuthData == null)
                throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);
        
            final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
            final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
            if (factory == null)
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
            final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, entityAuthData);
            
            // Verify and decrypt the error data.
            try {
                this.errordata = DatatypeConverter.parseBase64Binary(errordata);
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.HEADER_DATA_INVALID, errordata, e).setEntityAuthenticationData(entityAuthData);
            }
            if (this.errordata == null || this.errordata.length == 0)
                throw new MslMessageException(MslError.HEADER_DATA_MISSING, errordata).setEntityAuthenticationData(entityAuthData);
            if (!cryptoContext.verify(this.errordata, this.signature))
                throw new MslCryptoException(MslError.MESSAGE_VERIFICATION_FAILED).setEntityAuthenticationData(entityAuthData);
            plaintext = cryptoContext.decrypt(this.errordata);
        } catch (final MslCryptoException e) {
            e.setEntityAuthenticationData(entityAuthData);
            throw e;
        } catch (final MslEntityAuthException e) {
            e.setEntityAuthenticationData(entityAuthData);
            throw e;
        }
        
        final String errordataJson = new String(plaintext, MslConstants.DEFAULT_CHARSET);
        final JSONObject errordataJO;
        try {
            errordataJO = new JSONObject(errordataJson);
            messageId = errordataJO.getLong(KEY_MESSAGE_ID);
            if (this.messageId < 0 || this.messageId > MslConstants.MAX_LONG_VALUE)
                throw new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE, "errordata " + errordataJson).setEntityAuthenticationData(entityAuthData);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "errordata " + errordataJson, e).setEntityAuthenticationData(entityAuthData);
        }
        
        try {
            recipient = (errordataJO.has(KEY_RECIPIENT)) ? errordataJO.getString(KEY_RECIPIENT) : null;
            timestamp = (errordataJO.has(KEY_TIMESTAMP)) ? errordataJO.getLong(KEY_TIMESTAMP) : null;
            
            // If we do not recognize the error code then default to fail.
            ResponseCode code = ResponseCode.FAIL;
            try {
                code = ResponseCode.valueOf(errordataJO.getInt(KEY_ERROR_CODE));
            } catch (final IllegalArgumentException e) {
                code = ResponseCode.FAIL;
            }
            errorCode = code;
            
            if (errordataJO.has(KEY_INTERNAL_CODE)) {
                internalCode = errordataJO.getInt(KEY_INTERNAL_CODE);
                if (this.internalCode < 0)
                    throw new MslMessageException(MslError.INTERNAL_CODE_NEGATIVE, "errordata " + errordataJO.toString()).setEntityAuthenticationData(entityAuthData).setMessageId(messageId);
            } else {
                internalCode = -1;
            }
            errorMsg = errordataJO.optString(KEY_ERROR_MESSAGE, null);
            userMsg = errordataJO.optString(KEY_USER_MESSAGE, null);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "errordata " + errordataJO.toString(), e).setEntityAuthenticationData(entityAuthData).setMessageId(messageId);
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
     * @return the recipient. May be null.
     */
    public String getRecipient() {
        return recipient;
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
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_ENTITY_AUTHENTICATION_DATA, entityAuthData);
            jsonObj.put(KEY_ERRORDATA, DatatypeConverter.printBase64Binary(errordata));
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
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
            (recipient == that.recipient || (recipient != null && recipient.equals(that.recipient))) &&
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
            ((recipient != null) ? recipient.hashCode() : 0) ^
            ((timestamp != null) ? timestamp.hashCode() : 0) ^
            Long.valueOf(messageId).hashCode() ^
            errorCode.hashCode() ^
            Integer.valueOf(internalCode).hashCode() ^
            ((errorMsg != null) ? errorMsg.hashCode() : 0) ^
            ((userMsg != null) ? userMsg.hashCode() : 0);
    }

    /** Entity authentication data. */
    private final EntityAuthenticationData entityAuthData;
    /** Error data (ciphertext). */
    private final byte[] errordata;
    /** Signature. */
    private final byte[] signature;
    
    /** Recipient. */
    private final String recipient;
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
}
