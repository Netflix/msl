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

import lombok.EqualsAndHashCode;
import lombok.Getter;
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
@EqualsAndHashCode(callSuper = false)
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

    /** Entity authentication data. */
    @Getter
    private final EntityAuthenticationData entityAuthenticationData;

    /** Error data (ciphertext). */
    private final byte[] errordata;

    /** Signature. */
    private final byte[] signature;

    /** Recipient. May be null. */
    @Getter
    private final String recipient;

    /** Timestamp in seconds since the epoch. May be null. */
    private final Long timestamp;

    /** Message ID. */
    @Getter
    private final long messageId;

    /** Error code.  If the parsed error code is not recognized then
     * returns {@code ResponseCode#FAIL}.
     */
    @Getter
    private final ResponseCode errorCode;

    /** Internal code -1 if none provided.*/
    @Getter
    private final int internalCode;

    /** Error message. May be null. */
    @Getter
    private final String errorMessage;

    /** User message. May be null. */
    @Getter
    private final String userMessage;

    /**
     * <p>Construct a new error header with the provided error data.</p>
     * 
     * <p>Headers are encrypted and signed using the crypto context appropriate
     * for the entity authentication scheme.</p>
     * 
     * @param ctx MSL context.
     * @param entityAuthenticationData the entity authentication data.
     * @param recipient the intended recipient's entity identity. May be null.
     * @param messageId the message ID.
     * @param errorCode the error code.
     * @param internalCode the internal code. Negative to indicate no code.
     * @param errorMessage the error message. May be null.
     * @param userMessage the user message. May be null.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if no entity authentication data is
     *         provided.
     */
    public ErrorHeader(final MslContext ctx, final EntityAuthenticationData entityAuthenticationData, final String recipient, final long messageId, final ResponseCode errorCode, final int internalCode, final String errorMessage, final String userMessage) throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslMessageException {
        this.entityAuthenticationData = entityAuthenticationData;
        this.recipient = recipient;
        this.timestamp = ctx.getTime() / MILLISECONDS_PER_SECOND;
        this.messageId = messageId;
        this.errorCode = errorCode;
        this.internalCode = (internalCode >= 0) ? internalCode : -1;
        this.errorMessage = errorMessage;
        this.userMessage = userMessage;
        
        // Message ID must be within range.
        if (this.messageId < 0 || this.messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + this.messageId + " is out of range.");
        
        // Message entity must be provided.
        if (entityAuthenticationData == null)
            throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);
        
        // Construct the JSON.
        final JSONObject errorJO = new JSONObject();
        try {
            if (this.recipient != null) errorJO.put(KEY_RECIPIENT, this.recipient);
            errorJO.put(KEY_TIMESTAMP, this.timestamp);
            errorJO.put(KEY_MESSAGE_ID, this.messageId);
            errorJO.put(KEY_ERROR_CODE, this.errorCode.intValue());
            if (this.internalCode > 0) errorJO.put(KEY_INTERNAL_CODE, this.internalCode);
            if (this.errorMessage != null) errorJO.put(KEY_ERROR_MESSAGE, this.errorMessage);
            if (this.userMessage != null) errorJO.put(KEY_USER_MESSAGE, this.userMessage);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "errordata", e).setEntity(entityAuthenticationData).setMessageId(messageId);
        }

        try {
            // Create the crypto context.
            final EntityAuthenticationScheme scheme = entityAuthenticationData.getScheme();
            final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
            if (factory == null)
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
            final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, entityAuthenticationData);
        
            // Encrypt and sign the error data.
            final byte[] plaintext = errorJO.toString().getBytes(MslConstants.DEFAULT_CHARSET);
            this.errordata = cryptoContext.encrypt(plaintext);
            this.signature = cryptoContext.sign(this.errordata);
        } catch (final MslCryptoException e) {
            e.setEntity(entityAuthenticationData);
            e.setMessageId(messageId);
            throw e;
        } catch (final MslEntityAuthException e) {
            e.setEntity(entityAuthenticationData);
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
     * @param entityAuthenticationData the entity authentication data.
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
    protected ErrorHeader(final MslContext ctx, final String errordata, final EntityAuthenticationData entityAuthenticationData, final byte[] signature) throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslMessageException {
        final byte[] plaintext;
        try {
            this.entityAuthenticationData = entityAuthenticationData;
            this.signature = signature;
            if (entityAuthenticationData == null)
                throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);
        
            final EntityAuthenticationScheme scheme = entityAuthenticationData.getScheme();
            final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
            if (factory == null)
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
            final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, entityAuthenticationData);
            
            // Verify and decrypt the error data.
            try {
                this.errordata = DatatypeConverter.parseBase64Binary(errordata);
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.HEADER_DATA_INVALID, errordata, e).setEntity(entityAuthenticationData);
            }
            if (this.errordata == null || this.errordata.length == 0)
                throw new MslMessageException(MslError.HEADER_DATA_MISSING, errordata).setEntity(entityAuthenticationData);
            if (!cryptoContext.verify(this.errordata, this.signature))
                throw new MslCryptoException(MslError.MESSAGE_VERIFICATION_FAILED).setEntity(entityAuthenticationData);
            plaintext = cryptoContext.decrypt(this.errordata);
        } catch (final MslCryptoException e) {
            e.setEntity(entityAuthenticationData);
            throw e;
        } catch (final MslEntityAuthException e) {
            e.setEntity(entityAuthenticationData);
            throw e;
        }
        
        final String errordataJson = new String(plaintext, MslConstants.DEFAULT_CHARSET);
        final JSONObject errordataJO;
        try {
            errordataJO = new JSONObject(errordataJson);
            messageId = errordataJO.getLong(KEY_MESSAGE_ID);
            if (this.messageId < 0 || this.messageId > MslConstants.MAX_LONG_VALUE)
                throw new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE, "errordata " + errordataJson).setEntity(entityAuthenticationData);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "errordata " + errordataJson, e).setEntity(entityAuthenticationData);
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
                    throw new MslMessageException(MslError.INTERNAL_CODE_NEGATIVE, "errordata " + errordataJO.toString()).setEntity(entityAuthenticationData).setMessageId(messageId);
            } else {
                internalCode = -1;
            }
            errorMessage = errordataJO.optString(KEY_ERROR_MESSAGE, null);
            userMessage = errordataJO.optString(KEY_USER_MESSAGE, null);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "errordata " + errordataJO.toString(), e).setEntity(entityAuthenticationData).setMessageId(messageId);
        }
    }

    /**
     * @return the timestamp. May be null.
     */
    public Date getTimestamp() {
        return (timestamp != null) ? new Date(timestamp * MILLISECONDS_PER_SECOND) : null;
    }
    
    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_ENTITY_AUTHENTICATION_DATA, entityAuthenticationData);
            jsonObj.put(KEY_ERRORDATA, DatatypeConverter.printBase64Binary(errordata));
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }

}
