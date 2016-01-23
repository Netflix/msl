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
package com.netflix.msl.tokens;

import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslUtils;

/**
 * <p>Service tokens are service-defined tokens carried as part of any MSL
 * message. These tokens should be used to carry service state.</p>
 * 
 * <p>Service tokens are optionally bound to a specific master token and user
 * ID token by their serial numbers.</p>
 * 
 * <p>Service tokens are either verified or encrypted. Verified tokens carry
 * their data in the clear but are accompanied by a signature allowing the
 * issuer to ensure the data has not been tampered with. Encrypted tokens
 * encrypt their data as well as contain a signature.</p>
 * 
 * <p>Service tokens should use application- or service-specific crypto
 * contexts and not the crypto context associated with the entity credentials
 * or master token.</p>
 * 
 * <p>Service tokens are represented as
 * {@code
 * servicetoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "base64,
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the Base64-encoded service token data (servicetokendata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the service token data</li>
 * </ul></p>
 * 
 * <p>The token data is represented as
 * {@code
 * servicetokendata = {
 *   "#mandatory" : [ "name", "mtserialnumber", "uitserialnumber", "encrypted", "servicedata" ],
 *   "name" : "string",
 *   "mtserialnumber" : "int64(0,2^53^)",
 *   "uitserialnumber" : "int64(0,2^53^)",
 *   "encrypted" : "boolean",
 *   "compressionalgo" : "enum(GZIP|LZW)",
 *   "servicedata" : "base64"
 * }} where:
 * <ul>
 * <li>{@code name} is the token name</li>
 * <li>{@code mtserialnumber} is the master token serial number or -1 if unbound</li>
 * <li>{@code utserialnumber} is the user ID token serial number or -1 if unbound</li>
 * <li>{@code encrypted} indicates if the service data is encrypted or not</li>
 * <li>{@code compressionalgo} indicates the algorithm used to compress the data</li>
 * <li>{@code servicedata} is the Base64-encoded optionally encrypted service data</li>
 * </ul></p>  
 * 
 * <p>Service token names should follow a reverse fully-qualified domain
 * hierarchy. e.g. {@literal com.netflix.service.tokenname}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@EqualsAndHashCode(of = {"name", "masterTokenSerialNumber", "userIdTokenSerialNumber"})
public class ServiceToken implements JSONString {
    /** JSON key token data. */
    private static final String KEY_TOKENDATA = "tokendata";
    /** JSON key signature. */
    private static final String KEY_SIGNATURE = "signature";

    /** JSON key token name. */
    private static final String KEY_NAME = "name";
    /** JSON key master token serial number. */
    private static final String KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** JSON key user ID token serial number. */
    private static final String KEY_USER_ID_TOKEN_SERIAL_NUMBER = "uitserialnumber";
    /** JSON key encrypted. */
    private static final String KEY_ENCRYPTED = "encrypted";
    /** JSON key compression algorithm. */
    private static final String KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** JSON key service data. */
    private static final String KEY_SERVICEDATA = "servicedata";

    /** Token data. */
    private final byte[] tokendata;

    /** Token data signature. */
    private final byte[] signature;

    /** The application token name. */
    @Getter
    private final String name;

    /**
     * Serial number of the master token this service token is bound to or -1 if unbound.
     */
    @Getter
    private final long masterTokenSerialNumber;

    /**
     * Serial number of the user ID token this service token is bound to or -1 if unbound.
     */
    @Getter
    private final long userIdTokenSerialNumber;

    /** Service token data is encrypted. */
    @Getter
    private final boolean encrypted;

    /** Compression algorithm.  May be {@code null} if not compressed.*/
    @Getter
    private final CompressionAlgorithm compressionAlgo;

    /**
     * The service token data, if the token data was not encrypted or we were
     * unable to decrypt it. Zero-length data indicates this token should be deleted.
     * Null if we don't have it.
     * @see #isDeleted()
     */
    @Getter
    private final byte[] data;

    /** Token has been verified. */
    @Getter
    private final boolean verified;

    /**
     * <p>Select the appropriate crypto context for the service token
     * represented by the provided JSON object.</p>
     * 
     * <p>If the service token name exists as a key in the map of crypto
     * contexts, the mapped crypto context will be returned. Otherwise the
     * default crypto context mapped from the empty string key will be
     * returned. If no explicit or default crypto context exists null will be
     * returned.</p>
     * 
     * @param serviceTokenJO the JSON object.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @return the correct crypto context for the service token or null.
     * @throws MslEncodingException if there is a problem parsing the JSON.
     */
    private static ICryptoContext selectCryptoContext(final JSONObject serviceTokenJO, final Map<String,ICryptoContext> cryptoContexts) throws MslEncodingException {
        try {
            final byte[] tokendata;
            try {
                tokendata = DatatypeConverter.parseBase64Binary(serviceTokenJO.getString(KEY_TOKENDATA));
            } catch (final IllegalArgumentException e) {
                throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_INVALID, "servicetoken " + serviceTokenJO.toString(), e);
            }
            if (tokendata == null || tokendata.length == 0)
                throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_MISSING, "servicetoken " + serviceTokenJO.toString());
            final JSONObject tokenDataJO = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
            final String name = tokenDataJO.getString(KEY_NAME);
            if (cryptoContexts.containsKey(name))
                return cryptoContexts.get(name);
            return cryptoContexts.get("");
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "servicetoken " + serviceTokenJO.toString(), e);
        }
    }
    
    /**
     * <p>Construct a new service token with the specified name and data. If a
     * master token is provided, the service token is bound to the master
     * token's serial number. If a user ID token is provided, the service token
     * is bound to the user ID token's serial number.</p>
     * 
     * <p>For encrypted tokens, the token data is encrypted using the provided
     * crypto context. For verified tokens, the token data is signed using the
     * provided crypto context.</p>
     * 
     * @param ctx the MSL context.
     * @param name the service token name--must be unique.
     * @param data the service token data (unencrypted).
     * @param masterToken the master token. May be null.
     * @param userIdToken the user ID token. May be null.
     * @param encrypted true if the token should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @param cryptoContext the crypto context.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if there is an error compressing the data.
     */
    public ServiceToken(final MslContext ctx, final String name, final byte[] data, final MasterToken masterToken, final UserIdToken userIdToken, final boolean encrypted, final CompressionAlgorithm compressionAlgo, final ICryptoContext cryptoContext) throws MslEncodingException, MslCryptoException, MslException {
        // If both master token and user ID token are provided the user ID
        // token must be bound to the master token.
        if (masterToken != null && userIdToken != null && !userIdToken.isBoundTo(masterToken))
            throw new MslInternalException("Cannot construct a service token bound to a master token and user ID token where the user ID token is not bound to the same master token.");
        
        // Optionally compress the service data.
        final byte[] plaintext;
        if (compressionAlgo != null) {
            final byte[] compressed = MslUtils.compress(compressionAlgo, data);
            
            // Only use compression if the compressed data is smaller than the
            // uncompressed data.
            if (compressed.length < data.length) {
                this.compressionAlgo = compressionAlgo;
                plaintext = compressed;
            } else {
                this.compressionAlgo = null;
                plaintext = data;
            }
        } else {
            this.compressionAlgo = null;
            plaintext = data;
        }
        
        this.name = name;
        this.masterTokenSerialNumber = (masterToken != null) ? masterToken.getSerialNumber() : -1;
        this.userIdTokenSerialNumber = (userIdToken != null) ? userIdToken.getSerialNumber() : -1;
        this.data = data;
        this.encrypted = encrypted;
        
        try {
            // Encrypt the service data if the length is > 0. Otherwise encode
            // as empty data to indicate this token should be deleted.
            final byte[] ciphertext = (encrypted && plaintext.length > 0) ? cryptoContext.encrypt(plaintext) : plaintext;
            
            // Construct the token data.
            try {
                final JSONObject tokenDataJO = new JSONObject();
                tokenDataJO.put(KEY_NAME, this.name);
                if (this.masterTokenSerialNumber != -1) tokenDataJO.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, this.masterTokenSerialNumber);
                if (this.userIdTokenSerialNumber != -1) tokenDataJO.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, this.userIdTokenSerialNumber);
                tokenDataJO.put(KEY_ENCRYPTED, this.encrypted);
                if (this.compressionAlgo != null) tokenDataJO.put(KEY_COMPRESSION_ALGORITHM, this.compressionAlgo.name());
                tokenDataJO.put(KEY_SERVICEDATA, DatatypeConverter.printBase64Binary(ciphertext));
                this.tokendata = tokenDataJO.toString().getBytes(MslConstants.DEFAULT_CHARSET);
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "servicetoken", e).setEntity(masterToken).setUser(userIdToken);
            }
            
            // Sign the token data.
            this.signature = cryptoContext.sign(this.tokendata);
            this.verified = true;
        } catch (final MslCryptoException e) {
            e.setEntity(masterToken);
            e.setUser(userIdToken);
            throw e;
        }
    }
    
    /**
     * <p>Construct a new service token from the provided JSON object and
     * attempt to decrypt and verify the signature of the service token using
     * the appropriate crypto context. If the data cannot be decrypted or the
     * signature cannot be verified, the token will still be created.</p>
     * 
     * <p>If the service token name exists as a key in the map of crypto
     * contexts, the mapped crypto context will be used. Otherwise the default
     * crypto context mapped from the empty string key will be used.</p>
     * 
     * <p>If a matching crypto context is found, the token data will be
     * decrypted and its signature verified.</p>
     * 
     * <p>If the service token is bound to a master token or user ID token it
     * will be verified against the provided master token or user ID tokens
     * which must not be null.</p>
     * 
     * @param ctx the MSL context.
     * @param serviceTokenJO the JSON object.
     * @param masterToken the master token. May be null.
     * @param userIdToken the user ID token. May be null.
     * @param cryptoContexts a map of service token names onto crypto contexts.
     * @throws MslEncodingException if there is a problem parsing the JSON.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the token data.
     * @throws MslException if the service token is bound to a master token or
     *         user ID token and the provided tokens are null or the serial
     *         numbers do not match, or if bound to a user ID token but not to
     *         a master token, or if the service data is missing, or if the
     *         compression algorithm is not known or there is an error
     *         uncompressing the data.
     */
    public ServiceToken(final MslContext ctx, final JSONObject serviceTokenJO, final MasterToken masterToken, final UserIdToken userIdToken, final Map<String,ICryptoContext> cryptoContexts) throws MslEncodingException, MslCryptoException, MslException {
        this(ctx, serviceTokenJO, masterToken, userIdToken, selectCryptoContext(serviceTokenJO, cryptoContexts));
    }
    
    /**
     * <p>Construct a new service token from the provided JSON object.</p>
     * 
     * <p>If a crypto context is provided, the token data will be decrypted and
     * its signature verified. If the data cannot be decrypted or the signature
     * cannot be verified, the token will still be created.</p>
     * 
     * <p>If the service token is bound to a master token or user ID token it
     * will be verified against the provided master token or user ID tokens
     * which must not be null.</p>
     * 
     * @param ctx the MSL context.
     * @param serviceTokenJO the JSON object.
     * @param masterToken the master token. May be null.
     * @param userIdToken the user ID token. May be null.
     * @param cryptoContext the crypto context. May be null.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the token data.
     * @throws MslEncodingException if there is a problem parsing the JSON, the
     *         token data is missing or invalid, or the signature is invalid.
     * @throws MslException if the service token is bound to a master token or
     *         user ID token and the provided tokens are null or the serial
     *         numbers do not match, or if bound to a user ID token but not to
     *         a master token, or if the service data is missing, or if the
     *         service token master token serial number is out of range, or if
     *         the service token user ID token serial number is out of range,
     *         or if the compression algorithm is not known or there is an
     *         error uncompressing the data.
     */
    public ServiceToken(final MslContext ctx, final JSONObject serviceTokenJO, final MasterToken masterToken, final UserIdToken userIdToken, final ICryptoContext cryptoContext) throws MslCryptoException, MslEncodingException, MslException {
        // Verify the JSON representation.
        try {
            try {
                tokendata = DatatypeConverter.parseBase64Binary(serviceTokenJO.getString(KEY_TOKENDATA));
            } catch (final IllegalArgumentException e) {
                throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_INVALID, "servicetoken " + serviceTokenJO.toString(), e).setEntity(masterToken).setUser(userIdToken);
            }
            if (tokendata == null || tokendata.length == 0)
                throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_MISSING, "servicetoken " + serviceTokenJO.toString()).setEntity(masterToken).setUser(userIdToken);
            try {
                signature = DatatypeConverter.parseBase64Binary(serviceTokenJO.getString(KEY_SIGNATURE));
            } catch (final IllegalArgumentException e) {
                throw new MslEncodingException(MslError.SERVICETOKEN_SIGNATURE_INVALID, "servicetoken " + serviceTokenJO.toString(), e).setEntity(masterToken).setUser(userIdToken);
            }
            verified = (cryptoContext != null) ? cryptoContext.verify(tokendata, signature) : false;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "servicetoken " + serviceTokenJO.toString(), e).setEntity(masterToken).setUser(userIdToken);
        } catch (final MslCryptoException e) {
            e.setEntity(masterToken);
            throw e;
        }
        
        // Pull the token data.
        final String tokenDataJson = new String(tokendata, MslConstants.DEFAULT_CHARSET);
        try {
            final JSONObject tokenDataJO = new JSONObject(tokenDataJson);
            name = tokenDataJO.getString(KEY_NAME);
            if (tokenDataJO.has(KEY_MASTER_TOKEN_SERIAL_NUMBER)) {
                masterTokenSerialNumber = tokenDataJO.getLong(KEY_MASTER_TOKEN_SERIAL_NUMBER);
                if (masterTokenSerialNumber < 0 || masterTokenSerialNumber > MslConstants.MAX_LONG_VALUE)
                    throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "servicetokendata " + tokenDataJson).setEntity(masterToken).setUser(userIdToken);
            } else {
                masterTokenSerialNumber = -1;
            }
            if (tokenDataJO.has(KEY_USER_ID_TOKEN_SERIAL_NUMBER)) {
                userIdTokenSerialNumber = tokenDataJO.getLong(KEY_USER_ID_TOKEN_SERIAL_NUMBER);
                if (userIdTokenSerialNumber < 0 || userIdTokenSerialNumber > MslConstants.MAX_LONG_VALUE)
                    throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "servicetokendata " + tokenDataJson).setEntity(masterToken).setUser(userIdToken);
            } else {
                userIdTokenSerialNumber = -1;
            }
            // There has to be a master token serial number if there is a
            // user ID token serial number.
            
            encrypted = tokenDataJO.getBoolean(KEY_ENCRYPTED);
            if (tokenDataJO.has(KEY_COMPRESSION_ALGORITHM)) {
                final String algoName = tokenDataJO.getString(KEY_COMPRESSION_ALGORITHM);
                try {
                    compressionAlgo = CompressionAlgorithm.valueOf(algoName);
                } catch (final IllegalArgumentException e) {
                    throw new MslException(MslError.UNIDENTIFIED_COMPRESSION, algoName, e);
                }
            } else {
                compressionAlgo = null;
            }

            // If encrypted, and we were able to verify the data then we better
            // be able to decrypt it. (An exception is thrown if decryption
            // fails.)
            final String data = tokenDataJO.getString(KEY_SERVICEDATA);
            if (verified) {
                final byte[] ciphertext;
                try {
                    ciphertext = DatatypeConverter.parseBase64Binary(data);
                } catch (final IllegalArgumentException e) {
                    throw new MslException(MslError.SERVICETOKEN_SERVICEDATA_INVALID, "servicetokendata " + tokenDataJson).setEntity(masterToken).setUser(userIdToken);
                }
                if (ciphertext == null)
                    throw new MslException(MslError.SERVICETOKEN_SERVICEDATA_INVALID, "servicetokendata " + tokenDataJson).setEntity(masterToken).setUser(userIdToken);
                final byte[] compressedData = (encrypted && ciphertext.length > 0)
                    ? cryptoContext.decrypt(ciphertext)
                    : ciphertext;
                this.data = (compressionAlgo != null)
                    ? MslUtils.uncompress(compressionAlgo, compressedData)
                    : compressedData;
            } else {
                this.data = (data.isEmpty()) ? new byte[0] : null;
            }
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "servicetokendata " + tokenDataJson, e).setEntity(masterToken).setUser(userIdToken);
        } catch (final MslCryptoException e) {
            e.setEntity(masterToken);
            e.setUser(userIdToken);
            throw e;
        }
        
        // Verify serial numbers.
        if (masterTokenSerialNumber != -1 && (masterToken == null || masterTokenSerialNumber != masterToken.getSerialNumber()))
            throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH, "st mtserialnumber " + masterTokenSerialNumber + "; mt " + masterToken).setEntity(masterToken).setUser(userIdToken);
        if (userIdTokenSerialNumber != -1 && (userIdToken == null || userIdTokenSerialNumber != userIdToken.getSerialNumber()))
            throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH, "st uitserialnumber " + userIdTokenSerialNumber + "; uit " + userIdToken).setEntity(masterToken).setUser(userIdToken);
    }

    /**
     * @return true if the decrypted content is available. (Implies verified.)
     */
    public boolean isDecrypted() {
        return data != null;
    }
    
    /**
     * @return true if this token has been marked for deletion.
     * @see #getData()
     */
    public boolean isDeleted() {
        return data != null && data.length == 0;
    }
    
    /**
     * @return true if this token is bound to a master token.
     */
    public boolean isMasterTokenBound() {
        return masterTokenSerialNumber != -1;
    }
    
    /**
     * @param masterToken master token. May be null.
     * @return true if this token is bound to the provided master token.
     */
    public boolean isBoundTo(final MasterToken masterToken) {
        return masterToken != null && masterToken.getSerialNumber() == masterTokenSerialNumber;
    }
    
    /**
     * Returns true if this token is bound to a user ID token. This implies the
     * token is bound to a master token as well.
     * 
     * @return true if this token is bound to a user ID token.
     */
    public boolean isUserIdTokenBound() {
        return userIdTokenSerialNumber != -1;
    }
    
    /**
     * @param userIdToken user ID token. May be null.
     * @return true if this token is bound to the provided user ID token.
     */
    public boolean isBoundTo(final UserIdToken userIdToken) {
        return userIdToken != null && userIdToken.getSerialNumber() == userIdTokenSerialNumber;
    }
    
    /**
     * @return true if this token is not bound to a master token or user ID
     *         token.
     */
    public boolean isUnbound() {
        return masterTokenSerialNumber == -1 && userIdTokenSerialNumber == -1;
    }

    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendata));
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        try {
            final JSONObject tokendataJO = new JSONObject();
            tokendataJO.put(KEY_NAME, name);
            tokendataJO.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, masterTokenSerialNumber);
            tokendataJO.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, userIdTokenSerialNumber);
            tokendataJO.put(KEY_SERVICEDATA, DatatypeConverter.printBase64Binary(data));
            
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_TOKENDATA, tokendataJO);
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }

}
