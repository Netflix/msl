/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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

import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslCompression;
import com.netflix.msl.util.MslContext;

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
 *   "tokendata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the service token data (servicetokendata)</li>
 * <li>{@code signature} is the verification data of the service token data</li>
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
 *   "servicedata" : "binary"
 * }} where:
 * <ul>
 * <li>{@code name} is the token name</li>
 * <li>{@code mtserialnumber} is the master token serial number or -1 if unbound</li>
 * <li>{@code utserialnumber} is the user ID token serial number or -1 if unbound</li>
 * <li>{@code encrypted} indicates if the service data is encrypted or not</li>
 * <li>{@code compressionalgo} indicates the algorithm used to compress the data</li>
 * <li>{@code servicedata} is the optionally encrypted service data</li>
 * </ul></p>  
 * 
 * <p>Service token names should follow a reverse fully-qualified domain
 * hierarchy. e.g. {@literal com.netflix.service.tokenname}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ServiceToken implements MslEncodable {
    /** Key token data. */
    private static final String KEY_TOKENDATA = "tokendata";
    /** Key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // tokendata
    /** Key token name. */
    private static final String KEY_NAME = "name";
    /** Key master token serial number. */
    private static final String KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** Key user ID token serial number. */
    private static final String KEY_USER_ID_TOKEN_SERIAL_NUMBER = "uitserialnumber";
    /** Key encrypted. */
    private static final String KEY_ENCRYPTED = "encrypted";
    /** Key compression algorithm. */
    private static final String KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** Key service data. */
    private static final String KEY_SERVICEDATA = "servicedata";
    
    /**
     * <p>Select the appropriate crypto context for the service token
     * represented by the provided MSL object.</p>
     * 
     * <p>If the service token name exists as a key in the map of crypto
     * contexts, the mapped crypto context will be returned. Otherwise the
     * default crypto context mapped from the empty string key will be
     * returned. If no explicit or default crypto context exists null will be
     * returned.</p>
     * 
     * @param encoder the MSL encoder factory.
     * @param serviceTokenMo the MSL object.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @return the correct crypto context for the service token or null.
     * @throws MslEncodingException if there is a problem parsing the data.
     */
    private static ICryptoContext selectCryptoContext(final MslEncoderFactory encoder, final MslObject serviceTokenMo, final Map<String,ICryptoContext> cryptoContexts) throws MslEncodingException {
        try {
            final byte[] tokendata = serviceTokenMo.getBytes(KEY_TOKENDATA);
            if (tokendata.length == 0)
                throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_MISSING, "servicetoken " + serviceTokenMo);
            final MslObject tokenDataMo = encoder.parseObject(tokendata);
            final String name = tokenDataMo.getString(KEY_NAME);
            if (cryptoContexts.containsKey(name))
                return cryptoContexts.get(name);
            return cryptoContexts.get("");
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "servicetoken " + serviceTokenMo, e);
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
     * @throws MslException if there is an error compressing the data.
     */
    public ServiceToken(final MslContext ctx, final String name, final byte[] data, final MasterToken masterToken, final UserIdToken userIdToken, final boolean encrypted, final CompressionAlgorithm compressionAlgo, final ICryptoContext cryptoContext) throws MslException {
        this.ctx = ctx;
        
        // If both master token and user ID token are provided the user ID
        // token must be bound to the master token.
        if (masterToken != null && userIdToken != null && !userIdToken.isBoundTo(masterToken))
            throw new MslInternalException("Cannot construct a service token bound to a master token and user ID token where the user ID token is not bound to the same master token.");
        
        // The crypto context may not be null.
        if (cryptoContext == null)
            throw new NullPointerException("Crypto context may not be null.");
        
        // Set token properties.
        this.name = name;
        this.mtSerialNumber = (masterToken != null) ? masterToken.getSerialNumber() : -1;
        this.uitSerialNumber = (userIdToken != null) ? userIdToken.getSerialNumber() : -1;
        this.servicedata = data;
        this.encrypted = encrypted;
        
        // Optionally compress the service data.
        if (compressionAlgo != null) {
            final byte[] compressed = MslCompression.compress(compressionAlgo, data);
            
            // Only use compression if the compressed data is smaller than the
            // uncompressed data.
            if (compressed != null && compressed.length < data.length) {
                this.compressionAlgo = compressionAlgo;
                this.compressedServicedata = compressed;
            } else {
                this.compressionAlgo = null;
                this.compressedServicedata = data;
            }
        } else {
            this.compressionAlgo = null;
            this.compressedServicedata = data;
        }
        
        // Save the crypto context.
        this.cryptoContext = cryptoContext;
        
        this.tokendataBytes = null;
        this.signatureBytes = null;
        this.verified = true;
    }
    
    /**
     * <p>Construct a new service token from the provided MSL object and
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
     * @param serviceTokenMo the MSL object.
     * @param masterToken the master token. May be null.
     * @param userIdToken the user ID token. May be null.
     * @param cryptoContexts a map of service token names onto crypto contexts.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the token data.
     * @throws MslException if the service token is bound to a master token or
     *         user ID token and the provided tokens are null or the serial
     *         numbers do not match, or if bound to a user ID token but not to
     *         a master token, or if the service data is missing, or if the
     *         compression algorithm is not known or there is an error
     *         uncompressing the data.
     */
    public ServiceToken(final MslContext ctx, final MslObject serviceTokenMo, final MasterToken masterToken, final UserIdToken userIdToken, final Map<String,ICryptoContext> cryptoContexts) throws MslEncodingException, MslCryptoException, MslException {
        this(ctx, serviceTokenMo, masterToken, userIdToken, selectCryptoContext(ctx.getMslEncoderFactory(), serviceTokenMo, cryptoContexts));
    }
    
    /**
     * <p>Construct a new service token from the provided MSL object.</p>
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
     * @param serviceTokenMo the MSL object.
     * @param masterToken the master token. May be null.
     * @param userIdToken the user ID token. May be null.
     * @param cryptoContext the crypto context. May be null.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the token data.
     * @throws MslEncodingException if there is a problem parsing the data, the
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
    public ServiceToken(final MslContext ctx, final MslObject serviceTokenMo, final MasterToken masterToken, final UserIdToken userIdToken, final ICryptoContext cryptoContext) throws MslCryptoException, MslEncodingException, MslException {
        this.ctx = ctx;
        this.cryptoContext = cryptoContext;
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        
        // Verify the data representation.
        try {
            tokendataBytes = serviceTokenMo.getBytes(KEY_TOKENDATA);
            if (tokendataBytes.length == 0)
                throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_MISSING, "servicetoken " + serviceTokenMo).setMasterToken(masterToken).setUserIdToken(userIdToken);
            signatureBytes = serviceTokenMo.getBytes(KEY_SIGNATURE);
            verified = (cryptoContext != null) ? cryptoContext.verify(tokendataBytes, signatureBytes, encoder) : false;
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "servicetoken " + serviceTokenMo, e).setMasterToken(masterToken).setUserIdToken(userIdToken);
        } catch (final MslCryptoException e) {
            e.setMasterToken(masterToken);
            throw e;
        }
        
        // Pull the token data.
        try {
            final MslObject tokendata = encoder.parseObject(tokendataBytes);
            name = tokendata.getString(KEY_NAME);
            if (tokendata.has(KEY_MASTER_TOKEN_SERIAL_NUMBER)) {
                mtSerialNumber = tokendata.getLong(KEY_MASTER_TOKEN_SERIAL_NUMBER);
                if (mtSerialNumber < 0 || mtSerialNumber > MslConstants.MAX_LONG_VALUE)
                    throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "servicetokendata " + tokendata).setMasterToken(masterToken).setUserIdToken(userIdToken);
            } else {
                mtSerialNumber = -1;
            }
            if (tokendata.has(KEY_USER_ID_TOKEN_SERIAL_NUMBER)) {
                uitSerialNumber = tokendata.getLong(KEY_USER_ID_TOKEN_SERIAL_NUMBER);
                if (uitSerialNumber < 0 || uitSerialNumber > MslConstants.MAX_LONG_VALUE)
                    throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "servicetokendata " + tokendata).setMasterToken(masterToken).setUserIdToken(userIdToken);
            } else {
                uitSerialNumber = -1;
            }
            // There has to be a master token serial number if there is a
            // user ID token serial number.
            
            encrypted = tokendata.getBoolean(KEY_ENCRYPTED);
            if (tokendata.has(KEY_COMPRESSION_ALGORITHM)) {
                final String algoName = tokendata.getString(KEY_COMPRESSION_ALGORITHM);
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
            final byte[] data = tokendata.getBytes(KEY_SERVICEDATA);
            if (verified) {
                final byte[] ciphertext = data;
                compressedServicedata = (encrypted && ciphertext.length > 0)
                    ? cryptoContext.decrypt(ciphertext, encoder)
                    : ciphertext;
                servicedata = (compressionAlgo != null)
                    ? MslCompression.uncompress(compressionAlgo, compressedServicedata)
                    : compressedServicedata;
            } else {
                compressedServicedata = data;
                servicedata = (data.length == 0) ? new byte[0] : null;
            }
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "servicetokendata " + Base64.encode(tokendataBytes), e).setMasterToken(masterToken).setUserIdToken(userIdToken);
        } catch (final MslCryptoException e) {
            e.setMasterToken(masterToken);
            e.setUserIdToken(userIdToken);
            throw e;
        }
        
        // Verify serial numbers.
        if (mtSerialNumber != -1 && (masterToken == null || mtSerialNumber != masterToken.getSerialNumber()))
            throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH, "st mtserialnumber " + mtSerialNumber + "; mt " + masterToken).setMasterToken(masterToken).setUserIdToken(userIdToken);
        if (uitSerialNumber != -1 && (userIdToken == null || uitSerialNumber != userIdToken.getSerialNumber()))
            throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH, "st uitserialnumber " + uitSerialNumber + "; uit " + userIdToken).setMasterToken(masterToken).setUserIdToken(userIdToken);
    }
    
    /**
     * @return true if the content is encrypted.
     */
    public boolean isEncrypted() {
        return encrypted;
    }
    
    /**
     * @return true if the decrypted content is available. (Implies verified.)
     */
    public boolean isDecrypted() {
        return servicedata != null;
    }
    
    /**
     * @return true if the token has been verified.
     */
    public boolean isVerified() {
        return verified;
    }
    
    /**
     * @return the application token name.
     */
    public String getName() {
        return name;
    }
    
    /**
     * @return true if this token has been marked for deletion.
     * @see #getData()
     */
    public boolean isDeleted() {
        return servicedata != null && servicedata.length == 0;
    }
    
    /**
     * @return the compression algorithm. May be {@code null} if not
     *         compressed.
     */
    public CompressionAlgorithm getCompressionAlgo() {
        return compressionAlgo;
    }
    
    /**
     * Returns the service data if the token data was not encrypted or we were
     * able to decrypt it.
     * 
     * Zero-length data indicates this token should be deleted.
     * 
     * @return the service data or null if we don't have it.
     * @see #isDeleted()
     */
    public byte[] getData() {
        return servicedata;
    }
    
    /**
     * Returns the serial number of the master token this service token is
     * bound to.
     * 
     * @return the master token serial number or -1 if unbound.
     */
    public long getMasterTokenSerialNumber() {
        return mtSerialNumber;
    }
    
    /**
     * @return true if this token is bound to a master token.
     */
    public boolean isMasterTokenBound() {
        return mtSerialNumber != -1;
    }
    
    /**
     * @param masterToken master token. May be null.
     * @return true if this token is bound to the provided master token.
     */
    public boolean isBoundTo(final MasterToken masterToken) {
        return masterToken != null && masterToken.getSerialNumber() == mtSerialNumber;
    }
    
    /**
     * Returns the serial number of the user ID token this service token is
     * bound to.
     * 
     * @return the user ID token serial number or -1 if unbound.
     */
    public long getUserIdTokenSerialNumber() {
        return uitSerialNumber;
    }
    
    /**
     * Returns true if this token is bound to a user ID token. This implies the
     * token is bound to a master token as well.
     * 
     * @return true if this token is bound to a user ID token.
     */
    public boolean isUserIdTokenBound() {
        return uitSerialNumber != -1;
    }
    
    /**
     * @param userIdToken user ID token. May be null.
     * @return true if this token is bound to the provided user ID token.
     */
    public boolean isBoundTo(final UserIdToken userIdToken) {
        return userIdToken != null && userIdToken.getSerialNumber() == uitSerialNumber;
    }
    
    /**
     * @return true if this token is not bound to a master token or user ID
     *         token.
     */
    public boolean isUnbound() {
        return mtSerialNumber == -1 && uitSerialNumber == -1;
    }
    
    /** MSL context. */
    private final MslContext ctx;
    /** Service token crypto context. */
    private final ICryptoContext cryptoContext;
    
    /** The service token name. */
    private final String name;
    /** The service token master token serial number. */
    private final long mtSerialNumber;
    /** The service token user ID token serial number. */
    private final long uitSerialNumber;
    /** Service token data is encrypted. */
    private final boolean encrypted;
    /** Compression algorithm. */
    private final CompressionAlgorithm compressionAlgo;
    /** The service token data. */
    private final byte[] servicedata;
    /** The compressed service token data. */
    private final byte[] compressedServicedata;

    /** Token data bytes. */
    private final byte[] tokendataBytes;
    /** Signature bytes. */
    private final byte[] signatureBytes;
    
    /** Token is verified. */
    private final boolean verified;
    
    /** Cached encodings. */
    private final Map<MslEncoderFormat,byte[]> encodings = new HashMap<MslEncoderFormat,byte[]>();
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        // Return any cached encoding.
        if (encodings.containsKey(format))
            return encodings.get(format);
        
        // If we parsed this token (i.e. did not create it from scratch) then
        // we should not re-encrypt or re-sign as there is no guarantee out MSL
        // crypto context is capable of encrypting and signing with the same
        // keys, even if it is capable of decrypting and verifying.
        final byte[] data, signature;
        if (tokendataBytes != null || signatureBytes != null) {
            data = tokendataBytes;
            signature = signatureBytes;
        }
        //
        // Otherwise create the token data and signature.
        else {
            // Encrypt the service data if the length is > 0. Otherwise encode
            // as empty data to indicate this token should be deleted.
            final byte[] ciphertext;
            try {
                ciphertext = (encrypted && compressedServicedata.length > 0)
                    ? cryptoContext.encrypt(compressedServicedata, encoder, format)
                    : compressedServicedata;
            } catch (final MslCryptoException e) {
                throw new MslEncoderException("Error encrypting the service data.", e);
            }
            
            // Construct the token data.
            final MslObject tokendata = encoder.createObject();
            tokendata.put(KEY_NAME, this.name);
            if (this.mtSerialNumber != -1) tokendata.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, this.mtSerialNumber);
            if (this.uitSerialNumber != -1) tokendata.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, this.uitSerialNumber);
            tokendata.put(KEY_ENCRYPTED, this.encrypted);
            if (this.compressionAlgo != null) tokendata.put(KEY_COMPRESSION_ALGORITHM, this.compressionAlgo.name());
            tokendata.put(KEY_SERVICEDATA, ciphertext);

            // Sign the token data.
            data = encoder.encodeObject(tokendata, format);
            try {
                signature = cryptoContext.sign(data, encoder, format);
            } catch (final MslCryptoException e) {
                throw new MslEncoderException("Error signing the token data.", e);
            }
        }

        // Encode the token.
        final MslObject token = encoder.createObject();
        token.put(KEY_TOKENDATA, data);
        token.put(KEY_SIGNATURE, signature);
        final byte[] encoding = encoder.encodeObject(token, format);

        // Cache and return the encoding.
        encodings.put(format, encoding);
        return encoding;
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();

        final MslObject tokendata = encoder.createObject();
        tokendata.put(KEY_NAME, name);
        tokendata.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, mtSerialNumber);
        tokendata.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, uitSerialNumber);
        tokendata.put(KEY_SERVICEDATA, "(redacted)");

        final MslObject token = encoder.createObject();
        token.put(KEY_TOKENDATA, tokendata);
        token.put(KEY_SIGNATURE, (signatureBytes != null) ? signatureBytes : "(null)");
        return token.toString();
    }

    /**
     * <p>Returns true if the other object is a service token with the same
     * name and bound to the same tokens.</p>
     * 
     * <p>This function is designed for use with sets and maps to guarantee
     * uniqueness of individual service tokens.</p>
     * 
     * @param obj the reference object with which to compare.
     * @return true if the other object is a service token with the same name
     *         and bound to the same tokens.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (obj instanceof ServiceToken) {
            final ServiceToken that = (ServiceToken)obj;
            return this.name.equals(that.name) &&
                this.mtSerialNumber == that.mtSerialNumber &&
                this.uitSerialNumber == that.uitSerialNumber;
        }
        return false;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return (this.name + ":" + String.valueOf(mtSerialNumber) + ":" + String.valueOf(uitSerialNumber)).hashCode();
    }
}
