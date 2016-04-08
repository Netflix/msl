/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.keyx;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.CryptoCache;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.JsonWebKey;
import com.netflix.msl.crypto.JsonWebKey.Algorithm;
import com.netflix.msl.crypto.JsonWebKey.KeyOp;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

/**
 * <p>JSON Web Key ladder key exchange.</p>
 * 
 * <p>The key ladder consists of a symmetric wrapping key used to protect the
 * session keys. The wrapping key is only permitted to wrap and unwrap data. It
 * cannot be used for encrypt/decrypt or sign/verify operations.</p>
 * 
 * <p>The wrapping key is protected by wrapping it with a known common key
 * (e.g. preshared keys) or the previously used wrapping key. The previous
 * wrapping key must be provided by the requesting entity in the form found in
 * the response data.</p> 
 * 
 * <p>The wrapping key is always an AES-128 key for AES key wrap/unwrap.</p>
 * 
 * <p>This key exchange scheme does not provide perfect forward secrecy and
 * should only be used if necessary to satisfy other security requirements.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonWebKeyLadderExchange extends KeyExchangeFactory {
    /** Encoding charset. */
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    
    /** Dummy wrapping key ID. */
    private static final String WRAP_KEY_ID = "wrapKeyId";
    
    /** Encrypt/decrypt key operations. */
    private static final Set<KeyOp> ENCRYPT_DECRYPT = new HashSet<KeyOp>(Arrays.asList(KeyOp.encrypt, KeyOp.decrypt));
    /** Wrap/unwrap key operations. */
    private static final Set<KeyOp> WRAP_UNWRAP = new HashSet<KeyOp>(Arrays.asList(KeyOp.wrapKey, KeyOp.unwrapKey));
    /** Sign/verify key operations. */
    private static final Set<KeyOp> SIGN_VERIFY = new HashSet<KeyOp>(Arrays.asList(KeyOp.sign, KeyOp.verify));
    
    /** Wrapping key wrap mechanism. */
    public enum Mechanism {
        /** Wrapping key wrapped by PSK (AES-128 key wrap). */
        PSK,
        /** Wrapping key wrapped by previous wrapping key (AES-128 key wrap). */
        WRAP,
    }
    
    /**
     * <p>JSON Web Key ladder key request data.</p>
     * 
     * <p>
     * {@code {
     *   "#mandatory" : [ "mechanism" ],
     *   "mechanism" : "enum(PSK|MGK|WRAP)",
     *   "wrapdata" : "base64",
     * }} where:
     * <ul>
     * <li>{@code mechanism} identifies the mechanism for wrapping and unwrapping the wrapping key</li>
     * <li>{@code wrapdata} the Base64-encoded wrapping data for the previous wrapping key</li>
     * </ul></p>
     */
    public static class RequestData extends KeyRequestData {
        /** JSON key wrap key wrapping mechanism. */
        private static final String KEY_MECHANISM = "mechanism";
        /** JSON key wrap data. */
        private static final String KEY_WRAPDATA = "wrapdata";
        
        /**
         * <p>Create a new JSON Web Key ladder key request data instance
         * with the specified mechanism and wrapping key data.</p>
         * 
         * <p>Arguments not applicable to the specified mechanism are
         * ignored.</p>
         * 
         * @param mechanism the wrap key wrapping mechanism.
         * @param wrapdata the wrap data for reconstructing the previous
         *        wrapping key. May be null if the mechanism does not use the
         *        previous wrapping key.
         * @throws MslInternalException if the mechanism requires wrap data and
         *         the required argument is null.
         */
        public RequestData(final Mechanism mechanism, final byte[] wrapdata) {
            super(KeyExchangeScheme.JWK_LADDER);
            this.mechanism = mechanism;
            
            switch (mechanism) {
                case WRAP:
                    if (wrapdata == null)
                        throw new MslInternalException("Previous wrapping key based key exchange requires the previous wrapping key data and ID.");
                    this.wrapdata = wrapdata;
                    break;
                default:
                    this.wrapdata = null;
                    break;
            }
        }
        
        /**
         * Create a new JSON Web Key ladder key request data instance
         * from the provided JSON object.
         * 
         * @param keyRequestJO the JSON object.
         * @throws MslEncodingException if there is an error parsing the JSON.
         * @throws MslCryptoException the wrapped key data cannot be verified
         *         or decrypted, or the specified mechanism is not supported.
         * @throws MslKeyExchangeException if the specified mechanism is not
         *         recognized or the wrap data is missing or invalid.
         */
        public RequestData(final JSONObject keyRequestJO) throws MslCryptoException, MslKeyExchangeException, MslEncodingException {
            super(KeyExchangeScheme.JWK_LADDER);
            
            try {
                final String mechanismName = keyRequestJO.getString(KEY_MECHANISM);
                try {
                    mechanism = Mechanism.valueOf(mechanismName);
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_MECHANISM, mechanismName, e);
                }
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + keyRequestJO.toString(), e);
            }
            
            try {
                switch (mechanism) {
                    case PSK:
                    {
                        wrapdata = null;
                        break;
                    }
                    case WRAP:
                    {
                        try {
                            wrapdata = Base64.decode(keyRequestJO.getString(KEY_WRAPDATA));
                        } catch (final IllegalArgumentException e) {
                            throw new MslKeyExchangeException(MslError.KEYX_INVALID_WRAPDATA, "keydata " + keyRequestJO.toString(), e);
                        }
                        if (wrapdata == null || wrapdata.length == 0)
                            throw new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING, "keydata " + keyRequestJO.toString());
                        break;
                    }
                    default:
                        throw new MslCryptoException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name());
                }
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + keyRequestJO.toString(), e);
            }
        }

        /**
         * @return the wrap key wrapping mechanism.
         */
        public Mechanism getMechanism() {
            return mechanism;
        }
        
        /**
         * @return the previous wrapping key data or null if not applicable.
         */
        public byte[] getWrapdata() {
            return wrapdata;
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyRequestData#getKeydata()
         */
        @Override
        protected JSONObject getKeydata() throws JSONException {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_MECHANISM, mechanism.name());
            if (wrapdata != null) jsonObj.put(KEY_WRAPDATA, Base64.encode(wrapdata));
            return jsonObj;
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyRequestData#equals(java.lang.Object)
         */
        @Override
        public boolean equals(final Object obj) {
            if (obj == this) return true;
            if (!(obj instanceof RequestData)) return false;
            final RequestData that = (RequestData)obj;
            final boolean wrapdataEqual = Arrays.equals(wrapdata, that.wrapdata);
            return super.equals(obj) &&
                mechanism.equals(that.mechanism) &&
                wrapdataEqual;
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyRequestData#hashCode()
         */
        @Override
        public int hashCode() {
            final int wrapdataHashCode = (wrapdata != null) ? Arrays.hashCode(wrapdata) : 0;
            return super.hashCode() ^
                mechanism.hashCode() ^
                wrapdataHashCode;
        }
        
        /** Wrap key wrapping mechanism. */
        private final Mechanism mechanism;
        /** Wrap data. */
        private final byte[] wrapdata;
    }
    
    /**
     * <p>JSON Web Key ladder key response data.</p>
     * 
     * <p>
     * {@code {
     *   "#mandatory" : [ "wrapkey", "wrapdata", "encryptionkey", "hmackey" ],
     *   "wrapkey" : "base64",
     *   "wrapdata" : "base64",
     *   "encryptionkey" : "base64",
     *   "hmackey" : "base64",
     * }} where:
     * <ul>
     * <li>{@code wrapkey} the Base64-encoded new wrapping key in JWK format, wrapped by the wrapping key</li>
     * <li>{@code wrapdata} the Base64-encoded wrapping key data for use in subsequent key request data</li>
     * <li>{@code encryptionkey} the Base64-encoded session encryption key in JWK format, wrapped with the new wrapping key</li>
     * <li>{@code hmackey} the Base64-encoded session HMAC key in JWK format, wrapped with the new wrapping key</li>
     * </ul></p>
     */
    public static class ResponseData extends KeyResponseData {
        /** JSON key wrapping key. */
        private static final String KEY_WRAP_KEY = "wrapkey";
        /** JSON key wrapping key data. */
        private static final String KEY_WRAPDATA = "wrapdata";
        /** JSON key encrypted encryption key. */
        private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
        /** JSON key encrypted HMAC key. */
        private static final String KEY_HMAC_KEY = "hmackey";
        
        /**
         * Create a new JSON Web Key ladder key response data instance
         * with the provided master token and wrapped keys.
         * 
         * @param masterToken the master token.
         * @param wrapKey the wrapped wrap key.
         * @param wrapdata the wrap data for reconstructing the wrap key.
         * @param encryptionKey the wrap key wrapped encryption key.
         * @param hmacKey the wrap key wrapped HMAC key.
         */
        public ResponseData(final MasterToken masterToken, final byte[] wrapKey, final byte[] wrapdata, final byte[] encryptionKey, final byte[] hmacKey) {
            super(masterToken, KeyExchangeScheme.JWK_LADDER);
            this.wrapKey = wrapKey;
            this.wrapdata = wrapdata;
            this.encryptionKey = encryptionKey;
            this.hmacKey = hmacKey;
        }

        /**
         * Create a new JSON Web Key ladder key response data instance
         * with the provided master token from the provided JSON object.
         * 
         * @param masterToken the master token.
         * @param keyDataJO the JSON object.
         * @throws MslEncodingException if there is an error parsing the JSON.
         * @throws MslKeyExchangeException if the mechanism is not recognized.
         */
        public ResponseData(final MasterToken masterToken, final JSONObject keyDataJO) throws MslKeyExchangeException, MslEncodingException {
            super(masterToken, KeyExchangeScheme.JWK_LADDER);
            try {
                try {
                    wrapKey = Base64.decode(keyDataJO.getString(KEY_WRAP_KEY));
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_WRAPPING_KEY, "keydata " + keyDataJO.toString(), e);
                }
                try {
                    wrapdata = Base64.decode(keyDataJO.getString(KEY_WRAPDATA));
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_WRAPDATA, "keydata " + keyDataJO.toString(), e);
                }
                try {
                    encryptionKey = Base64.decode(keyDataJO.getString(KEY_ENCRYPTION_KEY));
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_ENCRYPTION_KEY, "keydata " + keyDataJO.toString(), e);
                }
                try {
                    hmacKey = Base64.decode(keyDataJO.getString(KEY_HMAC_KEY));
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_HMAC_KEY, "keydata " + keyDataJO.toString(), e);
                }
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + keyDataJO.toString(), e);
            }
        }
        
        /**
         * @return the session key wrapping key.
         */
        public byte[] getWrapKey() {
            return wrapKey;
        }
        
        /**
         * @return the session key wrapping key data.
         */
        public byte[] getWrapdata() {
            return wrapdata;
        }

        /**
         * @return the wrapped session encryption key.
         */
        public byte[] getEncryptionKey() {
            return encryptionKey;
        }

        /**
         * @return the wrapped session HMAC key.
         */
        public byte[] getHmacKey() {
            return hmacKey;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyResponseData#getKeydata()
         */
        @Override
        protected JSONObject getKeydata() throws JSONException {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_WRAP_KEY, Base64.encode(wrapKey));
            jsonObj.put(KEY_WRAPDATA, Base64.encode(wrapdata));
            jsonObj.put(KEY_ENCRYPTION_KEY, Base64.encode(encryptionKey));
            jsonObj.put(KEY_HMAC_KEY, Base64.encode(hmacKey));
            return jsonObj;
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyResponseData#equals(java.lang.Object)
         */
        @Override
        public boolean equals(final Object obj) {
            if (obj == this) return true;
            if (!(obj instanceof ResponseData)) return false;
            final ResponseData that = (ResponseData)obj;
            return super.equals(obj) &&
                Arrays.equals(wrapKey, that.wrapKey) &&
                Arrays.equals(wrapdata, that.wrapdata) &&
                Arrays.equals(encryptionKey, that.encryptionKey) &&
                Arrays.equals(hmacKey, that.hmacKey);
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyResponseData#hashCode()
         */
        @Override
        public int hashCode() {
            return super.hashCode() ^
                Arrays.hashCode(wrapKey) ^
                Arrays.hashCode(wrapdata) ^
                Arrays.hashCode(encryptionKey) ^
                Arrays.hashCode(hmacKey);
        }
        
        /** Wrapped wrap key. */
        private final byte[] wrapKey;
        /** Wrap data. */
        private final byte[] wrapdata;
        /** Wrapped encryption key. */
        private final byte[] encryptionKey;
        /** Wrapped HMAC key. */
        private final byte[] hmacKey;
    }
    
    /**
     * <p>A specialized crypto context for wrapping and unwrapping JSON web
     * keys.</p>
     * 
     * <p>Implementations of this class must add and remove padding to the JSON
     * web key string representation's binary encoding for compatibility with
     * the wrapping algorithm used.</p> 
     */
    public static abstract class JwkCryptoContext implements ICryptoContext {
        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#encrypt(byte[])
         */
        @Override
        public byte[] encrypt(final byte[] data) throws MslCryptoException {
            throw new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#decrypt(byte[])
         */
        @Override
        public byte[] decrypt(final byte[] data) throws MslCryptoException {
            throw new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#sign(byte[])
         */
        @Override
        public byte[] sign(final byte[] data) throws MslCryptoException {
            throw new MslCryptoException(MslError.SIGN_NOT_SUPPORTED);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#verify(byte[], byte[])
         */
        @Override
        public boolean verify(final byte[] data, final byte[] signature) throws MslCryptoException {
            throw new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED);
        }
    }
    
    /**
     * AES key wrap JSON web key crypto context.
     */
    public static class AesKwJwkCryptoContext extends JwkCryptoContext {
        /** AES key wrap cipher transform. */
        private static final String A128_KW_TRANSFORM = "AESWrap";
        /** AES key wrap block size in bytes. */
        private static final int AES_KW_BLOCK_SIZE = 8;
        
        /** Space character. */
        private static final byte SPACE = (byte)' ';
        
        /**
         * Create an AES key wrap JSON web key crypto context. The provided
         * crypto context must perform AES key wrap for its wrap and unwrap
         * functions.
         * 
         * @param cryptoContext the backing crypto context.
         */
        public AesKwJwkCryptoContext(final ICryptoContext cryptoContext) {
            this.key = null;
            this.cryptoContext = cryptoContext;
        }
        
        /**
         * Create an AES key wrap JSON web key crypto context with the provided
         * key.
         * 
         * @param key AES secret key.
         */
        public AesKwJwkCryptoContext(final SecretKey key) {
            if (!key.getAlgorithm().equals(JcaAlgorithm.AESKW))
                throw new IllegalArgumentException("Secret key must be an " + JcaAlgorithm.AESKW + " key.");
            this.key = key;
            this.cryptoContext = null;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[])
         */
        @Override
        public byte[] wrap(final byte[] data) throws MslCryptoException {
            // Compute the number of bytes that are not aligned to the block
            // size.
            final int unalignedBytes = data.length % AES_KW_BLOCK_SIZE;
            
            // If there are no unaligned bytes then we're good. Otherwise add
            // spaces after the opening brace as padding. This assumes the data
            // is actually the UTF-8 binary representation of a JSON web key.
            final byte[] alignedJwk;
            if (unalignedBytes == 0) {
                alignedJwk = data;
            } else {
                final int paddingCount = AES_KW_BLOCK_SIZE - unalignedBytes;
                alignedJwk = new byte[data.length + paddingCount];
                alignedJwk[0] = '{';
                final int dataOffset = 1 + paddingCount;
                Arrays.fill(alignedJwk, 1, dataOffset, SPACE);
                System.arraycopy(data, 1, alignedJwk, dataOffset, data.length - 1);
            }
            
            // If a secret key is provided use it.
            if (key != null) {
                try {
                    // Encrypt plaintext.
                    final Cipher cipher = CryptoCache.getCipher(A128_KW_TRANSFORM);
                    cipher.init(Cipher.WRAP_MODE, key);
                    // The wrap() function requires a key object, but the data
                    // we are trying to wrap is not necessarily a key. However
                    // it should be aligned to the AES key wrap block size so
                    // we can use the AES key wrap algorithm.
                    final Key secretKey = new SecretKeySpec(alignedJwk, JcaAlgorithm.AESKW);
                    return cipher.wrap(secretKey);
                } catch (final NoSuchPaddingException e) {
                    throw new MslInternalException("Unsupported padding exception.", e);
                } catch (final NoSuchAlgorithmException e) {
                    throw new MslInternalException("Invalid cipher algorithm specified.", e);
                } catch (final IllegalArgumentException e) {
                    throw new MslInternalException("Zero-length plaintext provided.", e);
                } catch (final InvalidKeyException e) {
                    throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, e);
                } catch (final IllegalBlockSizeException e) {
                    throw new MslCryptoException(MslError.PLAINTEXT_ILLEGAL_BLOCK_SIZE, "not expected when padding is specified", e);
                }
            }
            
            // Otherwise use the backing crypto context.
            return cryptoContext.wrap(alignedJwk);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#unwrap(byte[])
         */
        @Override
        public byte[] unwrap(final byte[] data) throws MslCryptoException {
            // If a secret key is provided use it.
            if (key != null) {
                try {
                    // Decrypt ciphertext.
                    final Cipher cipher = CryptoCache.getCipher(A128_KW_TRANSFORM);
                    cipher.init(Cipher.UNWRAP_MODE, key);
                    return cipher.unwrap(data, "AES", Cipher.SECRET_KEY).getEncoded();
                } catch (final NoSuchPaddingException e) {
                    throw new MslInternalException("Unsupported padding exception.", e);
                } catch (final NoSuchAlgorithmException e) {
                    throw new MslInternalException("Invalid cipher algorithm specified.", e);
                } catch (final InvalidKeyException e) {
                    throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, e);
                }
            }
            
            // Otherwise use the backing crypto context.
            return cryptoContext.unwrap(data);
        }
        
        /** AES secret key. */
        private final SecretKey key;
        /** AES key wrap crypto context. */
        private final ICryptoContext cryptoContext;
    }
    
    /**
     * Create the JSON web key crypto context identified by the mechanism.
     * 
     * @param ctx MSL context.
     * @param mechanism the wrap key wrapping mechanism.
     * @param wrapdata the wrap key previous wrapping key data. May be null.
     * @param identity the entity identity.
     * @return the JSON web key crypto context.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslKeyExchangeException if the mechanism is unsupported.
     * @throws MslEntityAuthException if there is a problem with the entity
     *         identity.
     */
    private static JwkCryptoContext createCryptoContext(final MslContext ctx, final Mechanism mechanism, final byte[] wrapdata, final String identity) throws MslKeyExchangeException, MslCryptoException, MslEntityAuthException {
        switch (mechanism) {
            case PSK:
            {
                final EntityAuthenticationData authdata = new PresharedAuthenticationData(identity);
                final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
                if (factory == null)
                    throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name());
                final ICryptoContext aesKwCryptoContext = factory.getCryptoContext(ctx, authdata);
                return new AesKwJwkCryptoContext(aesKwCryptoContext);
            }
            case WRAP:
            {
                final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
                final byte[] wrapBytes = cryptoContext.unwrap(wrapdata);
                if (wrapBytes == null || wrapBytes.length == 0)
                    throw new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING);
                final SecretKey wrapKey = new SecretKeySpec(wrapBytes, JcaAlgorithm.AESKW);
                return new AesKwJwkCryptoContext(wrapKey);
            }
            default:
                throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name());
        }
    }
    
    /**
     * Create a new JSON Web Key ladder key exchange factory.
     * 
     * @param repository the wrapping key crypto context repository.
     * @param authutils authentication utilities.
     */
    public JsonWebKeyLadderExchange(final WrapCryptoContextRepository repository, final AuthenticationUtils authutils) {
        super(KeyExchangeScheme.JWK_LADDER);
        this.repository = repository;
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createRequestData(com.netflix.msl.util.MslContext, org.json.JSONObject)
     */
    @Override
    protected KeyRequestData createRequestData(final MslContext ctx, final JSONObject keyRequestJO) throws MslEncodingException, MslKeyExchangeException, MslCryptoException {
        return new RequestData(keyRequestJO);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createResponseData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, org.json.JSONObject)
     */
    @Override
    protected KeyResponseData createResponseData(final MslContext ctx, final MasterToken masterToken, final JSONObject keyDataJO) throws MslEncodingException, MslKeyExchangeException {
        return new ResponseData(masterToken, keyDataJO);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public KeyExchangeData generateResponse(final MslContext ctx, final KeyRequestData keyRequestData, final MasterToken masterToken) throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException, MslException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData)keyRequestData;

        // If the master token was not issued by the local entity then we
        // should not be generating a key response for it.
        if (!masterToken.isVerified())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        
        // Grab the request data.
        final Mechanism mechanism = request.getMechanism();
        final byte[] prevWrapdata = request.getWrapdata();
        final String identity = masterToken.getIdentity();
        
        // Verify the scheme is permitted.
        if(!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + this.getScheme());
        
        // Create random AES-128 wrapping key.
        final byte[] wrapBytes = new byte[16];
        ctx.getRandom().nextBytes(wrapBytes);
        final SecretKey wrapKey = new SecretKeySpec(wrapBytes, JcaAlgorithm.AESKW);
        
        // Create the wrap data.
        final ICryptoContext mslCryptoContext = ctx.getMslCryptoContext();
        final byte[] wrapdata = mslCryptoContext.wrap(wrapBytes);
        
        // Create random AES-128 encryption and SHA-256 HMAC keys.
        final byte[] encryptionBytes = new byte[16];
        final byte[] hmacBytes = new byte[32];
        ctx.getRandom().nextBytes(encryptionBytes);
        ctx.getRandom().nextBytes(hmacBytes);
        final SecretKey encryptionKey = new SecretKeySpec(encryptionBytes, JcaAlgorithm.AES);
        final SecretKey hmacKey = new SecretKeySpec(hmacBytes, JcaAlgorithm.HMAC_SHA256);
        
        // Wrap wrapping key using specified wrapping key.
        final JsonWebKey wrapJwk = new JsonWebKey(WRAP_UNWRAP, Algorithm.A128KW, false, WRAP_KEY_ID, wrapKey);
        final ICryptoContext wrapKeyCryptoContext = createCryptoContext(ctx, mechanism, prevWrapdata, identity);
        final byte[] wrappedWrapJwk = wrapKeyCryptoContext.wrap(wrapJwk.toJSONString().getBytes(UTF_8));
        
        // Wrap session keys inside JSON Web Key objects with the wrapping key.
        final ICryptoContext wrapCryptoContext = new AesKwJwkCryptoContext(wrapKey);
        final JsonWebKey encryptionJwk = new JsonWebKey(ENCRYPT_DECRYPT, Algorithm.A128CBC, false, null, encryptionKey);
        final JsonWebKey hmacJwk = new JsonWebKey(SIGN_VERIFY, Algorithm.HS256, false, null, hmacKey);
        final byte[] wrappedEncryptionJwk = wrapCryptoContext.wrap(encryptionJwk.toJSONString().getBytes(UTF_8));
        final byte[] wrappedHmacJwk = wrapCryptoContext.wrap(hmacJwk.toJSONString().getBytes(UTF_8));
        
        // Create the master token.
        final TokenFactory tokenFactory = ctx.getTokenFactory();
        final MasterToken newMasterToken = tokenFactory.renewMasterToken(ctx, masterToken, encryptionKey, hmacKey, null);
        
        // Create session crypto context.
        final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, newMasterToken);
        
        // Return the key exchange data.
        final KeyResponseData keyResponseData = new ResponseData(newMasterToken, wrappedWrapJwk, wrapdata, wrappedEncryptionJwk, wrappedHmacJwk);
        return new KeyExchangeData(keyResponseData, cryptoContext);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public KeyExchangeData generateResponse(final MslContext ctx, final KeyRequestData keyRequestData,final EntityAuthenticationData entityAuthData) throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData)keyRequestData;
        
        // Verify the scheme is permitted.
        final String identity = entityAuthData.getIdentity();
        if(!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + this.getScheme());

        // Create random AES-128 wrapping key.
        final byte[] wrapBytes = new byte[16];
        ctx.getRandom().nextBytes(wrapBytes);
        final SecretKey wrapKey = new SecretKeySpec(wrapBytes, JcaAlgorithm.AESKW);
        
        // Create the wrap data.
        final ICryptoContext mslCryptoContext = ctx.getMslCryptoContext();
        final byte[] wrapdata = mslCryptoContext.wrap(wrapBytes);
        
        // Create random AES-128 encryption and SHA-256 HMAC keys.
        final byte[] encryptionBytes = new byte[16];
        final byte[] hmacBytes = new byte[32];
        ctx.getRandom().nextBytes(encryptionBytes);
        ctx.getRandom().nextBytes(hmacBytes);
        final SecretKey encryptionKey = new SecretKeySpec(encryptionBytes, JcaAlgorithm.AES);
        final SecretKey hmacKey = new SecretKeySpec(hmacBytes, JcaAlgorithm.HMAC_SHA256);
        
        // Grab the request data.
        final Mechanism mechanism = request.getMechanism();
        final byte[] prevWrapdata = request.getWrapdata();
        
        // Wrap wrapping key using specified wrapping key.
        final JsonWebKey wrapJwk = new JsonWebKey(WRAP_UNWRAP, Algorithm.A128KW, false, WRAP_KEY_ID, wrapKey);
        final ICryptoContext wrapKeyCryptoContext = createCryptoContext(ctx, mechanism, prevWrapdata, identity);
        final byte[] wrappedWrapJwk = wrapKeyCryptoContext.wrap(wrapJwk.toJSONString().getBytes(UTF_8));
        
        // Wrap session keys inside JSON Web Key objects with the wrapping key.
        final ICryptoContext wrapCryptoContext = new AesKwJwkCryptoContext(wrapKey);
        final JsonWebKey encryptionJwk = new JsonWebKey(ENCRYPT_DECRYPT, Algorithm.A128CBC, false, null, encryptionKey);
        final JsonWebKey hmacJwk = new JsonWebKey(SIGN_VERIFY, Algorithm.HS256, false, null, hmacKey);
        final byte[] wrappedEncryptionJwk = wrapCryptoContext.wrap(encryptionJwk.toJSONString().getBytes(UTF_8));
        final byte[] wrappedHmacJwk = wrapCryptoContext.wrap(hmacJwk.toJSONString().getBytes(UTF_8));
        
        // Create the master token.
        final TokenFactory tokenFactory = ctx.getTokenFactory();
        final MasterToken newMasterToken = tokenFactory.createMasterToken(ctx, entityAuthData, encryptionKey, hmacKey, null);
        
        // Create session crypto context.
        final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, newMasterToken);
        
        // Return the key exchange data.
        final KeyResponseData keyResponseData = new ResponseData(newMasterToken, wrappedWrapJwk, wrapdata, wrappedEncryptionJwk, wrappedHmacJwk);
        return new KeyExchangeData(keyResponseData, cryptoContext);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.keyx.KeyResponseData, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final KeyRequestData keyRequestData, final KeyResponseData keyResponseData, final MasterToken masterToken) throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData)keyRequestData;
        if (!(keyResponseData instanceof ResponseData))
            throw new MslInternalException("Key response data " + keyResponseData.getClass().getName() + " was not created by this factory.");
        final ResponseData response = (ResponseData)keyResponseData;
        
        // Unwrap new wrapping key.
        final Mechanism mechanism = request.getMechanism();
        final byte[] requestWrapdata = request.getWrapdata();
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        final String identity = entityAuthData.getIdentity();
        final ICryptoContext wrapKeyCryptoContext;
        switch (mechanism) {
            case PSK:
            {
                final EntityAuthenticationData authdata = new PresharedAuthenticationData(identity);
                final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
                if (factory == null)
                    throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name()).setEntityAuthenticationData(entityAuthData);
                final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, authdata);
                wrapKeyCryptoContext = new AesKwJwkCryptoContext(cryptoContext);
                break;
            }
            case WRAP:
            {
                wrapKeyCryptoContext = repository.getCryptoContext(requestWrapdata);
                if (wrapKeyCryptoContext == null)
                    throw new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING, Base64.encode(requestWrapdata)).setEntityAuthenticationData(entityAuthData);
                break;
            }
            default:
                throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name()).setEntityAuthenticationData(entityAuthData);
        }
        
        // Unwrap wrapping key.
        final byte[] unwrappedWrapJwk = wrapKeyCryptoContext.unwrap(response.getWrapKey());
        final String wrapJwkJson = new String(unwrappedWrapJwk, UTF_8);
        final JsonWebKey wrapJwk;
        try {
            wrapJwk = new JsonWebKey(new JSONObject(wrapJwkJson));
        } catch (final JSONException e) {
            throw new MslKeyExchangeException(MslError.INVALID_JWK, wrapJwkJson, e).setEntityAuthenticationData(entityAuthData);
        }
        final SecretKey wrapKey = wrapJwk.getSecretKey();
        
        // Unwrap session keys with wrapping key.
        final ICryptoContext unwrapCryptoContext = new AesKwJwkCryptoContext(wrapKey);
        final byte[] unwrappedEncryptionJwk = unwrapCryptoContext.unwrap(response.getEncryptionKey());
        final byte[] unwrappedHmacJwk = unwrapCryptoContext.unwrap(response.getHmacKey());
        final String encryptionJwkJson = new String(unwrappedEncryptionJwk, UTF_8);
        final String hmacJwkJson = new String(unwrappedHmacJwk, UTF_8);
        final JsonWebKey encryptionJwk;
        try {
            encryptionJwk = new JsonWebKey(new JSONObject(encryptionJwkJson));
        } catch (final JSONException e) {
            throw new MslKeyExchangeException(MslError.INVALID_JWK, encryptionJwkJson, e).setEntityAuthenticationData(entityAuthData);
        }
        final JsonWebKey hmacJwk;
        try {
            hmacJwk = new JsonWebKey(new JSONObject(hmacJwkJson));
        } catch (final JSONException e) {
            throw new MslKeyExchangeException(MslError.INVALID_JWK, hmacJwkJson, e).setEntityAuthenticationData(entityAuthData);
        }
        
        // Deliver wrap data to wrap key repository.
        final byte[] wrapdata = response.getWrapdata();
        repository.addCryptoContext(wrapdata, unwrapCryptoContext);
        if (requestWrapdata != null)
            repository.removeCryptoContext(requestWrapdata);

        // Create crypto context.
        final MasterToken responseMasterToken = response.getMasterToken();
        final SecretKey encryptionKey = encryptionJwk.getSecretKey();
        final SecretKey hmacKey = hmacJwk.getSecretKey();
        return new SessionCryptoContext(ctx, responseMasterToken, identity, encryptionKey, hmacKey);
    }
    
    /** Wrapping keys crypto context repository. */
    private final WrapCryptoContextRepository repository;
    /** Authentication utilities. */
    private final AuthenticationUtils authutils;
}
