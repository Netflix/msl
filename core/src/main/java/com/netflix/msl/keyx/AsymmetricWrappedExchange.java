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
package com.netflix.msl.keyx;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.AsymmetricCryptoContext;
import com.netflix.msl.crypto.CryptoCache;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext.CekCryptoContext;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext.Format;
import com.netflix.msl.crypto.JsonWebKey;
import com.netflix.msl.crypto.JsonWebKey.KeyOp;
import com.netflix.msl.crypto.JsonWebKey.Usage;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>Asymmetric key wrapped key exchange.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class AsymmetricWrappedExchange extends KeyExchangeFactory {
    /** Encrypt/decrypt key operations. */
    private static final Set<KeyOp> ENCRYPT_DECRYPT = new HashSet<KeyOp>(Arrays.asList(KeyOp.encrypt, KeyOp.decrypt));
    /** Sign/verify key operations. */
    private static final Set<KeyOp> SIGN_VERIFY = new HashSet<KeyOp>(Arrays.asList(KeyOp.sign, KeyOp.verify));
    
    /**
     * <p>An RSA wrapping crypto context is unique in that it treats its wrap/
     * unwrap operations as encrypt/decrypt respectively. This is compatible
     * with the Web Crypto API.</p>
     */
    private static class RsaWrappingCryptoContext extends AsymmetricCryptoContext {
        /** JWK RSA crypto context mode. */
        public static enum Mode {
            /** RSA-OAEP wrap/unwrap */
            WRAP_UNWRAP_OAEP,
            /** RSA PKCS#1 wrap/unwrap */
            WRAP_UNWRAP_PKCS1,
        }
        
        /**
         * <p>Create a new RSA wrapping crypto context for the specified mode
         * using the provided public and private keys. The mode identifies the
         * operations to enable. All other operations are no-ops and return the
         * data unmodified.</p>
         * 
         * @param ctx MSL context.
         * @param id key pair identity.
         * @param privateKey the private key. May be null.
         * @param publicKey the public key. May be null.
         * @param mode crypto context mode.
         */
        public RsaWrappingCryptoContext(final MslContext ctx, final String id, final PrivateKey privateKey, final PublicKey publicKey, final Mode mode) {
            super(id, privateKey, publicKey, NULL_OP, null, NULL_OP);
            switch (mode) {
                case WRAP_UNWRAP_OAEP:
                    wrapTransform = "RSA/ECB/OAEPPadding";
                    wrapParams = OAEPParameterSpec.DEFAULT;
                    break;
                case WRAP_UNWRAP_PKCS1:
                    wrapTransform = "RSA/ECB/PKCS1Padding";
                    wrapParams = null;
                    break;
                default:
                    throw new MslInternalException("RSA wrapping crypto context mode " + mode + " not supported.");
            }
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[])
         */
        @Override
        public byte[] wrap(final byte[] data) throws MslCryptoException {
            if (NULL_OP.equals(wrapTransform))
                return data;
            if (publicKey == null)
                throw new MslCryptoException(MslError.WRAP_NOT_SUPPORTED, "no public key");
            Throwable reset = null;
            try {
                // Encrypt plaintext.
                final Cipher cipher = CryptoCache.getCipher(wrapTransform);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, wrapParams);
                return cipher.doFinal(data);
            } catch (final NoSuchPaddingException e) {
                reset = e;
                throw new MslInternalException("Unsupported padding exception.", e);
            } catch (final NoSuchAlgorithmException e) {
                reset = e;
                throw new MslInternalException("Invalid cipher algorithm specified.", e);
            } catch (final InvalidKeyException e) {
                reset = e;
                throw new MslCryptoException(MslError.INVALID_PUBLIC_KEY, e);
            } catch (final IllegalBlockSizeException e) {
                reset = e;
                throw new MslCryptoException(MslError.PLAINTEXT_ILLEGAL_BLOCK_SIZE, "not expected when padding is specified", e);
            } catch (final BadPaddingException e) {
                reset = e;
                throw new MslCryptoException(MslError.PLAINTEXT_BAD_PADDING, "not expected when encrypting", e);
            } catch (final InvalidAlgorithmParameterException e) {
                reset = e;
                throw new MslCryptoException(MslError.INVALID_ALGORITHM_PARAMS, e);
            } catch (final RuntimeException e) {
                reset = e;
                throw e;
            } finally {
                // FIXME Remove this once BouncyCastle Cipher is fixed in v1.48+
                if (reset != null)
                    CryptoCache.resetCipher(wrapTransform);
            }
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#unwrap(byte[])
         */
        @Override
        public byte[] unwrap(final byte[] data) throws MslCryptoException {
            if (NULL_OP.equals(wrapTransform))
                return data;
            if (privateKey == null)
                throw new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED, "no private key");
            Throwable reset = null;
            try {
                // Decrypt ciphertext.
                final Cipher cipher = CryptoCache.getCipher(wrapTransform);
                cipher.init(Cipher.DECRYPT_MODE, privateKey, wrapParams);
                return cipher.doFinal(data);
            } catch (final NoSuchPaddingException e) {
                reset = e;
                throw new MslInternalException("Unsupported padding exception.", e);
            } catch (final NoSuchAlgorithmException e) {
                reset = e;
                throw new MslInternalException("Invalid cipher algorithm specified.", e);
            } catch (final InvalidKeyException e) {
                reset = e;
                throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, e);
            } catch (final IllegalBlockSizeException e) {
                reset = e;
                throw new MslCryptoException(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE, e);
            } catch (final BadPaddingException e) {
                reset = e;
                throw new MslCryptoException(MslError.CIPHERTEXT_BAD_PADDING, e);
            } catch (final InvalidAlgorithmParameterException e) {
                reset = e;
                throw new MslCryptoException(MslError.INVALID_ALGORITHM_PARAMS, e);
            } catch (final RuntimeException e) {
                reset = e;
                throw e;
            } finally {
                // FIXME Remove this once BouncyCastle Cipher is fixed in v1.48+
                if (reset != null)
                    CryptoCache.resetCipher(wrapTransform);
            }
        }
        
        /** Wrap/unwrap transform. */
        private final String wrapTransform;
        /** Wrap/unwrap algorithm parameters. */
        private final AlgorithmParameterSpec wrapParams;
    }
    
    /**
     * <p>Asymmetric key wrapped key request data.</p>
     * 
     * <p>
     * {@code {
     *   "#mandatory" : [ "keypairid", "mechanism", "publickey" ],
     *   "keypairid" : "string",
     *   "mechanism" : "string",
     *   "publickey" : "base64"
     * }} where:
     * <ul>
     * <li>{@code keypairid} identifies the key pair for wrapping and unwrapping the session keys</li>
     * <li>{@code mechanism} the public key cryptographic mechanism of the key pair</li>
     * <li>{@code publickey} the Base64-encoded public key used to wrap the session keys</li>
     * </ul></p>
     */
    public static class RequestData extends KeyRequestData {
        public enum Mechanism {
            /** RSA-OAEP encrypt/decrypt */
            RSA,
            /** ECIES */
            ECC,
            /** JSON Web Encryption with RSA-OAEP */
            JWE_RSA,
            /** JSON Web Encryption JSON Serialization with RSA-OAEP */
            JWEJS_RSA,
            /** JSON Web Key with RSA-OAEP */
            JWK_RSA,
            /** JSON Web Key with RSA-PKCS v1.5 */
            JWK_RSAES,
        }
        
        /** JSON key key pair ID. */
        private static final String KEY_KEY_PAIR_ID = "keypairid";
        /** JSON key mechanism. */
        private static final String KEY_MECHANISM = "mechanism";
        /** JSON key public key. */
        private static final String KEY_PUBLIC_KEY = "publickey";
        
        /**
         * Create a new asymmetric key wrapped key request data instance with
         * the specified key pair ID and public key. The private key is also
         * required but is not included in the request data.
         * 
         * @param keyPairId the public/private key pair ID.
         * @param mechanism the key exchange mechanism.
         * @param publicKey the public key.
         * @param privateKey the private key.
         */
        public RequestData(final String keyPairId, final Mechanism mechanism, final PublicKey publicKey, final PrivateKey privateKey) {
            super(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            this.keyPairId = keyPairId;
            this.mechanism = mechanism;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
        
        /**
         * Create a new asymmetric key wrapped key request data instance from
         * the provided JSON object. The private key will be unknown.
         * 
         * @param keyRequestJO the JSON object.
         * @throws MslEncodingException if there is an error parsing the JSON.
         * @throws MslCryptoException if the encoded key is invalid or the
         *         specified mechanism is not supported.
         * @throws MslKeyExchangeException if the specified mechanism is not
         *         recognized.
         */
        public RequestData(final JSONObject keyRequestJO) throws MslEncodingException, MslCryptoException, MslKeyExchangeException {
            super(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            final byte[] encodedKey;
            try {
                keyPairId = keyRequestJO.getString(KEY_KEY_PAIR_ID);
                final String mechanismName = keyRequestJO.getString(KEY_MECHANISM);
                try {
                    mechanism = Mechanism.valueOf(mechanismName);
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_MECHANISM, mechanismName, e);
                }
                try {
                    encodedKey = DatatypeConverter.parseBase64Binary(keyRequestJO.getString(KEY_PUBLIC_KEY));
                } catch (final IllegalArgumentException e) {
                    throw new MslCryptoException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyRequestJO.toString(), e);
                }
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + keyRequestJO.toString(), e);
            }
            
            try {
                switch (mechanism) {
                    case RSA:
                    case JWE_RSA:
                    case JWEJS_RSA:
                    case JWK_RSA:
                    case JWK_RSAES:
                    {
                        final KeyFactory factory = CryptoCache.getKeyFactory("RSA");
                        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                        publicKey = factory.generatePublic(keySpec);
                        break;
                    }
                    /* Does not currently work.
                    case ECC:
                    {
                        final KeyFactory factory = CryptoCache.getKeyFactory("ECDSA");
                        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                        publicKey = factory.generatePublic(keySpec);
                        break;
                    }
                    */
                    default:
                        throw new MslCryptoException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name());
                }
            } catch (final NullPointerException e) {
                throw new MslCryptoException(MslError.INVALID_PUBLIC_KEY, "keydata " + keyRequestJO.toString(), e);
            } catch (final NoSuchAlgorithmException e) {
                throw new MslCryptoException(MslError.UNSUPPORTED_KEYX_MECHANISM, "keydata " + keyRequestJO.toString(), e);
            } catch (final InvalidKeySpecException e) {
                throw new MslCryptoException(MslError.INVALID_PUBLIC_KEY, "keydata " + keyRequestJO.toString(), e);
            }
            privateKey = null;
        }
        
        /**
         * @return the key pair ID.
         */
        public String getKeyPairId() {
            return keyPairId;
        }
        
        /**
         * @return the key mechanism.
         */
        public Mechanism getMechanism() {
            return mechanism;
        }
        
        /**
         * @return the public key.
         */
        public PublicKey getPublicKey() {
            return publicKey;
        }
        
        /**
         * @return the private key.
         */
        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyRequestData#getKeydata()
         */
        @Override
        protected JSONObject getKeydata() throws JSONException {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_KEY_PAIR_ID, keyPairId);
            jsonObj.put(KEY_MECHANISM, mechanism.name());
            jsonObj.put(KEY_PUBLIC_KEY, DatatypeConverter.printBase64Binary(publicKey.getEncoded()));
            return jsonObj;
        }

        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        @Override
        public boolean equals(final Object obj) {
            if (obj == this) return true;
            if (!(obj instanceof RequestData)) return false;
            final RequestData that = (RequestData)obj;
            // Private keys are optional but must be considered.
            final boolean privateKeysEqual =
                privateKey == that.privateKey ||
                (privateKey != null && that.privateKey != null &&
                    Arrays.equals(privateKey.getEncoded(), that.privateKey.getEncoded()));
            return super.equals(obj) &&
                keyPairId.equals(that.keyPairId) &&
                mechanism.equals(that.mechanism) &&
                Arrays.equals(publicKey.getEncoded(), that.publicKey.getEncoded()) &&
                privateKeysEqual;
        }

        /* (non-Javadoc)
         * @see java.lang.Object#hashCode()
         */
        @Override
        public int hashCode() {
            // Private keys are optional but must be considered.
            final int privateKeyHashCode = (privateKey != null)
                ? Arrays.hashCode(privateKey.getEncoded()) : 0;
            return super.hashCode() ^
                keyPairId.hashCode() ^
                mechanism.hashCode() ^
                Arrays.hashCode(publicKey.getEncoded()) ^
                privateKeyHashCode;
        }

        /** Public/private key pair ID. */
        private final String keyPairId;
        /** Key mechanism. */
        private final Mechanism mechanism;
        /** Public key. */
        private final PublicKey publicKey;
        /** Private key. */
        private final PrivateKey privateKey;
    }
    
    /**
     * <p>Asymmetric key wrapped key response data.</p>
     * 
     * <p>
     * {@code {
     *   "#mandatory" : [ "keypairid", "encryptionkey", "hmackey" ],
     *   "keypairid" : "string",
     *   "encryptionkey" : "base64",
     *   "hmackey" : "base64"
     * }} where:
     * <ul>
     * <li>{@code keypairid} identifies the key pair for wrapping and unwrapping the session keys</li>
     * <li>{@code encryptionkey} the Base64-encoded wrapped session encryption key</li>
     * <li>{@code hmackey} the Base64-encoded wrapped session HMAC key</li>
     * </ul></p>
     */
    public static class ResponseData extends KeyResponseData {
        /** JSON key key pair ID. */
        private static final String KEY_KEY_PAIR_ID = "keypairid";
        /** JSON key encrypted encryption key. */
        private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
        /** JSON key encrypted HMAC key. */
        private static final String KEY_HMAC_KEY = "hmackey";
        
        /**
         * Create a new asymmetric key wrapped key response data instance with
         * the provided master token, specified key pair ID, and public
         * key-encrypted encryption and HMAC keys.
         * 
         * @param masterToken the master token.
         * @param identity optional entity identity inside the master token.
         *        May be {@code null}.
         * @param keyPairId the public/private key pair ID.
         * @param encryptionKey the public key-encrypted encryption key.
         * @param hmacKey the public key-encrypted HMAC key.
         */
        public ResponseData(final MasterToken masterToken, final String identity, final String keyPairId, final byte[] encryptionKey, final byte[] hmacKey) {
            super(masterToken, identity, KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            this.keyPairId = keyPairId;
            this.encryptionKey = encryptionKey;
            this.hmacKey = hmacKey;
        }
        
        /**
         * Create a new asymmetric key wrapped key response data instance with
         * the provided master token from the provided JSON object.
         * 
         * @param masterToken the master token.
         * @param identity optional entity identity inside the master token.
         *        May be {@code null}.
         * @param keyDataJO the JSON object.
         * @throws MslEncodingException if there is an error parsing the JSON.
         * @throws MslKeyExchangeException if a session key is invalid.
         */
        public ResponseData(final MasterToken masterToken, final String identity, final JSONObject keyDataJO) throws MslEncodingException, MslKeyExchangeException {
            super(masterToken, identity, KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            try {
                keyPairId = keyDataJO.getString(KEY_KEY_PAIR_ID);
                try {
                    encryptionKey = DatatypeConverter.parseBase64Binary(keyDataJO.getString(KEY_ENCRYPTION_KEY));
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_ENCRYPTION_KEY, "keydata " + keyDataJO.toString(), e);
                }
                try {
                    hmacKey = DatatypeConverter.parseBase64Binary(keyDataJO.getString(KEY_HMAC_KEY));
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_HMAC_KEY, "keydata " + keyDataJO.toString(), e);
                }
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + keyDataJO.toString(), e);
            }
        }
        
        /**
         * @return the key pair ID.
         */
        public String getKeyPairId() {
            return keyPairId;
        }
        
        /**
         * @return the public key-encrypted encryption key.
         */
        public byte[] getEncryptionKey() {
            return encryptionKey;
        }
        
        /**
         * @return the public key-encrypted HMAC key.
         */
        public byte[] getHmacKey() {
            return hmacKey;
        }
        
        @Override
        protected JSONObject getKeydata() throws JSONException {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_KEY_PAIR_ID, keyPairId);
            jsonObj.put(KEY_ENCRYPTION_KEY, DatatypeConverter.printBase64Binary(encryptionKey));
            jsonObj.put(KEY_HMAC_KEY, DatatypeConverter.printBase64Binary(hmacKey));
            return jsonObj;
        }
        
        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        @Override
        public boolean equals(final Object obj) {
            if (obj == this) return true;
            if (!(obj instanceof ResponseData)) return false;
            final ResponseData that = (ResponseData)obj;
            return super.equals(obj) &&
                keyPairId.equals(that.keyPairId) &&
                Arrays.equals(encryptionKey, that.encryptionKey)&&
                Arrays.equals(hmacKey, that.hmacKey);
        }

        /* (non-Javadoc)
         * @see java.lang.Object#hashCode()
         */
        @Override
        public int hashCode() {
            return super.hashCode() ^ keyPairId.hashCode() ^ Arrays.hashCode(encryptionKey) ^ Arrays.hashCode(hmacKey);
        }

        /** Public/private key pair ID. */
        private final String keyPairId;
        /** Public key-encrypted encryption key. */
        private final byte[] encryptionKey;
        /** Public key-encrypted HMAC key. */
        private final byte[] hmacKey;
    }

    /**
     * Create the crypto context identified by the key ID, mechanism, and
     * provided keys.
     * 
     * @param ctx MSL context.
     * @param keyPairId the key pair ID.
     * @param mechanism the key mechanism.
     * @param privateKey the private key. May be null.
     * @param publicKey the public key. May be null.
     * @return the crypto context.
     * @throws MslCryptoException if the key mechanism is unsupported.
     */
    private static ICryptoContext createCryptoContext(final MslContext ctx, final String keyPairId, final RequestData.Mechanism mechanism, final PrivateKey privateKey, final PublicKey publicKey) throws MslCryptoException {
        switch (mechanism) {
            case JWE_RSA:
            {
                final CekCryptoContext cryptoContext = new JsonWebEncryptionCryptoContext.RsaOaepCryptoContext(privateKey, publicKey);
                return new JsonWebEncryptionCryptoContext(ctx, cryptoContext, JsonWebEncryptionCryptoContext.Encryption.A128GCM, Format.JWE_CS);
            }
            case JWEJS_RSA:
            {
                final CekCryptoContext cryptoContext = new JsonWebEncryptionCryptoContext.RsaOaepCryptoContext(privateKey, publicKey);
                return new JsonWebEncryptionCryptoContext(ctx, cryptoContext, JsonWebEncryptionCryptoContext.Encryption.A128GCM, Format.JWE_JS);
            }
            case RSA:
            case JWK_RSA:
            {
                return new RsaWrappingCryptoContext(ctx, keyPairId, privateKey, publicKey, RsaWrappingCryptoContext.Mode.WRAP_UNWRAP_OAEP);
            }
            case JWK_RSAES:
            {
                return new RsaWrappingCryptoContext(ctx, keyPairId, privateKey, publicKey, RsaWrappingCryptoContext.Mode.WRAP_UNWRAP_PKCS1);
            }
            default:
                throw new MslCryptoException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name());
        }
    }
    
    /**
     * Create a new asymmetric wrapped key exchange factory.
     * 
     * @param authutils authentication utilities.
     */
    public AsymmetricWrappedExchange(final AuthenticationUtils authutils) {
        super(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createRequestData(com.netflix.msl.util.MslContext, org.json.JSONObject)
     */
    @Override
    protected KeyRequestData createRequestData(final MslContext ctx, final JSONObject keyRequestJO) throws MslEncodingException, MslCryptoException, MslKeyExchangeException {
        return new RequestData(keyRequestJO);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createResponseData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, java.lang.String, org.json.JSONObject)
     */
    @Override
    protected KeyResponseData createResponseData(final MslContext ctx, final MasterToken masterToken, final String identity, final JSONObject keyDataJO) throws MslEncodingException, MslKeyExchangeException {
        return new ResponseData(masterToken, identity, keyDataJO);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public KeyExchangeData generateResponse(final MslContext ctx, final KeyRequestData keyRequestData, final MasterToken masterToken) throws MslKeyExchangeException, MslCryptoException, MslMasterTokenException, MslEncodingException, MslException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData)keyRequestData;

        // If the master token was not issued by the local entity then we
        // should not be generating a key response for it.
        if (!masterToken.isVerified())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);

        // Verify the scheme is permitted.
        final String identity = masterToken.getIdentity();
        if (!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication scheme for entity not permitted " + identity + ":" + this.getScheme()).setMasterToken(masterToken);

        // Create random AES-128 encryption and SHA-256 HMAC keys.
        final byte[] encryptionBytes = new byte[16];
        final byte[] hmacBytes = new byte[32];
        ctx.getRandom().nextBytes(encryptionBytes);
        ctx.getRandom().nextBytes(hmacBytes);
        final SecretKey encryptionKey, hmacKey;
        try {
            encryptionKey = new SecretKeySpec(encryptionBytes, JcaAlgorithm.AES);
            hmacKey = new SecretKeySpec(hmacBytes, JcaAlgorithm.HMAC_SHA256);
        } catch (final IllegalArgumentException e) {
            throw new MslCryptoException(MslError.SESSION_KEY_CREATION_FAILURE, e).setMasterToken(masterToken);
        }
        
        // Wrap session keys with public key.
        final String keyPairId = request.getKeyPairId();
        final RequestData.Mechanism mechanism = request.getMechanism();
        final PublicKey publicKey = request.getPublicKey();
        final ICryptoContext wrapCryptoContext = createCryptoContext(ctx, keyPairId, mechanism, null, publicKey);
        final byte[] wrappedEncryptionKey, wrappedHmacKey;
        switch (mechanism) {
            case JWE_RSA:
            case JWEJS_RSA:
            {
                final JsonWebKey encryptionJwk = new JsonWebKey(Usage.enc, JsonWebKey.Algorithm.A128CBC, false, null, encryptionKey);
                final JsonWebKey hmacJwk = new JsonWebKey(Usage.sig, JsonWebKey.Algorithm.HS256, false, null, hmacKey);
                wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionJwk.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
                wrappedHmacKey = wrapCryptoContext.wrap(hmacJwk.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
                break;
            }
            case JWK_RSA:
            case JWK_RSAES:
            {
                final JsonWebKey encryptionJwk = new JsonWebKey(ENCRYPT_DECRYPT, JsonWebKey.Algorithm.A128CBC, false, null, encryptionKey);
                final JsonWebKey hmacJwk = new JsonWebKey(SIGN_VERIFY, JsonWebKey.Algorithm.HS256, false, null, hmacKey);
                wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionJwk.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
                wrappedHmacKey = wrapCryptoContext.wrap(hmacJwk.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
                break;
            }
            default:
            {
                wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionBytes);
                wrappedHmacKey = wrapCryptoContext.wrap(hmacBytes);
                break;
            }
        }
        
        // Create the master token.
        final TokenFactory tokenFactory = ctx.getTokenFactory();
        final MasterToken newMasterToken = tokenFactory.renewMasterToken(ctx, masterToken, encryptionKey, hmacKey, null);
        
        // Create crypto context.
        final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, newMasterToken);
        
        // Return the key exchange data.
        final KeyResponseData keyResponseData = new ResponseData(newMasterToken, identity, request.getKeyPairId(), wrappedEncryptionKey, wrappedHmacKey);
        return new KeyExchangeData(keyResponseData, cryptoContext);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public KeyExchangeData generateResponse(final MslContext ctx, final KeyRequestData keyRequestData, final EntityAuthenticationData entityAuthData) throws MslException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData)keyRequestData;

        // Verify the scheme is permitted.
        final String identity = entityAuthData.getIdentity();
        if (!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication scheme for entity not permitted " + identity + ":" + this.getScheme()).setEntityAuthenticationData(entityAuthData);
        
        // Create random AES-128 encryption and SHA-256 HMAC keys.
        final byte[] encryptionBytes = new byte[16];
        final byte[] hmacBytes = new byte[32];
        ctx.getRandom().nextBytes(encryptionBytes);
        ctx.getRandom().nextBytes(hmacBytes);
        final SecretKey encryptionKey = new SecretKeySpec(encryptionBytes, JcaAlgorithm.AES);
        final SecretKey hmacKey = new SecretKeySpec(hmacBytes, JcaAlgorithm.HMAC_SHA256);

        // Wrap session keys with public key.
        final String keyPairId = request.getKeyPairId();
        final RequestData.Mechanism mechanism = request.getMechanism();
        final PublicKey publicKey = request.getPublicKey();
        final ICryptoContext wrapCryptoContext = createCryptoContext(ctx, keyPairId, mechanism, null, publicKey);
        final byte[] wrappedEncryptionKey, wrappedHmacKey;
        switch (mechanism) {
            case JWE_RSA:
            case JWEJS_RSA:
            {
                final JsonWebKey encryptionJwk = new JsonWebKey(Usage.enc, JsonWebKey.Algorithm.A128CBC, false, null, encryptionKey);
                final JsonWebKey hmacJwk = new JsonWebKey(Usage.sig, JsonWebKey.Algorithm.HS256, false, null, hmacKey);
                wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionJwk.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
                wrappedHmacKey = wrapCryptoContext.wrap(hmacJwk.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
                break;
            }
            case JWK_RSA:
            case JWK_RSAES:
            {
                final JsonWebKey encryptionJwk = new JsonWebKey(ENCRYPT_DECRYPT, JsonWebKey.Algorithm.A128CBC, false, null, encryptionKey);
                final JsonWebKey hmacJwk = new JsonWebKey(SIGN_VERIFY, JsonWebKey.Algorithm.HS256, false, null, hmacKey);
                wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionJwk.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
                wrappedHmacKey = wrapCryptoContext.wrap(hmacJwk.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
                break;
            }
            default:
            {
                wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionBytes);
                wrappedHmacKey = wrapCryptoContext.wrap(hmacBytes);
                break;
            }
        }
        
        // Create the master token.
        final TokenFactory tokenFactory = ctx.getTokenFactory();
        final MasterToken masterToken = tokenFactory.createMasterToken(ctx, entityAuthData, encryptionKey, hmacKey, null);
        
        // Create crypto context.
        final ICryptoContext cryptoContext;
        try {
            cryptoContext = new SessionCryptoContext(ctx, masterToken);
        } catch (final MslMasterTokenException e) {
            throw new MslInternalException("Master token constructed by token factory is not trusted.", e);
        }
        
        // Return the key exchange data.
        final KeyResponseData keyResponseData = new ResponseData(masterToken, identity, request.getKeyPairId(), wrappedEncryptionKey, wrappedHmacKey);
        return new KeyExchangeData(keyResponseData, cryptoContext);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.keyx.KeyResponseData, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final KeyRequestData keyRequestData, final KeyResponseData keyResponseData, final MasterToken masterToken) throws MslKeyExchangeException, MslCryptoException, MslEncodingException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData)keyRequestData;
        if (!(keyResponseData instanceof ResponseData))
            throw new MslInternalException("Key response data " + keyResponseData.getClass().getName() + " was not created by this factory.");

        final ResponseData response = (ResponseData)keyResponseData;
        
        // Verify response matches request.
        final String requestKeyPairId = request.getKeyPairId();
        final String responseKeyPairId = response.getKeyPairId();
        if (!requestKeyPairId.equals(responseKeyPairId))
            throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestKeyPairId + "; response " + responseKeyPairId);
        
        // Unwrap session keys with identified key.
        final PrivateKey privateKey = request.getPrivateKey();
        if (privateKey == null)
            throw new MslKeyExchangeException(MslError.KEYX_PRIVATE_KEY_MISSING, "request Asymmetric private key");
        final RequestData.Mechanism mechanism = request.getMechanism();
        final ICryptoContext unwrapCryptoContext = createCryptoContext(ctx, requestKeyPairId, mechanism, privateKey, null);
        final SecretKey encryptionKey, hmacKey;
        switch (mechanism) {
            case JWE_RSA:
            case JWEJS_RSA:
            case JWK_RSA:
            case JWK_RSAES:
            {
                final byte[] encryptionJwkBytes = unwrapCryptoContext.unwrap(response.getEncryptionKey());
                final byte[] hmacJwkBytes = unwrapCryptoContext.unwrap(response.getHmacKey());
                final JSONObject encryptionJwkJo, hmacJwkJo;
                try {
                    encryptionJwkJo = new JSONObject(new String(encryptionJwkBytes, MslConstants.DEFAULT_CHARSET));
                    hmacJwkJo = new JSONObject(new String(hmacJwkBytes, MslConstants.DEFAULT_CHARSET));
                } catch (final JSONException e) {
                    throw new MslCryptoException(MslError.SESSION_KEY_CREATION_FAILURE, e).setMasterToken(masterToken);
                }
                encryptionKey = new JsonWebKey(encryptionJwkJo).getSecretKey();
                hmacKey = new JsonWebKey(hmacJwkJo).getSecretKey();
                break;
            }
            default:
            {
                final byte[] unwrappedEncryptionKey = unwrapCryptoContext.unwrap(response.getEncryptionKey());
                final byte[] unwrappedHmacKey = unwrapCryptoContext.unwrap(response.getHmacKey());
                try {
                    encryptionKey = new SecretKeySpec(unwrappedEncryptionKey, JcaAlgorithm.AES);
                    hmacKey = new SecretKeySpec(unwrappedHmacKey, JcaAlgorithm.HMAC_SHA256);
                } catch (final IllegalArgumentException e) {
                    throw new MslCryptoException(MslError.SESSION_KEY_CREATION_FAILURE, e).setMasterToken(masterToken);
                }
                break;
            }
        }
        
        // Create crypto context.
        final String identity = ctx.getEntityAuthenticationData(null).getIdentity();
        final MasterToken responseMasterToken = response.getMasterToken();
        return new SessionCryptoContext(ctx, responseMasterToken, identity, encryptionKey, hmacKey);
    }
    
    /** Authentication utilities. */
    private final AuthenticationUtils authutils;
}
