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
package com.netflix.msl.keyx;

import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>Symmetric key wrapped key exchange.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SymmetricWrappedExchange extends KeyExchangeFactory {
    /** Key ID. */
    public enum KeyId {
        PSK,
        SESSION,
    }
    
    /**
     * <p>Symmetric key wrapped key request data.</p>
     * 
     * <p>
     * {@code {
     *   "#mandatory" : [ "keyid" ],
     *   "keyid" : "string",
     * }} where:
     * <ul>
     * <li>{@code keyid} identifies the key that should be used to wrap the session keys</li>
     * </ul></p>
     */
    public static class RequestData extends KeyRequestData {
        /** Key symmetric key ID. */
        private static final String KEY_KEY_ID = "keyid";
        
        /**
         * Create a new symmetric key wrapped key request data instance with
         * the specified key ID.
         * 
         * @param keyId symmetric key identifier.
         */
        public RequestData(final KeyId keyId) {
            super(KeyExchangeScheme.SYMMETRIC_WRAPPED);
            this.keyId = keyId;
        }
        
        /**
         * Create a new symmetric key wrapped key request data instance from
         * the provided MSL object.
         * 
         * @param keyDataMo the MSL object.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslKeyExchangeException if the key ID is not recognized.
         */
        public RequestData(final MslObject keyDataMo) throws MslEncodingException, MslKeyExchangeException {
            super(KeyExchangeScheme.SYMMETRIC_WRAPPED);
            try {
                final String keyIdName = keyDataMo.getString(KEY_KEY_ID);
                try {
                    keyId = KeyId.valueOf(keyIdName);
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_KEY_ID, keyIdName, e);
                }
            } catch (final MslEncoderException e) {
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keydata " + keyDataMo, e);
            }
        }
        
        /**
         * @return the wrapping key ID.
         */
        public KeyId getKeyId() {
            return keyId;
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyRequestData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        @Override
        protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
            final MslObject mo = encoder.createObject();
            mo.put(KEY_KEY_ID, keyId.name());
            return mo;
        }
        
        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        @Override
        public boolean equals(final Object obj) {
            if (obj == this) return true;
            if (!(obj instanceof RequestData)) return false;
            final RequestData that = (RequestData)obj;
            return super.equals(obj) && keyId.equals(that.keyId);
        }

        /* (non-Javadoc)
         * @see java.lang.Object#hashCode()
         */
        @Override
        public int hashCode() {
            return super.hashCode() ^ keyId.hashCode();
        }

        /** Symmetric key ID. */
        private final KeyId keyId;
    }
    
    /**
     * <p>Symmetric key wrapped key response data.</p>
     * 
     * <p>
     * {@code {
     *   "#mandatory" : [ "keyid", "encryptionkey", "hmackey" ],
     *   "keyid" : "string",
     *   "encryptionkey" : "binary",
     *   "hmackey" : "binary"
     * }} where:
     * <ul>
     * <li>{@code keyid} identifies the key that was used to wrap the session keys</li>
     * <li>{@code encryptionkey} the wrapped session encryption key</li>
     * <li>{@code hmackey} the wrapped session HMAC key</li>
     * </ul></p>
     */
    public static class ResponseData extends KeyResponseData {
        /** Key symmetric key ID. */
        private static final String KEY_KEY_ID = "keyid";
        /** Key wrapped encryption key. */
        private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
        /** Key wrapped HMAC key. */
        private static final String KEY_HMAC_KEY = "hmackey";
        
        /**
         * Create a new symmetric key wrapped key response data instance with
         * the provided master token, specified key ID and wrapped encryption
         * and HMAC keys.
         * 
         * @param masterToken the master token.
         * @param keyId the wrapping key ID.
         * @param encryptionKey the wrapped encryption key.
         * @param hmacKey the wrapped HMAC key.
         */
        public ResponseData(final MasterToken masterToken, final KeyId keyId, final byte[] encryptionKey, final byte[] hmacKey) {
            super(masterToken, KeyExchangeScheme.SYMMETRIC_WRAPPED);
            this.keyId = keyId;
            this.encryptionKey = encryptionKey;
            this.hmacKey = hmacKey;
        }
        
        /**
         * Create a new symmetric key wrapped key response data instance with
         * the provided master token from the provided MSL object.
         * 
         * @param masterToken the master token.
         * @param keyDataMo the MSL object.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslKeyExchangeException if the key ID is not recognized or
         *         a session key is invalid.
         */
        public ResponseData(final MasterToken masterToken, final MslObject keyDataMo) throws MslEncodingException, MslKeyExchangeException {
            super(masterToken, KeyExchangeScheme.SYMMETRIC_WRAPPED);
            try {
                final String keyIdName = keyDataMo.getString(KEY_KEY_ID);
                try {
                    keyId = KeyId.valueOf(keyIdName);
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_KEY_ID, keyIdName, e);
                }
                encryptionKey = keyDataMo.getBytes(KEY_ENCRYPTION_KEY);
                hmacKey = keyDataMo.getBytes(KEY_HMAC_KEY);
            } catch (final MslEncoderException e) {
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keydata " + keyDataMo, e);
            }
        }
        
        /**
         * @return the wrapping key ID.
         */
        public KeyId getKeyId() {
            return keyId;
        }
        
        /**
         * @return the wrapped encryption key.
         */
        public byte[] getEncryptionKey() {
            return encryptionKey;
        }
        
        /**
         * @return the wrapped HMAC key.
         */
        public byte[] getHmacKey() {
            return hmacKey;
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyResponseData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        @Override
        protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) {
            final MslObject mo = encoder.createObject();
            mo.put(KEY_KEY_ID, keyId.name());
            mo.put(KEY_ENCRYPTION_KEY, encryptionKey);
            mo.put(KEY_HMAC_KEY, hmacKey);
            return mo;
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
                keyId.equals(that.keyId) &&
                Arrays.equals(encryptionKey, that.encryptionKey) &&
                Arrays.equals(hmacKey, that.hmacKey);
        }

        /* (non-Javadoc)
         * @see java.lang.Object#hashCode()
         */
        @Override
        public int hashCode() {
            return super.hashCode() ^
                keyId.hashCode() ^
                Arrays.hashCode(encryptionKey) ^
                Arrays.hashCode(hmacKey);
        }

        /** Symmetric key ID. */
        private final KeyId keyId;
        /** Wrapped encryption key. */
        private final byte[] encryptionKey;
        /** Wrapped HMAC key. */
        private final byte[] hmacKey;
    }

    /**
     * Create the crypto context identified by the key ID.
     * 
     * @param ctx MSL context.
     * @param keyId the key ID.
     * @param masterToken the existing master token. May be null.
     * @param identity the entity identity.
     * @return the crypto context.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslKeyExchangeException if the key ID is unsupported.
     * @throws MslEntityAuthException if there is an problem with the entity
     *         identity.
     */
    private static ICryptoContext createCryptoContext(final MslContext ctx, final KeyId keyId, final MasterToken masterToken, final String identity) throws MslCryptoException, MslKeyExchangeException, MslEntityAuthException, MslMasterTokenException {
        switch (keyId) {
            case SESSION:
            {
                // If the master token is null session wrapped is unsupported.
                if (masterToken == null)
                    throw new MslKeyExchangeException(MslError.KEYX_MASTER_TOKEN_MISSING, keyId.name());
                
                // Use a stored master token crypto context if we have one.
                final ICryptoContext cachedCryptoContext = ctx.getMslStore().getCryptoContext(masterToken);
                if (cachedCryptoContext != null)
                    return cachedCryptoContext;

                // If there was no stored crypto context try making one from
                // the master token. We can only do this if we can open up the
                // master token.
                if (!masterToken.isDecrypted())
                    throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
                final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);
                return cryptoContext;
            }
            case PSK:
            {
                final EntityAuthenticationData authdata = new PresharedAuthenticationData(identity);
                final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
                if (factory == null)
                    throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_KEY_ID, keyId.name());
                return factory.getCryptoContext(ctx, authdata);
            }
            default:
                throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_KEY_ID, keyId.name());
        }
    }

    /**
     * Create a new symmetric wrapped key exchange factory.
     *
     * @param authutils authentication utiliites.
     */
    public SymmetricWrappedExchange(final AuthenticationUtils authutils) {
        super(KeyExchangeScheme.SYMMETRIC_WRAPPED);
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createRequestData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    protected KeyRequestData createRequestData(final MslContext ctx, final MslObject keyRequestMo) throws MslEncodingException, MslKeyExchangeException {
        return new RequestData(keyRequestMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createResponseData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
     */
    @Override
    protected KeyResponseData createResponseData(final MslContext ctx, final MasterToken masterToken, final MslObject keyDataMo) throws MslEncodingException, MslKeyExchangeException {
        return new ResponseData(masterToken, keyDataMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslEncoderFormat, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public KeyExchangeData generateResponse(final MslContext ctx, final MslEncoderFormat format, final KeyRequestData keyRequestData, final MasterToken masterToken) throws MslException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData)keyRequestData;

        // Verify the scheme is permitted.
        final String identity = masterToken.getIdentity();
        if (!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + this.getScheme()).setMasterToken(masterToken);

        // If the master token was not issued by the local entity then we
        // should not be generating a key response for it.
        if (!masterToken.isVerified())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken).setMasterToken(masterToken);
        
        // Create random AES-128 encryption and SHA-256 HMAC keys.
        final byte[] encryptionBytes = new byte[16];
        final byte[] hmacBytes = new byte[32];
        ctx.getRandom().nextBytes(encryptionBytes);
        ctx.getRandom().nextBytes(hmacBytes);
        final SecretKey encryptionKey = new SecretKeySpec(encryptionBytes, JcaAlgorithm.AES);
        final SecretKey hmacKey = new SecretKeySpec(hmacBytes, JcaAlgorithm.HMAC_SHA256);
        
        // Wrap session keys with identified key...
        final KeyId keyId = request.getKeyId();
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final ICryptoContext wrapCryptoContext = createCryptoContext(ctx, keyId, masterToken, masterToken.getIdentity());
        final byte[] wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionBytes, encoder, format);
        final byte[] wrappedHmacKey = wrapCryptoContext.wrap(hmacBytes, encoder, format);
        
        // Create the master token.
        final TokenFactory tokenFactory = ctx.getTokenFactory();
        final MasterToken newMasterToken = tokenFactory.renewMasterToken(ctx, masterToken, encryptionKey, hmacKey, null);
        
        // Create crypto context.
        final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, newMasterToken);
        
        // Return the key exchange data.
        final KeyResponseData keyResponseData = new ResponseData(newMasterToken, keyId, wrappedEncryptionKey, wrappedHmacKey);
        return new KeyExchangeData(keyResponseData, cryptoContext);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslEncoderFormat, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public KeyExchangeData generateResponse(final MslContext ctx, final MslEncoderFormat format, final KeyRequestData keyRequestData, final EntityAuthenticationData entityAuthData) throws MslException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData)keyRequestData;

        // Verify the scheme is permitted.
        final String identity = entityAuthData.getIdentity();
        if (!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + this.getScheme());

        // Create random AES-128 encryption and SHA-256 HMAC keys.
        final byte[] encryptionBytes = new byte[16];
        final byte[] hmacBytes = new byte[32];
        ctx.getRandom().nextBytes(encryptionBytes);
        ctx.getRandom().nextBytes(hmacBytes);
        final SecretKey encryptionKey = new SecretKeySpec(encryptionBytes, JcaAlgorithm.AES);
        final SecretKey hmacKey = new SecretKeySpec(hmacBytes, JcaAlgorithm.HMAC_SHA256);
        
        // Wrap session keys with identified key.
        final KeyId keyId = request.getKeyId();
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final ICryptoContext wrapCryptoContext;
        try {
            wrapCryptoContext = createCryptoContext(ctx, keyId, null, identity);
        } catch (final MslMasterTokenException e) {
            throw new MslInternalException("Master token exception thrown when the master token is null.", e);
        }
        final byte[] wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionBytes, encoder, format);
        final byte[] wrappedHmacKey = wrapCryptoContext.wrap(hmacBytes, encoder, format);
        
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
        final KeyResponseData keyResponseData = new ResponseData(masterToken, keyId, wrappedEncryptionKey, wrappedHmacKey);
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

        // Verify response matches request.
        final KeyId requestKeyId = request.getKeyId();
        final KeyId responseKeyId = response.getKeyId();
        if (!requestKeyId.equals(responseKeyId))
            throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestKeyId + "; response " + responseKeyId).setMasterToken(masterToken);
        
        // Unwrap session keys with identified key.
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        final String identity = entityAuthData.getIdentity();
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final ICryptoContext unwrapCryptoContext = createCryptoContext(ctx, responseKeyId, masterToken, identity);
        final byte[] unwrappedEncryptionKey = unwrapCryptoContext.unwrap(response.getEncryptionKey(), encoder);
        final byte[] unwrappedHmacKey = unwrapCryptoContext.unwrap(response.getHmacKey(), encoder);
        
        // Create crypto context.
        final SecretKey encryptionKey = new SecretKeySpec(unwrappedEncryptionKey, JcaAlgorithm.AES);
        final SecretKey hmacKey = new SecretKeySpec(unwrappedHmacKey, JcaAlgorithm.HMAC_SHA256);
        final MasterToken responseMasterToken = response.getMasterToken();
        return new SessionCryptoContext(ctx, responseMasterToken, identity, encryptionKey, hmacKey);
    }

    /** Authentication utilities. */
    private final AuthenticationUtils authutils;
}
