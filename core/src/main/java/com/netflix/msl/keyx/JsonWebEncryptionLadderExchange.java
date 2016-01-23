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
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import lombok.EqualsAndHashCode;
import lombok.Getter;
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
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext.AesKwCryptoContext;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext.CekCryptoContext;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext.Encryption;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext.Format;
import com.netflix.msl.crypto.JsonWebKey;
import com.netflix.msl.crypto.JsonWebKey.Algorithm;
import com.netflix.msl.crypto.JsonWebKey.Usage;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>JSON Web Encryption ladder key exchange.</p>
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
public class JsonWebEncryptionLadderExchange extends KeyExchangeFactory {
    /** Encoding charset. */
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    
    /** Wrapping key wrap mechanism. */
    public enum Mechanism {
        /** Wrapping key wrapped by PSK (AES-128 key wrap). */
        PSK,
        /** Wrapping key wrapped by previous wrapping key (AES-128 key wrap). */
        WRAP,
    }
    
    /**
     * <p>JSON Web Encryption ladder key request data.</p>
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
    @EqualsAndHashCode(callSuper = true)
    @Getter
    public static class RequestData extends KeyRequestData {
        /** JSON key wrap key wrapping mechanism. */
        private static final String KEY_MECHANISM = "mechanism";
        /** JSON key wrap data. */
        private static final String KEY_WRAPDATA = "wrapdata";

        /** Wrap key wrapping mechanism. */
        private final Mechanism mechanism;

        /** Wrap data. */
        private final byte[] wrapdata;

        /**
         * <p>Create a new JSON Web Encryption ladder key request data instance
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
            super(KeyExchangeScheme.JWE_LADDER);
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
         * Create a new JSON Web Encryption ladder key request data instance
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
            super(KeyExchangeScheme.JWE_LADDER);
            
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
                            wrapdata = DatatypeConverter.parseBase64Binary(keyRequestJO.getString(KEY_WRAPDATA));
                        } catch (final IllegalArgumentException e) {
                            throw new MslKeyExchangeException(MslError.KEYX_INVALID_WRAPPING_KEY, "keydata " + keyRequestJO.toString());
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

        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyRequestData#getKeydata()
         */
        @Override
        protected JSONObject getKeydata() throws JSONException {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_MECHANISM, mechanism.name());
            if (wrapdata != null) jsonObj.put(KEY_WRAPDATA, DatatypeConverter.printBase64Binary(wrapdata));
            return jsonObj;
        }

    }
    
    /**
     * <p>JSON Web Encryption ladder key response data.</p>
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
     * <li>{@code wrapkey} the Base64-encoded new wrapping key in JWE format, wrapped by the wrapping key</li>
     * <li>{@code wrapdata} the Base64-encoded wrapping key data for use in subsequent key request data</li>
     * <li>{@code encryptionkey} the Base64-encoded session encryption key in JWE format, wrapped with the new wrapping key</li>
     * <li>{@code hmackey} the Base64-encoded session HMAC key in JWE format, wrapped with the new wrapping key</li>
     * </ul></p>
     */
    @EqualsAndHashCode(callSuper = true)
    @Getter
    public static class ResponseData extends KeyResponseData {
        /** JSON key wrapping key. */
        private static final String KEY_WRAP_KEY = "wrapkey";

        /** JSON key wrapping key data. */
        private static final String KEY_WRAPDATA = "wrapdata";

        /** JSON key encrypted encryption key. */
        private static final String KEY_ENCRYPTION_KEY = "encryptionkey";

        /** JSON key encrypted HMAC key. */
        private static final String KEY_HMAC_KEY = "hmackey";

        /** Wrapped wrap key. */
        private final byte[] wrapKey;

        /** Wrap data. */
        private final byte[] wrapdata;

        /** Wrapped encryption key. */
        private final byte[] encryptionKey;

        /** Wrapped Session HMAC key. */
        private final byte[] hmacKey;

        /**
         * Create a new JSON Web Encryption ladder key response data instance
         * with the provided master token and wrapped keys.
         * 
         * @param masterToken the master token.
         * @param wrapKey the wrapped wrap key.
         * @param wrapdata the wrap data for reconstructing the wrap key.
         * @param encryptionKey the wrap key wrapped encryption key.
         * @param hmacKey the wrap key wrapped HMAC key.
         */
        public ResponseData(final MasterToken masterToken, final byte[] wrapKey, final byte[] wrapdata, final byte[] encryptionKey, final byte[] hmacKey) {
            super(masterToken, KeyExchangeScheme.JWE_LADDER);
            this.wrapKey = wrapKey;
            this.wrapdata = wrapdata;
            this.encryptionKey = encryptionKey;
            this.hmacKey = hmacKey;
        }

        /**
         * Create a new JSON Web Encryption ladder key response data instance
         * with the provided master token from the provided JSON object.
         * 
         * @param masterToken the master token.
         * @param keyDataJO the JSON object.
         * @throws MslEncodingException if there is an error parsing the JSON.
         * @throws MslKeyExchangeException if the mechanism is not recognized,
         *         any of the keys are invalid, or if the wrap data is invalid.
         */
        public ResponseData(final MasterToken masterToken, final JSONObject keyDataJO) throws MslKeyExchangeException, MslEncodingException {
            super(masterToken, KeyExchangeScheme.JWE_LADDER);
            try {
                try {
                    wrapKey = DatatypeConverter.parseBase64Binary(keyDataJO.getString(KEY_WRAP_KEY));
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_WRAPPING_KEY, "keydata " + keyDataJO.toString(), e);
                }
                try {
                    wrapdata = DatatypeConverter.parseBase64Binary(keyDataJO.getString(KEY_WRAPDATA));
                } catch (final IllegalArgumentException e) {
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_WRAPDATA, "keydata " + keyDataJO.toString(), e);
                }
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

        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.KeyResponseData#getKeydata()
         */
        @Override
        protected JSONObject getKeydata() throws JSONException {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_WRAP_KEY, DatatypeConverter.printBase64Binary(wrapKey));
            jsonObj.put(KEY_WRAPDATA, DatatypeConverter.printBase64Binary(wrapdata));
            jsonObj.put(KEY_ENCRYPTION_KEY, DatatypeConverter.printBase64Binary(encryptionKey));
            jsonObj.put(KEY_HMAC_KEY, DatatypeConverter.printBase64Binary(hmacKey));
            return jsonObj;
        }

    }
    
    /**
     * Create the crypto context identified by the mechanism.
     * 
     * @param ctx MSL context.
     * @param mechanism the wrap key wrapping mechanism.
     * @param wrapdata the wrap key previous wrapping key data. May be null.
     * @param identity the entity identity.
     * @return the crypto context.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslKeyExchangeException if the mechanism is unsupported.
     * @throws MslEntityAuthException if there is a problem with the entity
     *         identity.
     */
    private static ICryptoContext createCryptoContext(final MslContext ctx, final Mechanism mechanism, final byte[] wrapdata, final String identity) throws MslKeyExchangeException, MslCryptoException, MslEntityAuthException {
        switch (mechanism) {
            case PSK:
            {
                final EntityAuthenticationData authdata = new PresharedAuthenticationData(identity);
                final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
                if (factory == null)
                    throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name());
                final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, authdata);
                final CekCryptoContext cekCryptoContext = new AesKwCryptoContext(cryptoContext);
                return new JsonWebEncryptionCryptoContext(ctx, cekCryptoContext, Encryption.A128GCM, Format.JWE_JS);
            }
            case WRAP:
            {
                final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
                final byte[] wrapBytes = cryptoContext.unwrap(wrapdata);
                if (wrapBytes == null || wrapBytes.length == 0)
                    throw new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING);
                final SecretKey wrapKey = new SecretKeySpec(wrapBytes, JcaAlgorithm.AESKW);
                final CekCryptoContext cekCryptoContext = new AesKwCryptoContext(wrapKey);
                return new JsonWebEncryptionCryptoContext(ctx, cekCryptoContext, Encryption.A128GCM, Format.JWE_JS);
            }
            default:
                throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name());
        }
    }
    
    /**
     * Create a new JSON Web Encryption ladder key exchange factory.
     * 
     * @param repository the wrapping key crypto context repository.
     * @param authutils authentication utilities.
     */
    public JsonWebEncryptionLadderExchange(final WrapCryptoContextRepository repository, final AuthenticationUtils authutils) {
        super(KeyExchangeScheme.JWE_LADDER);
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
        
        // Create random AES-128 wrapping key with a random key ID.
        final String wrapKeyId = String.valueOf(ctx.getRandom().nextLong());
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
        final String identity = masterToken.getIdentity();
        
        // Verify the scheme is permitted.
        if(!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + this.getScheme());
        
        // Wrap wrapping key using specified wrapping key.
        final JsonWebKey wrapJwk = new JsonWebKey(Usage.wrap, Algorithm.A128KW, false, wrapKeyId, wrapKey);
        final ICryptoContext wrapKeyCryptoContext = createCryptoContext(ctx, mechanism, prevWrapdata, identity);
        final byte[] wrappedWrapJwk = wrapKeyCryptoContext.wrap(wrapJwk.toJSONString().getBytes(UTF_8));
        
        // Wrap session keys inside JSON Web Key objects with the wrapping key.
        final CekCryptoContext cekCryptoContext = new AesKwCryptoContext(wrapKey);
        final ICryptoContext wrapCryptoContext = new JsonWebEncryptionCryptoContext(ctx, cekCryptoContext, Encryption.A128GCM, Format.JWE_JS);
        final JsonWebKey encryptionJwk = new JsonWebKey(Usage.enc, Algorithm.A128CBC, false, null, encryptionKey);
        final JsonWebKey hmacJwk = new JsonWebKey(Usage.sig, Algorithm.HS256, false, null, hmacKey);
        final byte[] wrappedEncryptionJwk = wrapCryptoContext.wrap(encryptionJwk.toJSONString().getBytes(UTF_8));
        final byte[] wrappedHmacJwk = wrapCryptoContext.wrap(hmacJwk.toJSONString().getBytes(UTF_8));
        
        // Create the master token.
        final TokenFactory tokenFactory = ctx.getTokenFactory();
        final MasterToken newMasterToken = tokenFactory.renewMasterToken(ctx, masterToken, encryptionKey, hmacKey);
        
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

        // Create random AES-128 wrapping key with a random key ID.
        final String wrapKeyId = String.valueOf(ctx.getRandom().nextLong());
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
        final JsonWebKey wrapJwk = new JsonWebKey(Usage.wrap, Algorithm.A128KW, false, wrapKeyId, wrapKey);
        final ICryptoContext wrapKeyCryptoContext = createCryptoContext(ctx, mechanism, prevWrapdata, identity);
        final byte[] wrappedWrapJwk = wrapKeyCryptoContext.wrap(wrapJwk.toJSONString().getBytes(UTF_8));
        
        // Wrap session keys inside JSON Web Key objects with the wrapping key.
        final CekCryptoContext cekCryptoContext = new AesKwCryptoContext(wrapKey);
        final ICryptoContext wrapCryptoContext = new JsonWebEncryptionCryptoContext(ctx, cekCryptoContext, Encryption.A128GCM, Format.JWE_JS);
        final JsonWebKey encryptionJwk = new JsonWebKey(Usage.enc, Algorithm.A128CBC, false, null, encryptionKey);
        final JsonWebKey hmacJwk = new JsonWebKey(Usage.sig, Algorithm.HS256, false, null, hmacKey);
        final byte[] wrappedEncryptionJwk = wrapCryptoContext.wrap(encryptionJwk.toJSONString().getBytes(UTF_8));
        final byte[] wrappedHmacJwk = wrapCryptoContext.wrap(hmacJwk.toJSONString().getBytes(UTF_8));
        
        // Create the master token.
        final TokenFactory tokenFactory = ctx.getTokenFactory();
        final MasterToken newMasterToken = tokenFactory.createMasterToken(ctx, entityAuthData, encryptionKey, hmacKey);
        
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
                    throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name()).setEntity(entityAuthData);
                final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, authdata);
                final CekCryptoContext cekCryptoContext = new AesKwCryptoContext(cryptoContext);
                wrapKeyCryptoContext = new JsonWebEncryptionCryptoContext(ctx, cekCryptoContext, Encryption.A128GCM, Format.JWE_JS);
                break;
            }
            case WRAP:
            {
                wrapKeyCryptoContext = repository.getCryptoContext(requestWrapdata);
                if (wrapKeyCryptoContext == null)
                    throw new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING, DatatypeConverter.printBase64Binary(requestWrapdata)).setEntity(entityAuthData);
                break;
            }
            default:
                throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism.name()).setEntity(entityAuthData);
        }
        
        // Unwrap wrapping key.
        final byte[] unwrappedWrapJwk = wrapKeyCryptoContext.unwrap(response.getWrapKey());
        final String wrapJwkJson = new String(unwrappedWrapJwk, UTF_8);
        final JsonWebKey wrapJwk;
        try {
            wrapJwk = new JsonWebKey(new JSONObject(wrapJwkJson));
        } catch (final JSONException e) {
            throw new MslKeyExchangeException(MslError.INVALID_JWK, wrapJwkJson, e).setEntity(entityAuthData);
        }
        final SecretKey wrapKey = wrapJwk.getSecretKey();
        
        // Unwrap session keys with wrapping key.
        final CekCryptoContext cekCryptoContext = new AesKwCryptoContext(wrapKey);
        final ICryptoContext unwrapCryptoContext = new JsonWebEncryptionCryptoContext(ctx, cekCryptoContext, Encryption.A128GCM, Format.JWE_JS);
        final byte[] unwrappedEncryptionJwk = unwrapCryptoContext.unwrap(response.getEncryptionKey());
        final byte[] unwrappedHmacJwk = unwrapCryptoContext.unwrap(response.getHmacKey());
        final String encryptionJwkJson = new String(unwrappedEncryptionJwk, UTF_8);
        final String hmacJwkJson = new String(unwrappedHmacJwk, UTF_8);
        final JsonWebKey encryptionJwk;
        try {
            encryptionJwk = new JsonWebKey(new JSONObject(encryptionJwkJson));
        } catch (final JSONException e) {
            throw new MslKeyExchangeException(MslError.INVALID_JWK, encryptionJwkJson, e).setEntity(entityAuthData);
        }
        final JsonWebKey hmacJwk;
        try {
            hmacJwk = new JsonWebKey(new JSONObject(hmacJwkJson));
        } catch (final JSONException e) {
            throw new MslKeyExchangeException(MslError.INVALID_JWK, hmacJwkJson, e).setEntity(entityAuthData);
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
