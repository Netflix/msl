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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Value;
import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.CryptoCache;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>Diffie-Hellman key exchange.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class DiffieHellmanExchange extends KeyExchangeFactory {
    /** JSON key Diffie-Hellman parameters ID. */
    private static final String KEY_PARAMETERS_ID = "parametersid";

    /** JSON key Diffie-Hellman public key. */
    private static final String KEY_PUBLIC_KEY = "publickey";

    /** Diffie-Hellman parameters. */
    private final DiffieHellmanParameters params;

    /** Authentication utilities. */
    private final AuthenticationUtils authutils;

    /**
     * If the provided byte array begins with one and only one null byte this
     * function simply returns the original array. Otherwise a new array is
     * created that is a copy of the original array with exactly one null byte
     * in position zero, and this new array is returned.
     * 
     * @param b the original array.
     * @return the resulting byte array.
     */
    private static byte[] correctNullBytes(final byte[] b) {
        // Count the number of leading nulls.
        int leadingNulls = 0;
        for (byte aB : b) {
            if (aB != 0x00)
                break;
            ++leadingNulls;
        }
        
        // If there is exactly one leading null, return the original array.
        if (leadingNulls == 1)
            return b;
        
        // Create a copy of the non-null bytes and prepend exactly one null
        // byte.
        final int copyLength = b.length - leadingNulls;
        final byte[] result = new byte[copyLength + 1];
        result[0] = 0x00;
        System.arraycopy(b, leadingNulls, result, 1, copyLength);
        return result;
    }

    /**
     * <p>Diffie-Hellman key request data. </p>
     * 
     * <p>
     * {@code {
     *   "#mandatory" : [ "parametersid", "publickey" ],
     *   "parametersid" : "string",
     *   "publickey" : "base64",
     * }} where:
     * <ul>
     * <li>{@code parametersid} identifies the Diffie-Hellman paramters to use</li>
     * <li>{@code publickey} the Base64-encoded public key used to generate the shared secret</li>
     * </ul>
     * </p>
     */
    @EqualsAndHashCode(callSuper = true)
    @Getter
    public static class RequestData extends KeyRequestData {

        /** Diffie-Hellman parameters ID. */
        private final String parametersId;

        /** Diffie-Hellman public key Y-value. */
        private final BigInteger publicKey;

        /** Diffie-Hellman private key. */
        private final DHPrivateKey privateKey;

        /**
         * Create a new Diffie-Hellman request data repository with the
         * specified parameters ID and public key. The private key is also
         * required but is not included in the request data.
         * 
         * @param parametersId the parameters ID.
         * @param publicKey the public key Y-value.
         * @param privateKey the private key.
         */
        public RequestData(final String parametersId, final BigInteger publicKey, final DHPrivateKey privateKey) {
            super(KeyExchangeScheme.DIFFIE_HELLMAN);
            this.parametersId = parametersId;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        /**
         * Create a new Diffie-Hellman request data repository from the
         * provided JSON object. The private key will be unknown.
         * 
         * @param keyDataJO the JSON object.
         * @throws MslEncodingException if there is an error parsing the JSON.
         * @throws MslKeyExchangeException if the public key is invalid.
         */
        public RequestData(final JSONObject keyDataJO) throws MslEncodingException, MslKeyExchangeException {
            super(KeyExchangeScheme.DIFFIE_HELLMAN);
            try {
                parametersId = keyDataJO.getString(KEY_PARAMETERS_ID);
                final byte[] publicKeyY = DatatypeConverter.parseBase64Binary(keyDataJO.getString(KEY_PUBLIC_KEY));
                publicKey = new BigInteger(correctNullBytes(publicKeyY));
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + keyDataJO.toString(), e);
            } catch (final NullPointerException e) {
                throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataJO.toString(), e);
            } catch (final NumberFormatException e) {
                throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataJO.toString(), e);
            } catch (final IllegalArgumentException e) {
                throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataJO.toString(), e);
            }
            privateKey = null;
        }

        @Override
        protected JSONObject getKeydata() throws JSONException {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_PARAMETERS_ID, parametersId);
            final byte[] publicKeyY = publicKey.toByteArray();
            jsonObj.put(KEY_PUBLIC_KEY, DatatypeConverter.printBase64Binary(correctNullBytes(publicKeyY)));
            return jsonObj;
        }

    }

    /**
     * <p>Diffie-Hellman key response data.</p>
     * 
     * <p>
     * {@code {
     *   "#mandatory" : [ "parametersid", "publickey" ],
     *   "parametersid" : "string",
     *   "publickey" : "base64",
     * }} where:
     * <ul>
     * <li>{@code parametersid} identifies the Diffie-Hellman paramters to use</li>
     * <li>{@code publickey} the Base64-encoded public key used to generate the shared secret</li>
     * </ul>
     * </p>
     */
    @EqualsAndHashCode(callSuper = true)
    @Getter
    public static class ResponseData extends KeyResponseData {
        /** Diffie-Hellman parameters ID. */
        private final String parametersId;

        /** Diffie-Hellman public key. */
        private final BigInteger publicKey;

        /**
         * Create a new Diffie-Hellman response data repository with the
         * provided master token, specified parameters ID and public key.
         * 
         * @param masterToken the master token.
         * @param parametersId the parameters ID.
         * @param publicKey the public key Y-value.
         */
        public ResponseData(final MasterToken masterToken, final String parametersId, final BigInteger publicKey) {
            super(masterToken, KeyExchangeScheme.DIFFIE_HELLMAN);
            this.parametersId = parametersId;
            this.publicKey = publicKey;
        }

        /**
         * Create a new Diffie-Hellman response data repository with the
         * provided master token from the provided JSON object.
         * 
         * @param masterToken the master token.
         * @param keyDataJO the JSON object.
         * @throws MslEncodingException if there is an error parsing the JSON.
         * @throws MslKeyExchangeException if the public key is invalid.
         */
        public ResponseData(final MasterToken masterToken, final JSONObject keyDataJO) throws MslEncodingException, MslKeyExchangeException {
            super(masterToken, KeyExchangeScheme.DIFFIE_HELLMAN);
            try {
                parametersId = keyDataJO.getString(KEY_PARAMETERS_ID);
                final byte[] publicKeyY = DatatypeConverter.parseBase64Binary(keyDataJO.getString(KEY_PUBLIC_KEY));
                publicKey = new BigInteger(correctNullBytes(publicKeyY));
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + keyDataJO.toString(), e);
            } catch (final NullPointerException e) {
                throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataJO.toString(), e);
            } catch (final NumberFormatException e) {
                throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataJO.toString(), e);
            } catch (final IllegalArgumentException e) {
                throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataJO.toString(), e);
            }
        }

        @Override
        protected JSONObject getKeydata() throws JSONException {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_PARAMETERS_ID, parametersId);
            final byte[] publicKeyY = publicKey.toByteArray();
            jsonObj.put(KEY_PUBLIC_KEY, DatatypeConverter.printBase64Binary(correctNullBytes(publicKeyY)));
            return jsonObj;
        }

    }

    /**
     * Container struct for session keys.
     */
    @Value
    private static class SessionKeys {
        /** Encryption key. */
        public final SecretKey encryptionKey;

        /** HMAC key. */
        public final SecretKey hmacKey;
    }

    /**
     * Derives the encryption and HMAC session keys from a Diffie-Hellman
     * shared secret.
     * 
     * @param publicKey Diffie-Hellman public key.
     * @param privateKey Diffie-Hellman private key.
     * @param params Diffie-Hellman parameter specification.
     * @return the derived session keys.
     */
    private static SessionKeys deriveSessionKeys(final PublicKey publicKey, final PrivateKey privateKey, final DHParameterSpec params) {
        // Compute Diffie-Hellman shared secret.
        final byte[] sharedSecret;
        try {
            final KeyAgreement agreement = CryptoCache.getKeyAgreement("DiffieHellman");
            agreement.init(privateKey, params);
            agreement.doPhase(publicKey, true);
            sharedSecret = correctNullBytes(agreement.generateSecret());
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("DiffieHellman algorithm not found.", e);
        } catch (final InvalidKeyException e) {
            throw new MslInternalException("Diffie-Hellman private key or generated public key rejected by Diffie-Hellman key agreement.", e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new MslInternalException("Diffie-Hellman algorithm parameters rejected by Diffie-Hellman key agreement.", e);
        }

        // Derive encryption and HMAC keys.
        final MessageDigest sha384;
        try {
            sha384 = CryptoCache.getMessageDigest("SHA-384");
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("SHA-384 algorithm not found.", e);
        }
        final byte[] hash = sha384.digest(sharedSecret);
        final byte[] kcedata = new byte[128 / Byte.SIZE];
        System.arraycopy(hash, 0, kcedata, 0, kcedata.length);
        final byte[] kchdata = new byte[256 / Byte.SIZE];
        System.arraycopy(hash, kcedata.length, kchdata, 0, kchdata.length);

        // Return encryption and HMAC keys.
        final SecretKey encryptionKey = new SecretKeySpec(kcedata, JcaAlgorithm.AES);
        final SecretKey hmacKey = new SecretKeySpec(kchdata, JcaAlgorithm.HMAC_SHA256);
        return new SessionKeys(encryptionKey, hmacKey);
    }

    /**
     * Create a new Diffie-Hellman key exchange factory.
     * 
     * @param params Diffie-Hellman parameters.
     * @param authutils authentication utilities.
     */
    public DiffieHellmanExchange(final DiffieHellmanParameters params, final AuthenticationUtils authutils) {
        super(KeyExchangeScheme.DIFFIE_HELLMAN);
        this.params = params;
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
    public KeyExchangeData generateResponse(final MslContext ctx, final KeyRequestData keyRequestData, final MasterToken masterToken) throws MslException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData) keyRequestData;

        // If the master token was not issued by the local entity then we
        // should not be generating a key response for it.
        if (!masterToken.isVerified())
            throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
        final String identity = masterToken.getIdentity();

        // Verify the scheme is permitted.
        if(!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + this.getScheme()).setEntity(masterToken);

        // Load matching Diffie-Hellman parameter specification.
        final String parametersId = request.getParametersId();
        final DHParameterSpec paramSpec = params.getParameterSpec(parametersId);
        if (paramSpec == null)
            throw new MslKeyExchangeException(MslError.UNKNOWN_KEYX_PARAMETERS_ID, parametersId);

        // Reconstitute request public key.
        final PublicKey requestPublicKey;
        try {
            final KeyFactory factory = CryptoCache.getKeyFactory("DiffieHellman");
            final BigInteger y = request.getPublicKey();
            final DHPublicKeySpec publicKeySpec = new DHPublicKeySpec(y, paramSpec.getP(), paramSpec.getG());
            requestPublicKey = factory.generatePublic(publicKeySpec);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("DiffieHellman algorithm not found.", e);
        } catch (final InvalidKeySpecException e) {
            throw new MslInternalException("Diffie-Hellman public key specification rejected by Diffie-Hellman key factory.", e);
        }

        // Generate public/private key pair.
        final DHPublicKey responsePublicKey;
        final DHPrivateKey responsePrivateKey;
        try {
            final KeyPairGenerator generator = CryptoCache.getKeyPairGenerator("DH");
            generator.initialize(paramSpec);
            final KeyPair keyPair = generator.generateKeyPair();
            responsePublicKey = (DHPublicKey)keyPair.getPublic();
            responsePrivateKey = (DHPrivateKey)keyPair.getPrivate();
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("DiffieHellman algorithm not found.", e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new MslInternalException("Diffie-Hellman algorithm parameters rejected by Diffie-Hellman key agreement.", e);
        }

        // Construct encryption and HMAC keys.
        final SessionKeys sessionKeys = deriveSessionKeys(requestPublicKey, responsePrivateKey, paramSpec);

        // Create the master token.
        final TokenFactory tokenFactory = ctx.getTokenFactory();
        final MasterToken newMasterToken = tokenFactory.renewMasterToken(ctx, masterToken, sessionKeys.encryptionKey, sessionKeys.hmacKey);

        // Create crypto context.
        final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, newMasterToken);
        
        // Return the key exchange data.
        final KeyResponseData keyResponseData = new ResponseData(newMasterToken, parametersId, responsePublicKey.getY());
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
        if(!authutils.isSchemePermitted(identity, this.getScheme()))
            throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + this.getScheme()).setEntity(entityAuthData);

        // Load matching Diffie-Hellman parameter specification.
        final String parametersId = request.getParametersId();
        final DHParameterSpec paramSpec = params.getParameterSpec(parametersId);
        if (paramSpec == null)
            throw new MslKeyExchangeException(MslError.UNKNOWN_KEYX_PARAMETERS_ID, parametersId).setEntity(entityAuthData);

        // Reconstitute request public key.
        final PublicKey requestPublicKey;
        try {
            final KeyFactory factory = CryptoCache.getKeyFactory("DiffieHellman");
            final BigInteger y = request.getPublicKey();
            final DHPublicKeySpec publicKeySpec = new DHPublicKeySpec(y, paramSpec.getP(), paramSpec.getG());
            requestPublicKey = factory.generatePublic(publicKeySpec);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("DiffieHellman algorithm not found.", e);
        } catch (final InvalidKeySpecException e) {
            throw new MslInternalException("Diffie-Hellman public key specification rejected by Diffie-Hellman key factory.", e);
        }

        // Generate public/private key pair.
        final DHPublicKey responsePublicKey;
        final DHPrivateKey responsePrivateKey;
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
            generator.initialize(paramSpec);
            final KeyPair keyPair = generator.generateKeyPair();
            responsePublicKey = (DHPublicKey)keyPair.getPublic();
            responsePrivateKey = (DHPrivateKey)keyPair.getPrivate();
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("DiffieHellman algorithm not found.", e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new MslInternalException("Diffie-Hellman algorithm parameters rejected by Diffie-Hellman key agreement.", e);
        }

        // Construct encryption and HMAC keys.
        final SessionKeys sessionKeys = deriveSessionKeys(requestPublicKey, responsePrivateKey, paramSpec);

        // Create the master token.
        final TokenFactory tokenFactory = ctx.getTokenFactory();
        final MasterToken masterToken = tokenFactory.createMasterToken(ctx, entityAuthData, sessionKeys.encryptionKey, sessionKeys.hmacKey);

        // Create crypto context.
        final ICryptoContext cryptoContext;
        try {
            cryptoContext = new SessionCryptoContext(ctx, masterToken);
        } catch (final MslMasterTokenException e) {
            throw new MslInternalException("Master token constructed by token factory is not trusted.", e);
        }

        // Return the key exchange data.
        final KeyResponseData keyResponseData = new ResponseData(masterToken, parametersId, responsePublicKey.getY());
        return new KeyExchangeData(keyResponseData, cryptoContext);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.keyx.KeyResponseData, com.netflix.msl.tokens.MasterToken)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final KeyRequestData keyRequestData, final KeyResponseData keyResponseData, final MasterToken masterToken) throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException {
        if (!(keyRequestData instanceof RequestData))
            throw new MslInternalException("Key request data " + keyRequestData.getClass().getName() + " was not created by this factory.");
        final RequestData request = (RequestData)keyRequestData;
        if (!(keyResponseData instanceof ResponseData))
            throw new MslInternalException("Key response data " + keyResponseData.getClass().getName() + " was not created by this factory.");
        final ResponseData response = (ResponseData)keyResponseData;

        // Verify response matches request.
        final String requestParametersId = request.getParametersId();
        final String responseParametersId = response.getParametersId();
        if (!requestParametersId.equals(responseParametersId))
            throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestParametersId + "; response " + responseParametersId).setEntity(masterToken);

        // Reconstitute response public key.
        final DHPrivateKey privateKey = request.getPrivateKey();
        if (privateKey == null)
            throw new MslKeyExchangeException(MslError.KEYX_PRIVATE_KEY_MISSING, "request Diffie-Hellman private key").setEntity(masterToken);
        final DHParameterSpec params = privateKey.getParams();
        final PublicKey publicKey;
        try {
            final KeyFactory factory = CryptoCache.getKeyFactory("DiffieHellman");
            final BigInteger y = response.getPublicKey();
            final DHPublicKeySpec publicKeySpec = new DHPublicKeySpec(y, params.getP(), params.getG());
            publicKey = factory.generatePublic(publicKeySpec);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("DiffieHellman algorithm not found.", e);
        } catch (final InvalidKeySpecException e) {
            throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "Diffie-Hellman public key specification rejected by Diffie-Hellman key factory.", e);
        }

        // Create crypto context.
        final String identity = ctx.getEntityAuthenticationData(null).getIdentity();
        final SessionKeys sessionKeys = deriveSessionKeys(publicKey, privateKey, params);
        final MasterToken responseMasterToken = response.getMasterToken();
        return new SessionCryptoContext(ctx, responseMasterToken, identity, sessionKeys.encryptionKey, sessionKeys.hmacKey);
    }
}
