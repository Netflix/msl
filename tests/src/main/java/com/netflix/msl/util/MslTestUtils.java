/**
 * Copyright (c) 2012-2020 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;

/**
 * Helper functions common to many unit tests and mocks.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslTestUtils {
    /** Base service token name. */
    private static final String SERVICE_TOKEN_NAME = "serviceTokenName";
    /**
     * Maximum number of service tokens to randomly generate. This needs to be
     * large enough to statistically create the applicable set of service
     * tokens for the tests.
     */
    private static final int NUM_SERVICE_TOKENS = 12;
    
    /** Wrapping key derivation algorithm salt. */
    private static final byte[] SALT = {
        (byte)0x02, (byte)0x76, (byte)0x17, (byte)0x98, (byte)0x4f, (byte)0x62, (byte)0x27, (byte)0x53, 
        (byte)0x9a, (byte)0x63, (byte)0x0b, (byte)0x89, (byte)0x7c, (byte)0x01, (byte)0x7d, (byte)0x69 };
    /** Wrapping key derivation algorithm info. */
    private static final byte[] INFO = {
        (byte)0x80, (byte)0x9f, (byte)0x82, (byte)0xa7, (byte)0xad, (byte)0xdf, (byte)0x54, (byte)0x8d,
        (byte)0x3e, (byte)0xa9, (byte)0xdd, (byte)0x06, (byte)0x7f, (byte)0xf9, (byte)0xbb, (byte)0x91, };
    /** Wrapping key length in bytes. */
    private static final int WRAPPING_KEY_LENGTH = 128 / Byte.SIZE;

    
    /**
     * Parse a new {@link MslObject} from the {@link MslEncodable}.
     * 
     * @param encoder the {@link MslEncoderFactory}.
     * @param encode a {@link MslEncodable}.
     * @return the {@link MslObject}
     * @throws MslEncoderException if there is an error encoding and converting
     *         the  object cannot be encoded and converted
     */
    public static MslObject toMslObject(final MslEncoderFactory encoder, final MslEncodable encode) throws MslEncoderException {
        final byte[] encoding = encode.toMslEncoding(encoder, encoder.getPreferredFormat(null));
        return encoder.parseObject(encoding);
    }

    /**
     * Returns a master token with the identity of the MSL context entity
     * authentication data that is not renewable or expired.
     * 
     * @param ctx MSL context.
     * @param sequenceNumber master token sequence number to use.
     * @param serialNumber master token serial number to use.
     * @return a new master token.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    public static MasterToken getMasterToken(final MslContext ctx, final long sequenceNumber, final long serialNumber) throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 20000);
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        final String identity = entityAuthData.getIdentity();
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        return new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, null, identity, encryptionKey, hmacKey);
    }
    
    /**
     * Returns an untrusted master token with the identity of the MSL context
     * entity authentication data that is not renewable or expired.
     * 
     * @param ctx MSL context.
     * @return a new untrusted master token.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if the master token is constructed incorrectly.
     * @throws MslEncoderException if there is an error editing the data.
     */
    public static MasterToken getUntrustedMasterToken(final MslContext ctx) throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 20000);
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        final String identity = entityAuthData.getIdentity();
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, identity, encryptionKey, hmacKey);
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final MslObject mo = toMslObject(encoder, masterToken);
        final byte[] signature = mo.getBytes("signature");
        ++signature[1];
        mo.put("signature", signature);
        return new MasterToken(ctx, mo);
    }
    
    /**
     * Returns a user ID token with the identity of the provided user that is
     * not renewable or expired.
     * 
     * @param ctx MSL context.
     * @param masterToken master token to bind against.
     * @param serialNumber user ID token serial number to use.
     * @param user MSL user to use.
     * @return a new user ID token.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    public static UserIdToken getUserIdToken(final MslContext ctx, final MasterToken masterToken, final long serialNumber, final MslUser user) throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 20000);
        return new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, null, user);
    }
    
    /**
     * Returns an untrusted user ID token with the identity of the provided
     * user that is not renewable or expired.
     * 
     * @param ctx MSL context.
     * @param masterToken master token to bind against.
     * @param serialNumber user ID token serial number to use.
     * @param user MSL user to use.
     * @return a new untrusted user ID token.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncoderException if there is an error editing the data.
     * @throws MslException if the user ID token serial number is out of range.
     */
    public static UserIdToken getUntrustedUserIdToken(final MslContext ctx, final MasterToken masterToken, final long serialNumber, final MslUser user) throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 10000);
        final Date expiration = new Date(System.currentTimeMillis() + 20000);
        final UserIdToken userIdToken = new UserIdToken(ctx, renewalWindow, expiration, masterToken, serialNumber, null, user);
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final MslObject mo = toMslObject(encoder, userIdToken);
        final byte[] signature = mo.getBytes("signature");
        ++signature[1];
        mo.put("signature", signature);
        return new UserIdToken(ctx, mo, masterToken);
    }
    
    /**
     * @param ctx MSL context.
     * @param masterToken master token to bind against. May be null.
     * @param userIdToken user ID token to bind against. May be null.
     * @return a set of new service tokens with random token bindings.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if there is an error compressing the data.
     */
    public static Set<ServiceToken> getServiceTokens(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken) throws MslEncodingException, MslCryptoException, MslException {
        final Random random = new Random();
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> serviceTokens = new HashSet<ServiceToken>();
        final int numTokens = Math.max(NUM_SERVICE_TOKENS, 3);
        for (int i = 0; i < numTokens; ++i) {
            final String name = SERVICE_TOKEN_NAME + random.nextInt();
            final byte[] data = new byte[32];
            random.nextBytes(data);

            // Make sure one of each type of token is included.
            // Otherwise pick a random type.
            final int type = (i < 3) ? i : random.nextInt(3);
            switch (type) {
                case 0:
                    serviceTokens.add(new ServiceToken(ctx, name, data, null, null, false, null, cryptoContext));
                    break;
                case 1:
                    serviceTokens.add(new ServiceToken(ctx, name, data, masterToken, null, false, null, cryptoContext));
                    break;
                case 2:
                    serviceTokens.add(new ServiceToken(ctx, name, data, masterToken, userIdToken, false, null, cryptoContext));
                    break;
            }
        }
        return serviceTokens;
    }
    
    /**
     * @param ctx MSL context.
     * @param masterToken the master token to bind against.
     * @return a random set of master token bound service tokens.
     * @throws MslEncodingException if there is an error constructing the
     *         service token.
     * @throws MslCryptoException if there is an error constructing the service
     *         token.
     * @throws MslException if there is an error compressing the data.
     */
    public static Set<ServiceToken> getMasterBoundServiceTokens(final MslContext ctx, final MasterToken masterToken) throws MslEncodingException, MslCryptoException, MslException {
        final Random random = new Random();
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> tokens = new HashSet<ServiceToken>();
        for (int count = random.nextInt(NUM_SERVICE_TOKENS); count >= 0; --count) {
            final String name = SERVICE_TOKEN_NAME + random.nextInt();
            final byte[] data = new byte[8];
            random.nextBytes(data);
            final ServiceToken token = new ServiceToken(ctx, name, data, masterToken, null, false, null, cryptoContext);
            tokens.add(token);
        }
        return tokens;
    }
    
    /**
     * @param ctx MSL context.
     * @param masterToken the master token to bind against.
     * @param userIdToken the user ID token to bind against.
     * @return a random set of user ID token bound service tokens.
     * @throws MslEncodingException if there is an error constructing the
     *         service token.
     * @throws MslCryptoException if there is an error constructing the service
     *         token.
     * @throws MslException if there is an error compressing the data.
     */
    public static Set<ServiceToken> getUserBoundServiceTokens(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken) throws MslEncodingException, MslCryptoException, MslException {
        final Random random = new Random();
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> tokens = new HashSet<ServiceToken>();
        for (int count = random.nextInt(NUM_SERVICE_TOKENS); count >= 0; --count) {
            final String name = SERVICE_TOKEN_NAME + random.nextInt();
            final byte[] data = new byte[8];
            random.nextBytes(data);
            final ServiceToken token = new ServiceToken(ctx, name, data, masterToken, userIdToken, false, null, cryptoContext);
            tokens.add(token);
        }
        return tokens;
    }
    
    /**
     * Derives the pre-shared or model group keys AES-128 Key Wrap key from the
     * provided AES-128 encryption key and HMAC-SHA256 key.
     * 
     * @param encryptionKey the encryption key.
     * @param hmacKey the HMAC key.
     * @return the wrapping key.
     */
    public static byte[] deriveWrappingKey(final byte[] encryptionKey, final byte[] hmacKey) {
        try {
            // Concatenate the keys.
            final byte[] bits = Arrays.copyOf(encryptionKey, encryptionKey.length + hmacKey.length);
            System.arraycopy(hmacKey, 0, bits, encryptionKey.length, hmacKey.length);
    
            // HMAC-SHA256 the keys with the salt as the HMAC key.
            final SecretKey saltKey = new SecretKeySpec(SALT, JcaAlgorithm.HMAC_SHA256);
            final Mac intermediateMac = Mac.getInstance(saltKey.getAlgorithm());
            intermediateMac.init(saltKey);
            final byte[] intermediateBits = intermediateMac.doFinal(bits);
    
            // HMAC-SHA256 the info with the intermediate key as the HMAC key.
            final SecretKey intermediateKey = new SecretKeySpec(intermediateBits, JcaAlgorithm.HMAC_SHA256);
            final Mac finalMac = Mac.getInstance(intermediateKey.getAlgorithm());
            finalMac.init(intermediateKey);
            final byte[] finalBits = finalMac.doFinal(INFO);

            // Grab the first 128 bits.
            return Arrays.copyOf(finalBits, WRAPPING_KEY_LENGTH);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException(JcaAlgorithm.HMAC_SHA256 + " algorithm not found.", e);
        } catch (final InvalidKeyException e) {
            throw new MslInternalException("Invalid " + JcaAlgorithm.HMAC_SHA256 + " key.", e);
        }
    }
}
