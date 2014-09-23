/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
package kancolle.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.util.MslContext;

/**
 * <p>This crypto context derives an AES-128 and HMAC-SHA256 key pair from the
 * SHA-384 of a secret value.</p> 
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColleCryptoContext extends SymmetricCryptoContext {
    /** AES-128 algorithm. */
    private static final String AES_ALGO = "AES";
    /** HMAC-SHA256 algorithm. */
    private static final String HMAC_SHA256_ALGO = "HmacSHA256";
    /** SHA-384 algorithm. */
    private static final String SHA_384_ALGO = "SHA-384";
    
    /** AES-128 key length in bytes. */
    private static final int AES_128_LENGTH = 16;
    /** HMAC-SHA256 key length in bytes. */
    private static final int HMAC_SHA256_LENGTH = 32;
    
    /**
     * Derives an AES-128 key from the first 16 bytes of the SHA-384 of the
     * secret.
     * 
     * @param secret the secret.
     * @return the encryption key.
     */
    private static SecretKey deriveEncryptionKey(final String secret) {
        try {
            final MessageDigest sha384 = MessageDigest.getInstance(SHA_384_ALGO);
            final byte[] hash = sha384.digest(secret.getBytes());
            final byte[] keydata = Arrays.copyOf(hash, AES_128_LENGTH);
            return new SecretKeySpec(keydata, AES_ALGO);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException(SHA_384_ALGO + " algorithm not found.", e);
        }
    }
    
    /**
     * Derives an HMAC-SHA256 key from the last 32 bytes of the SHA-384 of the
     * secret.
     * 
     * @param secret the secret.
     * @return the HMAC key.
     */
    private static SecretKey deriveHmacKey(final String secret) {
        try {
            final MessageDigest sha384 = MessageDigest.getInstance(SHA_384_ALGO);
            final byte[] hash = sha384.digest(secret.getBytes());
            final byte[] keydata = Arrays.copyOfRange(hash, AES_128_LENGTH, AES_128_LENGTH + HMAC_SHA256_LENGTH);
            return new SecretKeySpec(keydata, HMAC_SHA256_ALGO);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException(SHA_384_ALGO + " algorithm not found.", e);
        }
    }
    
    /**
     * Create a new KanColle crypto context from the given secret.
     * 
     * @param ctx MSL context.
     * @param id the key set identity.
     * @param secret the secret.
     */
    public KanColleCryptoContext(final MslContext ctx, final String id, final String secret) {
        super(ctx, id, deriveEncryptionKey(secret), deriveHmacKey(secret), null);
    }
}
