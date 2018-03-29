/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslUtils;

/**
 * A symmetric crypto context performs AES-128 encryption/decryption, AES-128
 * key wrap/unwrap, and HMAC-SHA256 or AES-CMAC sign/verify.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SymmetricCryptoContext extends ICryptoContext {
    /** AES encryption cipher algorithm. */
    private static final String AES_ALGO = "AES";
    /** AES encryption cipher algorithm. */
    private static final String AES_TRANSFORM = AES_ALGO + "/CBC/PKCS5Padding";
    /** AES encryption initial value size in bytes. */
    private static final int AES_IV_SIZE = 16;
    
    /** HMAC SHA-256 algorithm. */
    private static final String HMAC_SHA256_ALGO = "HmacSHA256";
    
    /** AES key wrap cipher algorithm. */
    private static final String AESKW_ALGO = "AES";
    /** AES key wrap cipher transform. */
    private static final String AESKW_TRANSFORM = AESKW_ALGO + "/ECB/NoPadding";
    /** AES key wrap block size in bytes. */
    private static final int AESKW_BLOCK_SIZE = 8;
    /** Key wrap initial value. */
    private static final byte[] AESKW_AIV = { (byte)0xA6, (byte)0xA6, (byte)0xA6, (byte)0xA6, (byte)0xA6, (byte)0xA6, (byte)0xA6, (byte)0xA6 };
    
    /**
     * @param bytes number of bytes to return.
     * @param w the value.
     * @return the specified number of most significant (big-endian) bytes of
     *         the value.
     */
    private static byte[] msb(final int bytes, final byte[] w) {
        final byte[] msb = new byte[bytes];
        System.arraycopy(w, 0, msb, 0, bytes);
        return msb;
    }
    
    /**
     * @param bytes number of bytes to return.
     * @param w the value.
     * @return the specified number of least significant (big-endian) bytes of
     *         the value.
     */
    private static byte[] lsb(final int bytes, final byte[] w) {
        final int offset = w.length - bytes;
        final byte[] lsb = new byte[bytes];
        for (int i = 0; i < bytes; ++i)
            lsb[i] = w[offset + i];
        return lsb;
    }
    
    /**
     * Modifies the provided byte array by XOR'ing it with the provided value.
     * The byte array is processed in big-endian order.
     * 
     * @param b 8-byte value that will be modified.
     * @param t the 64-bit value to XOR the value with.
     */
    private static void xor(final byte[] b, final long t) {
        b[0] ^= t >>> 56;
        b[1] ^= t >>> 48;
        b[2] ^= t >>> 40;
        b[3] ^= t >>> 32;
        b[4] ^= t >>> 24;
        b[5] ^= t >>> 16;
        b[6] ^= t >>> 8;
        b[7] ^= t;
    }
    
    /**
     * <p>Create a new symmetric crypto context using the provided keys.</p>
     * 
     * <p>If there is no encryption key, encryption and decryption is
     * unsupported.</p>
     * 
     * <p>If there is no signature key, signing and verification is
     * unsupported.</p>
     * 
     * <p>If there is no wrapping key, wrap and unwrap is unsupported.</p>
     * 
     * @param ctx MSL context.
     * @param id the key set identity.
     * @param encryptionKey the key used for encryption/decryption.
     * @param signatureKey the key used for HMAC or CMAC computation.
     * @param wrappingKey the key used for wrap/unwrap.     */
    public SymmetricCryptoContext(final MslContext ctx, final String id, final SecretKey encryptionKey, final SecretKey signatureKey, final SecretKey wrappingKey) {
        if (encryptionKey != null && !encryptionKey.getAlgorithm().equals(JcaAlgorithm.AES))
            throw new IllegalArgumentException("Encryption key must be an " + JcaAlgorithm.AES + " key.");
        if (signatureKey != null &&
            !signatureKey.getAlgorithm().equals(JcaAlgorithm.HMAC_SHA256) &&
            !signatureKey.getAlgorithm().equals(JcaAlgorithm.AES_CMAC))
        {
            throw new IllegalArgumentException("Encryption key must be an " + JcaAlgorithm.HMAC_SHA256 + " or " + JcaAlgorithm.AES_CMAC + " key.");
        }
        if (wrappingKey != null && !wrappingKey.getAlgorithm().equals(JcaAlgorithm.AESKW))
            throw new IllegalArgumentException("Encryption key must be an " + JcaAlgorithm.AESKW + " key.");
        
        this.ctx = ctx;
        this.id = id;
        this.encryptionKey = encryptionKey;
        this.signatureKey = signatureKey;
        this.wrappingKey = wrappingKey;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#encrypt(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] encrypt(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
        if (encryptionKey == null)
            throw new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED, "no encryption/decryption key");
        try {
            // Generate IV.
            final Random random = ctx.getRandom();
            final byte[] iv = new byte[AES_IV_SIZE];
            random.nextBytes(iv);
            
            // Encrypt plaintext.
            final byte[] ciphertext;
            if (data.length != 0) {
                final Cipher cipher = CryptoCache.getCipher(AES_TRANSFORM);
                final AlgorithmParameterSpec params = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, params);
                ciphertext = cipher.doFinal(data);
            } else {
                ciphertext = new byte[0];
            }
            
            // Return encryption envelope byte representation.
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(id, iv, ciphertext);
            return envelope.toMslEncoding(encoder, format);
        } catch (final NoSuchPaddingException e) {
            throw new MslInternalException("Unsupported padding exception.", e);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("Invalid cipher algorithm specified.", e);
        } catch (final InvalidKeyException e) {
            throw new MslCryptoException(MslError.INVALID_ENCRYPTION_KEY, e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new MslCryptoException(MslError.INVALID_ALGORITHM_PARAMS, e);
        } catch (final IllegalBlockSizeException e) {
            throw new MslCryptoException(MslError.PLAINTEXT_ILLEGAL_BLOCK_SIZE, "not expected when padding is specified", e);
        } catch (final BadPaddingException e) {
            throw new MslCryptoException(MslError.PLAINTEXT_BAD_PADDING, "not expected when encrypting", e);
        } catch (final MslEncoderException e) {
            throw new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_ENCODE_ERROR, e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#decrypt(byte[], com.netflix.msl.io.MslEncoderFactory)
     */
    @Override
    public byte[] decrypt(final byte[] data, final MslEncoderFactory encoder) throws MslCryptoException {
        if (encryptionKey == null)
            throw new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED, "no encryption/decryption key");
        try {
            // Reconstitute encryption envelope.
            final MslObject encryptionEnvelopeMo = encoder.parseObject(data);
            final MslCiphertextEnvelope encryptionEnvelope = new MslCiphertextEnvelope(encryptionEnvelopeMo, MslCiphertextEnvelope.Version.V1);
            
            // Decrypt ciphertext.
            final byte[] ciphertext = encryptionEnvelope.getCiphertext();
            if (ciphertext.length == 0)
                return new byte[0];
            final byte[] iv = encryptionEnvelope.getIv();
            final Cipher cipher = CryptoCache.getCipher(AES_TRANSFORM);
            final AlgorithmParameterSpec params = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, params);
            return cipher.doFinal(ciphertext);
        } catch (final ArrayIndexOutOfBoundsException e) {
            throw new MslCryptoException(MslError.INSUFFICIENT_CIPHERTEXT, e);
        } catch (final MslEncoderException e) {
            throw new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR, e);
        } catch (final MslEncodingException e) {
            throw new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR, e);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("Invalid cipher algorithm specified.", e);
        } catch (final NoSuchPaddingException e) {
            throw new MslInternalException("Unsupported padding exception.", e);
        } catch (final InvalidKeyException e) {
            throw new MslCryptoException(MslError.INVALID_ENCRYPTION_KEY, e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new MslCryptoException(MslError.INVALID_ALGORITHM_PARAMS, e);
        } catch (final IllegalBlockSizeException e) {
            throw new MslCryptoException(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE, e);
        } catch (final BadPaddingException e) {
            throw new MslCryptoException(MslError.CIPHERTEXT_BAD_PADDING, e);
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] wrap(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
        if (wrappingKey == null)
            throw new MslCryptoException(MslError.WRAP_NOT_SUPPORTED, "no wrap/unwrap key");
        if (data.length % 8 != 0)
            throw new MslCryptoException(MslError.PLAINTEXT_ILLEGAL_BLOCK_SIZE, "data.length " + data.length);
        
        // Compute alternate initial value.
        byte[] a = AESKW_AIV.clone();
        final byte[] r = data.clone();
        try {
            final Cipher cipher = CryptoCache.getCipher(AESKW_TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, wrappingKey);
            
            // Initialize variables.
            final int n = r.length / AESKW_BLOCK_SIZE;
            
            // Calculate intermediate values.
            for (int j = 0; j < 6; ++j) {
                for (int i = 1; i <= n; ++i) {
                    byte[] r_i = Arrays.copyOfRange(r, (i - 1) * AESKW_BLOCK_SIZE, i * AESKW_BLOCK_SIZE);
                    final byte[] ar_i = Arrays.copyOf(a, a.length + r_i.length);
                    System.arraycopy(r_i, 0, ar_i, a.length, r_i.length);
                    final byte[] b = cipher.doFinal(ar_i);
                    a = msb(AESKW_BLOCK_SIZE, b);
                    final long t = (n * j) + i;
                    xor(a, t);
                    r_i = lsb(AESKW_BLOCK_SIZE, b);
                    System.arraycopy(r_i, 0, r, (i - 1) * AESKW_BLOCK_SIZE, AESKW_BLOCK_SIZE);
                }
            }
            
            // Output results.
            final byte[] c = new byte[a.length + r.length];
            System.arraycopy(a, 0, c, 0, a.length);
            System.arraycopy(r, 0, c, a.length, r.length);
            return c;
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("Invalid cipher algorithm specified.", e);
        } catch (final NoSuchPaddingException e) {
            throw new MslInternalException("Unsupported padding exception.", e);
        } catch (final InvalidKeyException e) {
            throw new MslCryptoException(MslError.INVALID_WRAPPING_KEY, e);
        } catch (final IllegalBlockSizeException e) {
            throw new MslCryptoException(MslError.PLAINTEXT_ILLEGAL_BLOCK_SIZE, "not expected when padding is no padding", e);
        } catch (final BadPaddingException e) {
            throw new MslCryptoException(MslError.PLAINTEXT_BAD_PADDING, "not expected when encrypting", e);
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#unwrap(byte[], com.netflix.msl.io.MslEncoderFactory)
     */
    @Override
    public byte[] unwrap(final byte[] data, final MslEncoderFactory encoder) throws MslCryptoException {
        if (wrappingKey == null)
            throw new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED, "no wrap/unwrap key");
        if (data.length % 8 != 0)
            throw new MslCryptoException(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE, "data.length " + data.length);
        
        try {
            final Cipher cipher = CryptoCache.getCipher(AESKW_TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, wrappingKey);
            
            byte[] a = Arrays.copyOf(data, AESKW_BLOCK_SIZE);
            final byte[] r = Arrays.copyOfRange(data, a.length, data.length);
            final int n = (data.length - AESKW_BLOCK_SIZE) / AESKW_BLOCK_SIZE;
            
            // Calculate intermediate values.
            for (int j = 5; j >= 0; --j) {
                for (int i = n; i >= 1; --i) {
                    final long t = (n * j) + i;
                    xor(a, t);
                    byte[] r_i = Arrays.copyOfRange(r, (i - 1) * AESKW_BLOCK_SIZE, i * AESKW_BLOCK_SIZE);
                    final byte[] ar_i = Arrays.copyOf(a, a.length + r_i.length);
                    System.arraycopy(r_i, 0, ar_i, a.length, r_i.length);
                    final byte[] b = cipher.doFinal(ar_i);
                    a = msb(AESKW_BLOCK_SIZE, b);
                    r_i = lsb(AESKW_BLOCK_SIZE, b);
                    System.arraycopy(r_i, 0, r, (i - 1) * AESKW_BLOCK_SIZE, AESKW_BLOCK_SIZE);
                }
            }
            
            // Output results.
            if (MslUtils.safeEquals(a, AESKW_AIV) && r.length % AESKW_BLOCK_SIZE == 0)
                return r;
            throw new MslCryptoException(MslError.UNWRAP_ERROR, "initial value " + Arrays.toString(a));
        } catch (final NoSuchPaddingException e) {
            throw new MslInternalException("Unsupported padding exception.", e);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("Invalid cipher algorithm specified.", e);
        } catch (final InvalidKeyException e) {
            throw new MslCryptoException(MslError.INVALID_WRAPPING_KEY, e);
        } catch (final IllegalBlockSizeException e) {
            throw new MslCryptoException(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE, e);
        } catch (final BadPaddingException e) {
            throw new MslCryptoException(MslError.CIPHERTEXT_BAD_PADDING, e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#sign(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] sign(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
        if (signatureKey == null)
            throw new MslCryptoException(MslError.SIGN_NOT_SUPPORTED, "No signature key.");
        try {
            // Compute the xMac.
            final byte[] xmac;
            if (signatureKey.getAlgorithm().equals(JcaAlgorithm.HMAC_SHA256)) {
                final Mac mac = CryptoCache.getMac(HMAC_SHA256_ALGO);
                mac.init(signatureKey);
                xmac = mac.doFinal(data);
            } else if (signatureKey.getAlgorithm().equals(JcaAlgorithm.AES_CMAC)) {
                final CipherParameters params = new KeyParameter(signatureKey.getEncoded());
                final BlockCipher aes = new AESEngine();
                final CMac mac = new CMac(aes);
                mac.init(params);
                mac.update(data, 0, data.length);
                xmac = new byte[mac.getMacSize()];
                mac.doFinal(xmac, 0);
            } else {
                throw new MslCryptoException(MslError.SIGN_NOT_SUPPORTED, "Unsupported algorithm.");
            }
            
            // Return the signature envelope byte representation.
            return new MslSignatureEnvelope(xmac).getBytes(encoder, format);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("Invalid MAC algorithm specified.", e);
        } catch (final InvalidKeyException e) {
            throw new MslCryptoException(MslError.INVALID_HMAC_KEY, e);
        } catch (final MslEncoderException e) {
            throw new MslCryptoException(MslError.SIGNATURE_ENVELOPE_ENCODE_ERROR, e);
        }
    }

    @Override
    public boolean verify(final byte[] data, final byte[] signature, final MslEncoderFactory encoder) throws MslCryptoException {
        if (signatureKey == null)
            throw new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED, "No signature key.");
        try {
            // Reconstitute the signature envelope.
            final MslSignatureEnvelope envelope = MslSignatureEnvelope.parse(signature, encoder);
            
            // Compute the xMac.
            final byte[] xmac;
            if (signatureKey.getAlgorithm().equals(JcaAlgorithm.HMAC_SHA256)) {
                final Mac mac = CryptoCache.getMac(HMAC_SHA256_ALGO);
                mac.init(signatureKey);
                xmac = mac.doFinal(data);
            } else if (signatureKey.getAlgorithm().equals(JcaAlgorithm.AES_CMAC)) {
                final CipherParameters params = new KeyParameter(signatureKey.getEncoded());
                final BlockCipher aes = new AESEngine();
                final CMac mac = new CMac(aes);
                mac.init(params);
                mac.update(data, 0, data.length);
                xmac = new byte[mac.getMacSize()];
                mac.doFinal(xmac, 0);
            } else {
                throw new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED, "Unsupported algorithm.");
            }

            // Compare the computed hash to the provided signature.
            return MslUtils.safeEquals(xmac, envelope.getSignature());
        } catch (final MslEncodingException e) {
            throw new MslCryptoException(MslError.SIGNATURE_ENVELOPE_PARSE_ERROR, e);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("Invalid MAC algorithm specified.", e);
        } catch (final InvalidKeyException e) {
            throw new MslCryptoException(MslError.INVALID_HMAC_KEY, e);
        }
    }
    
    /** MSL context. */
    protected final MslContext ctx;
    /** Key set identity. */
    protected final String id;
    /** Encryption/decryption key. */
    protected final SecretKey encryptionKey;
    /** Signature key. */
    protected final SecretKey signatureKey;
    /** Wrapping key. */
    protected final SecretKey wrappingKey;
}
