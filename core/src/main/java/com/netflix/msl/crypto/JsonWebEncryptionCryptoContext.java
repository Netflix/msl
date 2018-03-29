/**
 * Copyright (c) 2013-2018 Netflix, Inc.  All rights reserved.
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

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.io.MslArray;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;

/**
 * <p>This key exchange crypto context provides an implementation of the JSON
 * web encryption algorithm as defined in
 * <a href="http://tools.ietf.org/html/draft-ietf-mose-json-web-encryption-08">JSON Web Encryption</a>.
 * It supports a limited subset of the algorithms.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonWebEncryptionCryptoContext extends ICryptoContext {
    /** Encoding charset. */
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    
    /** JSON key recipients. */
    private static final String KEY_RECIPIENTS = "recipients";
    /** JSON key header. */
    private static final String KEY_HEADER = "header";
    /** JSON key encrypted key. */
    private static final String KEY_ENCRYPTED_KEY = "encrypted_key";
    /** JSON key integrity value. */
    private static final String KEY_INTEGRITY_VALUE = "integrity_value";
    /** JSON key initialization vector. */
    private static final String KEY_INITIALIZATION_VECTOR = "initialization_vector";
    /** JSON key ciphertext. */
    private static final String KEY_CIPHERTEXT = "ciphertext";
    
    /** JSON key wrap algorithm. */
    private static final String KEY_ALGORITHM = "alg";
    /** JSON key encryption algorithm. */
    private static final String KEY_ENCRYPTION = "enc";
    
    /** AES-128 GCM authentication tag length in bits. */
    private static final int A128_GCM_AT_LENGTH = 128;
    /** AES-128 GCM key length in bytes. */
    private static final int A128_GCM_KEY_LENGTH = 16;
    /** AES-128 GCM initialization vector length in bytes. */
    private static final int A128_GCM_IV_LENGTH = 12;
    
    /** AES-256 GCM authentication tag length in bits. */
    private static final int A256_GCM_AT_LENGTH = 128;
    /** AES-256 GCM key length in bytes. */
    private static final int A256_GCM_KEY_LENGTH = 32;
    /** AES-256 GCM initialization vector length in bytes. */
    private static final int A256_GCM_IV_LENGTH = 12;
    
    /** Supported content encryption key encryption algorithms. */
    private static enum Algorithm {
        /** RSAES-OAEP */
        RSA_OAEP("RSA-OAEP"),
        /** AES-128 Key Wrap */
        A128KW("A128KW");
        
        /**
         * @param name JSON Web Encryption algorithm name.
         */
        private Algorithm(final String name) {
            this.name = name;
        }
        
        /* (non-Javadoc)
         * @see java.lang.Enum#toString()
         */
        @Override
        public String toString() {
            return name;
        }
        
        /**
         * @param name JSON Web Encryption algorithm name.
         * @return the algorithm.
         * @throws IllegalArgumentException if the algorithm name is unknown.
         */
        public static Algorithm fromString(final String name) {
            for (final Algorithm algo : values()) {
                if (algo.toString().equals(name))
                    return algo;
            }
            throw new IllegalArgumentException("Algorithm " + name + " is unknown.");
        }
        
        /** JSON Web Encryption algorithm name. */
        private final String name;
    }
    
    /**
     * The Content Encryption Key crypto context is used to encrypt/decrypt the
     * randomly generated content encryption key.
     */
    public static abstract class CekCryptoContext extends ICryptoContext {
        /**
         * Create a new content encryption key crypto context with the
         * specified content encryption key encryption algorithm.
         * 
         * @param algo content encryption key encryption algorithm.
         */
        protected CekCryptoContext(final Algorithm algo) {
            this.algo = algo;
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        @Override
        public byte[] wrap(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
            throw new MslCryptoException(MslError.WRAP_NOT_SUPPORTED);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#unwrap(byte[], com.netflix.msl.io.MslEncoderFactory)
         */
        @Override
        public byte[] unwrap(final byte[] data, final MslEncoderFactory encoder) throws MslCryptoException {
            throw new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#sign(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        @Override
        public byte[] sign(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
            throw new MslCryptoException(MslError.SIGN_NOT_SUPPORTED);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#verify(byte[], byte[], com.netflix.msl.io.MslEncoderFactory)
         */
        @Override
        public boolean verify(final byte[] data, final byte[] signature, final MslEncoderFactory encoder) throws MslCryptoException {
            throw new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED);
        }
        
        /**
         * @return the content encryption key encryption algorithm.
         */
        Algorithm getAlgorithm() {
            return algo;
        }
        
        /** Content encryption key encryption algorithm. */
        private final Algorithm algo;
    }
    
    /**
     * RSA-OAEP encrypt/decrypt of the content encryption key.
     */
    public static class RsaOaepCryptoContext extends CekCryptoContext {
        /** RSA-OAEP cipher transform. */
        private static final String RSA_OAEP_TRANSFORM = "RSA/ECB/OAEPPadding";
        
        /**
         * <p>Create a new RSA crypto context for encrypt/decrypt using the
         * provided public and private keys. All other operations are
         * unsupported.</p>
         * 
         * <p>If there is no private key decryption is unsupported.</p>
         * 
         * <p>If there is no public key encryption is unsupported.</p>
         * 
         * @param privateKey the private key. May be null.
         * @param publicKey the public key. May be null.
         */
        public RsaOaepCryptoContext(final PrivateKey privateKey, final PublicKey publicKey) {
            super(Algorithm.RSA_OAEP);
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#encrypt(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        @Override
        public byte[] encrypt(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
            if (publicKey == null)
                throw new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED, "no public key");
            Throwable reset = null;
            try {
                // Encrypt plaintext.
                final Cipher cipher = CryptoCache.getCipher(RSA_OAEP_TRANSFORM);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEPParameterSpec.DEFAULT);
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
                    CryptoCache.resetCipher(RSA_OAEP_TRANSFORM);
            }
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#decrypt(byte[], com.netflix.msl.io.MslEncoderFactory)
         */
        @Override
        public byte[] decrypt(final byte[] data, final MslEncoderFactory encoder) throws MslCryptoException {
            if (privateKey == null)
                throw new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED, "no private key");
            Throwable reset = null;
            try {
                // Decrypt ciphertext.
                final Cipher cipher = CryptoCache.getCipher(RSA_OAEP_TRANSFORM);
                cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEPParameterSpec.DEFAULT);
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
                    CryptoCache.resetCipher(RSA_OAEP_TRANSFORM);
            }
        }

        /** Encryption/decryption cipher. */
        protected final PrivateKey privateKey;
        /** Sign/verify signature. */
        protected final PublicKey publicKey;
    }
    
    /**
     * AES key wrap encrypt/decrypt of the content encryption key.
     */
    public static class AesKwCryptoContext extends CekCryptoContext {
        /** AES key wrap cipher transform. */
        private static final String A128_KW_TRANSFORM = "AESWrap";
        
        /**
         * Create a new AES key wrap crypto context with the provided secret
         * key.
         * 
         * @param key AES secret key.
         */
        public AesKwCryptoContext(final SecretKey key) {
            super(Algorithm.A128KW);
            if (!key.getAlgorithm().equals(JcaAlgorithm.AESKW))
                throw new IllegalArgumentException("Secret key must be an " + JcaAlgorithm.AESKW + " key.");
            this.key = key;
            this.cryptoContext = null;
        }
        
        /**
         * Create a new AES key wrap crypto context backed by the provided
         * AES crypto context.
         * 
         * @param cryptoContext AES crypto context.
         */
        public AesKwCryptoContext(final ICryptoContext cryptoContext) {
            super(Algorithm.A128KW);
            this.key = null;
            this.cryptoContext = cryptoContext;
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#encrypt(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        @Override
        public byte[] encrypt(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
            // If a secret key is provided use it.
            if (key != null) {
                try {
                    // Encrypt plaintext.
                    final Cipher cipher = CryptoCache.getCipher(A128_KW_TRANSFORM);
                    cipher.init(Cipher.WRAP_MODE, key);
                    // TODO: The key spec algorithm should be based on the JWE
                    // encryption algorithm. Right now that is always AES-GCM.
                    final Key secretKey = new SecretKeySpec(data, "AES");
                    return cipher.wrap(secretKey);
                } catch (final NoSuchPaddingException e) {
                    throw new MslInternalException("Unsupported padding exception.", e);
                } catch (final NoSuchAlgorithmException e) {
                    throw new MslInternalException("Invalid cipher algorithm specified.", e);
                } catch (final IllegalArgumentException e) {
                    throw new MslInternalException("Invalid content encryption key provided.", e);
                } catch (final InvalidKeyException e) {
                    throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, e);
                } catch (final IllegalBlockSizeException e) {
                    throw new MslCryptoException(MslError.PLAINTEXT_ILLEGAL_BLOCK_SIZE, "not expected when padding is specified", e);
                }
            }

            // Otherwise use the backing crypto context.
            return cryptoContext.wrap(data, encoder, format);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#decrypt(byte[], com.netflix.msl.io.MslEncoderFactory)
         */
        @Override
        public byte[] decrypt(final byte[] data, final MslEncoderFactory encoder) throws MslCryptoException {
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
            return cryptoContext.unwrap(data, encoder);
        }
        
        /** AES secret key. */
        private final SecretKey key;
        /** AES crypto context. */
        private final ICryptoContext cryptoContext;
    }
    
    /** Supported plaintext encryption algorithms. */
    public static enum Encryption {
        /** AES-128 GCM */
        A128GCM,
        /** AES-256 GCM */
        A256GCM,
    }
    
    /** Support serialization formats. */
    public static enum Format {
        /**
         * <a href="http://tools.ietf.org/html/draft-mones-mose-jwe-json-serialization-04">JSON Web Encryption JSON Serialization (JWE-JS)</a>
         */
        JWE_JS,
        /**
         * <a href="http://tools.ietf.org/html/draft-ietf-mose-json-web-encryption-08">JSON Web Encryption Compact Serialization</a>
         */
        JWE_CS
    }
    
    /**
     * Create a new JSON web encryption crypto context with the provided
     * content encryption key crypto context and specified plaintext encryption
     * algorithm.
     * 
     * @param ctx MSL context.
     * @param cryptoContext content encryption key crypto context.
     * @param enc plaintext encryption algorithm.
     * @param format serialization format.
     */
    public JsonWebEncryptionCryptoContext(final MslContext ctx, final CekCryptoContext cryptoContext, final Encryption enc, final Format format) {
        this.ctx = ctx;
        this.cekCryptoContext = cryptoContext;
        this.algo = cryptoContext.getAlgorithm();
        this.enc = enc;
        this.format = format;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#encrypt(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] encrypt(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
        throw new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#decrypt(byte[], com.netflix.msl.io.MslEncoderFactory)
     */
    @Override
    public byte[] decrypt(final byte[] data, final MslEncoderFactory encoder) throws MslCryptoException {
        throw new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] wrap(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
        // Create the header.
        final byte[] header;
        try {
            final MslObject headerMo = encoder.createObject();
            headerMo.put(KEY_ALGORITHM, algo.toString());
            headerMo.put(KEY_ENCRYPTION, enc.name());
            header = encoder.encodeObject(headerMo, MslEncoderFormat.JSON);
        } catch (final MslEncoderException e) {
            throw new MslCryptoException(MslError.JWE_ENCODE_ERROR, e);
        }

        // Determine algorithm byte lengths.
        final int keylen, ivlen, atlen;
        if (Encryption.A128GCM.equals(enc)) {
            keylen = A128_GCM_KEY_LENGTH;
            ivlen = A128_GCM_IV_LENGTH;
            atlen = A128_GCM_AT_LENGTH;
        } else if (Encryption.A256GCM.equals(enc)) {
            keylen = A256_GCM_KEY_LENGTH;
            ivlen = A256_GCM_IV_LENGTH;
            atlen = A256_GCM_AT_LENGTH;
        } else {
            throw new MslCryptoException(MslError.UNSUPPORTED_JWE_ALGORITHM, enc.name());
        }

        // Generate the key and IV.
        final Random random = ctx.getRandom();
        final byte[] key = new byte[keylen];
        random.nextBytes(key);
        final KeyParameter cek = new KeyParameter(key);
        final byte[] iv = new byte[ivlen];
        random.nextBytes(iv);

        // Encrypt the CEK.
        final byte[] ecek = cekCryptoContext.encrypt(cek.getKey(), encoder, MslEncoderFormat.JSON);

        // Base64-encode the data.
        final String headerB64 = MslEncoderUtils.b64urlEncode(header);
        final String ecekB64 = MslEncoderUtils.b64urlEncode(ecek);
        final String ivB64 = MslEncoderUtils.b64urlEncode(iv);

        // Create additional authenticated data.
        final String aad = headerB64 + "." + ecekB64 + "." + ivB64;

        // TODO: AES-GCM is not available via the JCE.
        //
        // Create and initialize the cipher for encryption.
        final GCMBlockCipher plaintextCipher = new GCMBlockCipher(new AESEngine());
        final AEADParameters params = new AEADParameters(cek, atlen, iv, aad.getBytes(UTF_8));
        plaintextCipher.init(true, params);
        
        // Encrypt the plaintext.
        final byte[] ciphertextATag;
        try {
            final int clen = plaintextCipher.getOutputSize(data.length);
            ciphertextATag = new byte[clen];
            // Encrypt the plaintext and get the resulting ciphertext length
            // which will be used for the authentication tag offset.
            final int offset = plaintextCipher.processBytes(data, 0, data.length, ciphertextATag, 0);
            // Append the authentication tag.
            plaintextCipher.doFinal(ciphertextATag, offset);
        } catch (final IllegalStateException e) {
            throw new MslCryptoException(MslError.WRAP_ERROR, e);
        } catch (final InvalidCipherTextException e) {
            throw new MslInternalException("Invalid ciphertext not expected when encrypting.", e);
        }
        
        // Split the result into the ciphertext and authentication tag.
        final byte[] ciphertext = Arrays.copyOfRange(ciphertextATag, 0, ciphertextATag.length - atlen/Byte.SIZE);
        final byte[] at = Arrays.copyOfRange(ciphertextATag, ciphertext.length, ciphertextATag.length);
        
        // Base64-encode the ciphertext and authentication tag.
        final String ciphertextB64 = MslEncoderUtils.b64urlEncode(ciphertext);
        final String atB64 = MslEncoderUtils.b64urlEncode(at);
        
        // Envelope the data.
        switch (this.format) {
            case JWE_CS:
            {
                final String serialization = aad + "." + ciphertextB64 + "." + atB64;
                return serialization.getBytes(UTF_8);
            }
            case JWE_JS:
            {
                try {
                    // Create recipients array.
                    final MslArray recipients = encoder.createArray();
                    final MslObject recipient = encoder.createObject();
                    recipient.put(KEY_HEADER, headerB64);
                    recipient.put(KEY_ENCRYPTED_KEY, ecekB64);
                    recipient.put(KEY_INTEGRITY_VALUE, atB64);
                    recipients.put(-1, recipient);

                    // Create JSON serialization.
                    final MslObject serialization = encoder.createObject();
                    serialization.put(KEY_RECIPIENTS, recipients);
                    serialization.put(KEY_INITIALIZATION_VECTOR, ivB64);
                    serialization.put(KEY_CIPHERTEXT, ciphertextB64);
                    return encoder.encodeObject(serialization, MslEncoderFormat.JSON);
                } catch (final MslEncoderException e) {
                    throw new MslCryptoException(MslError.JWE_ENCODE_ERROR, e);
                }
            }
            default:
                throw new MslCryptoException(MslError.UNSUPPORTED_JWE_SERIALIZATION, format.name());
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#unwrap(byte[], com.netflix.msl.io.MslEncoderFactory)
     */
    @Override
    public byte[] unwrap(final byte[] data, final MslEncoderFactory encoder) throws MslCryptoException {
        // Parse the serialization.
        final String serialization = new String(data, UTF_8);
        final String headerB64, ecekB64, ivB64;
        final byte[] ciphertext, at;
        if (data[0] == '{') {
            try {
                final MslObject serializationMo = encoder.parseObject(data);
                ivB64 = serializationMo.getString(KEY_INITIALIZATION_VECTOR);
                ciphertext = MslEncoderUtils.b64urlDecode(serializationMo.getString(KEY_CIPHERTEXT));
                
                // TODO: For now, we only support one recipient.
                final MslArray recipients = serializationMo.getMslArray(KEY_RECIPIENTS);
                if (recipients.size() < 1)
                    throw new MslCryptoException(MslError.JWE_PARSE_ERROR, serialization);
                final MslObject recipient = recipients.getMslObject(0, encoder);
                headerB64 = recipient.getString(KEY_HEADER);
                ecekB64 = recipient.getString(KEY_ENCRYPTED_KEY);
                at = MslEncoderUtils.b64urlDecode(recipient.getString(KEY_INTEGRITY_VALUE));
            } catch (final MslEncoderException e) {
                throw new MslCryptoException(MslError.JWE_PARSE_ERROR, serialization, e);
            }
        } else {
            // Separate the compact serialization.
            final String[] parts = serialization.split("\\.");
            if (parts.length != 5)
                throw new MslCryptoException(MslError.JWE_PARSE_ERROR, serialization);

            // Extract the data from the serialization.
            headerB64 = parts[0];
            ecekB64 = parts[1];
            ivB64 = parts[2];
            ciphertext = MslEncoderUtils.b64urlDecode(parts[3]);
            at = MslEncoderUtils.b64urlDecode(parts[4]);
        }
        
        // Decode header, encrypted content encryption key, and IV.
        final byte[] headerBytes = MslEncoderUtils.b64urlDecode(headerB64);
        final byte[] ecek = MslEncoderUtils.b64urlDecode(ecekB64);
        final byte[] iv = MslEncoderUtils.b64urlDecode(ivB64);
        
        // Verify data.
        if (headerBytes == null || headerBytes.length == 0 ||
            ecek == null || ecek.length == 0 ||
            iv == null || iv.length == 0 ||
            ciphertext == null || ciphertext.length == 0 ||
            at == null || at.length == 0)
        {
            throw new MslCryptoException(MslError.JWE_PARSE_ERROR, serialization);
        }
        
        // Reconstruct and parse the header.
        final String header = new String(headerBytes, UTF_8);
        final Algorithm algo;
        final Encryption enc;
        try {
            final MslObject headerMo = encoder.parseObject(headerBytes);
            final String algoName = headerMo.getString(KEY_ALGORITHM);
            try {
                algo = Algorithm.fromString(algoName);
            } catch (final IllegalArgumentException e) {
                throw new MslCryptoException(MslError.JWE_PARSE_ERROR, algoName, e);
            }
            final String encName = headerMo.getString(KEY_ENCRYPTION);
            try {
                enc = Encryption.valueOf(encName);
            } catch (final IllegalArgumentException e) {
                throw new MslCryptoException(MslError.JWE_PARSE_ERROR, encName, e);
            }
        } catch (final MslEncoderException e) {
            throw new MslCryptoException(MslError.JWE_PARSE_ERROR, header, e);
        }
        
        // Confirm header matches.
        if (!this.algo.equals(algo) || !this.enc.equals(enc))
            throw new MslCryptoException(MslError.JWE_ALGORITHM_MISMATCH, header);
        
        // Decrypt the CEK.
        final KeyParameter cek;
        try {
            final byte[] cekBytes = cekCryptoContext.decrypt(ecek, encoder);
            cek = new KeyParameter(cekBytes);
        } catch (final ArrayIndexOutOfBoundsException e) {
            // Thrown if the encrypted content encryption key is an invalid
            // length.
            throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, e);
        }
        
        // Create additional authenticated data.
        final String aad = headerB64 + "." + ecekB64 + "." + ivB64;
        
        // Determine algorithm byte lengths.
        final int keylen, atlen;
        if (Encryption.A128GCM.equals(enc)) {
            keylen = A128_GCM_KEY_LENGTH;
            atlen = A128_GCM_AT_LENGTH;
        } else if (Encryption.A256GCM.equals(enc)) {
            keylen = A256_GCM_KEY_LENGTH;
            atlen = A256_GCM_AT_LENGTH;
        } else {
            throw new MslCryptoException(MslError.UNSUPPORTED_JWE_ALGORITHM, enc.name());
        }

        // Verify algorithm parameters.
        if (cek.getKey().length != keylen)
            throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, "content encryption key length: " + cek.getKey().length);
        if (at.length != atlen / Byte.SIZE)
            throw new MslCryptoException(MslError.INVALID_ALGORITHM_PARAMS, "authentication tag length: " + at.length);

        // TODO: AES-GCM is not available via the JCE.
        //
        // Create and initialize the cipher for decryption.
        final GCMBlockCipher plaintextCipher = new GCMBlockCipher(new AESEngine());
        final AEADParameters params = new AEADParameters(cek, atlen, iv, aad.getBytes(UTF_8));
        plaintextCipher.init(false, params);

        // Decrypt the ciphertext.
        try {
            // Reconstruct the ciphertext and authentication tag.
            final byte[] ciphertextAtag = Arrays.copyOf(ciphertext, ciphertext.length + at.length);
            System.arraycopy(at, 0, ciphertextAtag, ciphertext.length, at.length);
            final int plen = plaintextCipher.getOutputSize(ciphertextAtag.length);
            final byte[] plaintext = new byte[plen];
            // Decrypt the ciphertext and get the resulting plaintext length
            // which will be used for the authentication tag offset.
            final int offset = plaintextCipher.processBytes(ciphertextAtag, 0, ciphertextAtag.length, plaintext, 0);
            // Verify the authentication tag.
            plaintextCipher.doFinal(plaintext, offset);
            return plaintext;
        } catch (final IllegalStateException e) {
            throw new MslCryptoException(MslError.UNWRAP_ERROR, e);
        } catch (final InvalidCipherTextException e) {
            throw new MslCryptoException(MslError.UNWRAP_ERROR, e);
        } catch (final ArrayIndexOutOfBoundsException e) {
            // Thrown if the ciphertext is an invalid length.
            throw new MslCryptoException(MslError.UNWRAP_ERROR, e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#sign(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] sign(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException {
        throw new MslCryptoException(MslError.SIGN_NOT_SUPPORTED);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.crypto.ICryptoContext#verify(byte[], byte[], com.netflix.msl.io.MslEncoderFactory)
     */
    @Override
    public boolean verify(final byte[] data, final byte[] signature, final MslEncoderFactory encoder) throws MslCryptoException {
        throw new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED);
    }
    
    /** MSL context. */
    private final MslContext ctx;
    /** Content encryption key crypto context. */
    private final ICryptoContext cekCryptoContext;
    /** Wrap algorithm. */
    private final Algorithm algo;
    /** Encryption algorithm. */
    private final Encryption enc;
    /** Serialization format. */
    private final Format format;
}
