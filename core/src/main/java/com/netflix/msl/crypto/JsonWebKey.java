/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.io.MslArray;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;

/**
 * This class implements the JSON web key structure as defined in
 * <a href="http://tools.ietf.org/html/draft-ietf-mose-json-web-key-08">JSON Web Key</a>.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonWebKey implements MslEncodable {
    /** JSON key key type. */
    private static final String KEY_TYPE = "kty";
    /** JSON key usage. */
    private static final String KEY_USAGE = "use";
    /** JSON key key operations. */
    private static final String KEY_KEY_OPS = "key_ops";
    /** JSON key algorithm. */
    private static final String KEY_ALGORITHM = "alg";
    /** JSON key extractable. */
    private static final String KEY_EXTRACTABLE = "extractable";
    /** JSON key key ID. */
    private static final String KEY_KEY_ID = "kid";
    
    // RSA keys.
    /** JSON key modulus. */
    private static final String KEY_MODULUS = "n";
    /** JSON key public exponent. */
    private static final String KEY_PUBLIC_EXPONENT = "e";
    /** JSON key private exponent. */
    private static final String KEY_PRIVATE_EXPONENT = "d";
    
    // Symmetric keys.
    /** JSON key key. */
    private static final String KEY_KEY = "k";
    
    /** Supported key types. */
    public static enum Type {
        /** RSA */
        rsa,
        /** Octet Sequence */
        oct,
    }
    
    /** Supported key usages. */
    public static enum Usage {
        /** Sign/verify. */
        sig,
        /** Encrypt/decrypt. */
        enc,
        /** Wrap/unwrap. */
        wrap,
    }
    
    /** Supported key operations. */
    public static enum KeyOp {
        sign,
        verify,
        encrypt,
        decrypt,
        wrapKey,
        unwrapKey,
        deriveKey,
        deriveBits
    }
    
    /** Supported key algorithms. */
    public static enum Algorithm {
        /** HMAC-SHA256 */
        HS256("HS256"),
        /** RSA PKCS#1 v1.5 */
        RSA1_5("RSA1_5"),
        /** RSA OAEP */
        RSA_OAEP("RSA-OAEP"),
        /** AES-128 Key Wrap */
        A128KW("A128KW"),
        /** AES-128 CBC */
        A128CBC("A128CBC");
        
        /**
         * @param name JSON Web Algorithm name.
         */
        private Algorithm(final String name) {
            this.name = name;
        }
        
        /**
         * @return the Java Cryptography Architecture standard algorithm name
         *         for this JSON Web Algorithm.
         */
        public String getJcaAlgorithmName() {
            switch (this) {
                case HS256:
                    return "HmacSHA256";
                case RSA1_5:
                case RSA_OAEP:
                    return "RSA";
                case A128KW:
                case A128CBC:
                    return "AES";
                default:
                    throw new MslInternalException("No JCA standard algorithm name defined for " + this + ".");
            }
        }
        
        /* (non-Javadoc)
         * @see java.lang.Enum#toString()
         */
        @Override
        public String toString() {
            return name;
        }

        /**
         * @param name JSON Web Algorithm name.
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
        
        /** JSON Web Algorithm name. */
        private final String name;
    }
    
    /**
     * Returns the big integer in big-endian format without any leading sign
     * bits.
     * 
     * @param bi the big integer.
     * @return the big integer in big-endian form.
     */
    private static byte[] bi2bytes(final BigInteger bi) {
        final byte[] bib = bi.toByteArray();
        final int len = (int)Math.ceil((double)bi.bitLength() / Byte.SIZE);
        return Arrays.copyOfRange(bib, bib.length - len, bib.length);
    }
    
    /**
     * Create a new JSON web key for an RSA public/private key pair with the
     * specified attributes. At least one of the public key or private key must
     * be encoded.
     * 
     * @param usage key usage. May be null.
     * @param algo key algorithm. May be null.
     * @param extractable true if the key is extractable.
     * @param id key ID. May be null.
     * @param publicKey RSA public key. May be null.
     * @param privateKey RSA private key. May be null.
     * @throws MslInternalException if both keys are null or the algorithm
     *         is incompatible.
     */
    public JsonWebKey(final Usage usage, final Algorithm algo, final boolean extractable, final String id, final RSAPublicKey publicKey, final RSAPrivateKey privateKey) {
        if (publicKey == null && privateKey == null)
            throw new MslInternalException("At least one of the public key or private key must be provided.");
        if (algo != null) {
            switch (algo) {
                case RSA1_5:
                case RSA_OAEP:
                    break;
                default:
                    throw new MslInternalException("The algorithm must be an RSA algorithm.");
            }
        }
        
        this.type = Type.rsa;
        this.usage = usage;
        this.keyOps = null;
        this.algo = algo;
        this.extractable = extractable;
        this.id = id;
        this.keyPair = new KeyPair(publicKey, privateKey);
        this.key = null;
        this.secretKey = null;
    }
    
    /**
     * Create a new JSON web key for a symmetric key with the specified
     * attributes.
     * 
     * @param usage key usage. May be null.
     * @param algo key algorithm. May be null.
     * @param extractable true if the key is extractable.
     * @param id key ID. May be null.
     * @param secretKey symmetric key.
     * @throws MslInternalException if the usage or algorithm is incompatible.
     */
    public JsonWebKey(final Usage usage, final Algorithm algo, final boolean extractable, final String id, final SecretKey secretKey) {
        if (algo != null) {
            switch (algo) {
                case HS256:
                case A128KW:
                case A128CBC:
                    break;
                default:
                    throw new MslInternalException("The algorithm must be a symmetric key algorithm.");
            }
        }
        
        this.type = Type.oct;
        this.usage = usage;
        this.keyOps = null;
        this.algo = algo;
        this.extractable = extractable;
        this.id = id;
        this.keyPair = null;
        this.key = secretKey.getEncoded();
        this.secretKey = secretKey;
    }
    
    /**
     * Create a new JSON web key for an RSA public/private key pair with the
     * specified attributes. At least one of the public key or private key must
     * be encoded.
     * 
     * @param keyOps key operations. May be null.
     * @param algo key algorithm. May be null.
     * @param extractable true if the key is extractable.
     * @param id key ID. May be null.
     * @param publicKey RSA public key. May be null.
     * @param privateKey RSA private key. May be null.
     * @throws MslInternalException if both keys are null or the algorithm
     *         is incompatible.
     */
    public JsonWebKey(final Set<KeyOp> keyOps, final Algorithm algo, final boolean extractable, final String id, final RSAPublicKey publicKey, final RSAPrivateKey privateKey) {
        if (publicKey == null && privateKey == null)
            throw new MslInternalException("At least one of the public key or private key must be provided.");
        if (algo != null) {
            switch (algo) {
                case RSA1_5:
                case RSA_OAEP:
                    break;
                default:
                    throw new MslInternalException("The algorithm must be an RSA algorithm.");
            }
        }
        
        this.type = Type.rsa;
        this.usage = null;
        this.keyOps = (keyOps != null) ? Collections.unmodifiableSet(keyOps) : null;
        this.algo = algo;
        this.extractable = extractable;
        this.id = id;
        this.keyPair = new KeyPair(publicKey, privateKey);
        this.key = null;
        this.secretKey = null;
    }
    
    /**
     * Create a new JSON web key for a symmetric key with the specified
     * attributes.
     * 
     * @param keyOps key operations. May be null.
     * @param algo key algorithm. May be null.
     * @param extractable true if the key is extractable.
     * @param id key ID. May be null.
     * @param secretKey symmetric key.
     * @throws MslInternalException if the usage or algorithm is incompatible.
     */
    public JsonWebKey(final Set<KeyOp> keyOps, final Algorithm algo, final boolean extractable, final String id, final SecretKey secretKey) {
        if (algo != null) {
            switch (algo) {
                case HS256:
                case A128KW:
                case A128CBC:
                    break;
                default:
                    throw new MslInternalException("The algorithm must be a symmetric key algorithm.");
            }
        }
        
        this.type = Type.oct;
        this.usage = null;
        this.keyOps = (keyOps != null) ? Collections.unmodifiableSet(keyOps) : null;
        this.algo = algo;
        this.extractable = extractable;
        this.id = id;
        this.keyPair = null;
        this.key = secretKey.getEncoded();
        this.secretKey = secretKey;
    }
    
    /**
     * Create a new JSON web key from the provided MSL object.
     * 
     * @param jsonMo JSON web key MSL object.
     * @throws MslCryptoException if the key type is unknown.
     * @throws MslEncodingException if there is an error parsing the data.
     */
    public JsonWebKey(final MslObject jsonMo) throws MslCryptoException, MslEncodingException {
        // Parse JSON object.
        final String typeName, usageName, algoName;
        final Set<String> keyOpsNames;
        try {
            typeName = jsonMo.getString(KEY_TYPE);
            usageName = jsonMo.has(KEY_USAGE) ? jsonMo.getString(KEY_USAGE) : null;
            if (jsonMo.has(KEY_KEY_OPS)) {
                keyOpsNames = new HashSet<String>();
                final MslArray ma = jsonMo.getMslArray(KEY_KEY_OPS);
                for (int i = 0; i < ma.size(); ++i)
                    keyOpsNames.add(ma.getString(i));
            } else {
                keyOpsNames = null;
            }
            algoName = jsonMo.has(KEY_ALGORITHM) ? jsonMo.getString(KEY_ALGORITHM) : null;
            extractable = jsonMo.has(KEY_EXTRACTABLE) ? jsonMo.getBoolean(KEY_EXTRACTABLE) : false;
            id = jsonMo.has(KEY_KEY_ID) ? jsonMo.getString(KEY_KEY_ID) : null;
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "jwk " + jsonMo, e);
        }
        
        // Set values.
        try {
            type = Type.valueOf(typeName);
        } catch (final IllegalArgumentException e) {
            throw new MslCryptoException(MslError.UNIDENTIFIED_JWK_TYPE, typeName, e);
        }
        try {
            usage = (usageName != null) ? Usage.valueOf(usageName) : null;
        } catch (final IllegalArgumentException e) {
            throw new MslCryptoException(MslError.UNIDENTIFIED_JWK_USAGE, usageName, e);
        }
        if (keyOpsNames != null) {
            final Set<KeyOp> keyOps = EnumSet.noneOf(KeyOp.class);
            for (final String keyOpName : keyOpsNames) {
                try {
                    keyOps.add(KeyOp.valueOf(keyOpName));
                } catch (final IllegalArgumentException e) {
                    throw new MslCryptoException(MslError.UNIDENTIFIED_JWK_KEYOP, usageName, e);
                }
            }
            this.keyOps = Collections.unmodifiableSet(keyOps);
        } else {
            this.keyOps = null;
        }
        try {
            algo = (algoName != null) ? Algorithm.fromString(algoName) : null;
        } catch (final IllegalArgumentException e) {
            throw new MslCryptoException(MslError.UNIDENTIFIED_JWK_ALGORITHM, algoName, e);
        }
        
        // Reconstruct keys.
        try {
            // Handle symmetric keys.
            if (type == Type.oct) {
                key = MslEncoderUtils.b64urlDecode(jsonMo.getString(KEY_KEY));
                if (key == null || key.length == 0)
                    throw new MslCryptoException(MslError.INVALID_JWK_KEYDATA, "symmetric key is empty");
                secretKey = (algo != null) ? new SecretKeySpec(key, algo.getJcaAlgorithmName()) : null;
                keyPair = null;
            }
            
            // Handle public/private keys (RSA only).
            else {
                key = null;
                final KeyFactory factory = CryptoCache.getKeyFactory("RSA");
                
                // Grab the modulus.
                final byte[] n = MslEncoderUtils.b64urlDecode(jsonMo.getString(KEY_MODULUS));
                if (n == null || n.length == 0)
                    throw new MslCryptoException(MslError.INVALID_JWK_KEYDATA, "modulus is empty");
                final BigInteger modulus = new BigInteger(1, n);
                
                // Reconstruct the public key if it exists.
                final PublicKey publicKey;
                if (jsonMo.has(KEY_PUBLIC_EXPONENT)) {
                    final byte[] e = MslEncoderUtils.b64urlDecode(jsonMo.getString(KEY_PUBLIC_EXPONENT));
                    if (e == null || e.length == 0)
                        throw new MslCryptoException(MslError.INVALID_JWK_KEYDATA, "public exponent is empty");
                    final BigInteger exponent = new BigInteger(1, e);
                    final KeySpec pubkeySpec = new RSAPublicKeySpec(modulus, exponent);
                    publicKey = factory.generatePublic(pubkeySpec);
                } else {
                    publicKey = null;
                }
                
                // Reconstruct the private key if it exists.
                final PrivateKey privateKey;
                if (jsonMo.has(KEY_PRIVATE_EXPONENT)) {
                    final byte[] d = MslEncoderUtils.b64urlDecode(jsonMo.getString(KEY_PRIVATE_EXPONENT));
                    if (d == null || d.length == 0)
                        throw new MslCryptoException(MslError.INVALID_JWK_KEYDATA, "private exponent is empty");
                    final BigInteger exponent = new BigInteger(1, d);
                    final KeySpec privkeySpec = new RSAPrivateKeySpec(modulus, exponent);
                    privateKey = factory.generatePrivate(privkeySpec);
                } else {
                    privateKey = null;
                }
                
                // Make sure there is at least one key.
                if (publicKey == null && privateKey == null)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "no public or private key");
                
                keyPair = new KeyPair(publicKey, privateKey);
                secretKey = null;
            }
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, e);
        } catch (final NoSuchAlgorithmException e) {
            throw new MslCryptoException(MslError.UNSUPPORTED_JWK_ALGORITHM, e);
        } catch (final InvalidKeySpecException e) {
            throw new MslCryptoException(MslError.INVALID_JWK_KEYDATA, e);
        }
    }
    
    /**
     * @return the key type.
     */
    public Type getType() {
        return type;
    }
    
    /**
     * @return the permitted key usage or null if not specified.
     */
    public Usage getUsage() {
        return usage;
    }
    
    /**
     * @return the permitted key operations or null if not specified.
     */
    public Set<KeyOp> getKeyOps() {
        return keyOps;
    }
    
    /**
     * @return the key algorithm or null if not specified.
     */
    public Algorithm getAlgorithm() {
        return algo;
    }
    
    /**
     * @return true if the key is allowed to be extracted.
     */
    public boolean isExtractable() {
        return extractable;
    }
    
    /**
     * @return the key ID or null if not specified.
     */
    public String getId() {
        return id;
    }
    
    /**
     * Returns the stored RSA key pair if the JSON web key type is RSA. The
     * public or private key may be null if only one of the pair is stored in
     * this JSON web key.
     * 
     * @return the stored RSA key pair or null if the type is not RSA.
     */
    public KeyPair getRsaKeyPair() {
        return keyPair;
    }
    
    /**
     * Returns the stored symmetric key if the JSON web key type is OCT and an
     * algorithm was specified. Because Java {@code SecretKey} requires a known
     * algorithm when it is constructed, the key material may be present when
     * this method returns {@code null}.
     * 
     * @return the stored symmetric key or null if the type is not OCT or no
     *         algorithm was specified.
     * @see #getSecretKey(String)
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }
    
    /**
     * Returns the stored symmetric key if the JSON web key type is OCT. The
     * returned key algorithm will be the one specified by the JSON web key
     * algorithm. If no JSON web key algorithm was specified the provided
     * algorithm will be used instead.
     * 
     * @param algorithm the symmetric key algorithm to use if one was not
     *        specified in the JSON web key.
     * @return the stored symmetric key or null if the type is not OCT.
     * @throws MslCryptoException if the key cannot be constructed.
     * @see #getSecretKey()
     */
    public SecretKey getSecretKey(final String algorithm) throws MslCryptoException {
        // Return the stored symmetric key if it already exists.
        if (secretKey != null)
            return secretKey;
        
        // Otherwise construct the secret key.
        if (key == null)
            return null;
        try {
            return new SecretKeySpec(key, algorithm);
        } catch (final IllegalArgumentException e) {
            throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, e);
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) {
        try {
            final MslObject mo = encoder.createObject();
            
            // Encode key attributes.
            mo.put(KEY_TYPE, type.name());
            if (usage != null) mo.put(KEY_USAGE, usage.name());
            if (keyOps != null) {
                final MslArray keyOpsMa = encoder.createArray();
                for (final KeyOp op : keyOps)
                    keyOpsMa.put(-1, op.name());
                mo.put(KEY_KEY_OPS, keyOpsMa);
            }
            if (algo != null) mo.put(KEY_ALGORITHM, algo.toString());
            mo.put(KEY_EXTRACTABLE, extractable);
            if (id != null) mo.put(KEY_KEY_ID, id);
            
            // Encode symmetric keys.
            if (type == Type.oct) {
                mo.put(KEY_KEY, MslEncoderUtils.b64urlEncode(key));
            }
            
            // Encode public/private keys (RSA only).
            else {
                final RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
                final RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
                
                // Encode modulus.
                final BigInteger modulus = (publicKey != null) ? publicKey.getModulus() : privateKey.getModulus();
                final byte[] n = bi2bytes(modulus);
                mo.put(KEY_MODULUS, MslEncoderUtils.b64urlEncode(n));
                
                // Encode public key.
                if (publicKey != null) {
                    final BigInteger exponent = publicKey.getPublicExponent();
                    final byte[] e = bi2bytes(exponent);
                    mo.put(KEY_PUBLIC_EXPONENT, MslEncoderUtils.b64urlEncode(e));
                }
                
                // Encode private key.
                if (privateKey != null) {
                    final BigInteger exponent = privateKey.getPrivateExponent();
                    final byte[] d = bi2bytes(exponent);
                    mo.put(KEY_PRIVATE_EXPONENT, MslEncoderUtils.b64urlEncode(d));
                }
            }
            
            // Return the result.
            //
            // We will always encode as JSON.
            return encoder.encodeObject(mo, MslEncoderFormat.JSON);
        } catch (final MslEncoderException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + ".", e);
        }
    }

    /** Key type. */
    private final Type type;
    /** Key usages. */
    private final Usage usage;
    /** Key operations. */
    private final Set<KeyOp> keyOps;
    /** Key algorithm. */
    private final Algorithm algo;
    /** Extractable. */
    private final boolean extractable;
    /** Key ID. */
    private final String id;
        
    /** RSA key pair. May be null. */
    private final KeyPair keyPair;
    /** Symmetric key raw bytes. May be null. */
    private final byte[] key;
    /** Symmetric key. May be null. */
    private final SecretKey secretKey;
}
