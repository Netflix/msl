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

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

/**
 * <p>The crypto context cache provides a thread-local cache of cipher and
 * signature objects.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class CryptoCache {
    private static class ThreadLocalMap<T> extends ThreadLocal<Map<String, T>> {
        @Override
        protected Map<String, T> initialValue() {
            return new HashMap<String, T>();
        }
    }

    /** Cache of transforms onto ciphers. */
    private static ThreadLocal<Map<String,Cipher>> cipherCache = new ThreadLocalMap<>();
    
    /** Cache of algorithms onto signatures. */
    private static ThreadLocal<Map<String,Signature>> signatureCache = new ThreadLocalMap<>();
    
    /** Cache of algorithms onto message digests. */
    private static ThreadLocal<Map<String,MessageDigest>> digestCache = new ThreadLocalMap<>();
    
    /** Cache of algorithms onto MACs. */
    private static ThreadLocal<Map<String,Mac>> macCache = new ThreadLocalMap<>();
    
    /** Cache of algorithms onto key factories. */
    private static ThreadLocal<Map<String,KeyFactory>> keyFactoryCache = new ThreadLocalMap<>();
    
    /** Cache of algorithms onto key agreements. */
    private static ThreadLocal<Map<String,KeyAgreement>> keyAgreementCache = new ThreadLocalMap<>();
    
    /** Cache of algorithms onto key pair generators. */
    private static ThreadLocal<Map<String,KeyPairGenerator>> keyPairGeneratorCache = new ThreadLocalMap<>();
    
    /**
     * Returns a {@code Cipher} object that implements the specified transform.
     * 
     * @param transform encrypt/decrypt transform.
     * @return the cipher instance.
     * @throws NoSuchAlgorithmException if transformation is null, empty, in an
     *         invalid format, or if no Provider supports a CipherSpi
     *         implementation for the specified algorithm.
     * @throws NoSuchPaddingException if transformation contains a padding
     *         scheme that is not available.
     * @see #resetCipher(String)
     */
    public static Cipher getCipher(final String transform) throws NoSuchAlgorithmException, NoSuchPaddingException {
        final Map<String,Cipher> ciphers = cipherCache.get();
        if (!ciphers.containsKey(transform)) {
            final Cipher cipher = Cipher.getInstance(transform);
            ciphers.put(transform, cipher);
        }
        return ciphers.get(transform);
    }
    
    /**
     * Resets the {@code Cipher} object that implements the specified transform.
     * This method must be called if the cipher throws an exception to ensure
     * a clean cipher is returned from the next call to
     * {@link #getCipher(String)}.
     * 
     * @param transform encrypt/decrypt transform.
     * @see #getCipher(String)
     */
    public static void resetCipher(final String transform) {
        final Map<String,Cipher> ciphers = cipherCache.get();
        ciphers.remove(transform);
    }
    
    /**
     * Returns a {@code Signature} object that implements the specified
     * algorithm.
     * 
     * @param algorithm the sign/verify algorithm.
     * @return the signature instance.
     * @throws NoSuchAlgorithmException if no Provider supports a Signature
     *         implementation for the specified algorithm.
     */
    public static Signature getSignature(final String algorithm) throws NoSuchAlgorithmException {
        final Map<String,Signature> signatures = signatureCache.get();
        if (!signatures.containsKey(algorithm)) {
            final Signature signature = Signature.getInstance(algorithm);
            signatures.put(algorithm, signature);
        }
        return signatures.get(algorithm);
    }
    
    /**
     * Returns a {@code MessageDigest} object that implements the specified
     * algorithm.
     * 
     * @param algorithm the digest algorithm.
     * @return the message digest instance.
     * @throws NoSuchAlgorithmException if no Provider supports a MessageDigest
     *         implementation for the specified algorithm.
     */
    public static MessageDigest getMessageDigest(final String algorithm) throws NoSuchAlgorithmException {
        final Map<String,MessageDigest> digests = digestCache.get();
        if (!digests.containsKey(algorithm)) {
            final MessageDigest digest = MessageDigest.getInstance(algorithm);
            digests.put(algorithm, digest);
        }
        return digests.get(algorithm);
    }
    
    /**
     * Returns a {@code Mac} object that implements the specified algorithm.
     * 
     * @param algorithm the MAC algorithm.
     * @return the MAC instance.
     * @throws NoSuchAlgorithmException if no Provider supports a Mac
     *         implementation for the specified algorithm.
     */
    public static Mac getMac(final String algorithm) throws NoSuchAlgorithmException {
        final Map<String,Mac> macs = macCache.get();
        if (!macs.containsKey(algorithm)) {
            final Mac mac = Mac.getInstance(algorithm);
            macs.put(algorithm, mac);
        }
        return macs.get(algorithm);
    }
    
    /**
     * Returns a {@code KeyFactory} object that implements the specified
     * algorithm.
     * 
     * @param algorithm the key factory algorithm.
     * @return the key factory instance.
     * @throws NoSuchAlgorithmException if no Provider supports a KeyFactory
     *         implementation for the specified algorithm.
     */
    public static KeyFactory getKeyFactory(final String algorithm) throws NoSuchAlgorithmException {
        final Map<String,KeyFactory> factories = keyFactoryCache.get();
        if (!factories.containsKey(algorithm)) {
            final KeyFactory factory = KeyFactory.getInstance(algorithm);
            factories.put(algorithm, factory);
        }
        return factories.get(algorithm);
    }
    
    /**
     * Returns a {@code KeyAgreement} object that implements the specified
     * algorithm.
     * 
     * @param algorithm the key agreement algorithm.
     * @return the key agreement instance.
     * @throws NoSuchAlgorithmException if no Provider supports a KeyAgreement
     *         implementation for the specified algorithm.
     */
    public static KeyAgreement getKeyAgreement(final String algorithm) throws NoSuchAlgorithmException {
        final Map<String,KeyAgreement> agreements = keyAgreementCache.get();
        if (!agreements.containsKey(algorithm)) {
            final KeyAgreement agreement = KeyAgreement.getInstance(algorithm);
            agreements.put(algorithm, agreement);
        }
        return agreements.get(algorithm);
    }
    
    /**
     * Returns a {@code KeyPairGenerator} object that implements the specified
     * algorithm.
     * 
     * @param algorithm the key pair generator algorithm.
     * @return the key pair generator instance.
     * @throws NoSuchAlgorithmException if no Provider supports a
     *         KeyPairGenerator implementation for the specified algorithm.
     */
    public static KeyPairGenerator getKeyPairGenerator(final String algorithm) throws NoSuchAlgorithmException {
        final Map<String,KeyPairGenerator> generators = keyPairGeneratorCache.get();
        if (!generators.containsKey(algorithm)) {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            generators.put(algorithm, generator);
        }
        return generators.get(algorithm);
    }
}
