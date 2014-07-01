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
package com.netflix.msl.crypto;

import com.netflix.msl.MslCryptoException;

/**
 * A generic cryptographic context suitable for encryption/decryption,
 * wrap/unwrap, and sign/verify operations.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface ICryptoContext {
    /**
     * Encrypts some data.
     * 
     * @param data the plaintext.
     * @return the ciphertext.
     * @throws MslCryptoException if there is an error encrypting the data.
     */
    public byte[] encrypt(final byte[] data) throws MslCryptoException;
    
    /**
     * Decrypts some data.
     * 
     * @param data the ciphertext.
     * @return the plaintext.
     * @throws MslCryptoException if there is an error decrypting the data.
     */
    public byte[] decrypt(final byte[] data) throws MslCryptoException;
    
    /**
     * Wraps some data.
     * 
     * @param data the plaintext.
     * @return the wrapped data.
     * @throws MslCryptoException if there is an error wrapping the data.
     */
    public byte[] wrap(final byte[] data) throws MslCryptoException;
    
    /**
     * Unwraps some data.
     *
     * @param data the wrapped data.
     * @return the plaintext.
     * @throws MslCryptoException if there is an error unwrapping the data.
     */
    public byte[] unwrap(final byte[] data) throws MslCryptoException;
    
    /**
     * Computes the signature for some data. The signature may not be a
     * signature proper, but the name suits the concept.
     * 
     * @param data the data.
     * @return the signature.
     * @throws MslCryptoException if there is an error computing the signature.
     */
    public byte[] sign(final byte[] data) throws MslCryptoException;
    
    /**
     * Verifies the signature for some data. The signature may not be a
     * signature proper, but the name suits the concept.
     * 
     * @param data the data.
     * @param signature the signature.
     * @return true if the data is verified, false if validation fails.
     * @throws MslCryptoException if there is an error verifying the signature.
     */
    public boolean verify(final byte[] data, final byte[] signature) throws MslCryptoException;
}
