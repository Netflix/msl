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

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.msg.ErrorHeader;

/**
 * A generic cryptographic context suitable for encryption/decryption,
 * wrap/unwrap, and sign/verify operations.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class ICryptoContext {
    /**
     * Encrypts some data.
     * 
     * @param data the plaintext.
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the ciphertext.
     * @throws MslCryptoException if there is an error encrypting the data.
     */
    public abstract byte[] encrypt(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException;
    
    /**
     * Decrypts some data.
     * 
     * @param data the ciphertext.
     * @param encoder MSL encoder factory.
     * @return the plaintext.
     * @throws MslCryptoException if there is an error decrypting the data.
     */
    public abstract byte[] decrypt(final byte[] data, final MslEncoderFactory encoder) throws MslCryptoException;
    
    /**
     * Wraps some data.
     * 
     * @param data the plaintext.
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the wrapped data.
     * @throws MslCryptoException if there is an error wrapping the data.
     */
    public abstract byte[] wrap(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException;
    
    /**
     * Unwraps some data.
     *
     * @param data the wrapped data.
     * @param encoder MSL encoder factory.
     * @return the plaintext.
     * @throws MslCryptoException if there is an error unwrapping the data.
     */
    public abstract byte[] unwrap(final byte[] data, final MslEncoderFactory encoder) throws MslCryptoException;
    
    /**
     * Computes the signature for some data. The signature may not be a
     * signature proper, but the name suits the concept.
     * 
     * @param data the data.
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the signature.
     * @throws MslCryptoException if there is an error computing the signature.
     */
    public abstract byte[] sign(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslCryptoException;

    /**
     * Computes the signature for some data. This form of the sign method
     * accepts an additional MSL ErrorHeader object that can be used as
     * operational context when signing errors. The default implementation
     * below ignores that parameter, but subclasses can provide an override.
     *
     * @param data the data.
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @param errorHeader MSL ErrorHeader instance
     * @return the signature.
     * @throws MslCryptoException if there is an error computing the signature.
     */
    public byte[] sign(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format, ErrorHeader errorHeader) throws MslCryptoException {
        return sign(data, encoder, format);
    }

    /**
     * Verifies the signature for some data. The signature may not be a
     * signature proper, but the name suits the concept.
     * 
     * @param data the data.
     * @param signature the signature.
     * @param encoder MSL encoder factory.
     * @return true if the data is verified, false if validation fails.
     * @throws MslCryptoException if there is an error verifying the signature.
     */
    public abstract boolean verify(final byte[] data, final byte[] signature, final MslEncoderFactory encoder) throws MslCryptoException;
}
