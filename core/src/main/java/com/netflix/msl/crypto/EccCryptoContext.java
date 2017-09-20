/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * An ECC crypto context performs ECIES encryption/decryption or SHA-1 with
 * ECDSA sign/verify using a public/private ECC key pair.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class EccCryptoContext extends AsymmetricCryptoContext {
    /** ECC crypto context mode. .*/
    public static enum Mode {
        ENCRYPT_DECRYPT,
        SIGN_VERIFY
    };
    
    /**
     * <p>Create a new ECC crypto context using the provided public and private
     * keys.</p>
     * 
     * <p>If there is no private key, decryption and signing is unsupported.</p>
     * 
     * <p>If there is no public key, encryption and verification is
     * unsupported.</p>
     * 
     * @param id the key pair identity.
     * @param privateKey the private key used for signing. May be null.
     * @param publicKey the public key used for verifying. May be null.
     * @param mode crypto context mode.
     */
    public EccCryptoContext(final String id, final PrivateKey privateKey, final PublicKey publicKey, final Mode mode) {
        super(id, privateKey, publicKey, Mode.ENCRYPT_DECRYPT.equals(mode) ? "ECIES" : NULL_OP, null, Mode.SIGN_VERIFY.equals(mode) ? "SHA256withECDSA" : NULL_OP);
    }
}
