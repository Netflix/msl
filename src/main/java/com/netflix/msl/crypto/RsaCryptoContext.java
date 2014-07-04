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

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.spec.OAEPParameterSpec;

import com.netflix.msl.MslInternalException;
import com.netflix.msl.util.MslContext;

/**
 * <p>An RSA crypto context supports RSA/ECB/OAEPPadding or RSA/ECB/PKCS#1
 * encryption/decryption, or SHA-256 with RSA sign/verify.</p>
 * 
 * <p>The {@link OAEPParameterSpec#DEFAULT} parameters are used for OAEP
 * encryption and decryption.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class RsaCryptoContext extends AsymmetricCryptoContext {
    /** RSA crypto context algorithm. .*/
    public static enum Mode {
        /** RSA-OAEP encrypt/decrypt */
        ENCRYPT_DECRYPT_OAEP,
        /** RSA PKCS#1 encrypt/decrypt */
        ENCRYPT_DECRYPT_PKCS1,
        /** RSA-KEM wrap/unwrap */
        WRAP_UNWRAP,
        /** RSA-SHA256 sign/verify */
        SIGN_VERIFY
    };
    
    /**
     * <p>Create a new RSA crypto context for encrypt/decrypt and sign/verify
     * using the provided public and private keys. The crypto context algorithm
     * identifies the operations to enable. All other operations are no-ops and
     * return the data unmodified.</p>
     * 
     * <p>If there is no private key, decryption and signing is unsupported.</p>
     * 
     * <p>If there is no public key, encryption and verification is
     * unsupported.</p>
     * 
     * @param ctx MSL context.
     * @param id the key pair identity.
     * @param privateKey the private key. May be null.
     * @param publicKey the public key. May be null.
     * @param algo crypto context algorithm.
     */
    public RsaCryptoContext(final MslContext ctx, final String id, final PrivateKey privateKey, final PublicKey publicKey, final Mode algo) {
        super(id, privateKey, publicKey,
            Mode.ENCRYPT_DECRYPT_PKCS1.equals(algo) ? "RSA/ECB/PKCS1Padding" : (Mode.ENCRYPT_DECRYPT_OAEP.equals(algo) ? "RSA/ECB/OAEPPadding" : NULL_OP),
            Mode.ENCRYPT_DECRYPT_OAEP.equals(algo) ? OAEPParameterSpec.DEFAULT : null,
            Mode.SIGN_VERIFY.equals(algo) ? "SHA256withRSA" : NULL_OP);
        if (algo == Mode.WRAP_UNWRAP)
            throw new MslInternalException("Wrap/unwrap unsupported.");
    }
}
