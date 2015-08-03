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
package com.netflix.msl.entityauth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Test RSA key store.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockRsaStore implements RsaStore {
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.RsaStore#getIdentities()
     */
    @Override
    public Set<String> getIdentities() {
        final Set<String> identities = new HashSet<String>();
        identities.addAll(keys.keySet());
        identities.addAll(privateKeys.keySet());
        return identities;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.RsaStore#getPublicKey(java.lang.String)
     */
    @Override
    public PublicKey getPublicKey(final String identity) {
        return keys.get(identity);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.RsaStore#getPrivateKey(java.lang.String)
     */
    public PrivateKey getPrivateKey(final String identity) {
        return privateKeys.get(identity);
    }

    /**
     * Add an RSA public key to the store.
     *
     * @param identity RSA key pair identity.
     * @param input DER-encoded RSA public key input stream.
     * @throws IOException if there is an error reading from the input stream.
     * @throws NoSuchAlgorithmException if no RSA provider is found.
     * @throws InvalidKeySpecException if the RSA public key is invalid.
     */
    public void addPublicKey(final String identity, final InputStream input) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final ByteArrayOutputStream der = new ByteArrayOutputStream();
        do {
            final byte[] b = new byte[16384];
            final int read = input.read(b);
            if (read == -1) break;
            der.write(b, 0, read);
        } while (true);
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(der.toByteArray());
        final KeyFactory factory = KeyFactory.getInstance("RSA");
        final PublicKey pubkey = factory.generatePublic(spec);
        addPublicKey(identity, pubkey);
    }

    /**
     * Add an RSA public key to the store.
     *
     * @param identity RSA key pair identity.
     * @param pubkey RSA public key.
     * @throws IllegalArgumentException if the public key is not a
     *         {@link RSAPublicKey}.
     */
    public void addPublicKey(final String identity, final PublicKey pubkey) {
        if (!(pubkey instanceof RSAPublicKey))
            throw new IllegalArgumentException("Public key is not an instance of RSAPublicKey.");
        keys.put(identity, pubkey);
    }
    
    /**
     * Add an RSA private key to the store.
     * 
     * @param identity RSA key pair identity.
     * @param privkey RSA private key.
     * @throws IllegalArgumentException if the private key is not a
     *         {@link RSAPrivateKey}.
     */
    public void addPrivateKey(final String identity, final PrivateKey privkey) {
        if (!(privkey instanceof RSAPrivateKey))
            throw new IllegalArgumentException("Private key is not an instance of RSAPrivateKey.");
        privateKeys.put(identity, privkey);
    }
    
    /**
     * <p>Clear the store of all public and private keys.</p>
     */
    public void clear() {
        keys.clear();
        privateKeys.clear();
    }

    /** Public keys. */
    private final Map<String,PublicKey> keys = new HashMap<String,PublicKey>();
    /** Private keys. */
    private final Map<String,PrivateKey> privateKeys = new HashMap<String,PrivateKey>();
}
