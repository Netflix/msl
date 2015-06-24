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

package mslcli.common.util;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.CryptoCache;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.PresharedKeyStore.KeySet;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.DiffieHellmanParameters;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.WrapCryptoContextRepository;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.SimpleMslStore;

import mslcli.common.entityauth.SimplePresharedKeyStore;
import mslcli.common.entityauth.SimpleRsaStore;
import mslcli.common.keyx.SimpleWrapCryptoContextRepository;
import mslcli.common.userauth.SimpleEmailPasswordStore;

import static mslcli.common.Constants.*;

/**
 * Collection of app configuration-specific functions
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class AppContext {

    /**
     * Singleton instance
     */
    private static AppContext _instance;

    public static synchronized AppContext getInstance(final MslProperties p) {
        if (_instance == null) {
            return (_instance = new AppContext(p));
        } else {
            throw new IllegalStateException("Illegal Attempt to Re-Initialize AppContext");
        }
    }

    private final MslProperties prop;
    private final MslControl mslControl;

    private AppContext(final MslProperties p) {
        if (p == null) {
            throw new IllegalArgumentException("NULL MslProperties");
        }
        this.prop = p;
        this.mslControl = new MslControl(prop.getNumMslControlThreads(0));
        this.simpleDiffieHellmanParameters = new SimpleDiffieHellmanParameters(this.prop);
    }

    /* An application should only use one instance of MslControl for all MSL communication.
     * This class is thread-safe.
     * Passing 0 parameter leads to MslControl executing on the caller's thread.
     */
    public synchronized MslControl getMslControl() {
        return mslControl;
    }

    /**
     * Initialize client pre-shared key store
     */
    public PresharedKeyStore getClientPresharedKeyStore() {
        final SecretKey encryptionKey = new SecretKeySpec(SharedUtil.hexStringToByteArray(CLIENT_ENCR_PSK_HEX), JcaAlgorithm.AES);
        final SecretKey hmacKey       = new SecretKeySpec(SharedUtil.hexStringToByteArray(CLIENT_HMAC_PSK_HEX), JcaAlgorithm.HMAC_SHA256);
        final SecretKey wrapKey       = new SecretKeySpec(SharedUtil.hexStringToByteArray(CLIENT_WRAP_PSK_HEX), JcaAlgorithm.AESKW);
        final KeySet keySet = new KeySet(encryptionKey, hmacKey, wrapKey);
        final Map<String,KeySet> keySets = new HashMap<String,KeySet>();
        keySets.put(CLIENT_ID, keySet);
        return new SimplePresharedKeyStore(keySets);
    }

    /**
     * Initialize server pre-shared key store
     * Real-life implementation is likely to support multiple clients
     */
    public PresharedKeyStore getServerPresharedKeyStore() {
        return getClientPresharedKeyStore();
    }

    /**
     * Initialize client {email,password} store
     */
    public EmailPasswordStore getClientEmailPasswordStore() {
        final Map<String,String> emailPasswords = new HashMap<String,String>();
        emailPasswords.put(CLIENT_USER_EMAIL, CLIENT_USER_PASSWORD);
        return new SimpleEmailPasswordStore(emailPasswords);
    }

    /**
     * Initialize server {email,password} store
     * Real-life implementation is likely to support multiple clients
     */
    public EmailPasswordStore getServerEmailPasswordStore() {
        return getClientEmailPasswordStore();
    }

    /**
     * Initialize client MSL store
     */
    public MslStore getClientMslStore() {
        return new SimpleMslStore();
    }

    /**
     * Initialize server MSL store
     */
    public MslStore getServerMslStore() {
        return new SimpleMslStore();
    }

    /**
     * Initialize client RSA key store
     * Real-life implementation may support multiple servers
     * Client only posesses server public key
     */
    public RsaStore getClientRsaStore() {
        final KeyPair kp = getServerRsaKeyPair();
        return new SimpleRsaStore(SERVER_RSA_KEY_ID, kp.getPublic(), null);
    }

    /**
     * Initialize server RSA key store
     * Real-life implementation may support multiple servers
     */
    public RsaStore getServerRsaStore() {
        final KeyPair kp = getServerRsaKeyPair();
        return new SimpleRsaStore(SERVER_RSA_KEY_ID, kp.getPublic(), kp.getPrivate());
    }

    private KeyPair getServerRsaKeyPair() {
        try {
            final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

            final byte[] privKeyEncoded = DatatypeConverter.parseBase64Binary(SERVER_RSA_PRIVKEY_B64);
            final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyEncoded);
            final PrivateKey privKey = rsaKeyFactory.generatePrivate(privKeySpec);

            final byte[] pubKeyEncoded = DatatypeConverter.parseBase64Binary(SERVER_RSA_PUBKEY_B64);
            final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyEncoded);
            final PublicKey pubKey = rsaKeyFactory.generatePublic(pubKeySpec);

            return new KeyPair(pubKey, privKey);

        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not found.", e);
        } catch (final InvalidKeySpecException e) {
            throw new RuntimeException("Invalid RSA private key.", e);
        }
    }

    /**
     * Key exchange factory comparator. The purpose is to list key exchange schemes in order of preference.
     */
    private class KeyExchangeFactoryComparator implements Comparator<KeyExchangeFactory> {
        /** Scheme priorities. Lower values are higher priority. */
        private final Map<KeyExchangeScheme,Integer> schemePriorities = new HashMap<KeyExchangeScheme,Integer>();

        /**
         * Create a new key exchange factory comparator.
         */
        public KeyExchangeFactoryComparator() {
            schemePriorities.put(KeyExchangeScheme.JWK_LADDER, 0);
            schemePriorities.put(KeyExchangeScheme.JWE_LADDER, 1);
            schemePriorities.put(KeyExchangeScheme.DIFFIE_HELLMAN, 2);
            schemePriorities.put(KeyExchangeScheme.SYMMETRIC_WRAPPED, 3);
            schemePriorities.put(KeyExchangeScheme.ASYMMETRIC_WRAPPED, 4);
        }

        /* (non-Javadoc)
         * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
         */
        @Override
        public int compare(KeyExchangeFactory a, KeyExchangeFactory b) {
            final KeyExchangeScheme schemeA = a.getScheme();
            final KeyExchangeScheme schemeB = b.getScheme();
            final Integer priorityA = schemePriorities.get(schemeA);
            final Integer priorityB = schemePriorities.get(schemeB);
            return priorityA.compareTo(priorityB);
        }
    }

    private final KeyExchangeFactoryComparator keyxFactoryComparator = new KeyExchangeFactoryComparator();

    /**
     * Convenience method creating SortedSet of multiple key exchange factories,
     * sorted in order of preference of their use.
     */
    public SortedSet<KeyExchangeFactory> getKeyExchangeFactorySet(KeyExchangeFactory... factories) {
        final TreeSet<KeyExchangeFactory> keyxFactoriesSet = new TreeSet<KeyExchangeFactory>(keyxFactoryComparator);
        keyxFactoriesSet.addAll(Arrays.asList(factories));
        return  Collections.unmodifiableSortedSet(keyxFactoriesSet);
    }

    private static final class SimpleDiffieHellmanParameters implements DiffieHellmanParameters {
        /** Default parameters. */

        private SimpleDiffieHellmanParameters(final MslProperties prop) {
            final Set<String> paramIds = prop.getDiffieHellmanParametersIds();
            for (String paramId : paramIds) {
                BigInteger p = new BigInteger(prop.getDiffieHellmanParameterP(paramId), 16);
                BigInteger g = new BigInteger(prop.getDiffieHellmanParameterG(paramId), 16);
                DHParameterSpec paramSpec = new DHParameterSpec(p, g);
                params.put(paramId, paramSpec);
            }
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.DiffieHellmanParameters#getParameterSpecs()
         */
        @Override
        public Map<String,DHParameterSpec> getParameterSpecs() {
            return Collections.unmodifiableMap(params);
        }

        /* (non-Javadoc)
         * @see com.netflix.msl.keyx.DiffieHellmanParameters#getParameterSpec(java.lang.String)
         */
        @Override
        public DHParameterSpec getParameterSpec(final String id) {
            return params.get(id);
        }

        /** Diffie-Hellman parameters Map. */
        private final Map<String,DHParameterSpec> params = new HashMap<String,DHParameterSpec>();
    }

    private final DiffieHellmanParameters simpleDiffieHellmanParameters;

    public final DiffieHellmanParameters getDiffieHellmanParameters() {
        return simpleDiffieHellmanParameters;
    }

    /**
     * To support per-entityId Difie-Hellman parameters configurations
     * TBD - make it configurable
     *
     * $param entityId entity identity string
     */
    public String getDiffieHellmanParametersId(String entityId) {
        return prop.getDiffieHellmanParametersId(entityId);
    }

    /**
     * Generate Diffie-Hellman key pair for key exchange, with parameters corresponding
     * to specified parameters ID
     */
    public KeyPair generateDiffieHellmanKeys(final String paramId) throws MslException {
        final DHParameterSpec paramSpec = getDiffieHellmanParameters().getParameterSpec(paramId);
        try {
            final KeyPairGenerator generator = CryptoCache.getKeyPairGenerator("DH");
            generator.initialize(paramSpec);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("DiffieHellman algorithm not found.", e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new MslInternalException("Diffie-Hellman algorithm parameters rejected by Diffie-Hellman key agreement.", e);
        }
    }

    /**
     * Generate RSA key pair used for wrapped kkey exchange
     */
    public KeyPair generateAsymmetricWrappedExchangeKeyPair() throws MslException {
        try {
            System.out.println("Generating RSA Key Pair - please, wait ...");
            final KeyPairGenerator generator = CryptoCache.getKeyPairGenerator("RSA");
            generator.initialize(4096);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("RSA algorithm not found.", e);
        }
    }

    /**
     * @param entityId entity identity
     */
    public Set<KeyExchangeScheme> getAllowedKeyExchangeSchemes(final String entityId) {
        final Set<KeyExchangeScheme> schemes = new HashSet<KeyExchangeScheme>();
        for (String scheme : prop.getSupportedKeyExchangeSchemes(entityId)) {
            final KeyExchangeScheme kxs = KeyExchangeScheme.getScheme(scheme);
            if (kxs == null) {
                throw new IllegalArgumentException(String.format("Illegal Key Exchange Scheme for Entity %s: %s", entityId, scheme));
            }
            schemes.add(kxs);
        }
        return Collections.unmodifiableSet(schemes);
    }

    /**
     * Simple implementation of WrappedCryptoContextRepository interface
     */
    public WrapCryptoContextRepository getWrapCryptoContextRepository() {
        return new SimpleWrapCryptoContextRepository();
    }
}
