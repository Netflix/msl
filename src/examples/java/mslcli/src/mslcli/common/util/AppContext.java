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
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.PresharedKeyStore.KeySet;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.DiffieHellmanParameters;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.WrapCryptoContextRepository;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.SimpleMslStore;

import mslcli.common.Pair;
import mslcli.common.Triplet;
import mslcli.common.entityauth.SimplePresharedKeyStore;
import mslcli.common.entityauth.SimpleRsaStore;
import mslcli.common.keyx.SimpleWrapCryptoContextRepository;
import mslcli.common.userauth.SimpleEmailPasswordStore;

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

    private final MslProperties prop;
    private final MslControl mslControl;
    private final MslStore mslStore;
    private final PresharedKeyStore presharedKeyStore;
    private final EmailPasswordStore emailPasswordStore;
    private final RsaStore rsaStore;
    private final WrapCryptoContextRepository wrapCryptoContextRepository;
    private final DiffieHellmanParameters diffieHellmanParameters;
    private final KeyExchangeFactoryComparator keyxFactoryComparator;
    private transient MslStoreWrapper mslStoreWrapper;


    /**
     * @param p properties loaded from some configuration source
     * @return singleton instance of AppContext
     */
    public static synchronized AppContext getInstance(final MslProperties p) {
        if (_instance == null) {
            return (_instance = new AppContext(p));
        } else {
            throw new IllegalStateException("Illegal Attempt to Re-Initialize AppContext");
        }
    }

    private AppContext(final MslProperties p) {
        if (p == null) {
            throw new IllegalArgumentException("NULL MslProperties");
        }
        this.prop = p;
        this.mslControl = new MslControl(p.getNumMslControlThreads());
        this.mslStore = new SimpleMslStore(); // TBD - add persistency
        this.diffieHellmanParameters = new SimpleDiffieHellmanParameters(p);
        this.presharedKeyStore = initPresharedKeyStore(p);
        this.emailPasswordStore = initEmailPasswordStore(p);
        this.rsaStore = initRsaStore(p);
        this.wrapCryptoContextRepository = new SimpleWrapCryptoContextRepository();
        this.keyxFactoryComparator = new KeyExchangeFactoryComparator();
    }

    /**
     * @return MslProperties
     */
    public MslProperties getProperties() {
        return prop;
    }

    /**
     * @return MSL control
     */
    public MslControl getMslControl() {
        return mslControl;
    }

    /**
     * @return preshared key store
     */
    public PresharedKeyStore getPresharedKeyStore() {
        return presharedKeyStore;
    }

    private static PresharedKeyStore initPresharedKeyStore(final MslProperties p) {
        final Map<String,KeySet> keySets = new HashMap<String,KeySet>();

        for (Map.Entry<String,Triplet<String,String,String>> entry : p.getPresharedKeyStore().entrySet()) {
            keySets.put(entry.getKey(), new KeySet(
                new SecretKeySpec(SharedUtil.hexStringToByteArray(entry.getValue().x), JcaAlgorithm.AES),
                new SecretKeySpec(SharedUtil.hexStringToByteArray(entry.getValue().y), JcaAlgorithm.HMAC_SHA256),
                new SecretKeySpec(SharedUtil.hexStringToByteArray(entry.getValue().z), JcaAlgorithm.AESKW)
            ));
        }
        return new SimplePresharedKeyStore(keySets);
    }

    /**
     * @return {email,password} store
     */
    public EmailPasswordStore getEmailPasswordStore() {
        return emailPasswordStore;
    }

    private static EmailPasswordStore initEmailPasswordStore(final MslProperties p) {
        return new SimpleEmailPasswordStore(p.getEmailPasswordStore());
    }

    /**
     * @return MSL store
     */
    public MslStore getMslStore() {
        return (mslStoreWrapper != null) ? mslStoreWrapper : mslStore;
    }

    /**
     * @param mslStoreWrapper MSL store wrapper instance which extends MslStoreWrapper class and can be implemented by the app to intercept and modify MslStore calls
     */
    public void setMslStoreWrapper(final MslStoreWrapper mslStoreWrapper) {
        this.mslStoreWrapper = mslStoreWrapper;
        if (mslStoreWrapper != null) {
            mslStoreWrapper.setMslStore(mslStore);
        }
    }

    /**
     * @return RSA key store
     */
    public RsaStore getRsaStore() {
        return rsaStore;
    }

    /* client would normally have only the server public key to authenticate server responses.
     * server would normally have both public and private keys
     */
    private static RsaStore initRsaStore(final MslProperties p) {
        try {
            final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
            final Map<String,Pair<String,String>> rsaKeyPairsB64 = p.getRsaKeyStore();
            final Map<String,KeyPair> rsaKeyPairs = new HashMap<String,KeyPair>();

            for (Map.Entry<String,Pair<String,String>> entry : rsaKeyPairsB64.entrySet()) {
                final PublicKey pubKey;
                if (entry.getValue().x != null) {
                    final byte[] pubKeyEncoded = DatatypeConverter.parseBase64Binary(entry.getValue().x);
                    final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyEncoded);
                    pubKey = rsaKeyFactory.generatePublic(pubKeySpec);
                } else {
                    pubKey = null;
                }

                final PrivateKey privKey;
                if (entry.getValue().y != null) {
                    final byte[] privKeyEncoded = DatatypeConverter.parseBase64Binary(entry.getValue().y);
                    final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyEncoded);
                    privKey = rsaKeyFactory.generatePrivate(privKeySpec);
                } else {
                    privKey = null;
                }

                rsaKeyPairs.put(entry.getKey(), new KeyPair(pubKey, privKey));
            }
            return new SimpleRsaStore(rsaKeyPairs);

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

    /**
     * Convenience method creating SortedSet of multiple key exchange factories,
     * sorted in order of preference of their use.
     */
    public SortedSet<KeyExchangeFactory> getKeyExchangeFactorySet(KeyExchangeFactory... factories) {
        final TreeSet<KeyExchangeFactory> keyxFactoriesSet = new TreeSet<KeyExchangeFactory>(keyxFactoryComparator);
        keyxFactoriesSet.addAll(Arrays.asList(factories));
        return  Collections.unmodifiableSortedSet(keyxFactoriesSet);
    }

    /*
     * Class encapsulating Diffie-Hellman parameters Map keyed by parameters ID.
     * Parameters are loaded from the configuration.
     */
    private static final class SimpleDiffieHellmanParameters implements DiffieHellmanParameters {
        /** Default parameters. */

        private SimpleDiffieHellmanParameters(final MslProperties prop) {
            for (Map.Entry<String,Pair<String,String>> entry : prop.getDHParameterStore().entrySet()) {
                params.put(entry.getKey(), new DHParameterSpec(
                    new BigInteger(entry.getValue().x, 16),
                    new BigInteger(entry.getValue().y, 16)
                ));
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

    /**
     * @return mapping from Diffie-Hellman parameters ID to Diffie-Hellman parameters
     */
    public final DiffieHellmanParameters getDiffieHellmanParameters() {
        return diffieHellmanParameters;
    }

    /**
     * @param entityId entity identity string
     * @return Diffie-Hellman parameters ID to be used by the given entity for key exchange
     */
    public String getDiffieHellmanParametersId(String entityId) {
        return prop.getEntityDiffieHellmanParametersId(entityId);
    }

    /**
     * Generate Diffie-Hellman key pair for key exchange, with parameters corresponding
     * to specified parameters ID
     * @param paramId Diffie-Hellman parameters ID
     * @return Diffie-Hellman key pair generated using parameters corresponding to the provided ID
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
     * Generate RSA key pair used for wrapped key exchange
     * @return RSA key pair
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
     * @return entity authentication schemes allowed for a given entity
     */
    public Set<EntityAuthenticationScheme> getAllowedEntityAuthenticationSchemes(final String entityId) {
        final Set<EntityAuthenticationScheme> schemes = new HashSet<EntityAuthenticationScheme>();
        for (String scheme : prop.getSupportedEntityAuthenticationSchemes(entityId)) {
            final EntityAuthenticationScheme eas = EntityAuthenticationScheme.getScheme(scheme);
            if (eas == null) {
                throw new IllegalArgumentException(String.format("Unknown Entity Authentication Scheme for Entity %s: %s", entityId, scheme));
            }
            schemes.add(eas);
        }
        return Collections.unmodifiableSet(schemes);
    }

    /**
     * @param entityId entity identity
     * @return entity authentication schemes allowed for a given entity
     */
    public Set<UserAuthenticationScheme> getAllowedUserAuthenticationSchemes(final String entityId) {
        final Set<UserAuthenticationScheme> schemes = new HashSet<UserAuthenticationScheme>();
        for (String scheme : prop.getSupportedUserAuthenticationSchemes(entityId)) {
            final UserAuthenticationScheme uas = UserAuthenticationScheme.getScheme(scheme);
            if (uas == null) {
                throw new IllegalArgumentException(String.format("Unknown User Authentication Scheme for Entity %s: %s", entityId, scheme));
            }
            schemes.add(uas);
        }
        return Collections.unmodifiableSet(schemes);
    }

    /**
     * @param entityId entity identity
     * @return key exchange schemes allowed for a given entity
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
     * @param entityId entity identity
     * @return RSA key pair ID to be used for a given entity for RSA entity authentication
     */
    public String getRsaKeyId(final String entityId) {
        return prop.getRsaKeyId(entityId);
    }

    /**
     * @return MSL encryption, HMAC, and wrapping keys
     */
    public Triplet<SecretKey,SecretKey,SecretKey> getMslKeys() {
        final Triplet<String,String,String> mslKeys = prop.getMslKeys();
        return new Triplet<SecretKey,SecretKey,SecretKey>(
            new SecretKeySpec(SharedUtil.hexStringToByteArray(mslKeys.x), JcaAlgorithm.AES),
            new SecretKeySpec(SharedUtil.hexStringToByteArray(mslKeys.y), JcaAlgorithm.HMAC_SHA256),
            new SecretKeySpec(SharedUtil.hexStringToByteArray(mslKeys.z), JcaAlgorithm.AESKW)
            );
    }

    /**
     * @return service token encryption and HMAC keys for a given key set ID
     */
    public Pair<SecretKey,SecretKey> getServiceTokenKeys(final String keySetId) {
        final Pair<String,String> keys = prop.getServiceTokenKeys(keySetId);
        return new Pair<SecretKey,SecretKey>(
            new SecretKeySpec(SharedUtil.hexStringToByteArray(keys.x), JcaAlgorithm.AES),
            new SecretKeySpec(SharedUtil.hexStringToByteArray(keys.y), JcaAlgorithm.HMAC_SHA256)
            );
    }

    /**
     * @return repository for storing mapping between wrapped key and crypto context
     */
    public WrapCryptoContextRepository getWrapCryptoContextRepository() {
        return wrapCryptoContextRepository;
    }

    /**
     * info logging
     * @param message info message
     */
    public void info(final String msg) {
        System.err.println("INFO: " + msg);
    }

    /**
     * warning logging
     * @param message warning message
     */
    public void warning(final String msg) {
        System.err.println("WARNING: " + msg);
    }
}
