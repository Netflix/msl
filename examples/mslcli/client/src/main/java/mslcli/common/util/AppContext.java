/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.CryptoCache;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.KeySetStore;
import com.netflix.msl.entityauth.KeySetStore.KeySet;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.DiffieHellmanParameters;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.userauth.UserAuthenticationScheme;

import mslcli.common.Pair;
import mslcli.common.Triplet;
import mslcli.common.entityauth.EntityAuthenticationHandle;
import mslcli.common.entityauth.SimplePresharedKeyStore;
import mslcli.common.entityauth.SimpleRsaStore;
import mslcli.common.keyx.KeyExchangeHandle;
import mslcli.common.userauth.SimpleEmailPasswordStore;
import mslcli.common.userauth.UserAuthenticationHandle;
import mslcli.common.util.SharedUtil.Base64Util;

/**
 * <p>
 * Collection of MSL configuration-specific functions, based
 * on the data extracted from MSL CLI configuration file.
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class AppContext {

    /**
     * Singleton instance
     */
    private static AppContext _instance;

    /** properties from the config file */
    private final MslProperties prop;
    /** MslControl implementing MSL protocol stack */
    private final MslControl mslControl;
    /** entity preshared keys database */
    private final KeySetStore presharedKeyStore;
    /** entity MGK keys database */
    private final KeySetStore mgkKeyStore;
    /** user email / password database */
    private final EmailPasswordStore emailPasswordStore;
    /** named RSA key pairs database */
    private final RsaStore rsaStore;
    /** named Diffie-Hellman algorithm parameters database */
    private final DiffieHellmanParameters diffieHellmanParameters;
    /** entity authentication handles configured for this app */
    private final Set<EntityAuthenticationHandle> entityAuthenticationHandles;
    /** ordered list of key exchange handles configured for this app in the order of their preference */
    private final List<KeyExchangeHandle> keyExchangeHandles;
    /** user authentication handles configured for this app */
    private final Set<UserAuthenticationHandle> userAuthenticationHandles;

    /**
     * @param p properties loaded from some configuration source
     * @return singleton instance of AppContext
     * @throws ConfigurationException
     */
    public static synchronized AppContext getInstance(final MslProperties p) throws ConfigurationException {
        if (_instance == null) {
            if (p == null) {
                throw new IllegalArgumentException("NULL properties");
            }
            return (_instance = new AppContext(p));
        } else {
            throw new IllegalStateException("Illegal Attempt to Re-Initialize AppContext");
        }
    }

    /**
     * Ctor
     *
     * @param p MslProperties based on the configuration properties file
     * @throws ConfigurationException
     */
    private AppContext(final MslProperties p) throws ConfigurationException {
        if (p == null) {
            throw new IllegalArgumentException("NULL MslProperties");
        }
        this.prop = p;
        this.mslControl = new MslControl(p.getNumMslControlThreads());
        this.diffieHellmanParameters = new SimpleDiffieHellmanParameters(p);
        this.presharedKeyStore = initPresharedKeyStore(p);
        this.mgkKeyStore = initMgkKeyStore(p);
        this.emailPasswordStore = initEmailPasswordStore(p);
        this.rsaStore = initRsaStore(p);
        this.entityAuthenticationHandles = new HashSet<EntityAuthenticationHandle>(populateHandles(EntityAuthenticationHandle.class, p.getEntityAuthenticationHandles()));
        this.keyExchangeHandles = populateHandles(KeyExchangeHandle.class, p.getKeyExchangeHandles());
        this.userAuthenticationHandles = new HashSet<UserAuthenticationHandle>(populateHandles(UserAuthenticationHandle.class, p.getUserAuthenticationHandles()));
    }

    /**
     * populate list of handles
     * @param cls handle super-class
     * @param clspaths list of handle class names
     * @param <T> handle super-class template type
     * @return list of handle instances
     * @throws ConfigurationException
     */
    private static <T> List<T> populateHandles(final Class<T> cls, final List<String> clspaths)
        throws ConfigurationException
    {
        final List<T> handles = new ArrayList<T>();
        for (String s : clspaths) {
            final Object h;
            try {
                h = Class.forName(s).newInstance();
            } catch (ClassNotFoundException e) {
                throw new ConfigurationException(String.format("%s class not found", s), e);
            } catch (InstantiationException e) {
                throw new ConfigurationException(String.format("%s class cannot be instantiated", s), e);
            } catch (IllegalAccessException e) {
                throw new ConfigurationException(String.format("%s class cannot be instantiated", s), e);
            }
            if (cls.isAssignableFrom(h.getClass())) {
                handles.add(cls.cast(h));
            } else {
                throw new ConfigurationException(String.format("%s class %s: wrong type", cls.getSimpleName(), s));
            }
        }
        return handles;
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
    public KeySetStore getPresharedKeyStore() {
        return presharedKeyStore;
    }

    /**
     * @return MGK key store
     */
    public KeySetStore getMgkKeyStore() {
        return mgkKeyStore;
    }

    /**
     * @return entity authentication data handle for a given scheme
     */
    public Set<EntityAuthenticationHandle> getEntityAuthenticationHandles() {
        return Collections.unmodifiableSet(entityAuthenticationHandles);
    }

    /**
     * @return key exchange handles
     */
    public List<KeyExchangeHandle> getKeyExchangeHandles() {
        return Collections.unmodifiableList(keyExchangeHandles);
    }

    /**
     * @return user authentication handles
     */
    public Set<UserAuthenticationHandle> getUserAuthenticationHandles() {
        return Collections.unmodifiableSet(userAuthenticationHandles);
    }

    /**
     * @param s key encoded as HEX or BASE64 string
     * @return key decoded into a byte array
     * @throws ConfigurationException
     */
    private static byte[] parseKey(final String s) throws ConfigurationException {
        if (s == null || s.trim().isEmpty()) {
            throw new ConfigurationException("Empty Key Value");
        }
        if (s.startsWith("b64:")) {
            try {
                return Base64Util.decodeToByteArray(s.trim().substring(4));
            } catch (IllegalArgumentException e) {
                throw new ConfigurationException("Invalid Base64 Value " + s);
            }
        } else {
            return SharedUtil.hexStringToByteArray(s.trim());
        }
    }

    /**
     * @param p MslProperties
     * @return preshared key store database
     * @throws ConfigurationException
     */
    private static KeySetStore initPresharedKeyStore(final MslProperties p) throws ConfigurationException {
        return _initKeyStore(p.getPresharedKeyStore());
    }

    /**
     * @param p MslProperties
     * @return MGK key store database
     * @throws ConfigurationException
     */
    private static KeySetStore initMgkKeyStore(final MslProperties p) throws ConfigurationException {
        return _initKeyStore(p.getMgkKeyStore());
    }

    /**
     * @param keys map of entity ID to key triplet
     * @return key store database
     * @throws ConfigurationException
     */
    private static KeySetStore _initKeyStore(final Map<String,Triplet<String,String,String>> keys) throws ConfigurationException {
        final Map<String,KeySet> keySets = new HashMap<String,KeySet>();

        for (Map.Entry<String,Triplet<String,String,String>> entry : keys.entrySet()) {
            final byte[] encKey = parseKey(entry.getValue().x);
            final byte[] hmacKey = parseKey(entry.getValue().y);
            final byte[] wrapKey;
            if (entry.getValue().z != null) {
                wrapKey = parseKey(entry.getValue().z);
            } else {
                try {
                    wrapKey = SharedUtil.deriveWrappingKey(encKey, hmacKey);
                } catch (InvalidKeyException e) {
                    throw new ConfigurationException("Failed to initialize preshared keys", e);
                } catch (NoSuchAlgorithmException e) {
                    throw new ConfigurationException("Failed to initialize preshared keys", e);
                }
            }
            keySets.put(entry.getKey(), new KeySet(
                new SecretKeySpec(encKey, JcaAlgorithm.AES),
                new SecretKeySpec(hmacKey, JcaAlgorithm.HMAC_SHA256),
                new SecretKeySpec(wrapKey, JcaAlgorithm.AESKW)
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

    /**
     * @param p MslProperties
     * @return user email / password database
     * @throws ConfigurationException
     */
    private static EmailPasswordStore initEmailPasswordStore(final MslProperties p) throws ConfigurationException {
        return new SimpleEmailPasswordStore(p.getEmailPasswordStore());
    }

    /**
     * @return RSA key store
     */
    public RsaStore getRsaStore() {
        return rsaStore;
    }

    /**
     * Client would normally have only the server public key to authenticate server responses.
     * Server would normally have both public and private keys
     *
     * @param p MslProperties
     * @return RSA key store
     * @throws ConfigurationException
     */
    private static RsaStore initRsaStore(final MslProperties p) throws ConfigurationException {
        try {
            final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
            final Map<String,Pair<String,String>> rsaKeyPairsB64 = p.getRsaKeyStore();
            final Map<String,KeyPair> rsaKeyPairs = new HashMap<String,KeyPair>();

            for (Map.Entry<String,Pair<String,String>> entry : rsaKeyPairsB64.entrySet()) {
                final PublicKey pubKey;
                if (entry.getValue().x != null) {
                    final byte[] pubKeyEncoded = Base64Util.decodeToByteArray(entry.getValue().x);
                    final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyEncoded);
                    pubKey = rsaKeyFactory.generatePublic(pubKeySpec);
                } else {
                    pubKey = null;
                }

                final PrivateKey privKey;
                if (entry.getValue().y != null) {
                    final byte[] privKeyEncoded = Base64Util.decodeToByteArray(entry.getValue().y);
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
     * Class encapsulating Diffie-Hellman parameters Map keyed by parameters ID.
     * Parameters are loaded from the configuration.
     */
    private static final class SimpleDiffieHellmanParameters implements DiffieHellmanParameters {
        /** Default parameters. */

        /**
         * Ctor
         * @param prop MslProperties
         * @throws ConfigurationException
         */
        private SimpleDiffieHellmanParameters(final MslProperties prop) throws ConfigurationException {
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
     * @throws ConfigurationException
     */
    public String getDiffieHellmanParametersId(String entityId) throws ConfigurationException {
        return prop.getEntityDiffieHellmanParametersId(entityId);
    }

    /**
     * Generate Diffie-Hellman key pair for key exchange, with parameters corresponding
     * to specified parameters ID
     * @param paramId Diffie-Hellman parameters ID
     * @return Diffie-Hellman key pair generated using parameters corresponding to the provided ID
     * @throws MslKeyExchangeException
     */
    public KeyPair generateDiffieHellmanKeys(final String paramId) throws MslKeyExchangeException {
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
     * @throws MslInternalException
     */
    public KeyPair generateAsymmetricWrappedExchangeKeyPair() throws MslInternalException {
        try {
            info("Generating RSA Key Pair - please, wait ...");
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
     * @throws ConfigurationException
     */
    public Set<EntityAuthenticationScheme> getAllowedEntityAuthenticationSchemes(final String entityId) throws ConfigurationException {
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
     * @throws ConfigurationException
     */
    public Set<UserAuthenticationScheme> getAllowedUserAuthenticationSchemes(final String entityId) throws ConfigurationException {
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
     * @throws ConfigurationException
     */
    public Set<KeyExchangeScheme> getAllowedKeyExchangeSchemes(final String entityId) throws ConfigurationException {
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
     * @throws ConfigurationException
     */
    public String getRsaKeyId(final String entityId) throws ConfigurationException {
        return prop.getRsaKeyId(entityId);
    }

    /**
     * @return MSL encryption, HMAC, and wrapping keys
     * @throws ConfigurationException
     */
    public Triplet<SecretKey,SecretKey,SecretKey> getMslKeys() throws ConfigurationException {
        final Triplet<String,String,String> mslKeys = prop.getMslKeys();
        return new Triplet<SecretKey,SecretKey,SecretKey>(
            new SecretKeySpec(SharedUtil.hexStringToByteArray(mslKeys.x), JcaAlgorithm.AES),
            new SecretKeySpec(SharedUtil.hexStringToByteArray(mslKeys.y), JcaAlgorithm.HMAC_SHA256),
            new SecretKeySpec(SharedUtil.hexStringToByteArray(mslKeys.z), JcaAlgorithm.AESKW)
            );
    }

    /**
     * @param keySetId for a given RSA key pair
     * @return service token encryption and HMAC keys for a given key set ID
     * @throws ConfigurationException
     */
    public Pair<SecretKey,SecretKey> getServiceTokenKeys(final String keySetId) throws ConfigurationException {
        final Pair<String,String> keys = prop.getServiceTokenKeys(keySetId);
        return new Pair<SecretKey,SecretKey>(
            new SecretKeySpec(SharedUtil.hexStringToByteArray(keys.x), JcaAlgorithm.AES),
            new SecretKeySpec(SharedUtil.hexStringToByteArray(keys.y), JcaAlgorithm.HMAC_SHA256)
            );
    }

    /**
     * info logging
     *
     * @param msg info message
     */
    public void info(final String msg) {
        System.err.println("INFO: " + msg);
    }

    /**
     * warning logging
     *
     * @param msg warning message
     */
    public void warning(final String msg) {
        System.err.println("WARNING: " + msg);
    }

    /**
     * error logging
     *
     * @param msg error message
     */
    public void error(final String msg) {
        System.err.println("ERROR: " + msg);
    }

    @Override
    public String toString() {
        return SharedUtil.toString(this);
    }
}
