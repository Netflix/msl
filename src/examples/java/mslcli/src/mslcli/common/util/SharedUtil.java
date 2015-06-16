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
import java.util.Map;
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
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.PresharedKeyStore.KeySet;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.DiffieHellmanParameters;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.SimpleMslStore;

import mslcli.common.entityauth.SimplePresharedKeyStore;
import mslcli.common.entityauth.SimpleRsaStore;
import mslcli.common.userauth.SimpleEmailPasswordStore;

import static mslcli.common.Constants.*;

public final class SharedUtil {
    private SharedUtil() {}

    // initialize pre-shared key store
    public static PresharedKeyStore getPresharedKeyStore() {
        final SecretKey encryptionKey = new SecretKeySpec(hexStringToByteArray(CLIENT_ENCR_PSK_HEX), JcaAlgorithm.AES);
        final SecretKey hmacKey       = new SecretKeySpec(hexStringToByteArray(CLIENT_HMAC_PSK_HEX), JcaAlgorithm.HMAC_SHA256);
        final SecretKey wrapKey       = new SecretKeySpec(hexStringToByteArray(CLIENT_WRAP_PSK_HEX), JcaAlgorithm.AESKW);
        final KeySet keySet = new KeySet(encryptionKey, hmacKey, wrapKey);
        final Map<String,KeySet> keySets = new HashMap<String,KeySet>();
        keySets.put(CLIENT_ID, keySet);
        return new SimplePresharedKeyStore(keySets);
    }

    public static EmailPasswordStore getEmailPasswordStore() {
        final Map<String,String> emailPasswords = new HashMap<String,String>();
        emailPasswords.put(CLIENT_USER_EMAIL, CLIENT_USER_PASSWORD);
        return new SimpleEmailPasswordStore(emailPasswords);
    }

    public static MslStore getClientMslStore() {
        return new SimpleMslStore();
    }

    public static MslStore getServerMslStore() {
        return new SimpleMslStore();
    }

    public static byte[] readIntoArray(final InputStream in) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            out.write(b);
        }
        return out.toByteArray();
    }

    public static byte[] hexStringToByteArray(final String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String readInput(final String prompt) throws IOException {
        final BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print(prompt.trim() + "> ");
        return br.readLine();
    }

    public static Throwable getCause(Throwable t) {
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }

    public static RsaStore getRsaStore() {
        // Create the RSA key store.
        final RsaStore rsaStore;
        try {
            final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

            final byte[] privKeyEncoded = DatatypeConverter.parseBase64Binary(SERVER_RSA_PRIVKEY_B64);
            final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyEncoded);
            final PrivateKey privKey = rsaKeyFactory.generatePrivate(privKeySpec);

            final byte[] pubKeyEncoded = DatatypeConverter.parseBase64Binary(SERVER_RSA_PUBKEY_B64);
            final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyEncoded);
            final PublicKey pubKey = rsaKeyFactory.generatePublic(pubKeySpec);

            rsaStore = new SimpleRsaStore(SERVER_RSA_KEY_ID, pubKey, privKey);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not found.", e);
        } catch (final InvalidKeySpecException e) {
            throw new RuntimeException("Invalid RSA private key.", e);
        }
        return rsaStore;
    }

    /**
     * Key exchange factory comparator.
     */
    private static class KeyExchangeFactoryComparator implements Comparator<KeyExchangeFactory> {
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

    private static final KeyExchangeFactoryComparator keyxFactoryComparator = new KeyExchangeFactoryComparator();

    public static KeyExchangeFactoryComparator getKeyExchangeFactoryComparator() {
        return keyxFactoryComparator;
    }

    private static class SharedDiffieHellmanParameters implements DiffieHellmanParameters {
        /** Default parameters. */
        private static BigInteger p =
            new BigInteger("C2048E076B268761DB1427BA3AD98473D32B0ABDEE98C0827923426F294EDA3392BF0032A1D8092055B58BAA07586A7D3E271C39A8C891F5CEEA4DEBDFA6B023", 16);
        private static BigInteger g = new BigInteger("02", 16);

        private SharedDiffieHellmanParameters() {
            final DHParameterSpec paramSpec = new DHParameterSpec(p, g);
            params.put(DEFAULT_DH_PARAMS_ID, paramSpec);
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

    private static final DiffieHellmanParameters sharedDiffieHellmanParameters = new SharedDiffieHellmanParameters();

    public static DiffieHellmanParameters getDiffieHellmanParameters() {
        return sharedDiffieHellmanParameters;
    }

    public static final class DiffieHellmanPair {
        private DiffieHellmanPair(DHPublicKey pub, DHPrivateKey priv) {
            this.pub  = pub;
            this.priv = priv;
        }

        public DHPublicKey getPublic() {
            return pub;
        }

        public DHPrivateKey getPrivate() {
            return priv;
        }

        private final DHPublicKey pub;
        private final DHPrivateKey priv;
    }

    public static DiffieHellmanPair generateDiffieHellmanKeys(final String paramId) throws MslException {
        final DHParameterSpec paramSpec = getDiffieHellmanParameters().getParameterSpec(paramId);
        final DHPublicKey pubKey;
        final DHPrivateKey privKey;
        try {
            final KeyPairGenerator generator = CryptoCache.getKeyPairGenerator("DH");
            generator.initialize(paramSpec);
            final KeyPair keyPair = generator.generateKeyPair();
            pubKey = (DHPublicKey)keyPair.getPublic();
            privKey = (DHPrivateKey)keyPair.getPrivate();
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("DiffieHellman algorithm not found.", e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new MslInternalException("Diffie-Hellman algorithm parameters rejected by Diffie-Hellman key agreement.", e);
        }
        return new DiffieHellmanPair(pubKey, privKey);
    }

    public static SortedSet<KeyExchangeFactory> getKeyExchangeFactorySet(KeyExchangeFactory... factories) {
        final TreeSet<KeyExchangeFactory> keyxFactoriesSet = new TreeSet<KeyExchangeFactory>(getKeyExchangeFactoryComparator());
        keyxFactoriesSet.addAll(Arrays.asList(factories));
        return  Collections.unmodifiableSortedSet(keyxFactoriesSet);
    }

    public static KeyPair generateAsymmetricWrapepdExchangeKeyPair() throws MslException {
        try {
            final KeyPairGenerator generator = CryptoCache.getKeyPairGenerator("RSA");
            generator.initialize(1024);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("RSA algorithm not found.", e);
        }
    }
}
