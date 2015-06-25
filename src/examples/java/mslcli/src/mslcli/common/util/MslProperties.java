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

import java.io.FileReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static mslcli.common.Constants.*;

/**
 * Msl Properties
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class MslProperties {

    private static final String MSL_CTRL_NUM_THR  = "mslctrl.nthr";
    private static final String ENTITY_KX_SCHEMES = "entity.kx.schemes.";

    private static final String RSA_NUM           = "store.rsa.num"; 
    private static final String RSA_KEY_ID        = "store.rsa.keyid."; 
    private static final String RSA_PUB           = "store.rsa.pub."; 
    private static final String RSA_PRIV          = "store.rsa.priv."; 

    private static final String ENTITY_RSA_KEY_ID = "entity.rsa.keyid."; 

    private static final String PSK_NUM           = "entity.psk.num";
    private static final String PSK_ENTITY_ID     = "entity.psk.id.";
    private static final String PSK_ENC           = "entity.psk.enc.";
    private static final String PSK_HMAC          = "entity.psk.hmac.";
    private static final String PSK_WRAP          = "entity.psk.wrap.";

    private static final String ENTITY_DH_ID      = "entity.dh.id.";

    private static final String DH_NUM            = "kx.dh.num";
    private static final String DH_ID             = "kx.dh.id.";
    private static final String DH_P              = "kx.dh.p.";
    private static final String DH_G              = "kx.dh.g.";

    private static final String USER_EMAIL_NUM    = "user.emailpwd.num";
    private static final String USER_EMAIL        = "user.email.";
    private static final String USER_PWD          = "user.pwd.";

    private static final String MSL_KEY_ENC       = "msl.key.enc";
    private static final String MSL_KEY_HMAC      = "msl.key.hmac";
    private static final String MSL_KEY_WRAP      = "msl.key.wrap";

    private static final String MSL_SERVER_PORT   = "msl.server.port";

    private static final String ANY               = "*"; 
    private static final String SPACE_REGEX       = "\\s";

    private final Properties p;

    public static final class RsaStoreKeyPair {
        public final String pubB64;
        public final String privB64; 
        private RsaStoreKeyPair(final String pubB64, final String privB64) {
            this.pubB64 = pubB64;
            this.privB64 = privB64;
        }
    }

    /**
     * data object class to carry Diffie-Hellman algorithm P and G parameters, HEX-encoded
     */
    public static final class DHPair {
        public final String pHex;
        public final String gHex; 
        private DHPair(final String pHex, final String gHex) {
            this.pHex = pHex;
            this.gHex = gHex;
        }
    }

    /**
     * data object class to carry encryption, hmac, and wrapping keys, HEX-encoded
     */
    public static final class KeyTriple {
        public final String encKeyHex;
        public final String hmacKeyHex;
        public final String wrapKeyHex;
        private KeyTriple(final String encKeyHex, final String hmacKeyHex, final String wrapKeyHex) {
            this.encKeyHex = encKeyHex;
            this.hmacKeyHex = hmacKeyHex;
            this.wrapKeyHex = wrapKeyHex;
        }
    }

    /**
     * Load properties from config file
     * @param configFile configuration file path
     */
    public static MslProperties getInstance(final String configFile) throws Exception {
        final Properties p = new Properties();
        p.load(new FileReader(configFile));
        return new MslProperties(p);
    }

    private MslProperties(final Properties p) {
        if (p != null) {
            this.p = p;
        } else {
            throw new IllegalArgumentException("NULL Properties");
        }
    }

    /**
     * @param entityId entity identity
     * @return supported key exchange scheme names
     */
    public Set<String> getSupportedKeyExchangeSchemes(final String entityId) {
        String kxProp;
        kxProp = p.getProperty(ENTITY_KX_SCHEMES + entityId);
        if (kxProp == null) {
            System.out.println(String.format("Missing Property %s%s", ENTITY_KX_SCHEMES, entityId));
            kxProp = p.getProperty(ENTITY_KX_SCHEMES + ANY);
            if (kxProp == null) {
                throw new IllegalArgumentException(String.format("Missing Property %s(%s|%s)", ENTITY_KX_SCHEMES, entityId, ANY));
            }
        }
        final Set<String> kx = new HashSet<String>();
        kx.addAll(Arrays.asList(kxProp.split(SPACE_REGEX)));
        return Collections.unmodifiableSet(kx);
    }

    /**
     * @param entityId entity identity
     * @param userId user identity
     * @return supported key exchange scheme names
     */
    public Set<String> getSupportedKeyExchangeSchemes(final String entityId, final String userId) {
        return getSupportedKeyExchangeSchemes(entityId);
    }

    /**
     * @return number of threads configured for MslControl
     */
    public int getNumMslControlThreads() {
        return getCountProperty(MSL_CTRL_NUM_THR);
    }

    /**
     * @return Diffie-Hellman {P,G) parameters keyed by parameter IDs
     */
    public Map<String,DHPair> getDHParameterStore() {
        final int num = getCountProperty(DH_NUM);
        final Map<String,DHPair> dhParams = new HashMap<String,DHPair>(num);
        for (int i = 0; i < num; i++) {
            dhParams.put(getRequiredProperty(DH_ID + i), new DHPair(
                         getRequiredProperty(DH_P  + i),
                         getRequiredProperty(DH_G  + i)));
        }
        return dhParams;
    }

    /**
     * @param entityId entity identity
     * @return Diffie-Hellman parameters ID to be used by given entity
     */
    public String getEntityDiffieHellmanParametersId(final String entityId) {
        return getRequiredProperty(ENTITY_DH_ID + entityId);
    }

    /**
     * @return { encryption, hmac, wrapping} key tuples keyed by entity identity
     */
    public Map<String,KeyTriple> getPresharedKeyStore() {
        final int numPSK = getCountProperty(PSK_NUM);
        final Map<String,KeyTriple> keys = new HashMap<String,KeyTriple>(numPSK);
        for (int i = 0; i < numPSK; i++) {
            keys.put(getRequiredProperty(PSK_ENTITY_ID + i), new KeyTriple(
                getRequiredProperty(PSK_ENC  + i),
                getRequiredProperty(PSK_HMAC + i),
                getRequiredProperty(PSK_WRAP + i)
            ));
        }
        return keys;
    }

    /**
     * @return { email,password } map 
     */
    public Map<String,String> getEmailPasswordStore() {
        final int num = getCountProperty(USER_EMAIL_NUM);
        final Map<String,String> emailPwd = new HashMap<String,String>(num);
        for (int i = 0; i < num; i++) {
            emailPwd.put(getRequiredProperty(USER_EMAIL + i), getRequiredProperty(USER_PWD + i));
        }
        return emailPwd;
    }

    /**
     * @return MSL encryption key, HEX-encoded
     */
    public String getMslEncKey() {
        return getRequiredProperty(MSL_KEY_ENC);
    }

    /**
     * @return MSL HMAC key, HEX-encoded
     */
    public String getMslHmacKey() {
        return getRequiredProperty(MSL_KEY_HMAC);
    }

    /**
     * @return MSL wrapping key, HEX-encoded
     */
    public String getMslWrapKey() {
        return getRequiredProperty(MSL_KEY_WRAP);
    }

    /**
     * @return { public, private } RSA key tuples keyed by RSA key ID
     */
    public Map<String,RsaStoreKeyPair> getRsaKeyStore() {
        final int numRSA = getCountProperty(RSA_NUM);
        final Map<String,RsaStoreKeyPair> keys = new HashMap<String,RsaStoreKeyPair>(numRSA);
        for (int i = 0; i < numRSA; i++) {
            keys.put(getRequiredProperty(RSA_KEY_ID + i), new RsaStoreKeyPair(
                     getRequiredProperty(RSA_PUB    + i),
                     getRequiredProperty(RSA_PRIV   + i)));
        }
        return keys;
    }

    /**
     * @param entityId entity identity, owner of RSA key pair used for RSA entity authentication
     * @return RSA key pair ID to be used for specified entity
     */
    public String getRsaKeyId(final String entityId) {
        String s = p.getProperty(ENTITY_RSA_KEY_ID + entityId);
        if (s == null) {
            System.out.println(String.format("Missing Property %s%s", ENTITY_RSA_KEY_ID, entityId));
            s = p.getProperty(ENTITY_RSA_KEY_ID + ANY);
        }
        if (s == null) {
            System.out.println(String.format("Missing Property %s%s", ENTITY_RSA_KEY_ID, ANY));
            throw new IllegalArgumentException(String.format("Missing Property %s(%s|%s)", ENTITY_RSA_KEY_ID, entityId, ANY));
        }
        return s;
    }

    /**
     * @return IP port to be used by the MSL server for listenning to incoming MSL messages
     */
    public int getServerPort() {
        return getCountProperty(MSL_SERVER_PORT);
    }

    private int getCountProperty(final String name) {
        final String s = getRequiredProperty(name);
        final int num = Integer.parseInt(s);
        if (num < 0) {
            throw new IllegalArgumentException(String.format("Invalid Property %s : %s --> %d", name, s, num));
        }
        return num;
    }

    private String getRequiredProperty(final String name) {
        final String s = p.getProperty(name);
        if (s == null) {
            throw new IllegalArgumentException("Missing Property " + name);
        }
        return s;
    }
}
