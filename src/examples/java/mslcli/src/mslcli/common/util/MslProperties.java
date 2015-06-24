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
    private static final String DH_PARAMS_ID      = "entity.kx.dh.";
    private static final String DH_PARAMS_IDS     = "kx.dh.ids";
    private static final String DH_PARAMS_P       = "kx.dh.p.";
    private static final String DH_PARAMS_G       = "kx.dh.g.";
    private static final String RSA_NUM           = "store.rsa.num"; 
    private static final String RSA_KEY_ID        = "store.rsa.keyid."; 
    private static final String RSA_PUB           = "store.rsa.pub."; 
    private static final String RSA_PRIV          = "store.rsa.priv."; 
    private static final String PSK_NUM           = "entity.psk.num";
    private static final String PSK_ENTITY_ID     = "entity.psk.id.";
    private static final String PSK_ENC           = "entity.psk.enc.";
    private static final String PSK_HMAC          = "entity.psk.hmac.";
    private static final String PSK_WRAP          = "entity.psk.wrap.";
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

    public static final class PresharedKeyTriple {
        public final String encKeyHex;
        public final String hmacKeyHex;
        public final String wrapKeyHex;
        private PresharedKeyTriple(final String encKeyHex, final String hmacKeyHex, final String wrapKeyHex) {
            this.encKeyHex = encKeyHex;
            this.hmacKeyHex = hmacKeyHex;
            this.wrapKeyHex = wrapKeyHex;
        }
    }

    /**
     * Load properties from config file
     * TBD
     * Currently using hard-coded values
     *
     * @param configFile configuration file path
     */
    public static MslProperties getInstance(final String configFile) throws Exception {
        final Properties p = new Properties();
        p.setProperty(MSL_CTRL_NUM_THR, "0");
        p.setProperty(ENTITY_KX_SCHEMES + ANY, "JWK_LADDER JWE_LADDER DIFFIE_HELLMAN SYMMETRIC_WRAPPED ASYMMETRIC_WRAPPED");
        p.setProperty(DH_PARAMS_IDS, DEFAULT_DH_PARAMS_ID);
        p.setProperty(DH_PARAMS_ID + CLIENT_ID, DEFAULT_DH_PARAMS_ID);
        p.setProperty(DH_PARAMS_ID + SERVER_ID, DEFAULT_DH_PARAMS_ID);
        p.setProperty(DH_PARAMS_P + DEFAULT_DH_PARAMS_ID, DEFAULT_DH_PARAM_P_HEX);
        p.setProperty(DH_PARAMS_G + DEFAULT_DH_PARAMS_ID, DEFAULT_DH_PARAM_G_HEX);

        p.setProperty(RSA_NUM, "1");
        p.setProperty(RSA_KEY_ID + 0, SERVER_RSA_KEY_ID);
        p.setProperty(RSA_PUB    + 0, SERVER_RSA_PUBKEY_B64);
        p.setProperty(RSA_PRIV   + 0, SERVER_RSA_PRIVKEY_B64);

        p.setProperty(PSK_NUM, "1");
        p.setProperty(PSK_ENTITY_ID + 0, CLIENT_ID);
        p.setProperty(PSK_ENC       + 0, CLIENT_ENCR_PSK_HEX);
        p.setProperty(PSK_HMAC      + 0, CLIENT_HMAC_PSK_HEX);
        p.setProperty(PSK_WRAP      + 0, CLIENT_WRAP_PSK_HEX);

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
     * get the list of supported key exchange schemes for a give entity
     */
    public Set<String> getSupportedKeyExchangeSchemes(final String entityId) {
        String kxProp;
        kxProp = p.getProperty(ENTITY_KX_SCHEMES + entityId);
        if (kxProp == null) {
            kxProp = p.getProperty(ENTITY_KX_SCHEMES + ANY);
            if (kxProp == null) return Collections.emptySet();
        }
        final Set<String> kx = new HashSet<String>();
        kx.addAll(Arrays.asList(kxProp.split(SPACE_REGEX)));
        return Collections.unmodifiableSet(kx);
    }

    public Set<String> getSupportedKeyExchangeSchemes(final String entityId, final String userId) {
        return getSupportedKeyExchangeSchemes(entityId);
    }

    public int getNumMslControlThreads() {
        return getCountProperty(MSL_CTRL_NUM_THR);
    }

    /**
     * return DH paremeters ID for a given entity
     */
    public String getDiffieHellmanParametersId(final String entityId) {
        String id = p.getProperty(DH_PARAMS_ID + entityId);
        if (id == null) {
            id = p.getProperty(DH_PARAMS_ID + ANY);
        }
        if (id == null) {
            throw new IllegalArgumentException(String.format("Missing Properties %s(%s|%s)", DH_PARAMS_ID, entityId, ANY));
        }
        return id;
    }

    /**
     * return the names of all supported DH parameter IDs
     */
    public Set<String> getDiffieHellmanParametersIds() {
        final String id = getRequiredProperty(DH_PARAMS_IDS);
        final Set<String> ids = new HashSet<String>();
        ids.addAll(Arrays.asList(id.split(SPACE_REGEX)));
        return Collections.unmodifiableSet(ids);
    }

    /**
     * return DH parameter P for a given parameters ID
     */ 
    public String getDiffieHellmanParameterP(final String paramId) {
        return getRequiredProperty(DH_PARAMS_P + paramId);
    }

    /**
     * return DH parameter G for a given parameters ID
     */ 
    public String getDiffieHellmanParameterG(final String paramId) {
        return getRequiredProperty(DH_PARAMS_G + paramId);
    }

    public Map<String,RsaStoreKeyPair> getRsaKeyStore() {
        final int numRSA = getCountProperty(RSA_NUM);
        final Map<String,RsaStoreKeyPair> keys = new HashMap<String,RsaStoreKeyPair>();
        for (int i = 0; i < numRSA; i++) {
            keys.put(getRequiredProperty(RSA_KEY_ID + i), new RsaStoreKeyPair(
                     getRequiredProperty(RSA_PUB    + i),
                     getRequiredProperty(RSA_PRIV   + i)));
        }
        return keys;
    }

    public Map<String,PresharedKeyTriple> getPresharedKeyStore() {
        final int numPSK = getCountProperty(PSK_NUM);
        final Map<String,PresharedKeyTriple> keys = new HashMap<String,PresharedKeyTriple>();
        for (int i = 0; i < numPSK; i++) {
            keys.put(getRequiredProperty(PSK_ENTITY_ID + i), new PresharedKeyTriple(
                getRequiredProperty(PSK_ENC  + i),
                getRequiredProperty(PSK_HMAC + i),
                getRequiredProperty(PSK_WRAP + i)
            ));
        }
        return keys;
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
            throw new IllegalArgumentException("Missing Property " + PSK_NUM);
        }
        return s;
    }
}
