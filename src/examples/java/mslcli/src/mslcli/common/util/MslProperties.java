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

import mslcli.common.Pair;
import mslcli.common.Triplet;

/**
 * Msl Properties
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class MslProperties {

  /*
   * APPLICATION-SPECIFIC CONFIGURATION PROPERTIY NAMES
   */
    private static final String APP_CTRL_NUM_THR      = "app.mslctrl.nthr";
    private static final String APP_SERVER_PORT       = "app.server.port";
    private static final String APP_CLIENT_ID         = "app.client.id";
    private static final String APP_SERVER_ID         = "app.server.id";
    private static final String APP_DEBUG_FLAG        = "app.debug";

   /*
    * ENTITY-SPECIFIC CONFIGURATION PROPERTY NAMES
    */
    private static final String ENTITY_KX_SCHEMES = "entity.kx.schemes.";
    private static final String ENTITY_RSA_KEY_ID = "entity.rsa.keyid."; 
    private static final String ENTITY_PSK_NUM    = "entity.psk.num";
    private static final String ENTITY_PSK_ID     = "entity.psk.id.";
    private static final String ENTITY_PSK_ENC    = "entity.psk.enc.";
    private static final String ENTITY_PSK_HMAC   = "entity.psk.hmac.";
    private static final String ENTITY_PSK_WRAP   = "entity.psk.wrap.";
    private static final String ENTITY_DH_ID      = "entity.dh.id.";

   /*
    * USER-SPECIFIC CONFIGURATION PROPERTY NAMES
    */
    private static final String USER_EP_NUM       = "user.ep.num";
    private static final String USER_EP_EMAIL     = "user.ep.email.";
    private static final String USER_EP_PWD       = "user.ep.pwd.";
    private static final String USER_EP_ID        = "user.ep.id.";

   /*
    * MSL ECOSYSTEM-WIDE CONFIGURATION PROPERTY NAMES
    */
    private static final String MSL_RSA_NUM       = "msl.rsa.num"; 
    private static final String MSL_RSA_KEY_ID    = "msl.rsa.keyid."; 
    private static final String MSL_RSA_PUB       = "msl.rsa.pub."; 
    private static final String MSL_RSA_PRIV      = "msl.rsa.priv."; 

    private static final String MSL_DH_NUM        = "msl.dh.num";
    private static final String MSL_DH_ID         = "msl.dh.id.";
    private static final String MSL_DH_P          = "msl.dh.p.";
    private static final String MSL_DH_G          = "msl.dh.g.";

    private static final String MSL_KEY_ENC       = "msl.key.enc";
    private static final String MSL_KEY_HMAC      = "msl.key.hmac";
    private static final String MSL_KEY_WRAP      = "msl.key.wrap";

    // local definitions
    private static final String ANY               = "*"; 
    private static final String SPACE_REGEX       = "\\s";

    private final Properties p;

    /**
     * Load properties from config file
     * @param configFile configuration file path
     */
    public static MslProperties getInstance(final Properties p) throws Exception {
        if (p == null) {
            throw new IllegalArgumentException("NULL Properties");
        }
        return new MslProperties(p);
    }

    private MslProperties(final Properties p) {
        this.p = p;
    }

    /* ****************************
     * ENTITY-SPECIFIC PROPERTIES *
     ******************************/

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
     * @param entityId entity identity
     * @return Diffie-Hellman parameters ID to be used by given entity
     */
    public String getEntityDiffieHellmanParametersId(final String entityId) {
        return getRequiredProperty(ENTITY_DH_ID + entityId);
    }

    /**
     * @return { encryption, hmac, wrapping} key tuples keyed by entity identity
     */
    public Map<String,Triplet<String,String,String>> getPresharedKeyStore() {
        final int numPSK = getCountProperty(ENTITY_PSK_NUM);
        final Map<String,Triplet<String,String,String>> keys = new HashMap<String,Triplet<String,String,String>>(numPSK);
        for (int i = 0; i < numPSK; i++) {
            keys.put(getRequiredProperty(ENTITY_PSK_ID + i), new Triplet<String,String,String>(
                getRequiredProperty(ENTITY_PSK_ENC  + i),
                getRequiredProperty(ENTITY_PSK_HMAC + i),
                getRequiredProperty(ENTITY_PSK_WRAP + i)
            ));
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

    /* **************************
     * USER-SPECIFIC PROPERTIES *
     ****************************/

    /**
     * @return ( email,password ) tuple for a given user ID
     */
    public Pair<String,String> getEmailPassword(final String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("Undefined userId");
        }
        final int num = getCountProperty(USER_EP_NUM);
        for (int i = 0; i < num; i++) {
            final String uid = p.getProperty(USER_EP_ID + i);
            if (userId.equals(uid)) {
                return new Pair<String,String>(getRequiredProperty(USER_EP_EMAIL + i), getRequiredProperty(USER_EP_PWD + i));
            }
        }
        throw new IllegalArgumentException("Missing Email-Password Entry for User Id " + userId);
    }

    /**
     * @return { email,password } for a given user ID
     */
    public Map<String,String> getEmailPasswordStore() {
        final int num = getCountProperty(USER_EP_NUM);
        final Map<String,String> emailPwd = new HashMap<String,String>(num);
        for (int i = 0; i < num; i++) {
            emailPwd.put(getRequiredProperty(USER_EP_EMAIL + i), getRequiredProperty(USER_EP_PWD + i));
        }
        return emailPwd;
    }

    /* *******************************
     * MSL ECOSYSTEM-WIDE PROPERTIES *
     *********************************/

    /**
     * Get MSL encryption, HMAC, and wrapping keys
     */
    public Triplet<String,String,String> getMslKeys() {
        return new Triplet<String,String,String>(
            getRequiredProperty(MSL_KEY_ENC),
            getRequiredProperty(MSL_KEY_HMAC),
            getRequiredProperty(MSL_KEY_WRAP)
            );
    }

    /**
     * @return { public, private } RSA key tuples keyed by RSA key ID
     */
    public Map<String,Pair<String,String>> getRsaKeyStore() {
        final int numRSA = getCountProperty(MSL_RSA_NUM);
        final Map<String,Pair<String,String>> keys = new HashMap<String,Pair<String,String>>(numRSA);
        for (int i = 0; i < numRSA; i++) {
            keys.put(getRequiredProperty(MSL_RSA_KEY_ID + i), new Pair<String,String>(
                     getRequiredProperty(MSL_RSA_PUB    + i),
                     getRequiredProperty(MSL_RSA_PRIV   + i)));
        }
        return keys;
    }

    /**
     * @return Diffie-Hellman {P,G) parameters keyed by parameter IDs
     */
    public Map<String,Pair<String,String>> getDHParameterStore() {
        final int num = getCountProperty(MSL_DH_NUM);
        final Map<String,Pair<String,String>> dhParams = new HashMap<String,Pair<String,String>>(num);
        for (int i = 0; i < num; i++) {
            dhParams.put(getRequiredProperty(MSL_DH_ID + i), new Pair<String,String>(
                         getRequiredProperty(MSL_DH_P  + i),
                         getRequiredProperty(MSL_DH_G  + i)));
        }
        return dhParams;
    }

    /* ************************
     * APPLICATION PROPERTIES *
     **************************/

    /**
     * @return number of threads configured for MslControl
     */
    public int getNumMslControlThreads() {
        return getCountProperty(APP_CTRL_NUM_THR);
    }

    /**
     * @return IP port to be used by "this" MSL server for listenning to incoming MSL messages
     */
    public int getServerPort() {
        return getCountProperty(APP_SERVER_PORT);
    }

    /**
     * @return "this" client id
     */
    public String getClientId() {
        return getRequiredProperty(APP_CLIENT_ID);
    }

    /**
     * @return "this" server id
     */
    public String getServerId() {
        return getRequiredProperty(APP_SERVER_ID);
    }

    /**
     * @return debug flag
     */
    public boolean isDebugOn() {
        final String s = p.getProperty(APP_DEBUG_FLAG);
        return Boolean.parseBoolean(s);
    }

    /* ****************
     * Helper classes *
     ******************/

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
