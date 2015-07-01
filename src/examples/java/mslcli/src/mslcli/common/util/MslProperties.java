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
    private static final String APP_MSL_STORE_PATH    = "app.msl.store";

    // not a property name, but if part of property value, to be replaced with the client's entity_id
    private static final String APP_ID_TOKEN = "{app_id}";

   /*
    * ENTITY-SPECIFIC CONFIGURATION PROPERTY NAMES
    */
    private static final String ENTITY_AUTH_SCHEMES  = "entity.auth.schemes.";
    private static final String ENTITY_UAUTH_SCHEMES = "entity.userauth.schemes.";
    private static final String ENTITY_KX_SCHEMES    = "entity.kx.schemes.";
    private static final String ENTITY_RSA_KEY_ID    = "entity.rsa.keyid."; 
    private static final String ENTITY_PSK_NUM       = "entity.psk.num";
    private static final String ENTITY_PSK_ID        = "entity.psk.id.";
    private static final String ENTITY_PSK_ENC       = "entity.psk.enc.";
    private static final String ENTITY_PSK_HMAC      = "entity.psk.hmac.";
    private static final String ENTITY_PSK_WRAP      = "entity.psk.wrap.";
    private static final String ENTITY_DH_ID         = "entity.dh.id.";
    private static final String ENTITY_STOKEN_KEY_ID = "entity.stoken.keyid.";

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

    private static final String MSL_MTOKEN_RENEWAL_OFFSET       = "msl.mtoken.renewal";
    private static final String MSL_MTOKEN_EXPIRATION_OFFSET    = "msl.mtoken.expiration";
    private static final String MSL_MTOKEN_NON_REPLAY_ID_WINDOW = "msl.mtoken.non_replay_id_window";

    private static final String MSL_STOKEN_KEY_ENC  = "msl.stoken.keys.enc.";
    private static final String MSL_STOKEN_KEY_HMAC = "msl.stoken.keys.hmac.";

    // local definitions
    private static final String ANY               = "*"; 
    private static final String SPACE_REGEX       = "\\s";

    private final Properties p;

    /**
     * @param properties provided in app-specific way
     * @return singleton instance of MslProperties
     */
    public static MslProperties getInstance(final Properties p) throws Exception {
        if (p == null) {
            throw new ConfigurationException("NULL Properties");
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
     * @return names of entity authentication schemes supported by given entity
     */
    public Set<String> getSupportedEntityAuthenticationSchemes(final String entityId) {
        return split(getWildcharProperty(ENTITY_AUTH_SCHEMES, entityId));
    }

    /**
     * @param entityId entity identity
     * @return names of entity authentication schemes supported by given entity
     */
    public Set<String> getSupportedUserAuthenticationSchemes(final String entityId) {
        return split(getWildcharProperty(ENTITY_UAUTH_SCHEMES, entityId));
    }

    /**
     * @param entityId entity identity
     * @return names of key exchange schemes supported by given entity
     */
    public Set<String> getSupportedKeyExchangeSchemes(final String entityId) {
        return split(getWildcharProperty(ENTITY_KX_SCHEMES, entityId));
    }

    /**
    /**
     * @param entityId entity identity
     * @param userId user identity
     * @return names of key exchange scheme supported by given entity
     */
    public Set<String> getSupportedKeyExchangeSchemes(final String entityId, final String userId) {
        return getSupportedKeyExchangeSchemes(entityId);
    }

    /**
     * @param entityId entity identity
     * @return ID of Diffie-Hellman parameters to be used by given entity
     */
    public String getEntityDiffieHellmanParametersId(final String entityId) {
        return getRequiredProperty(ENTITY_DH_ID + entityId);
    }

    /**
     * @return mappings between entity identity and { encryption, hmac, wrapping} hex-encoded pre-shared keys triplet
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
     * @param entity identity
     * @return ID of the { encryption, hmac } key set to be used by this entity for issuing service tokens
     */
    public String getServiceTokenKeySetId(final String entityId) {
        return getRequiredProperty(ENTITY_STOKEN_KEY_ID + entityId);
    }

    /**
     * @param entityId entity identity, owner of RSA key pair used for RSA entity authentication
     * @return ID of the RSA key pair to be used for specified entity's authentication
     */
    public String getRsaKeyId(final String entityId) {
        return getWildcharProperty(ENTITY_RSA_KEY_ID, entityId);
    }

    /* **************************
     * USER-SPECIFIC PROPERTIES *
     ****************************/

    /**
     * @param userId user id, corresponding to local user account of some kind. Has no meaning outside local context.
     * @return ( email,password ) tuple for a given user ID
     */
    public Pair<String,String> getEmailPassword(final String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            throw new ConfigurationException("Undefined userId");
        }
        final int num = getCountProperty(USER_EP_NUM);
        for (int i = 0; i < num; i++) {
            final String uid = p.getProperty(USER_EP_ID + i);
            if (userId.equals(uid)) {
                return new Pair<String,String>(getRequiredProperty(USER_EP_EMAIL + i), getRequiredProperty(USER_EP_PWD + i));
            }
        }
        throw new ConfigurationException("Missing Email-Password Entry for User Id " + userId);
    }

    /**
     * @return mappings between user email and user password
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
     * @return MSL {encryption, HMAC, and wrapping} keys triplet.
     */
    public Triplet<String,String,String> getMslKeys() {
        return new Triplet<String,String,String>(
            getRequiredProperty(MSL_KEY_ENC),
            getRequiredProperty(MSL_KEY_HMAC),
            getRequiredProperty(MSL_KEY_WRAP)
            );
    }

    /**
     * @return mappings between RSA key pair ID and { public, private } RSA key pair tuples
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
     * @return mappings between Diffie-Hellman parameters ID and actual Diffie-Hellman {P,G) parameters
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

    /**
     * @param keyId ID of the { encryption, hmac } key pair used for service token issuing
     * @return { encryption, hmac } key pair
     */
    public Pair<String,String> getServiceTokenKeys(final String keyId) {
        return new Pair<String,String>(getRequiredProperty(MSL_STOKEN_KEY_ENC + keyId), getRequiredProperty(MSL_STOKEN_KEY_HMAC + keyId));
    }

    /**
     * @return Master Token renewal offset in milliseconds
     */
    public int getMasterTokenRenewalOffset() {
        return getCountProperty(MSL_MTOKEN_RENEWAL_OFFSET);
    }

    /**
     * @return Master Token expiration offset in milliseconds
     */
    public int getMasterTokenExpirationOffset() {
        return getCountProperty(MSL_MTOKEN_RENEWAL_OFFSET);
    }

    /**
     * @return Master Token non-replay ID window
     */
    public int getMasterTokenNonReplayIdWindow() {
        return getCountProperty(MSL_MTOKEN_NON_REPLAY_ID_WINDOW);
    }

    /* ************************
     * APPLICATION PROPERTIES *
     **************************/

    /**
     * @return number of threads configured for "this" MslControl
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
     * @return debug flag for "this" app
     */
    public boolean isDebugOn() {
        final String s = p.getProperty(APP_DEBUG_FLAG);
        return Boolean.parseBoolean(s);
    }

    /**
     * @return MSL Store file path
     */
    public String getMslStorePath(final String appId) {
        if (appId == null || appId.isEmpty()) {
            throw new ConfigurationException("Missing app ID");
        }
        return getRequiredProperty(APP_MSL_STORE_PATH).replace(APP_ID_TOKEN, appId);
    }

    /* ****************
     * Helper classes *
     ******************/

    // return mandatory non-negative integer property
    private int getCountProperty(final String name) {
        final String s = getRequiredProperty(name);
        final int num = Integer.parseInt(s);
        if (num < 0) {
            throw new ConfigurationException(String.format("Invalid Property %s : %s --> %d", name, s, num));
        }
        return num;
    }

    // return mandatory property
    private String getRequiredProperty(final String name) {
        final String s = p.getProperty(name);
        if (s == null) {
            throw new ConfigurationException("Missing Property " + name);
        }
        return s;
    }

    // get property with the name that can have ".*" at the end to indicate "any" id
    private String getWildcharProperty(final String prefix, String id) {
        String s = p.getProperty(prefix + id);
        if (s == null) {
            s = p.getProperty(prefix + ANY);
        }
        if (s == null) {
            throw new ConfigurationException(String.format("Missing Property %s(%s|%s)", prefix, id, ANY));
        }
        return s;
    }

    // parse multi-value property into a Set of unique values
    private Set<String> split(final String value) {
        final Set<String> set = new HashSet<String>();
        set.addAll(Arrays.asList(value.split(SPACE_REGEX)));
        return Collections.unmodifiableSet(set);
    }
}
