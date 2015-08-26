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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import mslcli.common.Pair;
import mslcli.common.Triplet;

/**
 * <p>
 * Msl Properties extracted from MSL CLI configuration file.
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class MslProperties {

   /*
    * APPLICATION-SPECIFIC CONFIGURATION PROPERTIY NAMES
    */
    /** number of thread for MslControl to run on */
    private static final String APP_CTRL_NUM_THR       = "app.mslctrl.nthr";
    /** server port */
    private static final String APP_SERVER_PORT        = "app.server.port";
    /** entity authentication handle prefix */
    private static final String APP_ENTITY_AUTH_HANDLE = "app.entityauth.handle.";
    /** key exchange handle prefix */
    private static final String APP_KEYX_HANDLE        = "app.keyx.handle.";
    /** user authentication handle prefix */
    private static final String APP_USER_AUTH_HANDLE   = "app.userauth.handle.";

   /*
    * ENTITY-SPECIFIC CONFIGURATION PROPERTY NAMES
    */
    /** prefix for allowed entity authentication schemes for a given entity */
    private static final String ENTITY_AUTH_SCHEMES  = "entity.auth.schemes.";
    /** prefix for allowed user authentication schemes for a given entity */
    private static final String ENTITY_UAUTH_SCHEMES = "entity.userauth.schemes.";
    /** prefix for allowed key exchange schemes for a given entity */
    private static final String ENTITY_KX_SCHEMES    = "entity.kx.schemes.";
    /** prefix for RSA key ID used by a given entity */
    private static final String ENTITY_RSA_KEY_ID    = "entity.rsa.keyid."; 

    /** prefix for PSK key sets */
    private static final String ENTITY_PSK           = "entity.psk.";
    /** prefix for MGK key sets */
    private static final String ENTITY_MGK           = "entity.mgk.";

    /** prefix for the entity Diffie-Hellman key pair ID */
    private static final String ENTITY_DH_ID         = "entity.dh.id.";
    /** prefix for the entity key set ID used for securing service tokens */
    private static final String ENTITY_STOKEN_KEY_ID = "entity.stoken.keyid.";

   /*
    * USER-SPECIFIC CONFIGURATION PROPERTY NAMES
    */
    /** suffix for email/password entries */
    private static final String USER_EP = "user.ep.";
    /** email */
    private static final String EMAIL   = "email";
    /** password */
    private static final String PWD     = "pwd";

   /*
    * MSL ECOSYSTEM-WIDE CONFIGURATION PROPERTY NAMES
    */
    /** RSA key pair sets */
    private static final String MSL_RSA = "msl.rsa."; 
    /** Diffie-Hellman algorithm parameters sets */
    private static final String MSL_DH  = "msl.dh.";

    /** MSL encryption key */
    private static final String MSL_KEY_ENC       = "msl.key.enc";
    /** MSL HMAC key */
    private static final String MSL_KEY_HMAC      = "msl.key.hmac";
    /** MSL wrapping key */
    private static final String MSL_KEY_WRAP      = "msl.key.wrap";

    /** Master Token renewal offset in milliseconds */
    private static final String MSL_MTOKEN_RENEWAL_OFFSET       = "msl.mtoken.renewal";
    /** Master Token expiration offset in milliseconds */
    private static final String MSL_MTOKEN_EXPIRATION_OFFSET    = "msl.mtoken.expiration";
    /** Master Token non-replay ID window */
    private static final String MSL_MTOKEN_NON_REPLAY_ID_WINDOW = "msl.mtoken.non_replay_id_window";
    /** Master Token max number of skipped sequence numbers still allowed for renewal  */
    private static final String MSL_MTOKEN_MAX_SKIPPED = "msl.mtoken.max_skipped";

    /** User Id Token renewal offset in milliseconds */
    private static final String MSL_UITOKEN_RENEWAL_OFFSET      = "msl.uitoken.renewal";
    /** User Id Token expiration offset in milliseconds */
    private static final String MSL_UITOKEN_EXPIRATION_OFFSET   = "msl.uitoken.expiration";

    /** prefix for service token encryption key */
    private static final String MSL_STOKEN_KEY_ENC  = "msl.stoken.keys.enc.";
    /** prefix for service token HMAC key */
    private static final String MSL_STOKEN_KEY_HMAC = "msl.stoken.keys.hmac.";

    /** Common property name suffix for defining the number of properties of a given kind */
    private static final String NUM = "num";
    /** Common property name suffix for entry ID */
    private static final String ID = "id";
    /** Common property name suffix for encryption key */
    private static final String ENC_KEY = "enc";
    /** Common property name suffix for hmac key */
    private static final String HMAC_KEY = "hmac";
    /** Common property name suffix for hmac key */
    private static final String WRAP_KEY = "wrap";
    /** public key */
    private static final String PUB_KEY = "pub"; 
    /** private key */
    private static final String PRIV_KEY = "priv"; 
    /** Diffie-Hellman algorithm P parameter */
    private static final String DH_P = "p";
    /** Diffie-Hellman algorithm G parameter */
    private static final String DH_G = "g";

    /** Wildchar for "any" value in property name */
    private static final String ANY               = "*"; 
    /** Regex for space */
    private static final String SPACE_REGEX       = "\\s";
    /** Common separator between propert name elements */
    private static final String SEP = ".";

    /** lock object for synchronizing access to PSK store */
    private final Object pskStoreLock = new Object();
    /** lock object for synchronizing access to MGK store */
    private final Object mgkStoreLock = new Object();

    /** underlying representation of configuration properties */
    private final Properties p;

    /**
     * @param prop provided in app-specific way
     * @return singleton instance of MslProperties
     */
    public static MslProperties getInstance(final Properties prop) {
        if (prop == null) {
            throw new IllegalArgumentException("NULL Properties");
        }
        return new MslProperties(prop);
    }

    /**
     * @param p properties extracted from the configuration file
     */
    private MslProperties(final Properties p) {
        this.p = p;
    }

    /* ****************************
     * ENTITY-SPECIFIC PROPERTIES *
     ******************************/

    /**
     * @param entityId entity identity
     * @return names of entity authentication schemes supported by given entity
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Set<String> getSupportedEntityAuthenticationSchemes(final String entityId) throws ConfigurationException {
        return split(getWildcharProperty(ENTITY_AUTH_SCHEMES, entityId));
    }

    /**
     * @param entityId entity identity
     * @return names of entity authentication schemes supported by given entity
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Set<String> getSupportedUserAuthenticationSchemes(final String entityId) throws ConfigurationException {
        return split(getWildcharProperty(ENTITY_UAUTH_SCHEMES, entityId));
    }

    /**
     * @param entityId entity identity
     * @return names of key exchange schemes supported by given entity
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Set<String> getSupportedKeyExchangeSchemes(final String entityId) throws ConfigurationException {
        return split(getWildcharProperty(ENTITY_KX_SCHEMES, entityId));
    }

    /**
    /**
     * @param entityId entity identity
     * @param userId user identity
     * @return names of key exchange scheme supported by given entity
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Set<String> getSupportedKeyExchangeSchemes(final String entityId, final String userId) throws ConfigurationException {
        return getSupportedKeyExchangeSchemes(entityId);
    }

    /**
     * @param entityId entity identity
     * @return ID of Diffie-Hellman parameters to be used by given entity
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public String getEntityDiffieHellmanParametersId(final String entityId) throws ConfigurationException {
        return getWildcharProperty(ENTITY_DH_ID, entityId);
    }

    /**
     * @return mappings between entity identity and { encryption, hmac, wrapping} hex-encoded pre-shared keys triplet
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Map<String,Triplet<String,String,String>> getPresharedKeyStore() throws ConfigurationException {
        synchronized (pskStoreLock) {
            return getTripletMap(ENTITY_PSK, ID, ENC_KEY, HMAC_KEY, WRAP_KEY, true, true, false);
        }
    }

    /**
     * @return mappings between entity identity and { encryption, hmac, wrapping} hex-encoded mgk keys triplet
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Map<String,Triplet<String,String,String>> getMgkKeyStore() throws ConfigurationException {
        synchronized (mgkStoreLock) {
            return getTripletMap(ENTITY_MGK, ID, ENC_KEY, HMAC_KEY, WRAP_KEY, true, true, false);
        }
    }

    /**
     * @param entityId identity identity
     * @return ID of the { encryption, hmac } key set to be used by this entity for issuing service tokens
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public String getServiceTokenKeySetId(final String entityId) throws ConfigurationException {
        return getRequiredProperty(ENTITY_STOKEN_KEY_ID + entityId);
    }

    /**
     * @param entityId entity identity, owner of RSA key pair used for RSA entity authentication
     * @return ID of the RSA key pair to be used for specified entity's authentication
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public String getRsaKeyId(final String entityId) throws ConfigurationException {
        return getWildcharProperty(ENTITY_RSA_KEY_ID, entityId);
    }

    /**
     * add pre-shared key entry; it can be called by the client app
     * @param pskEntry { entityId, encryptionKey, hmacKey}. Wrapping key is assumed to be derived.
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public void addPresharedKeys(final Triplet<String,String,String> pskEntry) throws ConfigurationException {
        addKeyTriplet(pskEntry, ENTITY_PSK, pskStoreLock);
    }

    /**
     * add MGK key entry; it can be called by the client app
     * @param mgkEntry { entityId, encryptionKey, hmacKey}. Wrapping key is assumed to be derived.
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public void addMgkKeys(final Triplet<String,String,String> mgkEntry) throws ConfigurationException {
        addKeyTriplet(mgkEntry, ENTITY_MGK, mgkStoreLock);
    }

    /**
     * @param entry {enc,hmac,wrap} key triplet to be added to the configuration
     * @param prefix name of the key family
     * @param lock suncronization object for this key family
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    private void addKeyTriplet(final Triplet<String,String,String> entry, final String prefix, final Object lock) throws ConfigurationException {
        if (entry == null) {
            throw new IllegalArgumentException("NULL keys");
        }
        synchronized (lock) {
            final int num = getCountProperty(prefix + NUM);
            p.setProperty(prefix + NUM, String.valueOf(num + 1));
            p.setProperty(prefix + ID       + SEP + num, entry.x);
            p.setProperty(prefix + ENC_KEY  + SEP + num, entry.y);
            if (entry.z != null)
            p.setProperty(prefix + HMAC_KEY + SEP + num, entry.z);
        }
    }

    /* **************************
     * USER-SPECIFIC PROPERTIES *
     ****************************/

    /**
     * @param userId user id, corresponding to local user account of some kind. Has no meaning outside local context.
     * @return ( email,password ) tuple for a given user ID
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Pair<String,String> getEmailPassword(final String userId) throws ConfigurationException {
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("Undefined userId");
        }
        final Map<String,Pair<String,String>> map = getPairMap(USER_EP, ID, EMAIL, PWD, true, true);
        final Pair<String,String> emailPwd = map.get(userId.trim());
        if (emailPwd != null)
            return emailPwd;
        else
            throw new ConfigurationException("Missing Email-Password Entry for User Id " + userId);
    }

    /**
     * @return mappings between user email and user password
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Map<String,String> getEmailPasswordStore() throws ConfigurationException {
        return getMap(USER_EP, EMAIL, PWD);
    }

    /* *******************************
     * MSL ECOSYSTEM-WIDE PROPERTIES *
     *********************************/

    /**
     * @return MSL {encryption, HMAC, and wrapping} keys triplet.
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Triplet<String,String,String> getMslKeys() throws ConfigurationException {
        return new Triplet<String,String,String>(
            getRequiredProperty(MSL_KEY_ENC),
            getRequiredProperty(MSL_KEY_HMAC),
            getRequiredProperty(MSL_KEY_WRAP)
            );
    }

    /**
     * @return mappings between RSA key pair ID and { public, private } RSA key pair tuples
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Map<String,Pair<String,String>> getRsaKeyStore() throws ConfigurationException {
        return getPairMap(MSL_RSA, ID, PUB_KEY, PRIV_KEY, true, false);
    }

    /**
     * @return mappings between Diffie-Hellman parameters ID and actual Diffie-Hellman (P,G) parameters
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Map<String,Pair<String,String>> getDHParameterStore() throws ConfigurationException {
        return getPairMap(MSL_DH, ID, DH_P, DH_G, true, true);
    }

    /**
     * @param keyId ID of the { encryption, hmac } key pair used for service token issuing
     * @return { encryption, hmac } key pair
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public Pair<String,String> getServiceTokenKeys(final String keyId) throws ConfigurationException {
        return new Pair<String,String>(getRequiredProperty(MSL_STOKEN_KEY_ENC + keyId), getRequiredProperty(MSL_STOKEN_KEY_HMAC + keyId));
    }

    /**
     * @return Master Token renewal offset in milliseconds
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public int getMasterTokenRenewalOffset() throws ConfigurationException {
        return getCountProperty(MSL_MTOKEN_RENEWAL_OFFSET);
    }

    /**
     * @return Master Token expiration offset in milliseconds
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public int getMasterTokenExpirationOffset() throws ConfigurationException {
        return getCountProperty(MSL_MTOKEN_EXPIRATION_OFFSET);
    }

    /**
     * @return Master Token non-replay ID window
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public int getMasterTokenNonReplayIdWindow() throws ConfigurationException {
        return getCountProperty(MSL_MTOKEN_NON_REPLAY_ID_WINDOW);
    }

    /**
     * @return Master Token's max allowed skipped sequence numbers still allowed for renewal
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public int getMasterTokenMaxSkipped() throws ConfigurationException {
        return getCountProperty(MSL_MTOKEN_MAX_SKIPPED);
    }

    /**
     * @return User ID Token renewal offset in milliseconds
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public int getUserIdTokenRenewalOffset() throws ConfigurationException {
        return getCountProperty(MSL_UITOKEN_RENEWAL_OFFSET);
    }

    /**
     * @return User ID Token expiration offset in milliseconds
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public int getUserIdTokenExpirationOffset() throws ConfigurationException {
        return getCountProperty(MSL_UITOKEN_EXPIRATION_OFFSET);
    }

    /* ************************
     * APPLICATION PROPERTIES *
     **************************/

    /**
     * @return number of threads configured for "this" MslControl
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public int getNumMslControlThreads() throws ConfigurationException {
        return getCountProperty(APP_CTRL_NUM_THR);
    }

    /**
     * @return IP port to be used by "this" MSL server for listenning to incoming MSL messages
     * @throws ConfigurationException if server port is not defined or is not valid
     */
    public int getServerPort() throws ConfigurationException {
        return getCountProperty(APP_SERVER_PORT);
    }

    /**
     * @return list of entity authentication handle class names
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public List<String> getEntityAuthenticationHandles() throws ConfigurationException {
        return getValueList(APP_ENTITY_AUTH_HANDLE);
    }

    /**
     * @return list of key exchange handle class names
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public List<String> getKeyExchangeHandles() throws ConfigurationException {
        return getValueList(APP_KEYX_HANDLE);
    }

    /**
     * @return list of user authentication handle class names
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    public List<String> getUserAuthenticationHandles() throws ConfigurationException {
        return getValueList(APP_USER_AUTH_HANDLE);
    }

    /**
     * @param prefix property name prefix
     * @return subset of properties  with the given name prefix. Prefix is removed.
     * @throws ConfigurationException
     */
    public Map<String,String> getPropertyFamily(String prefix) throws ConfigurationException {
        if (prefix == null || prefix.trim().length() == 0)
            throw new IllegalArgumentException("NULL prefix");
        prefix = prefix.trim();
        if (!prefix.endsWith(SEP)) prefix += SEP;
        final Map<String,String> propFamily = new HashMap<String,String>();
        for (String name : p.stringPropertyNames()) {
            if (name.startsWith(prefix))
                propFamily.put(name.substring(prefix.length()), p.getProperty(name));
        }
        return propFamily;
    }

    /* ****************
     * Helper classes *
     ******************/

    /**
     * @param name prefix for all property names in the property triplets
     * @return list of property values
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    private List<String> getValueList(final String name) throws ConfigurationException {
        final int num = getCountProperty(name + NUM);
        final ArrayList<String> values = new ArrayList<String>(num);
        for (int i = 0; i < num; i++) {
            values.add(getRequiredProperty(name + i));
        }
        return values;
    }

    /**
     * @param prefix prefix for all property names
     * @param key suffix for property key names
     * @param value suffix for property value names
     * @return (key,value) map
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    private Map<String,String> getMap(final String prefix, final String key, final String value) throws ConfigurationException {
        final int num = getCountProperty(prefix + NUM);
        final Map<String,String> map = new HashMap<String,String>(num);
        for (int i = 0; i < num; i++) {
            map.put(getRequiredProperty(prefix + key + SEP + i), getRequiredProperty(prefix + value + SEP + i));
        }
        return map;
    }

    /**
     * @param prefix prefix for all property names in the property pairs
     * @param key name of the property reprsenting the key
     * @param name1 name of the property reprsenting the first value
     * @param name2 name of the property reprsenting the second value
     * @param required1 whether the property with name1 is required to be defined
     * @param required2 whether the property with name2 is required to be defined
     * @return Map of property pair values
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    private Map<String,Pair<String,String>> getPairMap(
        final String prefix, final String key,
        final String name1, final String name2,
        final boolean required1, final boolean required2)
        throws ConfigurationException
    {
        final int num = getCountProperty(prefix + NUM);
        final Map<String,Pair<String,String>> map = new HashMap<String,Pair<String,String>>(num);
        for (int i = 0; i < num; i++) {
            map.put(getRequiredProperty(prefix + key + SEP + i),
                new Pair<String,String>(
                    required1 ? getRequiredProperty(prefix + name1 + SEP + i) : getProperty(prefix + name1 + SEP + i),
                    required2 ? getRequiredProperty(prefix + name2 + SEP + i) : getProperty(prefix + name2 + SEP + i)
                )
            );
        }
        return map;
    }

    /**
     * @param prefix prefix for all property names in the property triplets
     * @param key name of the property reprsenting the key
     * @param name1 name of the property reprsenting the first value
     * @param name2 name of the property reprsenting the second value
     * @param name3 name of the property reprsenting the second value
     * @param required1 whether the property with name1 is required to be defined
     * @param required2 whether the property with name2 is required to be defined
     * @param required3 whether the property with name3 is required to be defined
     * @return Map of property pair values
     * @throws ConfigurationException if the value is not defined or is not valid
     */
    private Map<String,Triplet<String,String,String>> getTripletMap(
        final String prefix, final String key,
        final String name1, final String name2, final String name3,
        final boolean required1, final boolean required2, final boolean required3)
        throws ConfigurationException
    {
        final int num = getCountProperty(prefix + NUM);
        final Map<String,Triplet<String,String,String>> map = new HashMap<String,Triplet<String,String,String>>(num);
        for (int i = 0; i < num; i++) {
            map.put(getRequiredProperty(prefix + key + SEP + i),
                new Triplet<String,String,String>(
                    required1 ? getRequiredProperty(prefix + name1 + SEP + i) : getProperty(prefix + name1 + SEP + i),
                    required2 ? getRequiredProperty(prefix + name2 + SEP + i) : getProperty(prefix + name2 + SEP + i),
                    required3 ? getRequiredProperty(prefix + name3 + SEP + i) : getProperty(prefix + name3 + SEP + i)
                )
            );
        }
        return map;
    }

    /**
     * return non-mandatory property.
     * @param name property name
     * @return property value or null if property is missing
     * @throws ConfigurationException if property exists but its value is not defined
     */
    private String getProperty(final String name) throws ConfigurationException {
        final String value = p.getProperty(name);
        if (value != null) {
            if (value.trim().length() != 0) {
                return value.trim();
            } else {
                throw new ConfigurationException(String.format("Property %s with blank value", name));
            }
        } else if (p.containsKey(name)) {
            throw new ConfigurationException(String.format("Property %s with no value", name));
        } else {
            return null;
        }
    }

    /**
     * return mandatory non-negative integer property value
     * @param name mandatory non-negative integer property name
     * @return mandatory non-negative integer property value
     * @throws ConfigurationException if mandatory property is missing or has negative value
     */
    private int getCountProperty(final String name) throws ConfigurationException {
        final String s = getRequiredProperty(name);
        final int num = Integer.parseInt(s);
        if (num < 0) {
            throw new ConfigurationException(String.format("Invalid Property %s : %s --> %d", name, s, num));
        }
        return num;
    }

    /**
     * return mandatory property value
     * @param name mandatory property name
     * @return mandatory property value
     * @throws ConfigurationException if mandatory property is missing or has no value
     */
    private String getRequiredProperty(final String name) throws ConfigurationException {
        final String s = getProperty(name);
        if (s == null) {
            throw new ConfigurationException("Missing Property " + name);
        }
        return s;
    }

    /**
     * return the value of mandatory property that supports wildchar
     * @param prefix property name prefix
     * @param id property name suffix which can be replaced with "*" to match any suffix
     * @return mandatory property value
     * @throws ConfigurationException if mandatory property is missing or has no value
     */
    private String getWildcharProperty(final String prefix, String id) throws ConfigurationException {
        String s = getProperty(prefix + id);
        if (s == null) {
            s = getProperty(prefix + ANY);
        }
        if (s == null) {
            throw new ConfigurationException(String.format("Missing Property %s(%s|%s)", prefix, id, ANY));
        }
        return s;
    }

    /**
     * parse multi-value property into a Set of unique values
     * @param value string value that may contain multiple space-separated values
     * @return set of values parsed out of the input string
     */
    private Set<String> split(final String value) {
        return Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(value.split(SPACE_REGEX))));
    }

    @Override
    public String toString() {
        return SharedUtil.toString(this);
    }
}
