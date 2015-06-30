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

package mslcli.client;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class CliCmdParameters {

    // parameters
    public static final String P_INT  = "-int" ; // interactive mode
    public static final String P_EID  = "-eid" ; // entity id
    public static final String P_UID  = "-uid" ; // user id
    public static final String P_KX   = "-kx"  ; // key exchange type
    public static final String P_KXM  = "-kxm" ; // key exchange mechanism
    public static final String P_URL  = "-url" ; // remote url
    public static final String P_IF   = "-if"  ; // input message file
    public static final String P_OF   = "-of"  ; // output message file
    public static final String P_ENC  = "-enc" ; // message encrypted
    public static final String P_SIG  = "-sig" ; // message integrity protected
    public static final String P_NREP = "-nrep"; // message non-replayable
    public static final String P_CFG  = "-cfg" ; // configuration file
    public static final String P_DBG  = "-v"   ; // verbose
    public static final String P_HELP = "-help"; // help

    public static final List<String> supportedParameters =
        Collections.unmodifiableList(new ArrayList<String>(Arrays.asList(P_INT, P_EID, P_UID, P_KX, P_KXM, P_URL, P_IF, P_OF, P_ENC, P_SIG, P_NREP, P_CFG, P_DBG, P_HELP)));

    // supported key exchanges
    public static final String KX_DH   = "dh" ; // Diffie-Hellman             Key Exchange
    public static final String KX_SWE  = "sw" ; // Symmetric  Wrapped         Key Exchange
    public static final String KX_AWE  = "aw" ; // Asymmetric Wrapped         Key Exchange
    public static final String KX_JWEL = "jwe"; // JSON Web Encryption Ladder Key Exchange
    public static final String KX_JWKL = "jwk"; // JSON Web Key        Ladder Key Exchange

    public static final Set<String> supportedKxTypes =
        Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(KX_DH, KX_SWE, KX_AWE, KX_JWEL, KX_JWKL)));

   // Asymmetric Wrapped Key Exchange Mechanisms
    public static final String KXM_JWE_RSA   = "JWE_RSA";
    public static final String KXM_JWEJS_RSA = "JWEJS_RSA";
    public static final String KXM_JWK_RSA   = "JWK_RSA";
    public static final String KXM_JWK_RSAES = "JWK_RSAES";

    public static final Set<String> supportedAsymmetricWrappedExchangeMechanisms = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
        KXM_JWE_RSA, KXM_JWEJS_RSA, KXM_JWK_RSA, KXM_JWK_RSAES)));

    public CliCmdParameters(final String[] args) {
        if (args == null) {
            throw new IllegalArgumentException("NULL args");
        }
        this.argMap = new HashMap<String,String>();

        String param = null;
        String value = null;
        for (String s : args) {
            // one of the supported parameters
            if (supportedParameters.contains(s)) {
                // already occured - error
                if (argMap.containsKey(s)) {
                    throw new IllegalArgumentException("Multiple Occurences of " + s);
                }
                // expected value, not parameter
                if (param != null) {
                    throw new IllegalArgumentException("Missing Value for " + param);
                }
                // ok, new parameter; previous ones were successfully parsed
                param = s;
            // looks like partameter, but not one of the supported ones - error
            } else if (s.startsWith("-")) {
                throw new IllegalArgumentException("Illegal Parameter " + s);
            // looks like parameter value, and is expected
            } else if (param != null) {
                value = s;
                argMap.put(param, value);
                param = null;
                value = null;
            // looks like parameter value, but next parameter is expected
            } else {
                throw new IllegalArgumentException("Unexpected Value " + s);
            }
        }
    }

    public Map<String,String> getParameters() {
        return Collections.unmodifiableMap(argMap);
    }

    /**
     * @return interactive mode true/false
     */
    public boolean isInteractive() {
        return getBoolean(P_INT, false);
    }

    /**
     * @return remote URL - must exist
     */
    public URL getUrl() {
        final String url = getValue(P_URL);
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid URL " + url, e);
        }
    }

    /**
     * @return configuration file path - must exist and be a regular file
     */
    public String getConfigFilePath() {
        final String file = getValue(P_CFG);
        final File f = new File(file);
        if (f.isFile()) {
            return file;
        } else {
            throw new IllegalArgumentException("Not a File: " + file);
        }
    }

    /**
     * @return file path to read request payload from. Must exist and be a regular file.
     */
    public String getPayloadInputFile() {
        final String file = getValue(P_IF);
        final File f = new File(file);
        if (f.isFile()) {
            return file;
        } else {
            throw new IllegalArgumentException("Not a File: " + file);
        }
    }

    /**
     * @return file path to write response payload to
     */
    public String getPayloadOutputFile() {
        final String file = getValue(P_OF);
        final File f = new File(file);
        if (!f.exists()) {
            return file;
        } else {
            throw new IllegalArgumentException("Cannot Overwrite Existing File: " + file);
        }
    }

    /**
     * @return entityId - must be initialized
     */
    public String getEntityId() {
        return getValue(P_EID);
    }

    /**
     * @return userId - can be uninitialized
     */
    public String getUserId() {
        return argMap.get(P_UID);
    }

    /**
     * @return whether message needs encryption
     */
    public boolean isEncrypted() {
        return getBoolean(P_ENC, true);
    }

    /**
     * @return whether message needs integrity protection
     */
    public boolean isIntegrityProtected() {
        return getBoolean(P_SIG, true);
    }

    /**
     * @return whether message needs to be non-replayable
     */
    public boolean isNonReplayable() {
        return getBoolean(P_NREP, false);
    }

    /**
     * @return key exchange scheme - can be uninitialized
     */
    public String getKeyExchangeScheme() {
        return argMap.get(P_KX);
    }

    /**
     * @return key exchange mechanism - can be uninitialized
     */
    public String getKeyExchangeMechanism() {
        return argMap.get(P_KXM);
    }

    /**
     * @return verbose mode y/n
     */
    public boolean isVerbose() {
        return getBoolean(P_DBG, false);
    }

    private boolean getBoolean(final String name, final boolean def) {
        final String s = argMap.get(name);
        return (s != null) ? Boolean.parseBoolean(s) : def;
    }

    private String getValue(final String name) {
        final String s = argMap.get(name);
        if (s != null) {
            return s;
        } else {
            throw new IllegalArgumentException("Missing Required Parameter " + name);
        }
    }

    private final Map<String,String> argMap;
}
