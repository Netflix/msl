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

package mslcli.common;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import com.netflix.msl.MslConstants;

import mslcli.common.util.SharedUtil;

/**
 * <p>
 * MSL CLI command-line arguments parser, validator, and accessor class.
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class CmdArguments {

    // parameters
    /** interactive mode */
    public static final String P_INT  = "-int" ;
    /** configuration file */
    public static final String P_CFG  = "-cfg" ;
    /** remote url */
    public static final String P_URL  = "-url" ;
    /** entity id */
    public static final String P_EID  = "-eid" ;
    /** user id */
    public static final String P_UID  = "-uid" ;
    /** user authentication scheme */
    public static final String P_UAS  = "-uas" ;
    /** key exchange type */
    public static final String P_KX   = "-kx"  ;
    /** key exchange mechanism */
    public static final String P_KXM  = "-kxm" ;
    /** message encrypted */
    public static final String P_ENC  = "-enc" ;
    /** message integrity protected */
    public static final String P_SIG  = "-sig" ;
    /** message non-replayable */
    public static final String P_NREP = "-nrep";
    /** input message payload file */
    public static final String P_IF   = "-if"  ;
    /** output message payload file */
    public static final String P_OF   = "-of"  ;
    /** input message payload text */
    public static final String P_MSG  = "-msg" ;
    /** pre-shared key file path */
    public static final String P_PSK  = "-psk" ;
    /** MGK key file path */
    public static final String P_MGK  = "-mgk" ;
    /** MSL store file path */
    public static final String P_MST  = "-mst" ;
    /** entity authentication scheme */
    public static final String P_EAS  = "-eas" ;
    /** verbose */
    public static final String P_V    = "-v"   ;
    /** send message N times */
    public static final String P_NSND = "-nsnd";

    /** list of supported arguments */
    private static final List<String> supportedArguments =
        Collections.unmodifiableList(new ArrayList<String>(Arrays.asList(
            P_INT,
            P_CFG,
            P_URL,

            P_EID,
            P_EAS,

            P_KX,
            P_KXM,

            P_UID,
            P_UAS,

            P_PSK,
            P_MGK,
            P_MST,

            P_ENC,
            P_SIG,
            P_NREP,

            P_IF,
            P_OF,
            P_MSG,

            P_NSND,
            P_V
        )));

    /** prefix for ad-hock properties that can be set for functionality extensions */
    private static final String EXT_PREFIX = "-ext.";
    /** separator for ad-hock property names */
    private static final String EXT_SEP = ".";

    /** order of listing of supported arguments */
    private static final Map<String,Integer> supportedArgumentsRank = rankSupportedArguments();

    /**
     * @return mapping between argument name and its rank
     */
    private static Map<String,Integer> rankSupportedArguments() {
        final Map<String,Integer> hm = new HashMap<String,Integer>();
        int i = 0;
        for (String key : supportedArguments) {
            hm.put(key, i++);
        }
        return Collections.unmodifiableMap(hm);
    }

    /**
     * @param key propertry name
     * @return property order of preference
     */
    private static int getArgRank(final String key) {
        return supportedArgumentsRank.containsKey(key) ? supportedArgumentsRank.get(key) : -1;
    }

    /**
     * comparator class for listing arguments in preferable order
     */
    private static final class ArgComparator implements Comparator<String> {
        @Override
        public int compare(String x, String y) {
            final int rx = getArgRank(x);
            final int ry = getArgRank(y);
            if (rx != -1 && ry != -1) {
                return (rx - ry);
            } else if (rx != -1) {
                return -1;
            } else if (ry != -1) {
                return 1;
            } else {
                return x.compareTo(y);
            }
        }
        @Override
        public boolean equals(Object o) {
            return this == o;
        }
        @Override
        public int hashCode() {
            throw new UnsupportedOperationException();
        }
    }

    /** arg comparator */
    private static final Comparator<String> argComparator = new ArgComparator();

    /** underlying representation of arguments */
    private final Map<String,String> argMap;

    /**
     * Ctor.
     *
     * @param args array of arguments
     * @throws IllegalCmdArgumentException
     */
    public CmdArguments(final String[] args) throws IllegalCmdArgumentException {
        if (args == null) {
            throw new IllegalCmdArgumentException("NULL args");
        }
        this.argMap = new HashMap<String,String>();

        String param = null;
        String value = null;
        for (String s : args) {
            // one of the supported parameters or extension (ad hock) parameter
            if (supportedArguments.contains(s) || s.startsWith(EXT_PREFIX)) {
                // already occured - error
                if (argMap.containsKey(s)) {
                    throw new IllegalCmdArgumentException("Multiple Occurences of " + s);
                }
                // expected value, not parameter
                if (param != null) {
                    throw new IllegalCmdArgumentException("Missing Value for " + param);
                }
                // ok, new parameter; previous ones were successfully parsed
                param = s;
            // looks like partameter, but not one of the supported ones - error
            } else if (s.startsWith("-") && (s.length() > 1)) {
                throw new IllegalCmdArgumentException("Illegal Option " + s);
            // if not a parameter, then must be a value
            } else if (param != null) {
                value = s.equals("-") ? null : s; // special case "-" for deleting the value
                argMap.put(param, value);
                param = null;
                value = null;
            // looks like parameter value, but next parameter is expected
            } else {
                throw new IllegalCmdArgumentException("Unexpected Value \"" + s + "\"");
            }
        }
        if (param != null) {
            throw new IllegalCmdArgumentException("Missing Value for Option \"" + param + "\"");
        }
    }

    /**
     * Copy Ctor.
     *
     * @param other another CmdArguments instance
     * @throws IllegalCmdArgumentException
     */
    public CmdArguments(final CmdArguments other) throws IllegalCmdArgumentException {
        if (other == null) {
            throw new IllegalCmdArgumentException("NULL CmdArguments object passed for copying");
        }
        this.argMap = new HashMap<String,String>();
        this.argMap.putAll(other.argMap);
    }

    /**
     * @return all parameters as unmodifiable Map
     */
    public String getParameters() {
        final Map<String,String> m = new TreeMap<String,String>(argComparator);
        m.putAll(argMap);
        final StringBuilder sb = new StringBuilder();
        for (final Map.Entry<String,String> entry : m.entrySet()) {
            sb.append(entry.getKey()).append(' ').append(entry.getValue()).append(' ');
        }
        return sb.toString();
    }

    /**
     * merge parameters from another CmdArguments instance
     * @param other another CmdArguments instance to merge parameters from
     * @throws IllegalCmdArgumentException
     */
    public void merge(CmdArguments other) throws IllegalCmdArgumentException {
        if (other == null) {
            throw new IllegalArgumentException("NULL CmdArguments argument");
        }
        if (other.argMap.containsKey(P_CFG)) {
            throw new IllegalCmdArgumentException("Cannot reset Configuration File");
        }
        if (other.argMap.containsKey(P_INT)) {
            throw new IllegalCmdArgumentException("Cannot reset Interactive Mode");
        }
        if (other.argMap.containsKey(P_PSK)) {
            throw new IllegalCmdArgumentException("Cannot add PSK file interactively");
        }
        if (other.argMap.containsKey(P_MST) && argMap.containsKey(P_MST)) {
            throw new IllegalCmdArgumentException("Cannot reset MSL Store File");
        }
        for (Map.Entry<String,String> entry : other.argMap.entrySet()) {
            if (entry.getValue() != null) {
                argMap.put(entry.getKey(), entry.getValue());
            } else {
                argMap.remove(entry.getKey());
            }
        }
    }

    /**
     * @return interactive mode true/false
     */
    public boolean isInteractive() {
        return getBoolean(P_INT, false);
    }

    /**
     * @return remote URL - must exist
     * @throws IllegalCmdArgumentException
     */
    public URL getUrl() throws IllegalCmdArgumentException {
        final String url = getRequiredValue(P_URL);
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            throw new IllegalCmdArgumentException("Invalid URL " + url, e);
        }
    }

    /**
     * @return configuration file path - must exist and be a regular file
     * @throws IllegalCmdArgumentException
     */
    public String getConfigFilePath() throws IllegalCmdArgumentException {
        final String file = getRequiredValue(P_CFG);
        if (SharedUtil.isExistingFile(file)) {
            return file;
        } else {
            throw new IllegalCmdArgumentException("Not a File: " + file);
        }
    }

    /**
     * @return file path to read request payload from. Must exist and be a regular file.
     * @throws IllegalCmdArgumentException
     */
    public String getPayloadInputFile() throws IllegalCmdArgumentException {
        final String file = argMap.get(P_IF);
        if (file == null) {
            return null;
        }
        if (SharedUtil.isExistingFile(file)) {
            return file;
        } else {
            throw new IllegalCmdArgumentException("Not a File: " + file);
        }
    }

    /**
     * @return file path to write response payload to
     * @throws IllegalCmdArgumentException
     */
    public String getPayloadOutputFile() throws IllegalCmdArgumentException {
        final String file = argMap.get(P_OF);
        if (file == null) {
            return null;
        }
        if (SharedUtil.isValidNewFile(file)) {
            return file;
        } else if (SharedUtil.isExistingFile(file)) {
            throw new IllegalCmdArgumentException("Cannot Overwrite Existing File: " + file);
        } else {
            throw new IllegalCmdArgumentException("Invalid File Path: " + file);
        }
    }

    /**
     * @return file path to PSK file. If defined, must be a file.
     * @throws IllegalCmdArgumentException
     */
    public String getPskFile() throws IllegalCmdArgumentException {
        final String file = argMap.get(P_PSK);
        if (file == null) {
            return null;
        }
        if (SharedUtil.isExistingFile(file)) {
            return file;
        } else {
            throw new IllegalCmdArgumentException("Not a File: " + file);
        }
    }

    /**
     * @return file path to MGK file. If defined, must be a file.
     * @throws IllegalCmdArgumentException
     */
    public String getMgkFile() throws IllegalCmdArgumentException {
        final String file = argMap.get(P_MGK);
        if (file == null) {
            return null;
        }
        if (SharedUtil.isExistingFile(file)) {
            return file;
        } else {
            throw new IllegalCmdArgumentException("Not a File: " + file);
        }
    }

    /**
     * @return file path to PSK file. If defined, must be a file.
     * @throws IllegalCmdArgumentException
     */
    public String getMslStorePath() throws IllegalCmdArgumentException {
        final String file = argMap.get(P_MST);
        if (file == null) {
            return null;
        }
        if (SharedUtil.isExistingFile(file) || SharedUtil.isValidNewFile(file)) {
            return file;
        } else {
            throw new IllegalCmdArgumentException("Invalid File Path: " + file);
        }
    }

    /**
     * @return payload text message
     */
    public byte[] getPayloadMessage() {
        final String s = argMap.get(P_MSG);
        return (s != null) ? s.getBytes(MslConstants.DEFAULT_CHARSET) : null;
    }

    /**
     * @return entityId - must be initialized
     * @throws IllegalCmdArgumentException
     */
    public String getEntityId() throws IllegalCmdArgumentException {
        return getRequiredValue(P_EID);
    }

    /**
     * @return entityId or null if not initialized
     * @throws IllegalCmdArgumentException
     */
    public String getOptEntityId() {
        return argMap.get(P_EID);
    }

    /**
     * @return whether entity identity key is defined (value can be null)
     */
    public boolean hasEntityId() {
        return argMap.containsKey(P_EID);
    }

    /**
     * @return userId - can be uninitialized
     */
    public String getUserId() {
        return argMap.get(P_UID);
    }

    /**
     * @return user authentication scheme - can be uninitialized
     */
    public String getUserAuthenticationScheme() {
        return argMap.get(P_UAS);
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
     * @return get entity authentication scheme
     * @throws IllegalCmdArgumentException if property is not defined
     */
    public String getEntityAuthenticationScheme() throws IllegalCmdArgumentException {
        return getRequiredValue(P_EAS);
    }

    /**
     * @return key exchange scheme
     */
    public String getKeyExchangeScheme() {
        return argMap.get(P_KX);
    }

    /**
     * @return key exchange mechanism
     */
    public String getKeyExchangeMechanism() {
        return argMap.get(P_KXM);
    }

    /**
     * @return verbose mode y/n
     */
    public int getNumSends() {
        return getInteger(P_NSND, 1);
    }

    /**
     * @return verbose mode y/n
     */
    public boolean isVerbose() {
        return getBoolean(P_V, false);
    }

    /**
     * @param name name of the boolean property
     * @param def default value of the boolean property
     * @return property parsed as boolean or default value if it does not exist
     */
    private boolean getBoolean(final String name, final boolean def) {
        final String s = argMap.get(name);
        return (s != null) ? Boolean.parseBoolean(s) : def;
    }

    /**
     * @param name name of the integer property
     * @param def default value of the integer property
     * @return property parsed as integer or default value if it does not exist
     */
    private int getInteger(final String name, final int def) {
        final String s = argMap.get(name);
        return (s != null) ? Integer.parseInt(s) : def;
    }

    /**
     * @param name name of the mandatory property
     * @return property value
     * @throws IllegalCmdArgumentException if property is not defined
     */
    private String getRequiredValue(final String name) throws IllegalCmdArgumentException {
        final String s = argMap.get(name);
        if (s != null) {
            return s;
        } else {
            throw new IllegalCmdArgumentException("Missing Required Argument " + name);
        }
    }

    /**
     * @param group group of properties. property name prefix is composed as EXT_PREFIX + group.
     * @return Map of properties with stripped off preffixes
     */
    public Map<String,String> getExtensionProperties(String group) {
        group = EXT_PREFIX + group + EXT_SEP;
        final Map<String,String> m = new HashMap<String,String>();
        for (Map.Entry<String,String> entry : argMap.entrySet()) {
            if (entry.getKey().startsWith(group)) {
                m.put(entry.getKey().substring(group.length()), entry.getValue());
            }
        }
        return m;
    }

    @Override
    public String toString() {
        return SharedUtil.toString(this);
    }
}
