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
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Properties;

import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;

/**
 * Collection of utilities
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class SharedUtil {

    private SharedUtil() {}

    /**
     * extract useful info from MasterToken
     */
    public static final String getMasterTokenInfo(final MasterToken masterToken) {
        if (masterToken == null) {
            return null;
        }
        final long t_now = System.currentTimeMillis();
        final long t_rnw = (masterToken.getRenewalWindow().getTime() - t_now)/1000L;
        final long t_exp = (masterToken.getExpiration().getTime() - t_now)/1000L;
        return String.format("MasterToken{ser_num %d, seq_num %d, renewable in %d sec, expires in %d sec}",
            masterToken.getSerialNumber(), masterToken.getSequenceNumber(), t_rnw, t_exp);
    }

    /**
     * extract useful info from MasterToken
     */
    public static final String getUserIdTokenInfo(final UserIdToken userIdToken) {
        if (userIdToken == null) {
            return null;
        }
        final long t_now = System.currentTimeMillis();
        final long t_rnw = (userIdToken.getRenewalWindow().getTime() - t_now)/1000L;
        final long t_exp = (userIdToken.getExpiration().getTime() - t_now)/1000L;
        return String.format("UserIdToken{user %s, ser_num %d, mt_ser_num: %d, renewable in %d sec, expires in %d sec}",
            (userIdToken.getUser() != null) ? userIdToken.getUser().getEncoded() : null,
            userIdToken.getSerialNumber(),
            userIdToken.getMasterTokenSerialNumber(),
            t_rnw,
            t_exp);
    }

    /**
     * IO Helper: read input stream into byte array
     */
    public static byte[] readIntoArray(final InputStream in) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            out.write(b);
        }
        return out.toByteArray();
    }

    /**
     * IO Helper: read single line from STDIN
     */
    public static String readInput(final String prompt) throws IOException {
        final BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print(prompt.trim() + "> ");
        return br.readLine();
    }

    /**
     * IO Helper: read parameter from STDIN
     */
    public static String readParameter(final String prompt, final String def) throws IOException {
        final String value = readInput(String.format("%s[%s]", prompt, def));
        if (value == null || value.isEmpty()) {
            return def;
        } else if (value.trim().isEmpty()) {
            return null;
        } else {
            return value.trim();
        }
    }

    /**
     * IO Helper: read boolean value from STDIN.
     * Repeat prompt till one of the valid values is entered. 
     */
    public static boolean readBoolean(final String name, final boolean def, final String yesStr, final String noStr) throws IOException {
        String value;
        do {
            value = readInput(String.format("%s[%s]", name, def? "y" : "n"));
            if (value.trim().isEmpty()) {
                return def;
            } else if (yesStr.equalsIgnoreCase(value)) {
                return true;
            } else if (noStr.equalsIgnoreCase(value)) {
                return false;
            }
        } while (true);
    }

    /**
     * Helper: convert hex string into byte array
     */
    public static byte[] hexStringToByteArray(final String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i  ), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16)     );
        }
        return data;
    }

    /**
     * Helper: get innermost cause exception
     */
    public static Throwable getRootCause(Throwable t) {
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }

    /**
     * load properties from file
     */
    public static Properties loadPropertiesFromFile(final String file) throws IOException {
        final Properties p = new Properties();
        FileReader fr = null;
        try {
            fr = new FileReader(file);
            p.load(fr);
        } finally {
            if (fr != null) try { fr.close(); } catch (IOException ignore) {}
        }
        return p;
    }
}
