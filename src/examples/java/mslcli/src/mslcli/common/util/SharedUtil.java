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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslStore;

/**
 * Collection of utilities
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class SharedUtil {

    private SharedUtil() {}

    /**
     * extract useful info from MasterToken
     *
     * @param masterToken master token, can be null
     * @return partial master token info as a string, or null if masterToken is null
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
     * extract useful info from UserIdToken
     *
     * @param userIdToken user ID token, can be null
     * @return partial user ID token info as a string, or null if userIdToken is null
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
     *
     * @param in input stream
     * @return byte array read from the input stream
     */
    public static byte[] readIntoArray(final InputStream in) throws IOException {
        if (in == null) {
            throw new IllegalArgumentException("NULL input Stream");
        }
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            out.write(b);
        }
        return out.toByteArray();
    }

    /**
     * IO Helper: read single line from STDIN
     *
     * @param prompt  reading prompt
     * @return user input converted to a string
     */
    public static String readInput(final String prompt) throws IOException {
        if (prompt == null) {
            throw new IllegalArgumentException("NULL prompt");
        }
        final BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print(prompt.trim() + "> ");
        return br.readLine();
    }

    /**
     * IO Helper: read parameter from STDIN
     *
     * @param prompt  reading prompt
     * @param def  default value accepted if no input is supplied
     * @return user input converted to a string
     */
    public static String readParameter(final String prompt, final String def) throws IOException {
        if (prompt == null) {
            throw new IllegalArgumentException("NULL prompt");
        }
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
     *
     * @param prompt  reading prompt
     * @param def  default value accepted if no input is supplied
     * @param yesStr input accepted as true
     * @param noStr input accepted as false
     * @return user input converted to a string
     */
    public static boolean readBoolean(final String name, final boolean def, final String yesStr, final String noStr) throws IOException {
        if (name == null) {
            throw new IllegalArgumentException("NULL name");
        }
        if (yesStr == null) {
            throw new IllegalArgumentException("NULL yesStr");
        }
        if (noStr == null) {
            throw new IllegalArgumentException("NULL noStr");
        }
        String value;
        do {
            value = readInput(String.format("%s[%s]", name, def ? "y" : "n"));
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
     *
     * @param hex byte array hex-encoded as a string
     * @return byte array
     */
    public static byte[] hexStringToByteArray(final String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("NULL hex string");
        }
        final int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("hex-encoded string size " + len + " - must be even");
        }
        final byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i  ), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16)     );
        }
        return data;
    }

    /**
     * split string of space-separated tokens into a List of tokens, treating quoted group of tokens as a single token
     *
     * @param str input string
     * @return array of tokens
     */

    public static String[] split(final String str) {
        final List<String> list = new ArrayList<String>();
        final Matcher m = Pattern.compile("([^\"]\\S*|\".+?\")\\s*").matcher(str);
        while (m.find()) {
            list.add(m.group(1).replace("\"", ""));
        }
        return list.toArray(new String[list.size()]);
    }

    /**
     * Helper: get innermost cause exception
     *
     * @param t Throwable
     * @return innermost cause Throwable
     */
    public static Throwable getRootCause(Throwable t) {
        if (t == null) {
            throw new IllegalArgumentException("NULL throwable");
        }
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }

    /**
     * load properties from file
     *
     * @param file file name
     * @return properties loaded from this file
     */
    public static Properties loadPropertiesFromFile(final String file) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException("NULL file");
        }
        final File f = new File(file);
        if (!f.isFile()) {
            throw new IllegalArgumentException(file + " not a file");
        }
        final Properties p = new Properties();
        FileReader fr = null;
        try {
            fr = new FileReader(f);
            p.load(fr);
        } finally {
            if (fr != null) try { fr.close(); } catch (IOException ignore) {}
        }
        return p;
    }

    /**
     * load file content into a byte array
     *
     * @param filePath file path
     * @return file content as byte array
     */
    public static byte[] readFromFile(final String file) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException("NULL file");
        }
        final File f = new File(file);
        if (!f.isFile()) {
            throw new IllegalArgumentException(file + " not a file");
        }
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
            return readIntoArray(fis);
        } finally {
            if (fis != null) try { fis.close(); } catch (IOException ignore) {}
        }
    }
 
    /**
     * save byte array into a file
     *
     * @param filePath file path
     * @return file content as byte array
     */
    public static void saveToFile(final String file, final byte[] data) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException("NULL file");
        }
        if (data == null) {
            throw new IllegalArgumentException("NULL data");
        }
        final File f = new File(file);
        if (f.exists()) {
            throw new IllegalArgumentException("cannot overwrite file " + file);
        }
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f);
            fos.write(data);
        } finally {
            if (fos != null) try { fos.close(); } catch (IOException ignore) {}
        }
    }
 
    /**
     * Serialize MslStore
     *
     * @param mslStore MslStore instance
     * @return serialized MslStore
     */
    public static byte[] marshalMslStore(final MslStore mslStore) throws IOException {
        throw new UnsupportedOperationException();
    }

    /**
     * Serialize MslStore
     *
     * @param mslStore MslStore instance
     * @return serialized MslStore
     */
    public static MslStore unmarshalMslStore(final byte[] mslStoreData) throws IOException {
        throw new UnsupportedOperationException();
    }
}
