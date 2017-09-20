/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.SortedSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.crypto.ClientMslCryptoContext;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.DefaultMslEncoderFactory;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.SimpleMslStore;

import mslcli.common.Triplet;

/**
 * <p>Collection of utilities.</p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class SharedUtil {

    /** to disable instantiation */
    private SharedUtil() {}

    /**
     * extract useful info from MasterToken for display
     *
     * @param masterToken master token, can be null
     * @return master token info as a string, or null if masterToken is null
     */
    public static final String getMasterTokenInfo(final MasterToken masterToken) {
        if (masterToken == null) {
            return null;
        }
        final long t_now = System.currentTimeMillis();
        final long t_rnw = (masterToken.getRenewalWindow().getTime() - t_now)/1000L;
        final long t_exp = (masterToken.getExpiration().getTime() - t_now)/1000L;
        return String.format("%s{ser_num %x, seq_num %x, renew %d sec, expire %d sec}",
            getSimpleClassName(masterToken),
            masterToken.getSerialNumber(),
            masterToken.getSequenceNumber(),
            t_rnw,
            t_exp);
    }

    /**
     * extract useful info from UserIdToken for display
     *
     * @param userIdToken user ID token, can be null
     * @return user ID token info as a string, or null if userIdToken is null
     */
    public static final String getUserIdTokenInfo(final UserIdToken userIdToken) {
        if (userIdToken == null) {
            return null;
        }
        final long t_now = System.currentTimeMillis();
        final long t_rnw = (userIdToken.getRenewalWindow().getTime() - t_now)/1000L;
        final long t_exp = (userIdToken.getExpiration().getTime() - t_now)/1000L;
        return String.format("%s{user %s, ser_num %x, mt_ser_num %x, renew %d sec, expire %d sec}",
            getSimpleClassName(userIdToken),
            (userIdToken.getUser() != null) ? userIdToken.getUser().getEncoded() : "opaque",
            userIdToken.getSerialNumber(),
            userIdToken.getMasterTokenSerialNumber(),
            t_rnw,
            t_exp);
    }

    /**
     * extract useful info from ServiceToken for display
     *
     * @param serviceToken service token, can be null
     * @return service token info as a string, or null if serviceToken is null
     */
    public static final String getServiceTokenInfo(final ServiceToken serviceToken) {
        if (serviceToken == null) {
            return null;
        }
        return String.format("%s{name %s, mt_ser_num %x, ut_ser_num %x, enc %b}",
            getSimpleClassName(serviceToken),
            serviceToken.getName(),
            serviceToken.getMasterTokenSerialNumber(),
            serviceToken.getUserIdTokenSerialNumber(),
            serviceToken.isEncrypted());
    }

    /**
     * IO Helper: read input stream into byte array
     *
     * @param in input stream
     * @return byte array read from the input stream
     * @throws IOException
     */
    public static byte[] readIntoArray(final InputStream in) throws IOException {
        assertNotNull(in, "Input Stream");
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
     * @throws IOException
     */
    public static String readInput(final String prompt) throws IOException {
        assertNotNull(prompt, "prompt");
        final BufferedReader br = new BufferedReader(new InputStreamReader(System.in, MslConstants.DEFAULT_CHARSET));
        System.out.print(prompt.trim() + "> ");
        return br.readLine();
    }

    /**
     * IO Helper: read parameter from STDIN
     *
     * @param prompt  reading prompt
     * @param def  default value accepted if no input is supplied
     * @return user input converted to a string
     * @throws IOException
     */
    public static String readParameter(final String prompt, final String def) throws IOException {
        assertNotNull(prompt, "prompt");
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
     * @param name reading prompt
     * @param def default value accepted if no input is supplied
     * @param yesStr input accepted as true
     * @param noStr input accepted as false
     * @return user input converted to a string
     * @throws IOException
     */
    public static boolean readBoolean(final String name, final boolean def, final String yesStr, final String noStr) throws IOException {
        assertNotNull(name, "name");
        assertNotNull(yesStr, "yesStr");
        assertNotNull(noStr, "noStr");
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
        assertNotNull(hex, "hex string");
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
        assertNotNull(t, "throwable");
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
     * @throws IOException
     */
    public static Properties loadPropertiesFromFile(final String file) throws IOException {
        assertNotNull(file, "file");
        final File f = new File(file);
        if (!f.isFile()) {
            throw new IllegalArgumentException(file + " not a file");
        }
        final Properties p = new Properties();
        FileInputStream fis = null;
        InputStreamReader isr = null;
        BufferedReader br = null;
        try {
            fis = new FileInputStream(f);
            isr = new InputStreamReader(fis, MslConstants.DEFAULT_CHARSET);
            br  = new BufferedReader(isr);
            p.load(br);
        } finally {
            if (fis != null) try { fis.close(); } catch (final IOException ignore) {}
            if (isr != null) try { isr.close(); } catch (final IOException ignore) {}
            if (br != null) try { br.close(); } catch (final IOException ignore) {}
        }
        return p;
    }

    /**
     * load file content into a byte array
     *
     * @param file file path
     * @return file content as byte array
     * @throws IOException
     */
    public static byte[] readFromFile(final String file) throws IOException {
        assertNotNull(file, "file");
        final File f = new File(file);
        if (!f.isFile()) {
            throw new IllegalArgumentException(file + " not a file");
        }
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
            return readIntoArray(fis);
        } finally {
            if (fis != null) try { fis.close(); } catch (final IOException ignore) {}
        }
    }

    /**
     * read special pre-shared key file that contains exactly 3 lines:
     * entityId
     * encryption key, base64-encoded
     * hmac key, base64-encoded
     *
     * @param file PSK file path
     * @return { entityId, encryption_key, hmac_key } triplet
     * @throws IOException
     */
    public static Triplet<String,String,String> readPskFile(final String file) throws IOException {
        final List<String> lines = readTextFile(file);
        if (lines.size() != 3)
            throw new IOException("Invalid PSK File " + file);
        final String entityId = lines.get(0);
        final String encKey   = lines.get(1);
        final String hmacKey  = lines.get(2);
        return new Triplet<String,String,String>(entityId.trim(), "b64:" + encKey.trim(), "b64:" + hmacKey.trim());
    }

    /**
     * read text file into a list of strings
     *
     * @param file file path
     * @return List of strings, each string representing a line of text
     * @throws IOException
     */
    public static List<String> readTextFile(final String file) throws IOException {
        FileInputStream fis = null;
        InputStreamReader isr = null;
        BufferedReader br = null;
        try {
            fis = new FileInputStream(file);
            isr = new InputStreamReader(fis, MslConstants.DEFAULT_CHARSET);
            br  = new BufferedReader(isr);
            String line;
            final List<String> lines = new ArrayList<String>();
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
            return lines;
        } finally {
            if (fis != null) try { fis.close(); } catch (final IOException ignore) {}
            if (isr != null) try { isr.close(); } catch (final IOException ignore) {}
            if (br != null) try { br.close(); } catch (final IOException ignore) {}
        }
    }
 
    /**
     * save byte array into a file
     *
     * @param file file path
     * @param data data to save into a file
     * @param overwrite true if the existing file can be overwritten
     * @throws IOException
     */
    public static void saveToFile(final String file, final byte[] data, final boolean overwrite) throws IOException {
        assertNotNull(file, "file");
        assertNotNull(data, "data");
        final File f = new File(file);
        if (f.exists() && !overwrite) {
            throw new IllegalArgumentException("cannot overwrite file " + file);
        }
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f);
            fos.write(data);
        } finally {
            if (fos != null) try { fos.close(); } catch (final IOException ignore) {}
        }
    }
 
    /**
     * Serialize MslStore
     *
     * @param mslStore SimpleMslStore instance
     * @return serialized MslStore
     * @throws IOException
     * @throws MslEncodingException
     * @throws MslEncoderException 
     */
    public static byte[] marshalMslStore(final SimpleMslStore mslStore) throws IOException, MslEncodingException, MslEncoderException {
        return MslStoreData.serialize(mslStore, new DummyMslContext());
    }

    /**
     * Serialize MslStore
     *
     * @param mslStoreData MslStore blob
     * @return serialized MslStore
     * @throws IOException
     * @throws MslEncodingException
     * @throws MslException
     * @throws MslEncoderException 
     */
    public static MslStore unmarshalMslStore(final byte[] mslStoreData) throws IOException, MslEncodingException, MslException, MslEncoderException {
        return MslStoreData.deserialize(mslStoreData, new DummyMslContext());
    }

    /**
     * this class is needed exclusively for deserialization of SimpleMslStore on the client side
     */
    private static final class DummyMslContext extends MslContext {
        @Override
        public long getTime() {
            return System.currentTimeMillis();
        }
        @Override
        public Random getRandom() {
            return new SecureRandom();
        }
        @Override
        public boolean isPeerToPeer() {
            throw new UnsupportedOperationException();
        }
        @Override
        public MessageCapabilities getMessageCapabilities() {
            throw new UnsupportedOperationException();
        }
        @Override
        public EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode) {
            throw new UnsupportedOperationException();
        }
        @Override
        public ICryptoContext getMslCryptoContext() throws MslCryptoException {
            return mslCryptoContext;
        }
        @Override
        public EntityAuthenticationFactory getEntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
            throw new UnsupportedOperationException();
        }
        @Override
        public UserAuthenticationFactory getUserAuthenticationFactory(final UserAuthenticationScheme scheme) {
            throw new UnsupportedOperationException();
        }
        @Override
        public TokenFactory getTokenFactory() {
            throw new UnsupportedOperationException();
        }
        @Override
        public KeyExchangeFactory getKeyExchangeFactory(final KeyExchangeScheme scheme) {
            throw new UnsupportedOperationException();
        }
        @Override
        public SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
            throw new UnsupportedOperationException();
        }
        @Override
        public EntityAuthenticationScheme getEntityAuthenticationScheme(final String name) {
            throw new UnsupportedOperationException();
        }
        @Override
        public KeyExchangeScheme getKeyExchangeScheme(final String name) {
            throw new UnsupportedOperationException();
        }
        @Override
        public UserAuthenticationScheme getUserAuthenticationScheme(final String name) {
            throw new UnsupportedOperationException();
        }
        @Override
        public MslStore getMslStore() {
            throw new UnsupportedOperationException();
        }
        @Override
        public MslEncoderFactory getMslEncoderFactory() {
            return encoderFactory;
        }
        /** MSL crypto context */
        private final ICryptoContext mslCryptoContext = new ClientMslCryptoContext();
        /** MSL encoder factory. */
        private final MslEncoderFactory encoderFactory = new DefaultMslEncoderFactory();
    }

    /** Base64 utilities */
    public static final class Base64Util {
        /**
         * @param encoded base64-encoded string
         * @return decoded array
         */
        public static byte[] decodeToByteArray(final String encoded) {
            return Base64.decode(encoded);
        }
        /**
         * @param encoded base64-encoded string
         * @return decoded String
         */
        public static String decode(final String encoded) {
            return new String(Base64.decode(encoded), MslConstants.DEFAULT_CHARSET);
        }
        /**
         * @param data byte array to be encoded
         * @return base64 encoding of the input byte array
         */
        public static String encode(final byte[] data) {
            return Base64.encode(data);
        }
        /**
         * @param data byte array to be encoded
         * @return base64 encoding of the input byte array
         */
        public static String encode(final String data) {
            return Base64.encode(data.getBytes(MslConstants.DEFAULT_CHARSET));
        }
    }

    /**
     * extract useful info from MslException for display
     *
     * @param e MslException object
     * @return useful info from MslException for display
     */
    public static String getMslExceptionInfo(final MslException e) {
        if (e == null) return null;
        final MslError mErr = e.getError();
        if (mErr != null) {
            final ResponseCode respCode = mErr.getResponseCode();
            if (respCode != null) {
                return String.format("MslException: error_code %d, error_msg %s", respCode.intValue(), mErr.getMessage());
            } else {
                return String.format("MslException: error_msg %s", mErr.getMessage());
            }
        } else {
            return String.format("MslException: %s", e.getMessage());
        }
    }

    /** Wrapping key derivation algorithm salt. */
    private static final byte[] SALT = {
        (byte)0x02, (byte)0x76, (byte)0x17, (byte)0x98, (byte)0x4f, (byte)0x62, (byte)0x27, (byte)0x53,
        (byte)0x9a, (byte)0x63, (byte)0x0b, (byte)0x89, (byte)0x7c, (byte)0x01, (byte)0x7d, (byte)0x69 };

    /** Wrapping key derivation algorithm info. */
    private static final byte[] INFO = {
        (byte)0x80, (byte)0x9f, (byte)0x82, (byte)0xa7, (byte)0xad, (byte)0xdf, (byte)0x54, (byte)0x8d,
        (byte)0x3e, (byte)0xa9, (byte)0xdd, (byte)0x06, (byte)0x7f, (byte)0xf9, (byte)0xbb, (byte)0x91, };

    /** Wrapping key length in bytes. */
    private static final int WRAPPING_KEY_LENGTH = 128 / Byte.SIZE;


    /**
     * Derives the pre-shared or model group keys AES-128 Key Wrap key from the
     * provided AES-128 encryption key and HMAC-SHA256 key.
     *
     * @param encryptionKey the encryption key.
     * @param hmacKey the HMAC key.
     * @return the wrapping key.
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */

    public static byte[] deriveWrappingKey(final byte[] encryptionKey, final byte[] hmacKey) throws InvalidKeyException, NoSuchAlgorithmException {

        // Concatenate the keys.
        final byte[] bits = Arrays.copyOf(encryptionKey, encryptionKey.length + hmacKey.length);

        System.arraycopy(hmacKey, 0, bits, encryptionKey.length, hmacKey.length);

        final Mac mac = Mac.getInstance("HmacSHA256");

        // HMAC-SHA256 the keys with the salt as the HMAC key.
        final SecretKey saltKey = new SecretKeySpec(SALT, JcaAlgorithm.AESKW);
        mac.init(saltKey);
        final byte[] intermediateBits = mac.doFinal(bits);

        // HMAC-SHA256 the info with the intermediate key as the HMAC key.
        final SecretKey intermediateKey = new SecretKeySpec(intermediateBits, JcaAlgorithm.AESKW);
        mac.init(intermediateKey);

        final byte[] finalBits = mac.doFinal(INFO);

        // Grab the first 128 bits.
        return Arrays.copyOf(finalBits, WRAPPING_KEY_LENGTH);
    }

    /**
     * Compare two objects, one or both of which can be null. Null objects are considered equal.
     *
     * @param x first object
     * @param y second object
     * @return true if both objects are null or equal to each other per Object.equals() method
     */

    public static boolean safeEqual(final Object x, final Object y) {
        return (x == null) ? (y == null) : x.equals(y); 
    }

    /**
     * @param obj object to stringize
     * @param args object's parameters to include into the result
     * @return simple toString() implementation for this object and parameters
     */
    public static String toString(final Object obj, final Object... args) {
        if (args.length == 0) {
            return String.format("%s[%x]", getSimpleClassName(obj), (obj != null) ? obj.hashCode() : "");
        } else {
            return String.format("%s[%x]%s", getSimpleClassName(obj), (obj != null) ? obj.hashCode() : "",
                Arrays.toString(args).replaceFirst("^\\[", "{").replaceFirst("\\]$", "}"));
        }
    }

    /**
     * <p>
     * Class.getSimpleName() is stripping off too much for nested classes, so using this method instead.
     * </p>
     *
     * @param o object
     * @return object's simple class name
     */
    public static String getSimpleClassName(final Object o) {
        if (o == null) return "null";

        final String cls = o.getClass().getName();
        final int lastDot = cls.lastIndexOf('.');
        return (lastDot >= 0 && lastDot < (cls.length() - 1)) ? cls.substring(lastDot + 1) : cls;
    }

    /**
     * @param path file path
     * @return true if the file path corresponds to the existing file
     */
    public static boolean isExistingFile(final String path) {
        if (path == null || path.trim().length() == 0)
            throw new IllegalArgumentException("NULL or empty file path");
        return new File(path).isFile();
    }

    /**
     * @param path file path
     * @return true if the file path corresponds to the non-existing file that can be created
     * @throws IOException
     */
    public static boolean isValidNewFile(final String path) {
        if (path == null || path.trim().length() == 0)
            throw new IllegalArgumentException("NULL or empty file path");
        final File f = new File(path);
        try {
            return !f.exists() && f.getCanonicalFile().getParentFile().isDirectory();
        } catch (final IOException e) {
            throw new IllegalArgumentException(String.format("Invalid file path %s: %s", path, e.getMessage()), e);
        }
    }

    /**
     * @param wrapdata wrap data as raw bytes
     * @return wrap data as a string (implemented using b64 encoding) or null if wrapdata input parameter is null
     */
    public static String getWrapDataInfo(final byte[] wrapdata) {
        return (wrapdata != null) ? Base64Util.encode(wrapdata) : null;
    }

    /**
     * @param param parameter
     * @param name parameter name
     */
    public static void assertNotNull(final Object param, final String name) {
        if (param == null) throw new IllegalArgumentException(String.format("NULL %s", (name != null) ? name : "parameter"));
    }
}
