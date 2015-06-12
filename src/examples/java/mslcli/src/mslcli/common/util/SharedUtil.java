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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.PresharedKeyStore.KeySet;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.SimpleMslStore;

import mslcli.common.entityauth.SimplePresharedKeyStore;
import mslcli.common.entityauth.SimpleRsaStore;
import mslcli.common.userauth.SimpleEmailPasswordStore;

import static mslcli.common.Constants.*;

public final class SharedUtil {
    private SharedUtil() {}

    // initialize pre-shared key store
    public static PresharedKeyStore getPresharedKeyStore() {
        final SecretKey encryptionKey = new SecretKeySpec(ENCR_PSK, JcaAlgorithm.AES);
        final SecretKey hmacKey       = new SecretKeySpec(HMAC_PSK, JcaAlgorithm.HMAC_SHA256);
        final SecretKey wrapKey       = new SecretKeySpec(WRAP_PSK, JcaAlgorithm.AESKW);
        final KeySet keySet = new KeySet(encryptionKey, hmacKey, wrapKey);
        final Map<String,KeySet> keySets = new HashMap<String,KeySet>();
        keySets.put(CLIENT_ID, keySet);
        return new SimplePresharedKeyStore(keySets);
    }

    public static EmailPasswordStore getEmailPasswordStore() {
        final Map<String,String> emailPasswords = new HashMap<String,String>();
        emailPasswords.put(CLIENT_USER_EMAIL, CLIENT_USER_PASSWORD);
        return new SimpleEmailPasswordStore(emailPasswords);
    }

    public static MslStore getClientMslStore() {
        return new SimpleMslStore();
    }

    public static MslStore getServerMslStore() {
        return new SimpleMslStore();
    }

    public static byte[] readIntoArray(final InputStream in) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            out.write(b);
        }
        return out.toByteArray();
    }

    public static byte[] hexStringToByteArray(final String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String readInput() throws IOException {
        final BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Message> ");
        return br.readLine();
    }

    public static Throwable getCause(Throwable t) {
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }

    public static RsaStore getRsaStore() {
        // Create the RSA key store.
        final RsaStore rsaStore;
        try {
            final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

            final byte[] privKeyEncoded = DatatypeConverter.parseBase64Binary(RSA_PRIVKEY_B64);
            final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyEncoded);
            final PrivateKey privKey = rsaKeyFactory.generatePrivate(privKeySpec);

            final byte[] pubKeyEncoded = DatatypeConverter.parseBase64Binary(RSA_PUBKEY_B64);
            final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyEncoded);
            final PublicKey pubKey = rsaKeyFactory.generatePublic(pubKeySpec);

            rsaStore = new SimpleRsaStore(SERVER_RSA_KEY_ID, pubKey, privKey);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not found.", e);
        } catch (final InvalidKeySpecException e) {
            throw new RuntimeException("Invalid RSA private key.", e);
        }
        return rsaStore;
    }
}
