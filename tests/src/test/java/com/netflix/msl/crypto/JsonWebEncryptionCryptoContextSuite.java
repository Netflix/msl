/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext.CekCryptoContext;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext.Encryption;
import com.netflix.msl.crypto.JsonWebEncryptionCryptoContext.Format;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * JSON Web Encryption crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({JsonWebEncryptionCryptoContextSuite.JWE.class,
               JsonWebEncryptionCryptoContextSuite.RsaOaepCompactSerialization.class,
               JsonWebEncryptionCryptoContextSuite.RsaOaepJsonSerialization.class,
               JsonWebEncryptionCryptoContextSuite.AesKwCompactSerialization.class,
               JsonWebEncryptionCryptoContextSuite.AesKwJsonSerialization.class})
public class JsonWebEncryptionCryptoContextSuite {
    /** Encoding charset. */
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    /** JSON key recipients. */
    private static final String KEY_RECIPIENTS = "recipients";
    /** JSON key header. */
    private static final String KEY_HEADER = "header";
    /** JSON key encrypted key. */
    private static final String KEY_ENCRYPTED_KEY = "encrypted_key";
    /** JSON key integrity value. */
    private static final String KEY_INTEGRITY_VALUE = "integrity_value";
    /** JSON key initialization vector. */
    private static final String KEY_INITIALIZATION_VECTOR = "initialization_vector";
    /** JSON key ciphertext. */
    private static final String KEY_CIPHERTEXT = "ciphertext";
    
    /** JSON key wrap algorithm. */
    private static final String KEY_ALGORITHM = "alg";
    /** JSON key encryption algorithm. */
    private static final String KEY_ENCRYPTION = "enc";
    
    /** Compact serialization header part index. */
    private static final int HEADER_INDEX = 0;
    /** Compact serialization encrypted content encryption key part index. */
    private static final int ECEK_INDEX = 1;
    /** Compact serialization initialization vector part index. */
    private static final int IV_INDEX = 2;
    /** Compact serialization ciphertext part index. */
    private static final int CIPHERTEXT_INDEX = 3;
    /** Compact serialization authentication tag part index. */
    private static final int AUTHENTICATION_TAG_INDEX = 4;
    
    /**
     * Replace one part of the provided compact serialization with a specified
     * value.
     * 
     * @param serialization compact serialization.
     * @param part zero-based part number to replace.
     * @param value Base64-encoded replacement value.
     * @return the modified compact serialization.
     */
    private static byte[] replace(final byte[] serialization, final int part, final String value) {
        final String s = new String(serialization, UTF_8);
        String[] parts = s.split("\\.");
        parts[part] = value;
        final StringBuilder b = new StringBuilder(parts[0]);
        for (int i = 1; i < parts.length; ++i)
            b.append("." + parts[i]);
        return b.toString().getBytes(UTF_8);
    }
    
    /**
     * Return the requested value of the provided JSON serialization.
     * 
     * @param serialization JSON serialization.
     * @param key JSON key.
     * @return the requested Base64-encoded value.
     * @throws JSONException if there is an error parsing the serialization.
     */
    private static String get(final byte[] serialization, final String key) throws JSONException {
        final JSONObject serializationJo = new JSONObject(new String(serialization, UTF_8));
        final JSONArray recipients = serializationJo.getJSONArray(KEY_RECIPIENTS);
        final JSONObject recipient = recipients.getJSONObject(0);
        if (KEY_HEADER.equals(key) ||
            KEY_ENCRYPTED_KEY.equals(key) ||
            KEY_INTEGRITY_VALUE.equals(key))
        {
            return recipient.getString(key);
        }
        if (KEY_INITIALIZATION_VECTOR.equals(key) ||
            KEY_CIPHERTEXT.equals(key))
        {
            return serializationJo.getString(key);
        }
        throw new IllegalArgumentException("Unknown JSON key: " + key);
    }
    
    /**
     * Replace one part of the provided JSON serialization with a specified
     * value.
     * 
     * @param serialization JSON serialization.
     * @param key JSON key.
     * @param value replacement value.
     * @return the modified JSON serialization.
     * @throws JSONException if there is an error modifying the JSON
     *         serialization.
     */
    private static byte[] replace(final byte[] serialization, final String key, final Object value) throws JSONException {
        final JSONObject serializationJo = new JSONObject(new String(serialization, UTF_8));
        final JSONArray recipients = serializationJo.getJSONArray(KEY_RECIPIENTS);
        final JSONObject recipient = recipients.getJSONObject(0);
        if (KEY_RECIPIENTS.equals(key)) {
            // Return immediately after replacing because this creates a
            // malformed serialization.
            serializationJo.put(KEY_RECIPIENTS, value);
            return serializationJo.toString().getBytes(UTF_8);
        }
        if (KEY_HEADER.equals(key) ||
            KEY_ENCRYPTED_KEY.equals(key) ||
            KEY_INTEGRITY_VALUE.equals(key))
        {
            recipient.put(key, value);
        } else if (KEY_INITIALIZATION_VECTOR.equals(key) ||
                   KEY_CIPHERTEXT.equals(key))
        {
            serializationJo.put(key, value);
        } else {
            throw new IllegalArgumentException("Unknown JSON key: " + key);
        }
        recipients.put(0, recipient);
        serializationJo.put(KEY_RECIPIENTS, recipients);
        return serializationJo.toString().getBytes(UTF_8);
    }
    
    /**
     * Remove one part of the provided JSON serialization.
     * 
     * @param serialization JSON serialization.
     * @param key JSON key.
     * @return the modified JSON serialization.
     * @throws JSONException if there is an error modifying the JSON
     *         serialization.
     */
    private static byte[] remove(final byte[] serialization, final String key) throws JSONException {
        final JSONObject serializationJo = new JSONObject(new String(serialization, UTF_8));
        final JSONArray recipients = serializationJo.getJSONArray(KEY_RECIPIENTS);
        final JSONObject recipient = recipients.getJSONObject(0);
        if (KEY_RECIPIENTS.equals(key)) {
            // Return immediately after removing because this creates a
            // malformed serialization.
            serializationJo.remove(KEY_RECIPIENTS);
            return serializationJo.toString().getBytes(UTF_8);
        }
        if (KEY_HEADER.equals(key) ||
            KEY_ENCRYPTED_KEY.equals(key) ||
            KEY_INTEGRITY_VALUE.equals(key))
        {
            recipient.remove(key);
        } else if (KEY_INITIALIZATION_VECTOR.equals(key) ||
                   KEY_CIPHERTEXT.equals(key))
        {
            serializationJo.remove(key);
        } else {
            throw new IllegalArgumentException("Unknown JSON key: " + key);
        }
        recipients.put(0, recipient);
        serializationJo.put(KEY_RECIPIENTS, recipients);
        return serializationJo.toString().getBytes(UTF_8);
    }
    
    /** MSL context. */
    private static MslContext ctx;
    /** Random. */
    private static Random random;
    /** Random data. */
    private static byte[] data;
    /** RSA-OAEP content encryption key crypto context. */
    private static CekCryptoContext rsaCryptoContext;
    /** AES key wrap content encryption key crypto context. */
    private static CekCryptoContext aesCryptoContext;
    
    @BeforeClass
    public static synchronized void setup() throws NoSuchAlgorithmException, MslEncodingException, MslCryptoException {
        if (random == null) {
            random = new Random();
            
            data = new byte[1024];
            random.nextBytes(data);
            
            ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
    
            final KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("RSA");
            keypairGenerator.initialize(512);
            final KeyPair keypair = keypairGenerator.generateKeyPair();
            final PrivateKey privateKey = keypair.getPrivate();
            final PublicKey publicKey = keypair.getPublic();
            rsaCryptoContext = new JsonWebEncryptionCryptoContext.RsaOaepCryptoContext(privateKey, publicKey);
            
            final byte[] keydata = new byte[16];
            random.nextBytes(keydata);
            final SecretKey wrappingKey = new SecretKeySpec(keydata, JcaAlgorithm.AESKW);
            aesCryptoContext = new JsonWebEncryptionCryptoContext.AesKwCryptoContext(wrappingKey);
        }
    }
    
    @AfterClass
    public static synchronized void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }

    /** RSA-OAEP compact serialization unit tests. */
    public static class RsaOaepCompactSerialization {
        /** RFC RSA-OAEP keypair modulus. */
        private static final byte[] RFC_MODULUS = {
            (byte)161, (byte)168, (byte)84, (byte)34, (byte)133, (byte)176, (byte)208, (byte)173,
            (byte)46, (byte)176, (byte)163, (byte)110, (byte)57, (byte)30, (byte)135, (byte)227,
            (byte)9, (byte)31, (byte)226, (byte)128, (byte)84, (byte)92, (byte)116, (byte)241,
            (byte)70, (byte)248, (byte)27, (byte)227, (byte)193, (byte)62, (byte)5, (byte)91,
            (byte)241, (byte)145, (byte)224, (byte)205, (byte)141, (byte)176, (byte)184, (byte)133,
            (byte)239, (byte)43, (byte)81, (byte)103, (byte)9, (byte)161, (byte)153, (byte)157,
            (byte)179, (byte)104, (byte)123, (byte)51, (byte)189, (byte)34, (byte)152, (byte)69,
            (byte)97, (byte)69, (byte)78, (byte)93, (byte)140, (byte)131, (byte)87, (byte)182,
            (byte)169, (byte)101, (byte)92, (byte)142, (byte)3, (byte)22, (byte)167, (byte)8,
            (byte)212, (byte)56, (byte)35, (byte)79, (byte)210, (byte)222, (byte)192, (byte)208,
            (byte)252, (byte)49, (byte)109, (byte)138, (byte)173, (byte)253, (byte)210, (byte)166,
            (byte)201, (byte)63, (byte)102, (byte)74, (byte)5, (byte)158, (byte)41, (byte)90,
            (byte)144, (byte)108, (byte)160, (byte)79, (byte)10, (byte)89, (byte)222, (byte)231,
            (byte)172, (byte)31, (byte)227, (byte)197, (byte)0, (byte)19, (byte)72, (byte)81,
            (byte)138, (byte)78, (byte)136, (byte)221, (byte)121, (byte)118, (byte)196, (byte)17,
            (byte)146, (byte)10, (byte)244, (byte)188, (byte)72, (byte)113, (byte)55, (byte)221,
            (byte)162, (byte)217, (byte)171, (byte)27, (byte)57, (byte)233, (byte)210, (byte)101,
            (byte)236, (byte)154, (byte)199, (byte)56, (byte)138, (byte)239, (byte)101, (byte)48,
            (byte)198, (byte)186, (byte)202, (byte)160, (byte)76, (byte)111, (byte)234, (byte)71,
            (byte)57, (byte)183, (byte)5, (byte)211, (byte)171, (byte)136, (byte)126, (byte)64,
            (byte)40, (byte)75, (byte)58, (byte)89, (byte)244, (byte)254, (byte)107, (byte)84,
            (byte)103, (byte)7, (byte)236, (byte)69, (byte)163, (byte)18, (byte)180, (byte)251,
            (byte)58, (byte)153, (byte)46, (byte)151, (byte)174, (byte)12, (byte)103, (byte)197,
            (byte)181, (byte)161, (byte)162, (byte)55, (byte)250, (byte)235, (byte)123, (byte)110,
            (byte)17, (byte)11, (byte)158, (byte)24, (byte)47, (byte)133, (byte)8, (byte)199,
            (byte)235, (byte)107, (byte)126, (byte)130, (byte)246, (byte)73, (byte)195, (byte)20,
            (byte)108, (byte)202, (byte)176, (byte)214, (byte)187, (byte)45, (byte)146, (byte)182,
            (byte)118, (byte)54, (byte)32, (byte)200, (byte)61, (byte)201, (byte)71, (byte)243,
            (byte)1, (byte)255, (byte)131, (byte)84, (byte)37, (byte)111, (byte)211, (byte)168,
            (byte)228, (byte)45, (byte)192, (byte)118, (byte)27, (byte)197, (byte)235, (byte)232,
            (byte)36, (byte)10, (byte)230, (byte)248, (byte)190, (byte)82, (byte)182, (byte)140,
            (byte)35, (byte)204, (byte)108, (byte)190, (byte)253, (byte)186, (byte)186, (byte)27 };
        /** RFC RSA-OAEP keypair exponent. */
        private static final byte[] RFC_PUBLIC_EXPONENT = { (byte)1, (byte)0, (byte)1 };
        /** RFC RSA-OAEP private exponent. */
        private static final byte[] RFC_PRIVATE_EXPONENT = {
            (byte)144, (byte)183, (byte)109, (byte)34, (byte)62, (byte)134, (byte)108, (byte)57,
            (byte)44, (byte)252, (byte)10, (byte)66, (byte)73, (byte)54, (byte)16, (byte)181,
            (byte)233, (byte)92, (byte)54, (byte)219, (byte)101, (byte)42, (byte)35, (byte)178,
            (byte)63, (byte)51, (byte)43, (byte)92, (byte)119, (byte)136, (byte)251, (byte)41,
            (byte)53, (byte)23, (byte)191, (byte)164, (byte)164, (byte)60, (byte)88, (byte)227,
            (byte)229, (byte)152, (byte)228, (byte)213, (byte)149, (byte)228, (byte)169, (byte)237,
            (byte)104, (byte)71, (byte)151, (byte)75, (byte)88, (byte)252, (byte)216, (byte)77,
            (byte)251, (byte)231, (byte)28, (byte)97, (byte)88, (byte)193, (byte)215, (byte)202,
            (byte)248, (byte)216, (byte)121, (byte)195, (byte)211, (byte)245, (byte)250, (byte)112,
            (byte)71, (byte)243, (byte)61, (byte)129, (byte)95, (byte)39, (byte)244, (byte)122,
            (byte)225, (byte)217, (byte)169, (byte)211, (byte)165, (byte)48, (byte)253, (byte)220,
            (byte)59, (byte)122, (byte)219, (byte)42, (byte)86, (byte)223, (byte)32, (byte)236,
            (byte)39, (byte)48, (byte)103, (byte)78, (byte)122, (byte)216, (byte)187, (byte)88,
            (byte)176, (byte)89, (byte)24, (byte)1, (byte)42, (byte)177, (byte)24, (byte)99,
            (byte)142, (byte)170, (byte)1, (byte)146, (byte)43, (byte)3, (byte)108, (byte)64,
            (byte)194, (byte)121, (byte)182, (byte)95, (byte)187, (byte)134, (byte)71, (byte)88,
            (byte)96, (byte)134, (byte)74, (byte)131, (byte)167, (byte)69, (byte)106, (byte)143,
            (byte)121, (byte)27, (byte)72, (byte)44, (byte)245, (byte)95, (byte)39, (byte)194,
            (byte)179, (byte)175, (byte)203, (byte)122, (byte)16, (byte)112, (byte)183, (byte)17,
            (byte)200, (byte)202, (byte)31, (byte)17, (byte)138, (byte)156, (byte)184, (byte)210,
            (byte)157, (byte)184, (byte)154, (byte)131, (byte)128, (byte)110, (byte)12, (byte)85,
            (byte)195, (byte)122, (byte)241, (byte)79, (byte)251, (byte)229, (byte)183, (byte)117,
            (byte)21, (byte)123, (byte)133, (byte)142, (byte)220, (byte)153, (byte)9, (byte)59,
            (byte)57, (byte)105, (byte)81, (byte)255, (byte)138, (byte)77, (byte)82, (byte)54,
            (byte)62, (byte)216, (byte)38, (byte)249, (byte)208, (byte)17, (byte)197, (byte)49,
            (byte)45, (byte)19, (byte)232, (byte)157, (byte)251, (byte)131, (byte)137, (byte)175,
            (byte)72, (byte)126, (byte)43, (byte)229, (byte)69, (byte)179, (byte)117, (byte)82,
            (byte)157, (byte)213, (byte)83, (byte)35, (byte)57, (byte)210, (byte)197, (byte)252,
            (byte)171, (byte)143, (byte)194, (byte)11, (byte)47, (byte)163, (byte)6, (byte)253,
            (byte)75, (byte)252, (byte)96, (byte)11, (byte)187, (byte)84, (byte)130, (byte)210,
            (byte)7, (byte)121, (byte)78, (byte)91, (byte)79, (byte)57, (byte)251, (byte)138,
            (byte)132, (byte)220, (byte)60, (byte)224, (byte)173, (byte)56, (byte)224, (byte)201 };
        
        /** RFC RSA-OAEP wrapped compact serialization. */
        private static final byte[] RFC_SERIALIZATION =
            ("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ." +
            "M2XxpbORKezKSzzQL_95-GjiudRBTqn_omS8z9xgoRb7L0Jw5UsEbxmtyHn2T71m" +
            "rZLkjg4Mp8gbhYoltPkEOHvAopz25-vZ8C2e1cOaAo5WPcbSIuFcB4DjBOM3t0UA" +
            "O6JHkWLuAEYoe58lcxIQneyKdaYSLbV9cKqoUoFQpvKWYRHZbfszIyfsa18rmgTj" +
            "zrtLDTPnc09DSJE24aQ8w3i8RXEDthW9T1J6LsTH_vwHdwUgkI-tC2PNeGrnM-dN" +
            "SfzF3Y7-lwcGy0FsdXkPXytvDV7y4pZeeUiQ-0VdibIN2AjjfW60nfrPuOjepMFG" +
            "6BBBbR37pHcyzext9epOAQ." +
            "48V1_ALb6US04U3b." +
            "_e21tGGhac_peEFkLXr2dMPUZiUkrw." +
            "7V5ZDko0v_mf2PAc4JMiUg").getBytes(UTF_8);
        /** RFC RSA-OAEP plaintext. */
        private static final byte[] RFC_PLAINTEXT = 
            ("Live long and prosper.").getBytes(UTF_8);
        
        /*{
            (byte)76, (byte)105, (byte)118, (byte)101, (byte)32, (byte)108, (byte)111, (byte)110,
            (byte)103, (byte)32, (byte)97, (byte)110, (byte)100, (byte)32, (byte)112, (byte)114,
            (byte)111, (byte)115, (byte)112, (byte)101, (byte)114, (byte)46 };*/
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        /** JWE crypto context. */
        private static ICryptoContext cryptoContext;
        
        @BeforeClass
        public static void setup() throws NoSuchAlgorithmException, MslEncodingException, MslCryptoException {
            Security.addProvider(new BouncyCastleProvider());

            cryptoContext = new JsonWebEncryptionCryptoContext(ctx, rsaCryptoContext, Encryption.A128GCM, Format.JWE_CS);
        }
        
        @AfterClass
        public static void teardown() {
            cryptoContext = null;
        }
        
        @Test
        public void wrapUnwrap() throws MslCryptoException {
            final byte[] wrapped = cryptoContext.wrap(data);
            assertNotNull(wrapped);
            assertFalse(Arrays.equals(data, wrapped));
            final byte[] unwrapped = cryptoContext.unwrap(wrapped);
            assertArrayEquals(data, unwrapped);
        }
        
        @Test
        public void wrapUnwrapShort() throws MslCryptoException {
            final byte[] data = new byte[3];
            random.nextBytes(data);
            
            final byte[] wrapped = cryptoContext.wrap(data);
            assertNotNull(wrapped);
            assertFalse(Arrays.equals(data, wrapped));
            final byte[] unwrapped = cryptoContext.unwrap(wrapped);
            assertArrayEquals(data, unwrapped);
        }
        
        @Test
        public void wrapUnwrapRfc() throws InvalidKeySpecException, NoSuchAlgorithmException, MslCryptoException {
            final BigInteger modulus = new BigInteger(1, RFC_MODULUS);
            final BigInteger publicExponent = new BigInteger(1, RFC_PUBLIC_EXPONENT);
            final BigInteger privateExponent = new BigInteger(1, RFC_PRIVATE_EXPONENT);
            final KeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
            final KeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            final KeyFactory factory = KeyFactory.getInstance("RSA");
            final PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = factory.generatePublic(publicKeySpec);
            
            final CekCryptoContext cekCryptoContext = new JsonWebEncryptionCryptoContext.RsaOaepCryptoContext(privateKey, publicKey);
            final ICryptoContext cryptoContext = new JsonWebEncryptionCryptoContext(ctx, cekCryptoContext, Encryption.A256GCM, Format.JWE_CS);
            final byte[] plaintext = cryptoContext.unwrap(RFC_SERIALIZATION);
            assertNotNull(plaintext);
            assertArrayEquals(RFC_PLAINTEXT, plaintext);
        }
    
        @Test
        public void invalidSerialization() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = "x".getBytes(UTF_8);
            cryptoContext.unwrap(wrapped);
        }
    
        @Test
        public void shortSerialization() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String serialization = new String(wrapped, UTF_8);
            final String shortSerialization = serialization.substring(0, serialization.lastIndexOf('.'));
            final byte[] shortWrapped = shortSerialization.getBytes(UTF_8);
            
            cryptoContext.unwrap(shortWrapped);
        }
    
        @Test
        public void longSerialization() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] longWrapped = Arrays.copyOf(wrapped, 2 * wrapped.length);
            System.arraycopy(wrapped, 0, longWrapped, wrapped.length, wrapped.length);
    
            cryptoContext.unwrap(longWrapped);
        }
    
        @Test
        public void missingHeader() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidHeader() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingCek() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, ECEK_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidCek() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, ECEK_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingIv() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, IV_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidIv() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, IV_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingCiphertext() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, CIPHERTEXT_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidCiphertext() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, CIPHERTEXT_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingAuthenticationTag() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidAuthenticationTag() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_ALGORITHM_PARAMS);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
        
        @Test
        public void wrongAuthenticationTag() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] at = new byte[16];
            random.nextBytes(at);
            
            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, JsonUtils.b64urlEncode(at));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingAlgorithm() throws JSONException, MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String wrappedB64 = new String(wrapped, UTF_8);
            final String headerB64 = wrappedB64.substring(0, wrappedB64.indexOf('.'));
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            assertNotNull(header.remove(KEY_ALGORITHM));
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidAlgorithm() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String wrappedB64 = new String(wrapped, UTF_8);
            final String headerB64 = wrappedB64.substring(0, wrappedB64.indexOf('.'));
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            header.put(KEY_ALGORITHM, "x");
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingEncryption() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String wrappedB64 = new String(wrapped, UTF_8);
            final String headerB64 = wrappedB64.substring(0, wrappedB64.indexOf('.'));
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            assertNotNull(header.remove(KEY_ENCRYPTION));
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidEncryption() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String wrappedB64 = new String(wrapped, UTF_8);
            final String headerB64 = wrappedB64.substring(0, wrappedB64.indexOf('.'));
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            header.put(KEY_ENCRYPTION, "x");
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void badCek() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] ecek = new byte[137];
            random.nextBytes(ecek);
            final byte[] badWrapped = replace(wrapped, ECEK_INDEX, JsonUtils.b64urlEncode(ecek));
            
            cryptoContext.unwrap(badWrapped);
        }
    
        @Test
        public void badIv() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] iv = new byte[31];
            random.nextBytes(iv);
            final byte[] badWrapped = replace(wrapped, IV_INDEX, JsonUtils.b64urlEncode(iv));
            
            cryptoContext.unwrap(badWrapped);
        }
    
        @Test
        public void wrongCek() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            
            final byte[] cek = new byte[16];
            random.nextBytes(cek);
            final byte[] ecek = rsaCryptoContext.encrypt(cek);
            
            final byte[] wrongWrapped = replace(wrapped, ECEK_INDEX, JsonUtils.b64urlEncode(ecek));
            
            cryptoContext.unwrap(wrongWrapped);
        }
    
        @Test
        public void wrongIv() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] iv = new byte[16];
            random.nextBytes(iv);
            final byte[] wrongWrapped = replace(wrapped, IV_INDEX, JsonUtils.b64urlEncode(iv));
            
            cryptoContext.unwrap(wrongWrapped);
        }
    }
    
    /** RSA-OAEP JSON serialization unit tests. */
    public static class RsaOaepJsonSerialization {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        /** JWE crypto context. */
        private static ICryptoContext cryptoContext;
        
        @BeforeClass
        public static void setup() throws NoSuchAlgorithmException, MslEncodingException, MslCryptoException {
            Security.addProvider(new BouncyCastleProvider());

            cryptoContext = new JsonWebEncryptionCryptoContext(ctx, rsaCryptoContext, Encryption.A128GCM, Format.JWE_JS);
        }
        
        @AfterClass
        public static void teardown() {
            cryptoContext = null;
        }
        
        @Test
        public void wrapUnwrap() throws MslCryptoException {
            final byte[] wrapped = cryptoContext.wrap(data);
            assertNotNull(wrapped);
            assertFalse(Arrays.equals(data, wrapped));
            final byte[] unwrapped = cryptoContext.unwrap(wrapped);
            assertArrayEquals(data, unwrapped);
        }
        
        @Test
        public void wrapUnwrapShort() throws MslCryptoException {
            final byte[] data = new byte[3];
            random.nextBytes(data);
            
            final byte[] wrapped = cryptoContext.wrap(data);
            assertNotNull(wrapped);
            assertFalse(Arrays.equals(data, wrapped));
            final byte[] unwrapped = cryptoContext.unwrap(wrapped);
            assertArrayEquals(data, unwrapped);
        }
    
        @Test
        public void invalidSerialization() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = "x".getBytes(UTF_8);
            cryptoContext.unwrap(wrapped);
        }
        
        @Test
        public void missingRecipients() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_RECIPIENTS);
            
            cryptoContext.unwrap(missingWrapped);
        }
        
        @Test
        public void invalidRecipients() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_RECIPIENTS, "x");
            
            cryptoContext.unwrap(missingWrapped);
        }

        @Test
        public void missingRecipient() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_RECIPIENTS, new JSONArray());
            
            cryptoContext.unwrap(missingWrapped);
        }
        
        @Test
        public void invalidRecipient() throws JSONException, MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_RECIPIENTS, new JSONArray("['x']"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingHeader() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_HEADER);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidHeader() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingCek() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_ENCRYPTED_KEY);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidCek() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingIv() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_INITIALIZATION_VECTOR);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidIv() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingCiphertext() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_CIPHERTEXT);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidCiphertext() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_CIPHERTEXT, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingAuthenticationTag() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_INTEGRITY_VALUE);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidAuthenticationTag() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_ALGORITHM_PARAMS);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_INTEGRITY_VALUE, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
        
        @Test
        public void wrongAuthenticationTag() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] at = new byte[16];
            random.nextBytes(at);
            
            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_INTEGRITY_VALUE, JsonUtils.b64urlEncode(at));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingAlgorithm() throws JSONException, MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String headerB64 = get(wrapped, KEY_HEADER);
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            assertNotNull(header.remove(KEY_ALGORITHM));
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidAlgorithm() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String headerB64 = get(wrapped, KEY_HEADER);
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            header.put(KEY_ALGORITHM, "x");
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingEncryption() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String headerB64 = get(wrapped, KEY_HEADER);
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            assertNotNull(header.remove(KEY_ENCRYPTION));
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidEncryption() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String headerB64 = get(wrapped, KEY_HEADER);
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            header.put(KEY_ENCRYPTION, "x");
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void badCek() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] ecek = new byte[137];
            random.nextBytes(ecek);
            final byte[] badWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, JsonUtils.b64urlEncode(ecek));
            
            cryptoContext.unwrap(badWrapped);
        }
    
        @Test
        public void badIv() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] iv = new byte[31];
            random.nextBytes(iv);
            final byte[] badWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, JsonUtils.b64urlEncode(iv));
            
            cryptoContext.unwrap(badWrapped);
        }
    
        @Test
        public void wrongCek() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            
            final byte[] cek = new byte[16];
            random.nextBytes(cek);
            final byte[] ecek = rsaCryptoContext.encrypt(cek);
            
            final byte[] wrongWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, JsonUtils.b64urlEncode(ecek));
            
            cryptoContext.unwrap(wrongWrapped);
        }
    
        @Test
        public void wrongIv() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] iv = new byte[16];
            random.nextBytes(iv);
            final byte[] wrongWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, JsonUtils.b64urlEncode(iv));
            
            cryptoContext.unwrap(wrongWrapped);
        }
    }
    
    /** AES key wrap compact serialization unit tests. */
    public static class AesKwCompactSerialization {
        /** RFC AES key wrap symmetric key. */
        private static final byte[] RFC_KEY = {
            (byte)25, (byte)172, (byte)32, (byte)130, (byte)225, (byte)114, (byte)26, (byte)181,
            (byte)138, (byte)106, (byte)254, (byte)192, (byte)95, (byte)133, (byte)74, (byte)82 };
        
        /** RFC AES key wrap wrapped compact serialization. */
        private static final byte[] RFC_SERIALIZATION =
            ("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0." +
            "pP_7AUDIQcgixVGPK9PwJr-htXV3RCxQ." +
            "_dxQGaaYsqhhY0NZ." +
            "4wxZhLkQ-F2RVzWCX3M-aIpgbUd806VnymMVwQTiVOX-apDxJ1aUhKBoWOjkbVUH" +
            "VlCGaqYYXMfSvJm72kXj." +
            "miNQayWUUQZnBDzOq6VxQw").getBytes(UTF_8);
        /** RFC AES key wrap plaintext. */
        private static final byte[] RFC_PLAINTEXT = 
            ("The true sign of intelligence is not knowledge but imagination.").getBytes(UTF_8);
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();

        /** JWE crypto context. */
        private static ICryptoContext cryptoContext;
        
        @BeforeClass
        public static void setup() throws NoSuchAlgorithmException, MslEncodingException, MslCryptoException {
            Security.addProvider(new BouncyCastleProvider());

            cryptoContext = new JsonWebEncryptionCryptoContext(ctx, aesCryptoContext, Encryption.A256GCM, Format.JWE_CS);
        }
        
        @AfterClass
        public static void teardown() {
            cryptoContext = null;
        }
        
        @Test
        public void wrapUnwrap() throws MslCryptoException {
            final byte[] wrapped = cryptoContext.wrap(data);
            assertNotNull(wrapped);
            assertFalse(Arrays.equals(data, wrapped));
            final byte[] unwrapped = cryptoContext.unwrap(wrapped);
            assertArrayEquals(data, unwrapped);
        }
        
        @Test
        public void wrapUnwrapShort() throws MslCryptoException {
            final byte[] data = new byte[3];
            random.nextBytes(data);
            
            final byte[] wrapped = cryptoContext.wrap(data);
            assertNotNull(wrapped);
            assertFalse(Arrays.equals(data, wrapped));
            final byte[] unwrapped = cryptoContext.unwrap(wrapped);
            assertArrayEquals(data, unwrapped);
        }
        
        @Test
        public void wrapUnwrapRfc() throws InvalidKeySpecException, NoSuchAlgorithmException, MslCryptoException {
            final SecretKey key = new SecretKeySpec(RFC_KEY, JcaAlgorithm.AESKW);
            final CekCryptoContext cekCryptoContext = new JsonWebEncryptionCryptoContext.AesKwCryptoContext(key);
            final ICryptoContext cryptoContext = new JsonWebEncryptionCryptoContext(ctx, cekCryptoContext, Encryption.A128GCM, Format.JWE_CS);
            
            final byte[] plaintext = cryptoContext.unwrap(RFC_SERIALIZATION);
            assertNotNull(plaintext);
            assertArrayEquals(RFC_PLAINTEXT, plaintext);
        }
    
        @Test
        public void invalidSerialization() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = "x".getBytes(UTF_8);
            cryptoContext.unwrap(wrapped);
        }
    
        @Test
        public void shortSerialization() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String serialization = new String(wrapped, UTF_8);
            final String shortSerialization = serialization.substring(0, serialization.lastIndexOf('.'));
            final byte[] shortWrapped = shortSerialization.getBytes(UTF_8);
            
            cryptoContext.unwrap(shortWrapped);
        }
    
        @Test
        public void longSerialization() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] longWrapped = Arrays.copyOf(wrapped, 2 * wrapped.length);
            System.arraycopy(wrapped, 0, longWrapped, wrapped.length, wrapped.length);
    
            cryptoContext.unwrap(longWrapped);
        }
    
        @Test
        public void missingHeader() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidHeader() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingCek() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, ECEK_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidCek() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_SYMMETRIC_KEY);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, ECEK_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingIv() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, IV_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidIv() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, IV_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingCiphertext() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, CIPHERTEXT_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidCiphertext() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, CIPHERTEXT_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingAuthenticationTag() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, "");
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidAuthenticationTag() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_ALGORITHM_PARAMS);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
        
        @Test
        public void wrongAuthenticationTag() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] at = new byte[16];
            random.nextBytes(at);
            
            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, JsonUtils.b64urlEncode(at));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingAlgorithm() throws JSONException, MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String wrappedB64 = new String(wrapped, UTF_8);
            final String headerB64 = wrappedB64.substring(0, wrappedB64.indexOf('.'));
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            assertNotNull(header.remove(KEY_ALGORITHM));
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidAlgorithm() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String wrappedB64 = new String(wrapped, UTF_8);
            final String headerB64 = wrappedB64.substring(0, wrappedB64.indexOf('.'));
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            header.put(KEY_ALGORITHM, "x");
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingEncryption() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String wrappedB64 = new String(wrapped, UTF_8);
            final String headerB64 = wrappedB64.substring(0, wrappedB64.indexOf('.'));
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            assertNotNull(header.remove(KEY_ENCRYPTION));
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidEncryption() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String wrappedB64 = new String(wrapped, UTF_8);
            final String headerB64 = wrappedB64.substring(0, wrappedB64.indexOf('.'));
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            header.put(KEY_ENCRYPTION, "x");
            final byte[] missingWrapped = replace(wrapped, HEADER_INDEX, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void badCek() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_SYMMETRIC_KEY);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] ecek = new byte[137];
            random.nextBytes(ecek);
            final byte[] badWrapped = replace(wrapped, ECEK_INDEX, JsonUtils.b64urlEncode(ecek));
            
            cryptoContext.unwrap(badWrapped);
        }
    
        @Test
        public void badIv() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] iv = new byte[31];
            random.nextBytes(iv);
            final byte[] badWrapped = replace(wrapped, IV_INDEX, JsonUtils.b64urlEncode(iv));
            
            cryptoContext.unwrap(badWrapped);
        }
    
        @Test
        public void wrongCek() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_SYMMETRIC_KEY);

            final byte[] wrapped = cryptoContext.wrap(data);
            
            final byte[] cek = new byte[16];
            random.nextBytes(cek);
            final byte[] ecek = aesCryptoContext.encrypt(cek);
            
            final byte[] wrongWrapped = replace(wrapped, ECEK_INDEX, JsonUtils.b64urlEncode(ecek));
            
            cryptoContext.unwrap(wrongWrapped);
        }
    
        @Test
        public void wrongIv() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] iv = new byte[16];
            random.nextBytes(iv);
            final byte[] wrongWrapped = replace(wrapped, IV_INDEX, JsonUtils.b64urlEncode(iv));
            
            cryptoContext.unwrap(wrongWrapped);
        }
    }
    
    /** */
    public static class AesKwJsonSerialization {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        /** JWE crypto context. */
        private static ICryptoContext cryptoContext;
        
        @BeforeClass
        public static void setup() throws NoSuchAlgorithmException, MslEncodingException, MslCryptoException {
            Security.addProvider(new BouncyCastleProvider());

            cryptoContext = new JsonWebEncryptionCryptoContext(ctx, aesCryptoContext, Encryption.A256GCM, Format.JWE_JS);
        }
        
        @AfterClass
        public static void teardown() {
            cryptoContext = null;
        }
        
        @Test
        public void wrapUnwrap() throws MslCryptoException {
            final byte[] wrapped = cryptoContext.wrap(data);
            assertNotNull(wrapped);
            assertFalse(Arrays.equals(data, wrapped));
            final byte[] unwrapped = cryptoContext.unwrap(wrapped);
            assertArrayEquals(data, unwrapped);
        }
        
        @Test
        public void wrapUnwrapShort() throws MslCryptoException {
            final byte[] data = new byte[3];
            random.nextBytes(data);
            
            final byte[] wrapped = cryptoContext.wrap(data);
            assertNotNull(wrapped);
            assertFalse(Arrays.equals(data, wrapped));
            final byte[] unwrapped = cryptoContext.unwrap(wrapped);
            assertArrayEquals(data, unwrapped);
        }
        
        @Test
        public void invalidSerialization() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = "x".getBytes(UTF_8);
            cryptoContext.unwrap(wrapped);
        }
        
        @Test
        public void missingRecipients() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_RECIPIENTS);
            
            cryptoContext.unwrap(missingWrapped);
        }
        
        @Test
        public void invalidRecipients() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_RECIPIENTS, "x");
            
            cryptoContext.unwrap(missingWrapped);
        }

        @Test
        public void missingRecipient() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_RECIPIENTS, new JSONArray());
            
            cryptoContext.unwrap(missingWrapped);
        }
        
        @Test
        public void invalidRecipient() throws JSONException, MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_RECIPIENTS, new JSONArray("['x']"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingHeader() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_HEADER);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidHeader() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingCek() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_ENCRYPTED_KEY);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidCek() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_SYMMETRIC_KEY);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingIv() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_INITIALIZATION_VECTOR);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidIv() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingCiphertext() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_CIPHERTEXT);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidCiphertext() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_CIPHERTEXT, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingAuthenticationTag() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = remove(wrapped, KEY_INTEGRITY_VALUE);
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidAuthenticationTag() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_ALGORITHM_PARAMS);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_INTEGRITY_VALUE, JsonUtils.b64urlEncode("x"));
            
            cryptoContext.unwrap(missingWrapped);
        }
        
        @Test
        public void wrongAuthenticationTag() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] at = new byte[16];
            random.nextBytes(at);
            
            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] missingWrapped = replace(wrapped, KEY_INTEGRITY_VALUE, JsonUtils.b64urlEncode(at));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingAlgorithm() throws JSONException, MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String headerB64 = get(wrapped, KEY_HEADER);
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            assertNotNull(header.remove(KEY_ALGORITHM));
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidAlgorithm() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String headerB64 = get(wrapped, KEY_HEADER);
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            header.put(KEY_ALGORITHM, "x");
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void missingEncryption() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String headerB64 = get(wrapped, KEY_HEADER);
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            assertNotNull(header.remove(KEY_ENCRYPTION));
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void invalidEncryption() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_PARSE_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final String headerB64 = get(wrapped, KEY_HEADER);
            final JSONObject header = new JSONObject(JsonUtils.b64urlDecodeToString(headerB64));
            header.put(KEY_ENCRYPTION, "x");
            final byte[] missingWrapped = replace(wrapped, KEY_HEADER, JsonUtils.b64urlEncode(header.toString()));
            
            cryptoContext.unwrap(missingWrapped);
        }
    
        @Test
        public void badCek() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_SYMMETRIC_KEY);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] ecek = new byte[137];
            random.nextBytes(ecek);
            final byte[] badWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, JsonUtils.b64urlEncode(ecek));
            
            cryptoContext.unwrap(badWrapped);
        }
    
        @Test
        public void badIv() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] iv = new byte[31];
            random.nextBytes(iv);
            final byte[] badWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, JsonUtils.b64urlEncode(iv));
            
            cryptoContext.unwrap(badWrapped);
        }
    
        @Test
        public void wrongCek() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_SYMMETRIC_KEY);

            final byte[] wrapped = cryptoContext.wrap(data);
            
            final byte[] cek = new byte[16];
            random.nextBytes(cek);
            final byte[] ecek = aesCryptoContext.encrypt(cek);
            
            final byte[] wrongWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, JsonUtils.b64urlEncode(ecek));
            
            cryptoContext.unwrap(wrongWrapped);
        }
    
        @Test
        public void wrongIv() throws MslCryptoException, JSONException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_ERROR);

            final byte[] wrapped = cryptoContext.wrap(data);
            final byte[] iv = new byte[16];
            random.nextBytes(iv);
            final byte[] wrongWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, JsonUtils.b64urlEncode(iv));
            
            cryptoContext.unwrap(wrongWrapped);
        }
    }

    /** JSON Web Encryption unit tests. */
    public static class JWE {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        /** JWE crypto context. */
        private static ICryptoContext cryptoContext;
        
        @BeforeClass
        public static void setup() throws NoSuchAlgorithmException, MslEncodingException, MslCryptoException {
            Security.addProvider(new BouncyCastleProvider());
            
            cryptoContext = new JsonWebEncryptionCryptoContext(ctx, rsaCryptoContext, Encryption.A128GCM, Format.JWE_CS);
        }
        
        @AfterClass
        public static void teardown() {
            cryptoContext = null;
        }
        
        @Test
        public void encrypt() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.ENCRYPT_NOT_SUPPORTED);

            cryptoContext.encrypt(new byte[0]);
        }

        @Test
        public void decrypt() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.DECRYPT_NOT_SUPPORTED);

            cryptoContext.decrypt(new byte[0]);
        }

        @Test
        public void sign() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.SIGN_NOT_SUPPORTED);

            cryptoContext.sign(new byte[0]);
        }

        @Test
        public void verify() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.VERIFY_NOT_SUPPORTED);

            cryptoContext.verify(new byte[0], new byte[0]);
        }

        @Test
        public void algorithmMismatch() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_ALGORITHM_MISMATCH);

            final ICryptoContext cryptoContextA = new JsonWebEncryptionCryptoContext(ctx, rsaCryptoContext, Encryption.A128GCM, Format.JWE_CS);
            final ICryptoContext cryptoContextB = new JsonWebEncryptionCryptoContext(ctx, aesCryptoContext, Encryption.A128GCM, Format.JWE_CS);

            final byte[] wrapped = cryptoContextA.wrap(data);
            cryptoContextB.unwrap(wrapped);
        }

        @Test
        public void encryptionMismatch() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.JWE_ALGORITHM_MISMATCH);

            final ICryptoContext cryptoContextA = new JsonWebEncryptionCryptoContext(ctx, rsaCryptoContext, Encryption.A128GCM, Format.JWE_CS);
            final ICryptoContext cryptoContextB = new JsonWebEncryptionCryptoContext(ctx, rsaCryptoContext, Encryption.A256GCM, Format.JWE_CS);

            final byte[] wrapped = cryptoContextA.wrap(data);
            cryptoContextB.unwrap(wrapped);
        }
    }
}
