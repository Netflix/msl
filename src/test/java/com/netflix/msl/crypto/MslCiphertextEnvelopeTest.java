/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.netflix.msl.MslConstants.CipherSpec;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.crypto.MslCiphertextEnvelope.Version;
import com.netflix.msl.test.ExpectedMslException;

/**
 * MSL encryption envelope unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({MslCiphertextEnvelopeTest.Version1.class,
               MslCiphertextEnvelopeTest.Version2.class})
public class MslCiphertextEnvelopeTest {
    /** JSON key version. */
    private final static String KEY_VERSION = "version";
    /** JSON key key ID. */
    private final static String KEY_KEY_ID = "keyid";
    /** JSON key cipherspec. */
    private final static String KEY_CIPHERSPEC = "cipherspec";
    /** JSON key initialization vector. */
    private final static String KEY_IV = "iv";
    /** JSON key ciphertext. */
    private final static String KEY_CIPHERTEXT = "ciphertext";
    /** JSON key SHA-256. */
    private final static String KEY_SHA256 = "sha256";

    /** Key ID. */
    private final static String KEY_ID = "keyid";
    
    private static final byte[] IV = new byte[16];
    private static final byte[] CIPHERTEXT = new byte[32];
    
    @BeforeClass
    public static void setup() {
        final Random random = new Random();
        random.nextBytes(IV);
        random.nextBytes(CIPHERTEXT);
    }

    public static class Version1 {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctors() throws MslCryptoException, MslEncodingException, JSONException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);
            assertEquals(KEY_ID, envelope.getKeyId());
            assertNull(envelope.getCipherSpec());
            assertArrayEquals(IV, envelope.getIv());
            assertArrayEquals(CIPHERTEXT, envelope.getCiphertext());
            final String json = envelope.toJSONString();
            assertNotNull(json);
            
            final JSONObject jo = new JSONObject(json);
            final MslCiphertextEnvelope joEnvelope = new MslCiphertextEnvelope(jo);
            assertEquals(envelope.getKeyId(), joEnvelope.getKeyId());
            assertEquals(envelope.getCipherSpec(), joEnvelope.getCipherSpec());
            assertArrayEquals(envelope.getIv(), joEnvelope.getIv());
            assertArrayEquals(envelope.getCiphertext(), joEnvelope.getCiphertext());
            final String joJson = joEnvelope.toJSONString();
            assertEquals(json, joJson);
        }

        @Test
        public void ctorsNullIv() throws JSONException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, null, CIPHERTEXT);
            assertEquals(KEY_ID, envelope.getKeyId());
            assertNull(envelope.getCipherSpec());
            assertNull(envelope.getIv());
            assertArrayEquals(CIPHERTEXT, envelope.getCiphertext());
            final String json = envelope.toJSONString();
            assertNotNull(json);
            
            final JSONObject jo = new JSONObject(json);
            final MslCiphertextEnvelope joEnvelope = new MslCiphertextEnvelope(jo);
            assertEquals(envelope.getKeyId(), joEnvelope.getKeyId());
            assertEquals(envelope.getCipherSpec(), joEnvelope.getCipherSpec());
            assertArrayEquals(envelope.getIv(), joEnvelope.getIv());
            assertArrayEquals(envelope.getCiphertext(), joEnvelope.getCiphertext());
            final String joJson = joEnvelope.toJSONString();
            assertEquals(json, joJson);
        }

        @Test
        public void json() throws JSONException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);
            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            
            assertEquals(KEY_ID, jo.getString(KEY_KEY_ID));
            assertFalse(jo.has(KEY_CIPHERSPEC));
            assertArrayEquals(IV, DatatypeConverter.parseBase64Binary(jo.getString(KEY_IV)));
            assertArrayEquals(CIPHERTEXT, DatatypeConverter.parseBase64Binary(jo.getString(KEY_CIPHERTEXT)));
        }

        @Test
        public void jsonNullIv() throws MslCryptoException, MslEncodingException, JSONException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, null, CIPHERTEXT);
            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            
            assertEquals(KEY_ID, jo.getString(KEY_KEY_ID));
            assertFalse(jo.has(KEY_CIPHERSPEC));
            assertFalse(jo.has(KEY_IV));
            assertArrayEquals(CIPHERTEXT, DatatypeConverter.parseBase64Binary(jo.getString(KEY_CIPHERTEXT)));
        }
        
        @Test
        public void missingKeyId() throws JSONException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            jo.remove(KEY_KEY_ID);
            
            new MslCiphertextEnvelope(jo);
        }
        
        @Test
        public void missingCiphertext() throws JSONException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            jo.remove(KEY_CIPHERTEXT);
            
            new MslCiphertextEnvelope(jo);
        }
        
        @Test
        public void missingSha256() throws JSONException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            jo.remove(KEY_SHA256);
            
            new MslCiphertextEnvelope(jo);
        }

        @Test
        public void incorrectSha256() throws JSONException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            final byte[] hash = DatatypeConverter.parseBase64Binary(jo.getString(KEY_SHA256));
            assertNotNull(hash);
            hash[0] += 1;
            jo.put(KEY_SHA256, DatatypeConverter.printBase64Binary(hash));

            final MslCiphertextEnvelope joEnvelope = new MslCiphertextEnvelope(jo);
            assertEquals(KEY_ID, joEnvelope.getKeyId());
            assertNull(joEnvelope.getCipherSpec());
            assertArrayEquals(IV, joEnvelope.getIv());
            assertArrayEquals(CIPHERTEXT, joEnvelope.getCiphertext());
        }
    }
    
    @RunWith(Parameterized.class)
    public static class Version2 {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Parameters
        public static Collection<Object[]> data() {
            final List<Object[]> params = new ArrayList<Object[]>();
            for (final CipherSpec spec : CipherSpec.values())
                params.add(new Object[] { spec });
            return params;
        }
        
        /** Cipher specification. */
        private final CipherSpec cipherSpec;
        
        /**
         * Create a new Version 2 test set with the provided cipher
         * specification.
         * 
         * @param cipherSpec the cipher specification.
         */
        public Version2(final CipherSpec cipherSpec) {
            this.cipherSpec = cipherSpec;
        }
        
        @Test
        public void ctors() throws MslCryptoException, MslEncodingException, JSONException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);
            assertNull(envelope.getKeyId());
            assertEquals(cipherSpec, envelope.getCipherSpec());
            assertArrayEquals(IV, envelope.getIv());
            assertArrayEquals(CIPHERTEXT, envelope.getCiphertext());
            final String json = envelope.toJSONString();
            assertNotNull(json);
            
            final JSONObject jo = new JSONObject(json);
            final MslCiphertextEnvelope joEnvelope = new MslCiphertextEnvelope(jo);
            assertEquals(envelope.getKeyId(), joEnvelope.getKeyId());
            assertEquals(envelope.getCipherSpec(), joEnvelope.getCipherSpec());
            assertArrayEquals(envelope.getIv(), joEnvelope.getIv());
            assertArrayEquals(envelope.getCiphertext(), joEnvelope.getCiphertext());
            final String joJson = joEnvelope.toJSONString();
            assertEquals(json, joJson);
        }

        @Test
        public void ctorsNullIv() throws JSONException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, null, CIPHERTEXT);
            assertNull(envelope.getKeyId());
            assertEquals(cipherSpec, envelope.getCipherSpec());
            assertNull(envelope.getIv());
            assertArrayEquals(CIPHERTEXT, envelope.getCiphertext());
            final String json = envelope.toJSONString();
            assertNotNull(json);
            
            final JSONObject jo = new JSONObject(json);
            final MslCiphertextEnvelope joEnvelope = new MslCiphertextEnvelope(jo);
            assertEquals(envelope.getKeyId(), joEnvelope.getKeyId());
            assertEquals(envelope.getCipherSpec(), joEnvelope.getCipherSpec());
            assertArrayEquals(envelope.getIv(), joEnvelope.getIv());
            assertArrayEquals(envelope.getCiphertext(), joEnvelope.getCiphertext());
            final String joJson = joEnvelope.toJSONString();
            assertEquals(json, joJson);
        }

        @Test
        public void json() throws JSONException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);
            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);

            assertEquals(Version.V2.intValue(), jo.getInt(KEY_VERSION));
            assertFalse(jo.has(KEY_KEY_ID));
            assertEquals(cipherSpec.toString(), jo.getString(KEY_CIPHERSPEC));
            assertArrayEquals(IV, DatatypeConverter.parseBase64Binary(jo.getString(KEY_IV)));
            assertArrayEquals(CIPHERTEXT, DatatypeConverter.parseBase64Binary(jo.getString(KEY_CIPHERTEXT)));
        }

        @Test
        public void jsonNullIv() throws MslCryptoException, MslEncodingException, JSONException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, null, CIPHERTEXT);
            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);

            assertEquals(Version.V2.intValue(), jo.getInt(KEY_VERSION));
            assertFalse(jo.has(KEY_KEY_ID));
            assertEquals(cipherSpec.toString(), jo.getString(KEY_CIPHERSPEC));
            assertFalse(jo.has(KEY_IV));
            assertArrayEquals(CIPHERTEXT, DatatypeConverter.parseBase64Binary(jo.getString(KEY_CIPHERTEXT)));
        }
        
        @Test
        public void misingVersion() throws JSONException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            jo.remove(KEY_VERSION);

            new MslCiphertextEnvelope(jo);
        }
        
        @Test
        public void invalidVersion() throws JSONException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            jo.put(KEY_VERSION, "x");

            new MslCiphertextEnvelope(jo);
        }
        
        @Test
        public void unknownVersion() throws JSONException, MslCryptoException, MslEncodingException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            jo.put(KEY_VERSION, -1);

            new MslCiphertextEnvelope(jo);
        }
        
        @Test
        public void missingCipherSpec() throws JSONException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            jo.remove(KEY_CIPHERSPEC);

            new MslCiphertextEnvelope(jo);
        }
        
        @Test
        public void invalidCipherSpec() throws JSONException, MslCryptoException, MslEncodingException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNIDENTIFIED_CIPHERSPEC);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            jo.put(KEY_CIPHERSPEC, "x");

            new MslCiphertextEnvelope(jo);
        }
        
        @Test
        public void missingCiphertext() throws JSONException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final String json = envelope.toJSONString();
            final JSONObject jo = new JSONObject(json);
            jo.remove(KEY_CIPHERTEXT);

            new MslCiphertextEnvelope(jo);
        }
    }
}
