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
import static org.junit.Assert.assertEquals;
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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.netflix.msl.MslConstants.SignatureAlgo;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.crypto.MslSignatureEnvelope.Version;

/**
 * MSL signature envelope unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({MslSignatureEnvelopeTest.Version1.class,
               MslSignatureEnvelopeTest.Version2.class})
public class MslSignatureEnvelopeTest {
    /** JSON key version. */
    private final static String KEY_VERSION = "version";
    /** JSON key algorithm. */
    private final static String KEY_ALGORITHM = "algorithm";
    /** JSON key signature. */
    private final static String KEY_SIGNATURE = "signature";
    
    private static final byte[] SIGNATURE = new byte[32];
    
    @BeforeClass
    public static void setup() {
        final Random random = new Random();
        random.nextBytes(SIGNATURE);
    }
    
        public static class Version1 {
        @Test
        public void ctors() throws MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(SIGNATURE);
            assertNull(envelope.getAlgorithm());
            assertArrayEquals(SIGNATURE, envelope.getSignature());
            final byte[] envelopeBytes = envelope.getBytes();
            assertNotNull(envelopeBytes);
            
            final MslSignatureEnvelope joEnvelope = MslSignatureEnvelope.parse(envelopeBytes);
            assertEquals(envelope.getAlgorithm(), joEnvelope.getAlgorithm());
            assertArrayEquals(envelope.getSignature(), joEnvelope.getSignature());
            final byte[] joEnvelopeBytes = joEnvelope.getBytes();
            assertArrayEquals(envelopeBytes, joEnvelopeBytes);
        }
        
        @Test
        public void json() throws MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(SIGNATURE);
            final byte[] envelopeBytes = envelope.getBytes();
            assertNotNull(envelopeBytes);
            assertArrayEquals(SIGNATURE, envelopeBytes);
        }
    }
    
    @RunWith(Parameterized.class)
    public static class Version2 {
        @Parameters
        public static Collection<Object[]> data() {
            final List<Object[]> params = new ArrayList<Object[]>();
            for (final SignatureAlgo algo: SignatureAlgo.values())
                params.add(new Object[] { algo });
            return params;
        }
        
        /** Algorithm. */
        private final SignatureAlgo algorithm;
        
        /**
         * Create a new Version 2 test set with the provided algorithm.
         * 
         * @param algorithm the algorithm.
         */
        public Version2(final SignatureAlgo algorithm) {
            this.algorithm = algorithm;
        }
        
        @Test
        public void ctors() throws MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);
            assertEquals(algorithm, envelope.getAlgorithm());
            assertArrayEquals(SIGNATURE, envelope.getSignature());
            final byte[] envelopeBytes = envelope.getBytes();
            assertNotNull(envelopeBytes);
            
            final MslSignatureEnvelope joEnvelope = MslSignatureEnvelope.parse(envelopeBytes);
            assertEquals(envelope.getAlgorithm(), joEnvelope.getAlgorithm());
            assertArrayEquals(envelope.getSignature(), joEnvelope.getSignature());
            final byte[] joEnvelopeBytes = joEnvelope.getBytes();
            assertArrayEquals(envelopeBytes, joEnvelopeBytes);
        }
        
        @Test
        public void json() throws JSONException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);
            final byte[] envelopeBytes = envelope.getBytes();
            final JSONObject jo = new JSONObject(new String(envelopeBytes));
            
            assertEquals(Version.V2.intValue(), jo.getInt(KEY_VERSION));
            assertEquals(algorithm.toString(), jo.getString(KEY_ALGORITHM));
            assertArrayEquals(SIGNATURE, DatatypeConverter.parseBase64Binary(jo.getString(KEY_SIGNATURE)));
        }
        
        @Test
        public void missingVersion() throws JSONException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes();
            final JSONObject jo = new JSONObject(new String(envelopeBytes));
            jo.remove(KEY_VERSION);
            
            final byte[] joJson = jo.toString().getBytes();
            final MslSignatureEnvelope joEnvelope = MslSignatureEnvelope.parse(joJson);
            assertNull(joEnvelope.getAlgorithm());
            assertArrayEquals(joJson, joEnvelope.getSignature());
        }
        
        @Test
        public void invalidVersion() throws JSONException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes();
            final JSONObject jo = new JSONObject(new String(envelopeBytes));
            jo.put(KEY_VERSION, "x");
            
            final byte[] joJson = jo.toString().getBytes();
            final MslSignatureEnvelope joEnvelope = MslSignatureEnvelope.parse(joJson);
            assertNull(joEnvelope.getAlgorithm());
            assertArrayEquals(joJson, joEnvelope.getSignature());
        }
        
        @Test
        public void unknownVersion() throws JSONException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes();
            final JSONObject jo = new JSONObject(new String(envelopeBytes));
            jo.put(KEY_VERSION, "-1");
            
            final byte[] joJson = jo.toString().getBytes();
            final MslSignatureEnvelope joEnvelope = MslSignatureEnvelope.parse(joJson);
            assertNull(joEnvelope.getAlgorithm());
            assertArrayEquals(joJson, joEnvelope.getSignature());
        }
        
        @Test
        public void missingAlgorithm() throws JSONException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes();
            final JSONObject jo = new JSONObject(new String(envelopeBytes));
            jo.remove(KEY_ALGORITHM);
            
            final byte[] joJson = jo.toString().getBytes();
            final MslSignatureEnvelope joEnvelope = MslSignatureEnvelope.parse(joJson);
            assertNull(joEnvelope.getAlgorithm());
            assertArrayEquals(joJson, joEnvelope.getSignature());
        }
        
        @Test
        public void invalidAlgorithm() throws JSONException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes();
            final JSONObject jo = new JSONObject(new String(envelopeBytes));
            jo.put(KEY_ALGORITHM, "x");
            
            final byte[] joJson = jo.toString().getBytes();
            final MslSignatureEnvelope joEnvelope = MslSignatureEnvelope.parse(joJson);
            assertNull(joEnvelope.getAlgorithm());
            assertArrayEquals(joJson, joEnvelope.getSignature());
        }
        
        @Test
        public void missingSignature() throws JSONException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes();
            final JSONObject jo = new JSONObject(new String(envelopeBytes));
            jo.remove(KEY_SIGNATURE);
            
            final byte[] joJson = jo.toString().getBytes();
            final MslSignatureEnvelope joEnvelope = MslSignatureEnvelope.parse(joJson);
            assertNull(joEnvelope.getAlgorithm());
            assertArrayEquals(joJson, joEnvelope.getSignature());
        }
    }
}
