/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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

import org.junit.AfterClass;
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
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * MSL signature envelope unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({MslSignatureEnvelopeSuite.Version1.class,
               MslSignatureEnvelopeSuite.Version2.class})
public class MslSignatureEnvelopeSuite {
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key version. */
    private static final String KEY_VERSION = "version";
    /** Key algorithm. */
    private static final String KEY_ALGORITHM = "algorithm";
    /** Key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    private static final byte[] SIGNATURE = new byte[32];
    
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        final Random random = new Random();
        random.nextBytes(SIGNATURE);
        
        final MslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
    }
    
    @AfterClass
    public static void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }
    
    public static class Version1 {
        @Test
        public void ctors() throws MslCryptoException, MslEncodingException, MslEncoderException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(SIGNATURE);
            assertNull(envelope.getAlgorithm());
            assertArrayEquals(SIGNATURE, envelope.getSignature());
            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            assertNotNull(envelopeBytes);
            
            final MslSignatureEnvelope moEnvelope = MslSignatureEnvelope.parse(envelopeBytes, encoder);
            assertEquals(envelope.getAlgorithm(), moEnvelope.getAlgorithm());
            assertArrayEquals(envelope.getSignature(), moEnvelope.getSignature());
            final byte[] moEnvelopeBytes = moEnvelope.getBytes(encoder, ENCODER_FORMAT);
            assertArrayEquals(envelopeBytes, moEnvelopeBytes);
        }
        
        @Test
        public void encode() throws MslCryptoException, MslEncodingException, MslEncoderException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(SIGNATURE);
            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            assertNotNull(envelopeBytes);
            assertArrayEquals(SIGNATURE, envelopeBytes);
        }
    }
    
    @RunWith(Parameterized.class)
    public static class Version2 {
        @Parameters
        public static Collection<Object[]> data() throws MslEncodingException, MslCryptoException {
            MslSignatureEnvelopeSuite.setup();
            
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
        public void ctors() throws MslCryptoException, MslEncodingException, MslEncoderException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);
            assertEquals(algorithm, envelope.getAlgorithm());
            assertArrayEquals(SIGNATURE, envelope.getSignature());
            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            assertNotNull(envelopeBytes);
            
            final MslSignatureEnvelope moEnvelope = MslSignatureEnvelope.parse(envelopeBytes, encoder);
            assertEquals(envelope.getAlgorithm(), moEnvelope.getAlgorithm());
            assertArrayEquals(envelope.getSignature(), moEnvelope.getSignature());
            final byte[] moEnvelopeBytes = moEnvelope.getBytes(encoder, ENCODER_FORMAT);
            assertArrayEquals(envelopeBytes, moEnvelopeBytes);
        }
        
        @Test
        public void encode() throws MslEncoderException, MslEncoderException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);
            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(envelopeBytes);
            
            assertEquals(Version.V2.intValue(), mo.getInt(KEY_VERSION));
            assertEquals(algorithm.toString(), mo.getString(KEY_ALGORITHM));
            assertArrayEquals(SIGNATURE, mo.getBytes(KEY_SIGNATURE));
        }
        
        @Test
        public void missingVersion() throws MslCryptoException, MslEncodingException, MslEncoderException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(envelopeBytes);
            mo.remove(KEY_VERSION);
            
            final byte[] moEncode = encoder.encodeObject(mo, ENCODER_FORMAT);
            final MslSignatureEnvelope moEnvelope = MslSignatureEnvelope.parse(moEncode, encoder);
            assertNull(moEnvelope.getAlgorithm());
            assertArrayEquals(moEncode, moEnvelope.getSignature());
        }
        
        @Test
        public void invalidVersion() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(envelopeBytes);
            mo.put(KEY_VERSION, "x");

            final byte[] moEncode = encoder.encodeObject(mo, ENCODER_FORMAT);
            final MslSignatureEnvelope moEnvelope = MslSignatureEnvelope.parse(moEncode, encoder);
            assertNull(moEnvelope.getAlgorithm());
            assertArrayEquals(moEncode, moEnvelope.getSignature());
        }
        
        @Test
        public void unknownVersion() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(envelopeBytes);
            mo.put(KEY_VERSION, -1);

            final byte[] moEncode = encoder.encodeObject(mo, ENCODER_FORMAT);
            final MslSignatureEnvelope moEnvelope = MslSignatureEnvelope.parse(moEncode, encoder);
            assertNull(moEnvelope.getAlgorithm());
            assertArrayEquals(moEncode, moEnvelope.getSignature());
        }
        
        @Test
        public void missingAlgorithm() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(envelopeBytes);
            mo.remove(KEY_ALGORITHM);

            final byte[] moEncode = encoder.encodeObject(mo, ENCODER_FORMAT);
            final MslSignatureEnvelope moEnvelope = MslSignatureEnvelope.parse(moEncode, encoder);
            assertNull(moEnvelope.getAlgorithm());
            assertArrayEquals(moEncode, moEnvelope.getSignature());
        }
        
        @Test
        public void invalidAlgorithm() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(envelopeBytes);
            mo.put(KEY_ALGORITHM, "x");

            final byte[] moEncode = encoder.encodeObject(mo, ENCODER_FORMAT);
            final MslSignatureEnvelope moEnvelope = MslSignatureEnvelope.parse(moEncode, encoder);
            assertNull(moEnvelope.getAlgorithm());
            assertArrayEquals(moEncode, moEnvelope.getSignature());
        }
        
        @Test
        public void missingSignature() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslSignatureEnvelope envelope = new MslSignatureEnvelope(algorithm, SIGNATURE);

            final byte[] envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(envelopeBytes);
            mo.remove(KEY_SIGNATURE);

            final byte[] moEncode = encoder.encodeObject(mo, ENCODER_FORMAT);
            final MslSignatureEnvelope moEnvelope = MslSignatureEnvelope.parse(moEncode, encoder);
            assertNull(moEnvelope.getAlgorithm());
            assertArrayEquals(moEncode, moEnvelope.getSignature());
        }
    }
}
