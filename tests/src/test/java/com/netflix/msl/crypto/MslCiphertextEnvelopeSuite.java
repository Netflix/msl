/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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

import org.junit.AfterClass;
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
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * MSL encryption envelope unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({MslCiphertextEnvelopeSuite.Version1.class,
               MslCiphertextEnvelopeSuite.Version2.class})
public class MslCiphertextEnvelopeSuite {
    /** Key version. */
    private final static String KEY_VERSION = "version";
    /** Key key ID. */
    private final static String KEY_KEY_ID = "keyid";
    /** Key cipherspec. */
    private final static String KEY_CIPHERSPEC = "cipherspec";
    /** Key initialization vector. */
    private final static String KEY_IV = "iv";
    /** Key ciphertext. */
    private final static String KEY_CIPHERTEXT = "ciphertext";
    /** Key SHA-256. */
    private final static String KEY_SHA256 = "sha256";

    /** MSL encoder format. */
    private final static MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key ID. */
    private final static String KEY_ID = "keyid";
    
    private static final byte[] IV = new byte[16];
    private static final byte[] CIPHERTEXT = new byte[32];
    
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        final Random random = new Random();
        random.nextBytes(IV);
        random.nextBytes(CIPHERTEXT);
        
        final MslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
    }
    
    @AfterClass
    public static void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }

    public static class Version1 {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctors() throws MslCryptoException, MslEncodingException, MslEncoderException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);
            assertEquals(KEY_ID, envelope.getKeyId());
            assertNull(envelope.getCipherSpec());
            assertArrayEquals(IV, envelope.getIv());
            assertArrayEquals(CIPHERTEXT, envelope.getCiphertext());
            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            assertNotNull(encode);
            
            final MslObject mo = encoder.parseObject(encode);
            final MslCiphertextEnvelope moEnvelope = new MslCiphertextEnvelope(mo);
            assertEquals(envelope.getKeyId(), moEnvelope.getKeyId());
            assertEquals(envelope.getCipherSpec(), moEnvelope.getCipherSpec());
            assertArrayEquals(envelope.getIv(), moEnvelope.getIv());
            assertArrayEquals(envelope.getCiphertext(), moEnvelope.getCiphertext());
            final byte[] moEncode = moEnvelope.toMslEncoding(encoder, ENCODER_FORMAT);
            assertArrayEquals(encode, moEncode);
        }

        @Test
        public void ctorsNullIv() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, null, CIPHERTEXT);
            assertEquals(KEY_ID, envelope.getKeyId());
            assertNull(envelope.getCipherSpec());
            assertNull(envelope.getIv());
            assertArrayEquals(CIPHERTEXT, envelope.getCiphertext());
            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            assertNotNull(encode);
            
            final MslObject mo = encoder.parseObject(encode);
            final MslCiphertextEnvelope moEnvelope = new MslCiphertextEnvelope(mo);
            assertEquals(envelope.getKeyId(), moEnvelope.getKeyId());
            assertEquals(envelope.getCipherSpec(), moEnvelope.getCipherSpec());
            assertArrayEquals(envelope.getIv(), moEnvelope.getIv());
            assertArrayEquals(envelope.getCiphertext(), moEnvelope.getCiphertext());
            final byte[] moEncode = moEnvelope.toMslEncoding(encoder, ENCODER_FORMAT);
            assertArrayEquals(encode, moEncode);
        }

        @Test
        public void encode() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);
            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            
            assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
            assertFalse(mo.has(KEY_CIPHERSPEC));
            assertArrayEquals(IV, mo.getBytes(KEY_IV));
            assertArrayEquals(CIPHERTEXT, mo.getBytes(KEY_CIPHERTEXT));
        }

        @Test
        public void encodeNullIv() throws MslCryptoException, MslEncodingException, MslEncoderException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, null, CIPHERTEXT);
            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            
            assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
            assertFalse(mo.has(KEY_CIPHERSPEC));
            assertFalse(mo.has(KEY_IV));
            assertArrayEquals(CIPHERTEXT, mo.getBytes(KEY_CIPHERTEXT));
        }
        
        @Test
        public void missingKeyId() throws MslEncoderException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            mo.remove(KEY_KEY_ID);
            
            new MslCiphertextEnvelope(mo);
        }
        
        @Test
        public void missingCiphertext() throws MslEncoderException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            mo.remove(KEY_CIPHERTEXT);
            
            new MslCiphertextEnvelope(mo);
        }
        
        @Test
        public void missingSha256() throws MslEncoderException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            mo.remove(KEY_SHA256);
            
            new MslCiphertextEnvelope(mo);
        }

        @Test
        public void incorrectSha256() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(KEY_ID, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            final byte[] hash = mo.getBytes(KEY_SHA256);
            assertNotNull(hash);
            hash[0] += 1;
            mo.put(KEY_SHA256, hash);

            final MslCiphertextEnvelope moEnvelope = new MslCiphertextEnvelope(mo);
            assertEquals(KEY_ID, moEnvelope.getKeyId());
            assertNull(moEnvelope.getCipherSpec());
            assertArrayEquals(IV, moEnvelope.getIv());
            assertArrayEquals(CIPHERTEXT, moEnvelope.getCiphertext());
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
        public void ctors() throws MslCryptoException, MslEncodingException, MslEncoderException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);
            assertNull(envelope.getKeyId());
            assertEquals(cipherSpec, envelope.getCipherSpec());
            assertArrayEquals(IV, envelope.getIv());
            assertArrayEquals(CIPHERTEXT, envelope.getCiphertext());
            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            assertNotNull(encode);
            
            final MslObject mo = encoder.parseObject(encode);
            final MslCiphertextEnvelope moEnvelope = new MslCiphertextEnvelope(mo);
            assertEquals(envelope.getKeyId(), moEnvelope.getKeyId());
            assertEquals(envelope.getCipherSpec(), moEnvelope.getCipherSpec());
            assertArrayEquals(envelope.getIv(), moEnvelope.getIv());
            assertArrayEquals(envelope.getCiphertext(), moEnvelope.getCiphertext());
            final byte[] moEncode = moEnvelope.toMslEncoding(encoder, ENCODER_FORMAT);
            assertArrayEquals(encode, moEncode);
        }

        @Test
        public void ctorsNullIv() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, null, CIPHERTEXT);
            assertNull(envelope.getKeyId());
            assertEquals(cipherSpec, envelope.getCipherSpec());
            assertNull(envelope.getIv());
            assertArrayEquals(CIPHERTEXT, envelope.getCiphertext());
            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            assertNotNull(encode);
            
            final MslObject mo = encoder.parseObject(encode);
            final MslCiphertextEnvelope moEnvelope = new MslCiphertextEnvelope(mo);
            assertEquals(envelope.getKeyId(), moEnvelope.getKeyId());
            assertEquals(envelope.getCipherSpec(), moEnvelope.getCipherSpec());
            assertArrayEquals(envelope.getIv(), moEnvelope.getIv());
            assertArrayEquals(envelope.getCiphertext(), moEnvelope.getCiphertext());
            final byte[] moEncode = moEnvelope.toMslEncoding(encoder, ENCODER_FORMAT);
            assertArrayEquals(encode, moEncode);
        }

        @Test
        public void encode() throws MslEncoderException, MslCryptoException, MslEncodingException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);
            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);

            assertEquals(Version.V2.intValue(), mo.getInt(KEY_VERSION));
            assertFalse(mo.has(KEY_KEY_ID));
            assertEquals(cipherSpec.toString(), mo.getString(KEY_CIPHERSPEC));
            assertArrayEquals(IV, mo.getBytes(KEY_IV));
            assertArrayEquals(CIPHERTEXT, mo.getBytes(KEY_CIPHERTEXT));
        }

        @Test
        public void encodeNullIv() throws MslCryptoException, MslEncodingException, MslEncoderException {
            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, null, CIPHERTEXT);
            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);

            assertEquals(Version.V2.intValue(), mo.getInt(KEY_VERSION));
            assertFalse(mo.has(KEY_KEY_ID));
            assertEquals(cipherSpec.toString(), mo.getString(KEY_CIPHERSPEC));
            assertFalse(mo.has(KEY_IV));
            assertArrayEquals(CIPHERTEXT, mo.getBytes(KEY_CIPHERTEXT));
        }
        
        @Test
        public void misingVersion() throws MslEncoderException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            mo.remove(KEY_VERSION);

            new MslCiphertextEnvelope(mo);
        }
        
        @Test
        public void invalidVersion() throws MslEncoderException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            mo.put(KEY_VERSION, "x");

            new MslCiphertextEnvelope(mo);
        }
        
        @Test
        public void unknownVersion() throws MslEncoderException, MslCryptoException, MslEncodingException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            mo.put(KEY_VERSION, -1);

            new MslCiphertextEnvelope(mo);
        }
        
        @Test
        public void missingCipherSpec() throws MslEncoderException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            mo.remove(KEY_CIPHERSPEC);

            new MslCiphertextEnvelope(mo);
        }
        
        @Test
        public void invalidCipherSpec() throws MslEncoderException, MslCryptoException, MslEncodingException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNIDENTIFIED_CIPHERSPEC);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            mo.put(KEY_CIPHERSPEC, "x");

            new MslCiphertextEnvelope(mo);
        }
        
        @Test
        public void missingCiphertext() throws MslEncoderException, MslCryptoException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(cipherSpec, IV, CIPHERTEXT);

            final byte[] encode = envelope.toMslEncoding(encoder, ENCODER_FORMAT);
            final MslObject mo = encoder.parseObject(encode);
            mo.remove(KEY_CIPHERTEXT);

            new MslCiphertextEnvelope(mo);
        }
    }
}
