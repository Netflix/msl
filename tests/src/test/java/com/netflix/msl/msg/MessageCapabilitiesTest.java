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
package com.netflix.msl.msg;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslArray;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Message capabilities unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageCapabilitiesTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key compression algorithms. */
    private static final String KEY_COMPRESSION_ALGOS = "compressionalgos";
    /** Key encoder formats. */
    private static final String KEY_ENCODER_FORMATS = "encoderformats";
    
    private static final Set<CompressionAlgorithm> ALGOS = new HashSet<CompressionAlgorithm>();
    private static final List<String> LANGUAGES = Arrays.asList(new String[] { "en-US", "es" });
    private static final Set<MslEncoderFormat> FORMATS = new HashSet<MslEncoderFormat>();
    
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        final MslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        ALGOS.add(CompressionAlgorithm.GZIP);
        ALGOS.add(CompressionAlgorithm.LZW);
        FORMATS.add(MslEncoderFormat.JSON);
    }
    
    @AfterClass
    public static void teardown() {
        FORMATS.clear();
        ALGOS.clear();
        encoder = null;
    }

    @Test
    public void ctors() throws MslEncodingException, MslEncoderException {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        assertEquals(ALGOS, caps.getCompressionAlgorithms());
        assertEquals(LANGUAGES, caps.getLanguages());
        assertEquals(FORMATS, caps.getEncoderFormats());
        final byte[] encode = caps.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final MessageCapabilities moCaps = new MessageCapabilities(encoder.parseObject(encode));
        assertEquals(caps.getCompressionAlgorithms(), moCaps.getCompressionAlgorithms());
        assertEquals(caps.getLanguages(), moCaps.getLanguages());
        assertEquals(caps.getEncoderFormats(), moCaps.getEncoderFormats());
        final byte[] moEncode = moCaps.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // This test will not always pass since set data is unordered.
        //assertEquals(encode, moEncode);
        final MessageCapabilities mo2Caps = new MessageCapabilities(encoder.parseObject(moEncode));
        assertEquals(moCaps, mo2Caps);
    }
    
    @Test
    public void nullAlgos() throws MslEncodingException, MslEncoderException {
        final MessageCapabilities caps = new MessageCapabilities(null, LANGUAGES, FORMATS);
        final Set<CompressionAlgorithm> algos = caps.getCompressionAlgorithms();
        assertNotNull(algos);
        assertEquals(0, algos.size());
        assertEquals(LANGUAGES, caps.getLanguages());
        assertEquals(FORMATS, caps.getEncoderFormats());
        final byte[] encode = caps.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);

        final MessageCapabilities moCaps = new MessageCapabilities(encoder.parseObject(encode));
        assertEquals(caps.getCompressionAlgorithms(), moCaps.getCompressionAlgorithms());
        assertEquals(caps.getLanguages(), moCaps.getLanguages());
        assertEquals(caps.getEncoderFormats(), moCaps.getEncoderFormats());
        final byte[] moEncode = moCaps.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // This test will not always pass since set data is unordered.
        //assertEquals(encode, moEncode);
        final MessageCapabilities mo2Caps = new MessageCapabilities(encoder.parseObject(moEncode));
        assertEquals(moCaps, mo2Caps);
    }
    
    @Test
    public void unknownCompressionAlgo() throws MslEncoderException, MslEncodingException {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        final MslObject mo = MslTestUtils.toMslObject(encoder, caps);
        
        final MslArray ma = mo.getMslArray(KEY_COMPRESSION_ALGOS);
        ma.put(-1, "CATZ");
        mo.put(KEY_COMPRESSION_ALGOS, ma);
        
        final MessageCapabilities moCaps = new MessageCapabilities(mo);
        assertEquals(caps.getCompressionAlgorithms(), moCaps.getCompressionAlgorithms());
    }
    
    @Test
    public void nullLanguages() throws MslEncodingException, MslEncoderException {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, null, FORMATS);
        assertEquals(ALGOS, caps.getCompressionAlgorithms());
        final List<String> languages = caps.getLanguages();
        assertNotNull(languages);
        assertEquals(0, languages.size());
        assertEquals(FORMATS, caps.getEncoderFormats());
        final byte[] encode = caps.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final MessageCapabilities moCaps = new MessageCapabilities(encoder.parseObject(encode));
        assertEquals(caps.getCompressionAlgorithms(), moCaps.getCompressionAlgorithms());
        assertEquals(caps.getLanguages(), moCaps.getLanguages());
        assertEquals(caps.getEncoderFormats(), moCaps.getEncoderFormats());
        final byte[] moEncode = moCaps.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // This test will not always pass since set data is unordered.
        //assertEquals(encode, moEncode);
        final MessageCapabilities mo2Caps = new MessageCapabilities(encoder.parseObject(moEncode));
        assertEquals(moCaps, mo2Caps);
    }
    
    @Test
    public void nullEncoderFormats() throws MslEncodingException, MslEncoderException {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, LANGUAGES, null);
        assertEquals(ALGOS, caps.getCompressionAlgorithms());
        assertEquals(LANGUAGES, caps.getLanguages());
        final Set<MslEncoderFormat> formats = caps.getEncoderFormats();
        assertNotNull(formats);
        assertEquals(0, formats.size());
        final byte[] encode = caps.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);

        final MessageCapabilities moCaps = new MessageCapabilities(encoder.parseObject(encode));
        assertEquals(caps.getCompressionAlgorithms(), moCaps.getCompressionAlgorithms());
        assertEquals(caps.getLanguages(), moCaps.getLanguages());
        assertEquals(caps.getEncoderFormats(), moCaps.getEncoderFormats());
        final byte[] moEncode = moCaps.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // This test will not always pass since set data is unordered.
        //assertEquals(encode, moEncode);
        final MessageCapabilities mo2Caps = new MessageCapabilities(encoder.parseObject(moEncode));
        assertEquals(moCaps, mo2Caps);
    }
    
    @Test
    public void unknownEncoderFormat() throws MslEncoderException, MslEncodingException {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        final MslObject mo = MslTestUtils.toMslObject(encoder, caps);
        
        final MslArray ma = mo.getMslArray(KEY_ENCODER_FORMATS);
        ma.put(-1, "CATZ");
        mo.put(KEY_ENCODER_FORMATS, ma);
        
        final MessageCapabilities moCaps = new MessageCapabilities(mo);
        assertEquals(caps.getEncoderFormats(), moCaps.getEncoderFormats());
    }
    
    @Test
    public void equalsCompressionAlgos() throws MslEncodingException, MslEncoderException {
        final Set<CompressionAlgorithm> algosA = new HashSet<CompressionAlgorithm>(ALGOS);
        final Set<CompressionAlgorithm> algosB = new HashSet<CompressionAlgorithm>();
        
        final MessageCapabilities capsA = new MessageCapabilities(algosA, LANGUAGES, FORMATS);
        final MessageCapabilities capsB = new MessageCapabilities(algosB, LANGUAGES, FORMATS);
        final MessageCapabilities capsA2 = new MessageCapabilities(MslTestUtils.toMslObject(encoder, capsA));
        
        assertTrue(capsA.equals(capsA));
        assertEquals(capsA.hashCode(), capsA.hashCode());
        
        assertFalse(capsA.equals(capsB));
        assertFalse(capsB.equals(capsA));
        assertTrue(capsA.hashCode() != capsB.hashCode());
        
        assertTrue(capsA.equals(capsA2));
        assertTrue(capsA2.equals(capsA));
        assertEquals(capsA.hashCode(), capsA2.hashCode());
    }
    
    @Test
    public void equalsLanguages() throws MslEncodingException, MslEncoderException {
        final List<String> langsA = Arrays.asList(new String[] { "en-US" });
        final List<String> langsB = Arrays.asList(new String[] { "es" });
        
        final MessageCapabilities capsA = new MessageCapabilities(ALGOS, langsA, FORMATS);
        final MessageCapabilities capsB = new MessageCapabilities(ALGOS, langsB, FORMATS);
        final MessageCapabilities capsA2 = new MessageCapabilities(MslTestUtils.toMslObject(encoder, capsA));
        
        assertTrue(capsA.equals(capsA));
        assertEquals(capsA.hashCode(), capsA.hashCode());
        
        assertFalse(capsA.equals(capsB));
        assertFalse(capsB.equals(capsA));
        assertTrue(capsA.hashCode() != capsB.hashCode());
        
        assertTrue(capsA.equals(capsA2));
        assertTrue(capsA2.equals(capsA));
        assertEquals(capsA.hashCode(), capsA2.hashCode());
    }
    
    @Test
    public void equalsEncoderFormats() throws MslEncodingException, MslEncoderException {
        final Set<MslEncoderFormat> formatsA = new HashSet<MslEncoderFormat>(FORMATS);
        final Set<MslEncoderFormat> formatsB = new HashSet<MslEncoderFormat>();
        
        final MessageCapabilities capsA = new MessageCapabilities(ALGOS, LANGUAGES, formatsA);
        final MessageCapabilities capsB = new MessageCapabilities(ALGOS, LANGUAGES, formatsB);
        final MessageCapabilities capsA2 = new MessageCapabilities(MslTestUtils.toMslObject(encoder, capsA));
        
        assertTrue(capsA.equals(capsA));
        assertEquals(capsA.hashCode(), capsA.hashCode());
        
        assertFalse(capsA.equals(capsB));
        assertFalse(capsB.equals(capsA));
        assertTrue(capsA.hashCode() != capsB.hashCode());
        
        assertTrue(capsA.equals(capsA2));
        assertTrue(capsA2.equals(capsA));
        assertEquals(capsA.hashCode(), capsA2.hashCode());
    }
    
    @Test
    public void selfIntersection() {
        final MessageCapabilities capsA = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        final MessageCapabilities capsB = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        final MessageCapabilities intersection = MessageCapabilities.intersection(capsA, capsB);
        
        assertTrue(intersection.equals(capsA));
        assertTrue(intersection.equals(capsB));
    }
    
    @Test
    public void intersection() {
        final Set<CompressionAlgorithm> gzipOnly = new HashSet<CompressionAlgorithm>();
        gzipOnly.add(CompressionAlgorithm.GZIP);
        final List<String> oneLanguage = new ArrayList<String>();
        oneLanguage.add(LANGUAGES.get(0));
        final Set<MslEncoderFormat> noFormats = new HashSet<MslEncoderFormat>();
        
        final MessageCapabilities capsA = new MessageCapabilities(ALGOS, oneLanguage, FORMATS);
        final MessageCapabilities capsB = new MessageCapabilities(gzipOnly, LANGUAGES, FORMATS);
        final MessageCapabilities capsC = new MessageCapabilities(ALGOS, LANGUAGES, noFormats);
        final MessageCapabilities intersectionAB = MessageCapabilities.intersection(capsA, capsB);
        final MessageCapabilities intersectionBA = MessageCapabilities.intersection(capsB, capsA);
        final MessageCapabilities intersectionAC = MessageCapabilities.intersection(capsA, capsC);
        final MessageCapabilities intersectionCA = MessageCapabilities.intersection(capsC, capsA);
        final MessageCapabilities intersectionBC = MessageCapabilities.intersection(capsB, capsC);
        final MessageCapabilities intersectionCB = MessageCapabilities.intersection(capsC, capsB);
        
        assertTrue(intersectionAB.equals(intersectionBA));
        assertEquals(gzipOnly, intersectionAB.getCompressionAlgorithms());
        assertTrue(oneLanguage.containsAll(intersectionAB.getLanguages()));
        assertEquals(FORMATS, intersectionAB.getEncoderFormats());
        
        assertTrue(intersectionAC.equals(intersectionCA));
        assertEquals(ALGOS, intersectionAC.getCompressionAlgorithms());
        assertTrue(oneLanguage.containsAll(intersectionAC.getLanguages()));
        assertEquals(noFormats, intersectionAC.getEncoderFormats());
        
        assertTrue(intersectionBC.equals(intersectionCB));
        assertEquals(gzipOnly, intersectionBC.getCompressionAlgorithms());
        assertTrue(LANGUAGES.containsAll(intersectionBC.getLanguages()));
        assertEquals(noFormats, intersectionBC.getEncoderFormats());
    }
    
    @Test
    public void nullIntersection() {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        final MessageCapabilities intersectionA = MessageCapabilities.intersection(null, caps);
        final MessageCapabilities intersectionB = MessageCapabilities.intersection(caps, null);
        
        assertNull(intersectionA);
        assertNull(intersectionB);
    }
}
