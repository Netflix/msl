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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslEncodingException;

/**
 * Message capabilities unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageCapabilitiesTest {
    /** JSON key compression algorithms. */
    private static final String KEY_COMPRESSION_ALGOS = "compressionalgos";
    
    private static final Set<CompressionAlgorithm> ALGOS = new HashSet<CompressionAlgorithm>();
    private static final List<String> LANGUAGES = Arrays.asList(new String[] { "en-US", "es" });
    
    @BeforeClass
    public static void setup() {
        ALGOS.add(CompressionAlgorithm.GZIP);
        ALGOS.add(CompressionAlgorithm.LZW);
    }
    
    @AfterClass
    public static void teardown() {
        ALGOS.clear();
    }

    @Test
    public void ctors() throws MslEncodingException, JSONException {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, LANGUAGES);
        assertEquals(ALGOS, caps.getCompressionAlgorithms());
        assertEquals(LANGUAGES, caps.getLanguages());
        final String jsonString = caps.toJSONString();
        assertNotNull(jsonString);
        
        final MessageCapabilities joCaps = new MessageCapabilities(new JSONObject(jsonString));
        assertEquals(caps.getCompressionAlgorithms(), joCaps.getCompressionAlgorithms());
        assertEquals(caps.getLanguages(), joCaps.getLanguages());
        final String joJsonString = joCaps.toJSONString();
        assertNotNull(joJsonString);
        // This test will not always pass since the compression algorithms are
        // unordered.
        //assertTrue(JsonUtils.objectEquals(jsonString, joJsonString));
        final MessageCapabilities jo2Caps = new MessageCapabilities(new JSONObject(joJsonString));
        assertEquals(joCaps, jo2Caps);
    }
    
    @Test
    public void nullAlgos() throws MslEncodingException, JSONException {
        final MessageCapabilities caps = new MessageCapabilities((Set<CompressionAlgorithm>)null, LANGUAGES);
        final Set<CompressionAlgorithm> algos = caps.getCompressionAlgorithms();
        assertNotNull(algos);
        assertEquals(0, algos.size());
        assertEquals(LANGUAGES, caps.getLanguages());
        final String jsonString = caps.toJSONString();
        assertNotNull(jsonString);
        
        final MessageCapabilities joCaps = new MessageCapabilities(new JSONObject(jsonString));
        assertEquals(caps.getCompressionAlgorithms(), joCaps.getCompressionAlgorithms());
        assertEquals(caps.getLanguages(), joCaps.getLanguages());
        final String joJsonString = joCaps.toJSONString();
        assertNotNull(joJsonString);
        // This test will not always pass since the compression algorithms are
        // unordered.
        //assertTrue(JsonUtils.objectEquals(jsonString, joJsonString));
        final MessageCapabilities jo2Caps = new MessageCapabilities(new JSONObject(joJsonString));
        assertEquals(joCaps, jo2Caps);
    }
    
    @Test
    public void unknownCompressionAlgo() throws JSONException, MslEncodingException {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, LANGUAGES);
        final String jsonString = caps.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final JSONArray ja = jo.getJSONArray(KEY_COMPRESSION_ALGOS);
        ja.put("CATZ");
        jo.put(KEY_COMPRESSION_ALGOS, ja);
        
        final MessageCapabilities joCaps = new MessageCapabilities(jo);
        assertEquals(caps.getCompressionAlgorithms(), joCaps.getCompressionAlgorithms());
    }
    
    @Test
    public void nullLanguages() throws MslEncodingException, JSONException {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, null);
        assertEquals(ALGOS, caps.getCompressionAlgorithms());
        final List<String> languages = caps.getLanguages();
        assertNotNull(languages);
        assertEquals(0, languages.size());
        final String jsonString = caps.toJSONString();
        assertNotNull(jsonString);
        
        final MessageCapabilities joCaps = new MessageCapabilities(new JSONObject(jsonString));
        assertEquals(caps.getCompressionAlgorithms(), joCaps.getCompressionAlgorithms());
        assertEquals(caps.getLanguages(), joCaps.getLanguages());
        final String joJsonString = joCaps.toJSONString();
        assertNotNull(joJsonString);
        // This test will not always pass since the compression algorithms are
        // unordered.
        //assertTrue(JsonUtils.objectEquals(jsonString, joJsonString));
        final MessageCapabilities jo2Caps = new MessageCapabilities(new JSONObject(joJsonString));
        assertEquals(joCaps, jo2Caps);
    }
    
    @Test
    public void equalsCompressionAlgos() throws MslEncodingException, JSONException {
        final Set<CompressionAlgorithm> algosA = new HashSet<CompressionAlgorithm>(ALGOS);
        final Set<CompressionAlgorithm> algosB = new HashSet<CompressionAlgorithm>();
        
        final MessageCapabilities capsA = new MessageCapabilities(algosA, LANGUAGES);
        final MessageCapabilities capsB = new MessageCapabilities(algosB, LANGUAGES);
        final MessageCapabilities capsA2 = new MessageCapabilities(new JSONObject(capsA.toJSONString()));
        
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
    public void equalsLanguages() throws MslEncodingException, JSONException {
        final List<String> langsA = Arrays.asList(new String[] { "en-US" });
        final List<String> langsB = Arrays.asList(new String[] { "es" });
        
        final MessageCapabilities capsA = new MessageCapabilities(ALGOS, langsA);
        final MessageCapabilities capsB = new MessageCapabilities(ALGOS, langsB);
        final MessageCapabilities capsA2 = new MessageCapabilities(new JSONObject(capsA.toJSONString()));
        
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
        final MessageCapabilities capsA = new MessageCapabilities(ALGOS, LANGUAGES);
        final MessageCapabilities capsB = new MessageCapabilities(ALGOS, LANGUAGES);
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
        
        final MessageCapabilities capsA = new MessageCapabilities(ALGOS, oneLanguage);
        final MessageCapabilities capsB = new MessageCapabilities(gzipOnly, LANGUAGES);
        final MessageCapabilities intersectionAB = MessageCapabilities.intersection(capsA, capsB);
        final MessageCapabilities intersectionBA = MessageCapabilities.intersection(capsB, capsA);
        
        assertTrue(intersectionAB.equals(intersectionBA));
        assertEquals(gzipOnly, intersectionAB.getCompressionAlgorithms());
        assertTrue(oneLanguage.containsAll(intersectionAB.getLanguages()));
    }
    
    @Test
    public void nullIntersection() {
        final MessageCapabilities caps = new MessageCapabilities(ALGOS, LANGUAGES);
        final MessageCapabilities intersectionA = MessageCapabilities.intersection(null, caps);
        final MessageCapabilities intersectionB = MessageCapabilities.intersection(caps, null);
        
        assertNull(intersectionA);
        assertNull(intersectionB);
    }
}
