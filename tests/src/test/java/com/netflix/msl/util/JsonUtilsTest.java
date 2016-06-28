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
package com.netflix.msl.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * JSON utilities unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonUtilsTest {
    /** Encoding charset. */
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    
    /** URL-safe Base64 examples. */
    private static final String[][] B64_URL_EXAMPLES = new String[][] {
        { "The long winded author is going for a walk while the light breeze bellows in his ears.",
          "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4" },
        { "Sometimes porcupines need beds to sleep on.",
          "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg" },
        { "Even the restless dreamer enjoys home-cooked foods.",
          "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu" }
    };
    
    private static final String KEY_BOOLEAN = "boolean";
    private static final String KEY_NUMBER = "number";
    private static final String KEY_STRING = "string";
    private static final String KEY_NULL = "null";
    private static final String KEY_OBJECT = "object";
    private static final String KEY_ARRAY = "array";
    
    private static final int MAX_ELEMENTS = 12;
    private static final int MAX_DEPTH = 3;
    private static final int MAX_STRING_CHARS = 25;
    
    /**
     * @param random random source.
     * @return a random string of random length.
     */
    private static final String randomString(final Random random) {
        final byte[] raw = new byte[random.nextInt(MAX_STRING_CHARS) + 1];
        random.nextBytes(raw);
        return Base64.encode(raw);
    }
    
    /**
     * @param random random source.
     * @return a JSON object containing no JSON objects or JSON arrays.
     * @throws JSONException if there is an error building the JSON object.
     */
    private static JSONObject createFlatJSONObject(final Random random) throws JSONException {
        final JSONObject jo = new JSONObject();
        for (int i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(4)) {
                case 0:
                    jo.put(KEY_BOOLEAN + i, random.nextBoolean());
                    break;
                case 1:
                    jo.put(KEY_NUMBER + i, random.nextInt());
                    break;
                case 2:
                    jo.put(KEY_STRING + i, randomString(random));
                    break;
                case 3:
                    jo.put(KEY_NULL + i, JSONObject.NULL);
                    break;
            }
        }
        return jo;
    }
    
    /**
     * @param random random source.
     * @param depth maximum depth. A depth of 1 indicates no children may have
     *        more children.
     * @return a JSON object that may contain JSON objects or JSON arrays.
     * @throws JSONException if there is an error building the JSON object.
     */
    private static JSONObject createDeepJSONObject(final Random random, final int depth) throws JSONException {
        final JSONObject jo = new JSONObject();
        for (int i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(6)) {
                case 0:
                    jo.put(KEY_BOOLEAN + i, random.nextBoolean());
                    break;
                case 1:
                    jo.put(KEY_NUMBER + i, random.nextInt());
                    break;
                case 2:
                    jo.put(KEY_STRING + i, randomString(random));
                    break;
                case 3:
                    jo.put(KEY_NULL + i, JSONObject.NULL);
                    break;
                case 4:
                    jo.put(KEY_OBJECT + i, (depth > 1) ? createDeepJSONObject(random, depth - 1) : createFlatJSONObject(random));
                    break;
                case 5:
                    jo.put(KEY_ARRAY + i, (depth > 1) ? createDeepJSONArray(random, depth - 1) : createFlatJSONArray(random));
                    break;
            }
        }
        return jo;
    }
    
    /**
     * @param random random source.
     * @return a JSON array containing no JSON objects or JSON arrays.
     * @throws JSONException if there is an error building the JSON array.
     */
    private static JSONArray createFlatJSONArray(final Random random) throws JSONException {
        final JSONArray ja = new JSONArray();
        for (int i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(4)) {
                case 0:
                    ja.put(random.nextBoolean());
                    break;
                case 1:
                    ja.put(random.nextInt());
                    break;
                case 2:
                    ja.put(randomString(random));
                    break;
                case 3:
                    ja.put(JSONObject.NULL);
                    break;
            }
        }
        return ja;
    }
    
    /**
     * @param random random source.
     * @param depth maximum depth. A depth of 1 indicates no children may have
     *        more children.
     * @return a JSON array that may contain JSON objects or JSON arrays.
     * @throws JSONException if there is an error building the JSON array.
     */
    private static JSONArray createDeepJSONArray(final Random random, final int depth) throws JSONException {
        final JSONArray ja = new JSONArray();
        for (int i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(6)) {
                case 0:
                    ja.put(random.nextBoolean());
                    break;
                case 1:
                    ja.put(random.nextInt());
                    break;
                case 2:
                    ja.put(randomString(random));
                    break;
                case 3:
                    ja.put(JSONObject.NULL);
                    break;
                case 4:
                    ja.put((depth > 1) ? createDeepJSONObject(random, depth - 1) : createFlatJSONObject(random));
                    break;
                case 5:
                    ja.put((depth > 1) ? createDeepJSONArray(random, depth - 1) : createFlatJSONArray(random));
                    break;
            }
        }
        return ja;
    }
    
    /**
     * @param o the object to change.
     * @return a new object with a changed value.
     * @throws JSONException if the object type is unknown or there is an error
     *         parsing/building the JSON objects or arrays.
     */
    private static Object changeValue(final Object o) throws JSONException {
        final Random random = new Random();
        if (o instanceof String) {
            return (String)o + "x";
        } else if (o instanceof Number) {
            return ((Number)o).doubleValue() + 1;
        } else if (o instanceof Boolean) {
            return !((Boolean)o).booleanValue();
        } else if (o instanceof JSONObject) {
            final JSONObject childJo = new JSONObject(((JSONObject)o).toString());
            final String[] childNames = JSONObject.getNames(childJo);
            if (childNames != null) {
                final String childName = childNames[random.nextInt(childNames.length)];
                return changeValue(childJo, childName);
            } else {
                childJo.put(KEY_NUMBER + "1", 1);
                return childJo;
            }
        } else if (o instanceof JSONArray) {
            final JSONArray childJa = new JSONArray(((JSONArray)o).toString());
            childJa.put(random.nextInt());
            return childJa;
        } else if (o.equals(JSONObject.NULL)) {
            return true;
        }
        throw new JSONException("Unknown object type " + o.getClass());
    }
    
    /**
     * @param jo JSON object to create a changed version of.
     * @param name name of value to change.
     * @return a new JSON object with the value associated with the given name
     *         randomly changed.
     * @throws JSONException if the name does not exist or there is an error
     *         parsing/building the JSON objects.
     */
    private static JSONObject changeValue(final JSONObject jo, final String name) throws JSONException {
        final JSONObject newJo = new JSONObject(jo.toString());
        final Object o = newJo.get(name);
        newJo.put(name,  changeValue(o));
        return newJo;
    }
    
    private static JSONArray changeValue(final JSONArray ja, final int index) throws JSONException {
        final JSONArray newJa = new JSONArray(ja.toString());
        final Object o = newJa.get(index);
        newJa.put(index, changeValue(o));
        return newJa;
    }
    
    @BeforeClass
    public static void setup() throws JSONException {
        random = new Random();
        flatJo = createFlatJSONObject(random);
        deepJo = createDeepJSONObject(random, MAX_DEPTH);
        nullJo = null;
        flatJa = createFlatJSONArray(random);
        deepJa = createDeepJSONArray(random, MAX_DEPTH);
        nullJa = null;
    }
    
    @AfterClass
    public static void teardown() {
        flatJo = null;
        deepJo = null;
        flatJa = null;
        deepJa = null;
        random = null;
    }
    
    @Test
    public void b64url() {
        for (final String[] example : B64_URL_EXAMPLES) {
            final String text = example[0];
            final String base64 = example[1];
            
            // Encode the text as bytes and as a string.
            {
                final String encoded = JsonUtils.b64urlEncode(text.getBytes(UTF_8));
                final String encodedString = JsonUtils.b64urlEncode(text);
                assertEquals(base64, encoded);
                assertEquals(base64, encodedString);
            }
            
            // Decode the base64 to bytes and to a string.
            {
                final byte[] decoded = JsonUtils.b64urlDecode(base64);
                final String decodedString = JsonUtils.b64urlDecodeToString(base64);
                assertArrayEquals(text.getBytes(UTF_8), decoded);
                assertEquals(decodedString, text);
            }
        }
    }
    
    @Test
    public void jsonObjectEqual() throws JSONException {
        assertTrue(JsonUtils.equals(flatJo, flatJo));
        final JSONObject jo = new JSONObject(flatJo.toString());
        assertTrue(JsonUtils.equals(flatJo, jo));
    }
    
    @Test
    public void jsonObjectInequal() throws JSONException {
        final String[] names = JSONObject.getNames(flatJo);
        if (names != null) {
            for (final String name : names) {
                final JSONObject jo = changeValue(flatJo, name);
                assertFalse(JsonUtils.equals(flatJo, jo));
            }
        }
    }
    
    @Test
    public void jsonObjectNull() throws JSONException {
        assertFalse(JsonUtils.equals(null, new JSONObject()));
        assertFalse(JsonUtils.equals(new JSONObject(), null));
        assertTrue(JsonUtils.equals(nullJo, nullJo));
    }
    
    @Test
    public void jsonObjectChildrenEqual() throws JSONException {
        assertTrue(JsonUtils.equals(deepJo, deepJo));
        final JSONObject jo = new JSONObject(deepJo.toString());
        assertTrue(JsonUtils.equals(deepJo, jo));
    }
    
    @Test
    public void jsonObjectChildrenInequal() throws JSONException {
        final String[] names = JSONObject.getNames(deepJo);
        if (names != null) {
            for (final String name : names) {
                final JSONObject jo = changeValue(deepJo, name);
                assertFalse(JsonUtils.equals(deepJo, jo));
            }
        }
    }
    
    @Test
    public void jsonArrayEqual() throws JSONException {
        assertTrue(JsonUtils.equals(flatJa, flatJa));
        final JSONArray ja = new JSONArray(flatJa.toString());
        assertTrue(JsonUtils.equals(flatJa, ja));
        
    }
    
    @Test
    public void jsonArrayInequal() throws JSONException {
        final Random random = new Random();
        final JSONArray ja1 = new JSONArray(flatJa.toString());
        // The remove call is incompatible with netflix#json;1.1.0, which is what we getting with
        // the recent commonlibraries/extlib changes by jryan.
        //
        //if (ja1.length() > 0) {
        //    ja1.remove(random.nextInt(ja1.length()));
        //    assertFalse(JsonUtils.equals(flatJa, ja1));
        //}
        final JSONArray ja2 = new JSONArray(flatJa.toString());
        ja2.put(random.nextInt());
        assertFalse(JsonUtils.equals(flatJa, ja2));
        if (flatJa.length() > 0) {
            final JSONArray ja3 = changeValue(flatJa, random.nextInt(flatJa.length()));
            assertFalse(JsonUtils.equals(flatJa, ja3));
        }
    }
    
    @Test
    public void jsonArrayNull() throws JSONException {
        assertFalse(JsonUtils.equals(null, new JSONArray()));
        assertFalse(JsonUtils.equals(new JSONArray(), null));
        assertTrue(JsonUtils.equals(nullJa, nullJa));
    }
    
    @Test
    public void jsonArrayChildrenEqual() throws JSONException {
        assertTrue(JsonUtils.equals(deepJa, deepJa));
        final JSONArray ja = new JSONArray(deepJa.toString());
        assertTrue(JsonUtils.equals(deepJa, ja));
    }
    
    @Test
    public void jsonArrayChildrenInequal() throws JSONException {
        final Random random = new Random();
        final JSONArray ja1 = new JSONArray(deepJa.toString());
        // The remove call is incompatible with netflix#json;1.1.0, which is what we getting with
        // the recent commonlibraries/extlib changes by jryan.
        //
        //if (ja1.length() > 0) {
        //    ja1.remove(random.nextInt(ja1.length()));
        //    assertFalse(JsonUtils.equals(deepJa, ja1));
        //}
        final JSONArray ja2 = new JSONArray(deepJa.toString());
        ja2.put(random.nextInt());
        assertFalse(JsonUtils.equals(deepJa, ja2));
        if (deepJa.length() > 0) {
            final JSONArray ja3 = changeValue(deepJa, random.nextInt(deepJa.length()));
            assertFalse(JsonUtils.equals(deepJa, ja3));
        }
    }
    
    @Test
    public void mergeNulls() {
        final JSONObject jo1 = null;
        final JSONObject jo2 = null;
        final JSONObject merged = JsonUtils.merge(jo1, jo2);
        assertNull(merged);
    }
    
    @Test
    public void mergeFirstNull() {
        final JSONObject jo1 = null;
        final JSONObject jo2 = deepJo;
        final JSONObject merged = JsonUtils.merge(jo1, jo2);
        assertTrue(JsonUtils.equals(merged, jo2));
    }
    
    @Test
    public void mergeSecondNull() {
        final JSONObject jo1 = deepJo;
        final JSONObject jo2 = null;
        final JSONObject merged = JsonUtils.merge(jo1, jo2);
        assertTrue(JsonUtils.equals(merged, jo1));
    }
    
    @Test
    public void mergeOverwriting() {
        final JSONObject jo1 = createFlatJSONObject(random);
        final JSONObject jo2 = createFlatJSONObject(random);
        
        // Insert some shared keys.
        jo1.put("key1", true);
        jo2.put("key1", "value1");
        jo1.put("key2", 17);
        jo2.put("key2", 34);
        
        // Ensure second overwrites first.
        final JSONObject merged = JsonUtils.merge(jo1, jo2);
        for (final String key : JSONObject.getNames(merged)) {
            final Object value = merged.get(key);
            if (key.equals("key1") || key.equals("key2")) {
                assertEquals(jo2.get(key), value);
            } else if (jo2.has(key)) {
                assertEquals(jo2.get(key), value);
            } else {
                assertEquals(jo1.get(key), value);
            }
        }
    }
    
    private static Random random;
    private static JSONObject flatJo, deepJo, nullJo;
    private static JSONArray flatJa, deepJa, nullJa;
}
