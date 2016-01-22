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
package com.netflix.msl.io;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.Charset;
import java.util.Random;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * JSON utilities unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslEncoderUtilsTest {
    /** Encoding charset. */
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    
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
        return DatatypeConverter.printBase64Binary(raw);
    }
    
    /**
     * @param random random source.
     * @return a JSON object containing no JSON objects or JSON arrays.
     * @throws MslEncoderException if there is an error building the JSON object.
     */
    private static MslObject createFlatMslObject(final Random random) throws MslEncoderException {
        final MslObject mo = new MslObject();
        for (int i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(4)) {
                case 0:
                    mo.put(KEY_BOOLEAN + i, random.nextBoolean());
                    break;
                case 1:
                    mo.put(KEY_NUMBER + i, random.nextInt());
                    break;
                case 2:
                    mo.put(KEY_STRING + i, randomString(random));
                    break;
                case 3:
                    mo.put(KEY_NULL + i, null);
                    break;
            }
        }
        return mo;
    }
    
    /**
     * @param random random source.
     * @param depth maximum depth. A depth of 1 indicates no children may have
     *        more children.
     * @return a JSON object that may contain JSON objects or JSON arrays.
     * @throws MslEncoderException if there is an error building the JSON object.
     */
    private static MslObject createDeepMslObject(final Random random, final int depth) throws MslEncoderException {
        final MslObject mo = new MslObject();
        for (int i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(6)) {
                case 0:
                    mo.put(KEY_BOOLEAN + i, random.nextBoolean());
                    break;
                case 1:
                    mo.put(KEY_NUMBER + i, random.nextInt());
                    break;
                case 2:
                    mo.put(KEY_STRING + i, randomString(random));
                    break;
                case 3:
                    mo.put(KEY_NULL + i, null);
                    break;
                case 4:
                    mo.put(KEY_OBJECT + i, (depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslObject(random));
                    break;
                case 5:
                    mo.put(KEY_ARRAY + i, (depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslArray(random));
                    break;
            }
        }
        return mo;
    }
    
    /**
     * @param random random source.
     * @return a JSON array containing no JSON objects or JSON arrays.
     * @throws MslEncoderException if there is an error building the JSON array.
     */
    private static MslArray createFlatMslArray(final Random random) throws MslEncoderException {
        final MslArray ma = new MslArray();
        for (int i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(4)) {
                case 0:
                    ma.put(-1, random.nextBoolean());
                    break;
                case 1:
                    ma.put(-1, random.nextInt());
                    break;
                case 2:
                    ma.put(-1, randomString(random));
                    break;
                case 3:
                    ma.put(-1, null);
                    break;
            }
        }
        return ma;
    }

    
    /**
     * @param random random source.
     * @param depth maximum depth. A depth of 1 indicates no children may have
     *        more children.
     * @return a JSON array that may contain JSON objects or JSON arrays.
     * @throws MslEncoderException if there is an error building the JSON array.
     */
    private static MslArray createDeepMslArray(final Random random, final int depth) throws MslEncoderException {
        final MslArray ma = new MslArray();
        for (int i = random.nextInt(MAX_ELEMENTS); i > 0; --i) {
            switch (random.nextInt(4)) {
                case 0:
                    ma.put(-1, random.nextBoolean());
                    break;
                case 1:
                    ma.put(-1, random.nextInt());
                    break;
                case 2:
                    ma.put(-1, randomString(random));
                    break;
                case 3:
                    ma.put(-1, null);
                    break;
                case 4:
                    ma.put(-1, (depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslObject(random));
                    break;
                case 5:
                    ma.put(-1, (depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslArray(random));
                    break;
            }
        }
        return ma;
    }
    
    /**
     * @param o the object to change.
     * @return a new object with a changed value.
     * @throws MslEncoderException if the object type is unknown or there is an error
     *         parsing/building the JSON objects or arrays.
     */
    private static Object changeValue(final Object o) throws MslEncoderException {
        final Random random = new Random();
        if (o instanceof String) {
            return (String)o + "x";
        } else if (o instanceof Number) {
            return ((Number)o).doubleValue() + 1;
        } else if (o instanceof Boolean) {
            return !((Boolean)o).booleanValue();
        } else if (o instanceof MslObject) {
            final MslObject childMo = encoder.createObject(((MslObject)o).getMap());
            final Set<String> childNames = childMo.getKeys();
            if (childNames.size() > 0) {
                final String childName = childNames.toArray(new String[0])[random.nextInt(childNames.size())];
                return changeValue(childMo, childName);
            } else {
                childMo.put(KEY_NUMBER + "1", 1);
                return childMo;
            }
        } else if (o instanceof MslArray) {
            final MslArray childMa = encoder.createArray(((MslArray)o).getCollection());
            childMa.put(-1, random.nextInt());
            return childMa;
        } else if (o == null) {
            return true;
        }
        throw new MslEncoderException("Unknown object type " + o.getClass());
    }
    
    /**
     * @param mo JSON object to create a changed version of.
     * @param name name of value to change.
     * @return a new JSON object with the value associated with the given name
     *         randomly changed.
     * @throws MslEncoderException if the name does not exist or there is an error
     *         parsing/building the JSON objects.
     */
    private static MslObject changeValue(final MslObject mo, final String name) throws MslEncoderException {
        final MslObject newMo = encoder.createObject(mo.getMap());
        final Object o = newMo.opt(name);
        newMo.put(name,  changeValue(o));
        return newMo;
    }
    
    private static MslArray changeValue(final MslArray ma, final int index) throws MslEncoderException {
        final MslArray newMa = encoder.createArray(ma.getCollection());
        final Object o = newMa.opt(index);
        newMa.put(index, changeValue(o));
        return newMa;
    }
    
    @BeforeClass
    public static void setup() throws MslEncoderException, MslEncodingException, MslCryptoException {
        final MslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        
        final Random random = new Random();
        flatMo = createFlatMslObject(random);
        deepMo = createDeepMslObject(random, MAX_DEPTH);
        nullMo = null;
        flatMa = createFlatMslArray(random);
        deepMa = createDeepMslArray(random, MAX_DEPTH);
        nullMa = null;
    }
    
    @AfterClass
    public static void teardown() {
        flatMo = null;
        deepMo = null;
        flatMa = null;
        deepMa = null;
        
        encoder = null;
    }
    
    @Test
    public void b64url() {
        for (final String[] example : B64_URL_EXAMPLES) {
            final String text = example[0];
            final String base64 = example[1];
            
            // Encode the text as bytes and as a string.
            {
                final String encoded = MslEncoderUtils.b64urlEncode(text.getBytes(UTF_8));
                final String encodedString = MslEncoderUtils.b64urlEncode(text);
                assertEquals(base64, encoded);
                assertEquals(base64, encodedString);
            }
            
            // Decode the base64 to bytes and to a string.
            {
                final byte[] decoded = MslEncoderUtils.b64urlDecode(base64);
                final String decodedString = MslEncoderUtils.b64urlDecodeToString(base64);
                assertArrayEquals(text.getBytes(UTF_8), decoded);
                assertEquals(decodedString, text);
            }
        }
    }
    
    @Test
    public void mslObjectEqual() throws MslEncoderException {
        assertTrue(MslEncoderUtils.equals(flatMo, flatMo));
        final MslObject mo = encoder.createObject(flatMo.getMap());
        assertTrue(MslEncoderUtils.equals(flatMo, mo));
    }
    
    @Test
    public void mslObjectInequal() throws MslEncoderException {
        final Set<String> names = flatMo.getKeys();
        for (final String name : names) {
            final MslObject mo = changeValue(flatMo, name);
            assertFalse(MslEncoderUtils.equals(flatMo, mo));
        }
    }
    
    @Test
    public void mslObjectNull() throws MslEncoderException {
        assertFalse(MslEncoderUtils.equals(null, new MslObject()));
        assertFalse(MslEncoderUtils.equals(new MslObject(), null));
        assertTrue(MslEncoderUtils.equals(nullMo, nullMo));
    }
    
    @Test
    public void mslObjectChildrenEqual() throws MslEncoderException {
        assertTrue(MslEncoderUtils.equals(deepMo, deepMo));
        final MslObject mo = encoder.createObject(deepMo.getMap());
        assertTrue(MslEncoderUtils.equals(deepMo, mo));
    }
    
    @Test
    public void mslObjectChildrenInequal() throws MslEncoderException {
        final Set<String> names = deepMo.getKeys();
        for (final String name : names) {
            final MslObject mo = changeValue(deepMo, name);
            assertFalse(MslEncoderUtils.equals(deepMo, mo));
        }
    }
    
    @Test
    public void mslArrayEqual() throws MslEncoderException {
        assertTrue(MslEncoderUtils.equals(flatMa, flatMa));
        final MslArray ma = encoder.createArray(flatMa.getCollection());
        assertTrue(MslEncoderUtils.equals(flatMa, ma));
        
    }
    
    @Test
    public void mslArrayInequal() throws MslEncoderException {
        final Random random = new Random();
        final MslArray ma1 = encoder.createArray(flatMa.getCollection());
        if (ma1.size() > 0) {
            ma1.remove(random.nextInt(ma1.size()));
            assertFalse(MslEncoderUtils.equals(flatMa, ma1));
        }
        final MslArray ma2 = encoder.createArray(flatMa.getCollection());
        ma2.put(-1, random.nextInt());
        assertFalse(MslEncoderUtils.equals(flatMa, ma2));
        if (flatMa.size() > 0) {
            final MslArray ma3 = changeValue(flatMa, random.nextInt(flatMa.size()));
            assertFalse(MslEncoderUtils.equals(flatMa, ma3));
        }
    }
    
    @Test
    public void mslArrayNull() throws MslEncoderException {
        assertFalse(MslEncoderUtils.equals(null, new MslArray()));
        assertFalse(MslEncoderUtils.equals(new MslArray(), null));
        assertTrue(MslEncoderUtils.equals(nullMa, nullMa));
    }
    
    @Test
    public void mslArrayChildrenEqual() throws MslEncoderException {
        assertTrue(MslEncoderUtils.equals(deepMa, deepMa));
        final MslArray ma = encoder.createArray(deepMa.getCollection());
        assertTrue(MslEncoderUtils.equals(deepMa, ma));
    }
    
    @Test
    public void mslArrayChildrenInequal() throws MslEncoderException {
        final Random random = new Random();
        final MslArray ma1 = encoder.createArray(deepMa.getCollection());
        if (ma1.size() > 0) {
            ma1.remove(random.nextInt(ma1.size()));
            assertFalse(MslEncoderUtils.equals(deepMa, ma1));
        }
        final MslArray ma2 = encoder.createArray(deepMa.getCollection());
        ma2.put(-1, random.nextInt());
        assertFalse(MslEncoderUtils.equals(deepMa, ma2));
        if (deepMa.size() > 0) {
            final MslArray ma3 = changeValue(deepMa, random.nextInt(deepMa.size()));
            assertFalse(MslEncoderUtils.equals(deepMa, ma3));
        }
    }
    
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    
    private static MslObject flatMo, deepMo, nullMo;
    private static MslArray flatMa, deepMa, nullMa;
}
