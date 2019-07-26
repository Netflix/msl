/**
 * Copyright (c) 2012-2019 Netflix, Inc.  All rights reserved.
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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.Charset;
import java.util.Random;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * MSL utilities unit tests.
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
        final byte[] raw = new byte[1 + random.nextInt(MAX_STRING_CHARS - 1)];
        return Base64.encode(raw);
    }

    /**
     * @param random random source.
     * @return a MSL object containing no MSL objects or MSL arrays.
     * @throws MslEncoderException if there is an error building the MSL object.
     */
    private static MslObject createFlatMslObject(final Random random) throws MslEncoderException {
        final MslObject mo = new MslObject();
        for (int i = 1 + random.nextInt(MAX_ELEMENTS - 1); i > 0; --i) {
            switch (random.nextInt(3)) {
                case 0:
                    mo.put(KEY_BOOLEAN + i, random.nextBoolean());
                    break;
                case 1:
                    mo.put(KEY_NUMBER + i, random.nextInt());
                    break;
                case 2:
                    mo.put(KEY_STRING + i, randomString(random));
                    break;
            }
        }
        return mo;
    }

    /**
     * @param random random source.
     * @param depth maximum depth. A depth of 1 indicates no children may have
     *        more children.
     * @return a MSL object that may contain MSL objects or MSL arrays.
     * @throws MslEncoderException if there is an error building the MSL object.
     */
    private static MslObject createDeepMslObject(final Random random, final int depth) throws MslEncoderException {
        final MslObject mo = new MslObject();
        for (int i = 1 + random.nextInt(MAX_ELEMENTS - 1); i > 0; --i) {
            switch (random.nextInt(5)) {
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
                    mo.put(KEY_OBJECT + i, (depth > 1) ? createDeepMslObject(random, depth - 1) : createFlatMslObject(random));
                    break;
                case 4:
                    mo.put(KEY_ARRAY + i, (depth > 1) ? createDeepMslArray(random, depth - 1) : createFlatMslArray(random));
                    break;
            }
        }
        return mo;
    }

    /**
     * @param random random source.
     * @return a MSL array containing no MSL objects or MSL arrays.
     * @throws MslEncoderException if there is an error building the MSL array.
     */
    private static MslArray createFlatMslArray(final Random random) throws MslEncoderException {
        final MslArray ma = new MslArray();
        for (int i = 1 + random.nextInt(MAX_ELEMENTS - 1); i > 0; --i) {
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
     * @return a MSL array that may contain MSL objects or MSL arrays.
     * @throws MslEncoderException if there is an error building the MSL array.
     */
    private static MslArray createDeepMslArray(final Random random, final int depth) throws MslEncoderException {
        final MslArray ma = new MslArray();
        for (int i = 1 + random.nextInt(MAX_ELEMENTS - 1); i > 0; --i) {
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
                    ma.put(-1, (depth > 1) ? createDeepMslArray(random, depth - 1) : createFlatMslArray(random));
                    break;
            }
        }
        return ma;
    }

    /**
     * @param o the object to change.
     * @return a new object with a changed value.
     * @throws MslEncoderException if the object type is unknown or there is an error
     *         parsing/building the MSL objects or arrays.
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
     * @param mo MSL object to create a changed version of.
     * @param name name of value to change.
     * @return a new MSL object with the value associated with the given name
     *         randomly changed.
     * @throws MslEncoderException if the name does not exist or there is an error
     *         parsing/building the MSL objects.
     */
    private static MslObject changeValue(final MslObject mo, final String name) throws MslEncoderException {
        final MslObject newMo = encoder.createObject(mo.getMap());
        final Object o = newMo.opt(name);
        newMo.put(name, changeValue(o));
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

        random = new Random();
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
        random = null;

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
                assertArrayEquals(text.getBytes(UTF_8), decoded);
            }
        }
    }

    @Test
    public void mslObjectEqual() throws MslEncoderException {
        assertTrue(MslEncoderUtils.equalObjects(flatMo, flatMo));
        assertEquals(MslEncoderUtils.hashObject(flatMo), MslEncoderUtils.hashObject(flatMo));
        final MslObject mo = encoder.createObject(flatMo.getMap());
        assertTrue(MslEncoderUtils.equalObjects(flatMo, mo));
        assertEquals(MslEncoderUtils.hashObject(flatMo), MslEncoderUtils.hashObject(mo));
    }

    @Test
    public void mslObjectInequal() throws MslEncoderException {
        final Set<String> names = flatMo.getKeys();
        for (final String name : names) {
            final MslObject mo = changeValue(flatMo, name);
            assertFalse(MslEncoderUtils.equalObjects(flatMo, mo));
            assertNotEquals(MslEncoderUtils.hashObject(flatMo), MslEncoderUtils.hashObject(mo));
        }
    }

    @Test
    public void mslObjectNull() throws MslEncoderException {
        assertFalse(MslEncoderUtils.equalObjects(null, new MslObject()));
        assertFalse(MslEncoderUtils.equalObjects(new MslObject(), null));
        assertTrue(MslEncoderUtils.equalObjects(nullMo, nullMo));
        assertEquals(MslEncoderUtils.hashObject(nullMo), MslEncoderUtils.hashObject(nullMo));
    }

    @Test
    public void mslObjectChildrenEqual() throws MslEncoderException {
        assertTrue(MslEncoderUtils.equalObjects(deepMo, deepMo));
        final MslObject mo = encoder.createObject(deepMo.getMap());
        assertTrue(MslEncoderUtils.equalObjects(deepMo, mo));
        assertEquals(MslEncoderUtils.hashObject(deepMo), MslEncoderUtils.hashObject(mo));
    }

    @Test
    public void mslObjectChildrenInequal() throws MslEncoderException {
        final Set<String> names = deepMo.getKeys();
        for (final String name : names) {
            final MslObject mo = changeValue(deepMo, name);
            assertFalse(MslEncoderUtils.equalObjects(deepMo, mo));
            assertNotEquals(MslEncoderUtils.hashObject(deepMo), MslEncoderUtils.hashObject(mo));
        }
    }

    @Test
    public void mslArrayEqual() throws MslEncoderException {
        assertTrue(MslEncoderUtils.equalArrays(flatMa, flatMa));
        assertEquals(MslEncoderUtils.hashArray(flatMa), MslEncoderUtils.hashArray(flatMa));
        final MslArray ma = encoder.createArray(flatMa.getCollection());
        assertTrue(MslEncoderUtils.equalArrays(flatMa, ma));
        assertEquals(MslEncoderUtils.hashArray(flatMa), MslEncoderUtils.hashArray(ma));
    }

    @Test
    public void mslArrayInequal() throws MslEncoderException {
        final Random random = new Random();
        final MslArray ma1 = encoder.createArray(flatMa.getCollection());
        if (ma1.size() > 0) {
            ma1.remove(random.nextInt(ma1.size()));
            assertFalse(MslEncoderUtils.equalArrays(flatMa, ma1));
            assertNotEquals(MslEncoderUtils.hashArray(flatMa), MslEncoderUtils.hashArray(ma1));
        }
        final MslArray ma2 = encoder.createArray(flatMa.getCollection());
        ma2.put(-1, random.nextInt());
        assertFalse(MslEncoderUtils.equalArrays(flatMa, ma2));
        assertNotEquals(MslEncoderUtils.hashArray(flatMa), MslEncoderUtils.hashArray(ma2));
        if (flatMa.size() > 0) {
            final MslArray ma3 = changeValue(flatMa, random.nextInt(flatMa.size()));
            assertFalse(MslEncoderUtils.equalArrays(flatMa, ma3));
            assertNotEquals(MslEncoderUtils.hashArray(flatMa), MslEncoderUtils.hashArray(ma3));
        }
    }

    @Test
    public void mslArrayNull() throws MslEncoderException {
        assertFalse(MslEncoderUtils.equalArrays(null, new MslArray()));
        assertFalse(MslEncoderUtils.equalArrays(new MslArray(), null));
        assertTrue(MslEncoderUtils.equalArrays(nullMa, nullMa));
        assertEquals(MslEncoderUtils.hashArray(nullMa), MslEncoderUtils.hashArray(nullMa));
    }

    @Test
    public void mslArrayChildrenEqual() throws MslEncoderException {
        assertTrue(MslEncoderUtils.equalArrays(deepMa, deepMa));
        assertEquals(MslEncoderUtils.hashArray(deepMa), MslEncoderUtils.hashArray(deepMa));
        final MslArray ma = encoder.createArray(deepMa.getCollection());
        assertTrue(MslEncoderUtils.equalArrays(deepMa, ma));
        assertEquals(MslEncoderUtils.hashArray(deepMa), MslEncoderUtils.hashArray(ma));
    }

    @Test
    public void mslArrayChildrenInequal() throws MslEncoderException {
        final Random random = new Random();
        final MslArray ma1 = encoder.createArray(deepMa.getCollection());
        if (ma1.size() > 0) {
            ma1.remove(random.nextInt(ma1.size()));
            assertFalse(MslEncoderUtils.equalArrays(deepMa, ma1));
            assertNotEquals(MslEncoderUtils.hashArray(deepMa), MslEncoderUtils.hashArray(ma1));
        }
        final MslArray ma2 = encoder.createArray(deepMa.getCollection());
        ma2.put(-1, random.nextInt());
        assertFalse(MslEncoderUtils.equalArrays(deepMa, ma2));
        assertNotEquals(MslEncoderUtils.hashArray(deepMa), MslEncoderUtils.hashArray(ma2));
        if (deepMa.size() > 0) {
            final MslArray ma3 = changeValue(deepMa, random.nextInt(deepMa.size()));
            assertFalse(MslEncoderUtils.equalArrays(deepMa, ma3));
            assertNotEquals(MslEncoderUtils.hashArray(deepMa), MslEncoderUtils.hashArray(ma3));
        }
    }

    @Test
    public void mergeNulls() throws MslEncoderException {
        final MslObject mo1 = null;
        final MslObject mo2 = null;
        final MslObject merged = MslEncoderUtils.merge(mo1, mo2);
        assertNull(merged);
    }

    @Test
    public void mergeFirstNull() throws MslEncoderException {
        final MslObject mo1 = null;
        final MslObject mo2 = deepMo;
        final MslObject merged = MslEncoderUtils.merge(mo1, mo2);
        assertTrue(MslEncoderUtils.equalObjects(merged, mo2));
        assertEquals(MslEncoderUtils.hashObject(merged), MslEncoderUtils.hashObject(mo2));
    }

    @Test
    public void mergeSecondNull() throws MslEncoderException {
        final MslObject mo1 = deepMo;
        final MslObject mo2 = null;
        final MslObject merged = MslEncoderUtils.merge(mo1, mo2);
        assertTrue(MslEncoderUtils.equalObjects(merged, mo1));
        assertEquals(MslEncoderUtils.hashObject(merged), MslEncoderUtils.hashObject(mo1));
    }

    @Test
    public void mergeOverwriting() throws MslEncoderException {
        final MslObject mo1 = createFlatMslObject(random);
        final MslObject mo2 = createFlatMslObject(random);

        // Insert some shared keys.
        mo1.put("key1", true);
        mo2.put("key1", "value1");
        mo1.put("key2", 17);
        mo2.put("key2", 34);

        // Ensure second overwrites first.
        final MslObject merged = MslEncoderUtils.merge(mo1, mo2);
        for (final String key : merged.getKeys()) {
            final Object value = merged.get(key);
            if (key.equals("key1") || key.equals("key2")) {
                assertEquals(mo2.get(key), value);
            } else if (mo2.has(key)) {
                assertEquals(mo2.get(key), value);
            } else {
                assertEquals(mo1.get(key), value);
            }
        }
    }

    @Test
    public void objectHash() throws MslEncoderException {
        final MslObject mo1 = deepMo;
        final MslObject mo2 = new MslObject(mo1.getMap());
        assertTrue(MslEncoderUtils.equalObjects(mo1, mo2));
        assertEquals(MslEncoderUtils.hashObject(mo2), MslEncoderUtils.hashObject(mo1));

        final String[] keys = mo1.getKeys().toArray(new String[0]);
        final String key = keys[0];
        final Object value = mo1.get(key);
        mo1.remove(key);
        mo1.put(key + "x", value);
        assertFalse(MslEncoderUtils.equalObjects(mo1, mo2));
        assertNotEquals(MslEncoderUtils.hashObject(mo2), MslEncoderUtils.hashObject(mo1));
        mo1.put(key, value);
        assertFalse(MslEncoderUtils.equalObjects(mo1, mo2));
        assertNotEquals(MslEncoderUtils.hashObject(mo2), MslEncoderUtils.hashObject(mo1));
        mo1.remove(key + "x");
        assertTrue(MslEncoderUtils.equalObjects(mo1, mo2));
        assertEquals(MslEncoderUtils.hashObject(mo2), MslEncoderUtils.hashObject(mo1));
    }

    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;

    private static Random random;
    private static MslObject flatMo, deepMo, nullMo;
    private static MslArray flatMa, deepMa, nullMa;
}
