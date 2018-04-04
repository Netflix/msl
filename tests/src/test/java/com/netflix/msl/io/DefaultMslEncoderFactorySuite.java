/**
 * Copyright (c) 2017-2018 Netflix, Inc.  All rights reserved.
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.msg.Header;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.msg.MessageHeader;
import com.netflix.msl.msg.MessageHeader.HeaderData;
import com.netflix.msl.msg.MessageHeader.HeaderPeerData;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.PayloadChunk;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * MSL encoder factory tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({DefaultMslEncoderFactorySuite.Tokenizer.class,
               DefaultMslEncoderFactorySuite.Container.class,
               DefaultMslEncoderFactorySuite.Accessor.class,
               DefaultMslEncoderFactorySuite.Encoding.class})
public class DefaultMslEncoderFactorySuite {
    /** Maximum number of object fields or array elements. */
    private static final int MAX_NUM_ELEMENTS = 20;
    /** MSL object base key name. */
    private static final String MSL_OBJECT_KEY = "KEY";
    
    /** MSL context. */
    private static MslContext ctx = null;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Random. */
    private static Random random = null;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        if (ctx == null) {
            ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            encoder = new DefaultMslEncoderFactory();
            random = ctx.getRandom();
        }
    }
    
    @AfterClass
    public static void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }

    /**
     * @return a random type.
     */
    private static Class<?> getRandomType() {
        final int i = random.nextInt(8);
        switch (i) {
            case 0:
                return Boolean.class;
            case 1:
                return byte[].class;
            case 2:
                return Double.class;
            case 3:
                return Integer.class;
            case 4:
                return MslArray.class;
            case 5:
                return MslObject.class;
            case 6:
                return Long.class;
            default:
                return String.class;
        }
    }

    /**
     * @param type the type. May be {@code null}.
     * @return a randomly generated object of the specified type or
     *         {@code null} if the type is {@code null}.
     */
    private static Object createTypedValue(final Class<?> type) {
        if (Boolean.class.equals(type))
            return random.nextBoolean();
        if (byte[].class.equals(type)) {
            final byte[] b = new byte[random.nextInt(10)];
            random.nextBytes(b);
            return b;
        }
        if (Double.class.equals(type))
            return random.nextDouble();
        if (Integer.class.equals(type))
            return random.nextInt();
        if (MslArray.class.equals(type)) {
            final MslArray ma = encoder.createArray();
            final Class<?> innerType = getRandomType();
            ma.put(-1, createTypedValue(innerType));
            return ma;
        }
        if (MslObject.class.equals(type)) {
            final MslObject mo = encoder.createObject();
            final Class<?> innerType = getRandomType();
            mo.put(MSL_OBJECT_KEY, createTypedValue(innerType));
            return mo;
        }
        if (Long.class.equals(type))
            return random.nextLong();
        if (String.class.equals(type))
            return "STRING";
        return null;
    }
    
    /**
     * @return a randomly generated object of a random type.
     */
    private static Object createRandomValue() {
        final Class<?> type = getRandomType();
        return createTypedValue(type);
    }
    
    /**
     * Returns the value found in the MSL object for the given key. The
     * value will be retrieved using the getter method that explicitly
     * matches the expected type. For type {@code null} the untyped getter
     * method is used.
     * 
     * @param key MSL object key.
     * @param type the expected type. May be {@code null}.
     * @param mo the MSL object.
     * @return the MSL object's value.
     * @throws MslEncoderException if the value type is not equal to the
     *         expected type.
     */
    private static Object getTypedField(final String key, final Class<?> type, final MslObject mo) throws MslEncoderException {
        if (Boolean.class.equals(type))
            return mo.getBoolean(key);
        if (byte[].class.equals(type))
            return mo.getBytes(key);
        if (Double.class.equals(type))
            return mo.getDouble(key);
        if (Integer.class.equals(type))
            return mo.getInt(key);
        if (MslArray.class.equals(type))
            return mo.getMslArray(key);
        if (MslObject.class.equals(type))
            return mo.getMslObject(key, encoder);
        if (Long.class.equals(type))
            return mo.getLong(key);
        if (String.class.equals(type))
            return mo.getString(key);
        return mo.get(key);
    }
    
    /**
     * Returns the value found in the MSL object for the given key. The
     * value will be retrieved using the optional method that explicitly
     * matches the expected type. For type {@code null} the untyped optional
     * method is used.
     * 
     * @param key MSL object key.
     * @param type the expected type. May be {@code null}.
     * @param mo the MSL object.
     * @return the MSL object's value.
     */
    private static Object optTypedField(final String key, final Class<?> type, final MslObject mo) {
        if (Boolean.class.equals(type))
            return mo.optBoolean(key);
        if (byte[].class.equals(type))
            return mo.optBytes(key);
        if (Double.class.equals(type))
            return mo.optDouble(key);
        if (Integer.class.equals(type))
            return mo.optInt(key);
        if (MslArray.class.equals(type))
            return mo.optMslArray(key);
        if (MslObject.class.equals(type))
            return mo.optMslObject(key, encoder);
        if (Long.class.equals(type))
            return mo.optLong(key);
        if (String.class.equals(type))
            return mo.optString(key);
        return mo.opt(key);
    }
    
    /**
     * Returns the value found in the MSL object for the given key. The
     * value will be retrieved using the optional method that explicitly
     * matches the expected type. For type {@code null} the untyped optional
     * method is used.
     * 
     * @param key MSL object key.
     * @param type the expected type. May be {@code null}.
     * @param mo the MSL object.
     * @return the MSL object's value.
     */
    private static Object optDefaultTypedField(final String key, final Class<?> type, final MslObject mo) {
        if (Boolean.class.equals(type))
            return mo.optBoolean(key, false);
        if (byte[].class.equals(type))
            return mo.optBytes(key, new byte[0]);
        if (Double.class.equals(type))
            return mo.optDouble(key, Double.NaN);
        if (Integer.class.equals(type))
            return mo.optInt(key, 0);
        if (MslArray.class.equals(type))
            return mo.optMslArray(key);
        if (MslObject.class.equals(type))
            return mo.optMslObject(key, encoder);
        if (Long.class.equals(type))
            return mo.optLong(key, 0);
        if (String.class.equals(type))
            return mo.optString(key, "");
        return mo.opt(key);
    }
    
    /**
     * Put a key/value pair into the MSL object. The value will be added using
     * the put method that explicitly matches the specified type. For type
     * {@code null} the untyped put method is used.
     * 
     * @param key MSL object key.
     * @param type the specified type. May be {@code null}.
     * @param value the value.
     * @param mo the MSL object.
     */
    private static void putTypedField(final String key, final Class<?> type, final Object value, final MslObject mo) {
        if (Boolean.class.equals(type))
            mo.putBoolean(key, (Boolean)value);
        if (byte[].class.equals(type))
            mo.putBytes(key, (byte[])value);
        if (Double.class.equals(type))
            mo.putDouble(key, (Double)value);
        if (Integer.class.equals(type))
            mo.putInt(key, (Integer)value);
        if (MslArray.class.equals(type))
            mo.putCollection(key, (value != null) ? ((MslArray)value).getCollection() : null);
        if (MslObject.class.equals(type))
            mo.putMap(key, (value != null) ? ((MslObject)value).getMap() : null);
        if (Long.class.equals(type))
            mo.putLong(key, (Long)value);
        if (String.class.equals(type))
            mo.putString(key, (String)value);
        mo.put(key, value);
    }
    
    /**
     * Returns the value found in the MSL array at the given index. The
     * value will be retrieved using the getter method that explicitly
     * matches the expected type. For type {@code null} the untyped getter
     * method is used.
     * 
     * @param index MSL array index.
     * @param type the expected type. May be {@code null}.
     * @param ma the MSL array.
     * @return the MSL array's element.
     * @throws MslEncoderException if the value type is not equal to the
     *         expected type.
     */
    private static Object getTypedElement(final int index, final Class<?> type, final MslArray ma) throws MslEncoderException {
        if (Boolean.class.equals(type))
            return ma.getBoolean(index);
        if (byte[].class.equals(type))
            return ma.getBytes(index);
        if (Double.class.equals(type))
            return ma.getDouble(index);
        if (Integer.class.equals(type))
            return ma.getInt(index);
        if (MslArray.class.equals(type))
            return ma.getMslArray(index);
        if (MslObject.class.equals(type))
            return ma.getMslObject(index, encoder);
        if (Long.class.equals(type))
            return ma.getLong(index);
        if (String.class.equals(type))
            return ma.getString(index);
        return ma.get(index);
    }

    /**
     * Returns the value found in the MSL array at the given index. The
     * value will be retrieved using the optional method that explicitly
     * matches the expected type. For type {@code null} the untyped optional
     * method is used.
     * 
     * @param index MSL array index.
     * @param type the expected type. May be {@code null}.
     * @param ma the MSL array.
     * @return the MSL array's element.
     */
    private static Object optTypedElement(final int index, final Class<?> type, final MslArray ma) {
        if (Boolean.class.equals(type))
            return ma.optBoolean(index);
        if (byte[].class.equals(type))
            return ma.optBytes(index);
        if (Double.class.equals(type))
            return ma.optDouble(index);
        if (Integer.class.equals(type))
            return ma.optInt(index);
        if (MslArray.class.equals(type))
            return ma.optMslArray(index);
        if (MslObject.class.equals(type))
            return ma.optMslObject(index, encoder);
        if (Long.class.equals(type))
            return ma.optLong(index);
        if (String.class.equals(type))
            return ma.optString(index);
        return ma.opt(index);
    }

    /**
     * Returns the value found in the MSL array at the given index. The
     * value will be retrieved using the optional method that explicitly
     * matches the expected type. For type {@code null} the untyped optional
     * method is used.
     * 
     * @param index MSL array index.
     * @param type the expected type. May be {@code null}.
     * @param ma the MSL array.
     * @return the MSL array's element.
     */
    private static Object optDefaultTypedElement(final int index, final Class<?> type, final MslArray ma) {
        if (Boolean.class.equals(type))
            return ma.optBoolean(index, false);
        if (byte[].class.equals(type))
            return ma.optBytes(index, new byte[0]);
        if (Double.class.equals(type))
            return ma.optDouble(index, Double.NaN);
        if (Integer.class.equals(type))
            return ma.optInt(index, 0);
        if (MslArray.class.equals(type))
            return ma.optMslArray(index);
        if (MslObject.class.equals(type))
            return ma.optMslObject(index, encoder);
        if (Long.class.equals(type))
            return ma.optLong(index, 0);
        if (String.class.equals(type))
            return ma.optString(index, "");
        return ma.opt(index);
    }

    /**
     * Put a value into the MSL array at the specified index. The value will be
     * added using the put method that explicitly matches the specified type.
     * For type {@code null} the untyped put method is used.
     * 
     * @param key MSL object key.
     * @param type the specified type. May be {@code null}.
     * @param value the value.
     * @param mo the MSL object.
     */
    private static void putTypedElement(final int index, final Class<?> type, final Object value, final MslArray ma) {
        if (Boolean.class.equals(type))
            ma.putBoolean(index, (Boolean)value);
        if (byte[].class.equals(type))
            ma.putBytes(index, (byte[])value);
        if (Double.class.equals(type))
            ma.putDouble(index, (Double)value);
        if (Integer.class.equals(type))
            ma.putInt(index, (Integer)value);
        if (MslArray.class.equals(type))
            ma.putCollection(index, (value != null) ? ((MslArray)value).getCollection() : null);
        if (MslObject.class.equals(type))
            ma.putMap(index, (value != null) ? ((MslObject)value).getMap() : null);
        if (Long.class.equals(type))
            ma.putLong(index, (Long)value);
        if (String.class.equals(type))
            ma.putString(index, (String)value);
        ma.put(index, value);
    }
    
    /** Tokenizer unit tests. */
    @RunWith(Parameterized.class)
    public static class Tokenizer {
        /** Example payloads. */
        private static final byte[][] PAYLOADS = {
            "payload1".getBytes(MslConstants.DEFAULT_CHARSET),
            "payload2".getBytes(MslConstants.DEFAULT_CHARSET),
        };
        
        @Rule
        public ExpectedException thrown = ExpectedException.none();
        
        @Parameters
        public static Collection<Object[]> data() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, IOException {
            DefaultMslEncoderFactorySuite.setup();
            
            // JSON encoder format.
            final Set<MslEncoderFormat> jsonFormat = new HashSet<MslEncoderFormat>();
            jsonFormat.add(MslEncoderFormat.JSON);
            final MessageCapabilities jsonCaps = new MessageCapabilities(null, null, jsonFormat);
            
            // Create MSL message.
            final ByteArrayOutputStream destination = new ByteArrayOutputStream();
            final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
            final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
            
            // Create JSON version.
            final HeaderData jsonHeaderData = new HeaderData(1, null, false, false, jsonCaps, null, null, null, null, null);
            final MessageHeader jsonMessageHeader = new MessageHeader(ctx, entityAuthData, null, jsonHeaderData, peerData);
            final ICryptoContext jsonCryptoContext = jsonMessageHeader.getCryptoContext();
            final MessageOutputStream jsonMos = new MessageOutputStream(ctx, destination, jsonMessageHeader, jsonCryptoContext);
            for (final byte[] payload : PAYLOADS) {
                jsonMos.write(payload);
                jsonMos.flush();
            }
            jsonMos.close();
            
            // JSON.
            final byte[] jsonMessageData = destination.toByteArray();
            
            // Unsupported.
            final byte[] unsupportedMessageData = Arrays.copyOf(jsonMessageData, jsonMessageData.length);
            unsupportedMessageData[0] = '1';
            
            // Parameters.
            return Arrays.asList(new Object[][] {
                { jsonMessageData, null },
                { unsupportedMessageData, MslEncoderException.class },
            });
        }
        
        /** Encoded message. */
        private final byte[] messageData;
        /** Expected exception class. */
        private final Class<? extends Exception> exceptionClass;
        
        /**
         * Create a new MSL encoder factory test instance with the specified
         * encoding format and provided message data.
         * 
         * @param messageData encoded message.
         * @param exceptionClass expected exception class.
         */
        public Tokenizer(final byte[] messageData, final Class<? extends Exception> exceptionClass) {
            this.messageData = messageData;
            this.exceptionClass = exceptionClass;
        }
        
        @Test
        public void detectTokenizer() throws IOException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslMessageException, MslException {
            if (exceptionClass != null)
                thrown.expect(exceptionClass);
            
            // Create the tokenizer.
            final InputStream source = new ByteArrayInputStream(messageData);
            final MslTokenizer tokenizer = encoder.createTokenizer(source);
            assertNotNull(tokenizer);
            
            // Pull data off the tokenizer.
            final List<MslObject> objects = new ArrayList<MslObject>();
            while (tokenizer.more(-1)) {
                final MslObject object = tokenizer.nextObject(-1);
                assertNotNull(object);
                objects.add(object);
            }
            // +1 for the header, +1 for the EOM payload.
            assertEquals(PAYLOADS.length + 2, objects.size());
            assertNull(tokenizer.nextObject(-1));
            
            // Pull message header.
            final MslObject headerO = objects.get(0);
            final Map<String,ICryptoContext> cryptoContexts = Collections.emptyMap();
            final Header header = Header.parseHeader(ctx, headerO, cryptoContexts);
            assertTrue(header instanceof MessageHeader);
            final MessageHeader messageHeader = (MessageHeader)header;
            
            // Verify payloads.
            final ICryptoContext payloadCryptoContext = messageHeader.getCryptoContext();
            for (int i = 0; i < PAYLOADS.length; ++i) {
                final byte[] expectedPayload = PAYLOADS[i];
                final MslObject payloadMo = objects.get(i + 1);
                final PayloadChunk payload = new PayloadChunk(ctx, payloadMo, payloadCryptoContext);
                final byte[] data = payload.getData();
                assertArrayEquals(expectedPayload, data);
            }
            
            // Close tokenizer.
            tokenizer.close();
        }
    }
    
    /** Container unit tests. */
    public static class Container {
        /**
         * Compare two numbers. The expected value is the original value. The
         * candidate value is the value that was the original was converted
         * into when retrieving it from the container.
         * 
         * @param expected the expected value.
         * @param candidate the value to test.
         * @return true if the two numbers are equal.
         */
        private static boolean numbersEqual(final Number expected, final Number candidate) {
            // Take the expected value and convert it to the candidate value's
            // type.
            if (candidate instanceof Integer)
                return expected.intValue() == candidate.intValue();
            if (candidate instanceof Long)
                return expected.longValue() == candidate.longValue();
            if (candidate instanceof Double)
                return expected.doubleValue() == candidate.doubleValue();
            return false;
        }
        
        @Rule
        public ExpectedException thrown = ExpectedException.none();
        
        @BeforeClass
        public static void setup() throws MslEncodingException, MslCryptoException {
            DefaultMslEncoderFactorySuite.setup();
        }

        @Test
        public void createObject() throws MslEncoderException {
            // Create the object.
            final MslObject mo = encoder.createObject();
            assertNotNull(mo);

            // Populate it with some stuff.
            final Map<String,Object> map = new HashMap<String,Object>();
            for (int i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                final String key = MSL_OBJECT_KEY + ":" + i;
                final Object value = createRandomValue();
                map.put(key, value);
                mo.put(key, value);
            }

            // Verify object state.
            for (final String key : map.keySet()) {
                final Object expected = map.get(key);
                final Object value = mo.get(key);
                assertEquals(expected, value);
                final Object typedValue = getTypedField(key, expected.getClass(), mo);
                assertEquals(expected, typedValue);
            }
            
            // Verify opt functions.
            for (final String key : map.keySet()) {
                final Object expected = map.get(key);
                final Object value = mo.opt(key);
                assertEquals(expected, value);
                final Object typedValue = optTypedField(key, expected.getClass(), mo);
                assertEquals(expected, typedValue);
            }
            
            // Verify opt functions with mismatched type.
            for (final String key : map.keySet()) {
                final Object expected = map.get(key);
                final Class<?> randomType = getRandomType();
                final Object typedValue = optTypedField(key, randomType, mo);
                
                // opt function returns the value if the type is correct...
                if (expected.getClass().equals(randomType)) {
                    assertEquals(expected, typedValue);
                }
                // Boolean expects false...
                else if (Boolean.class.equals(randomType)) {
                    assertTrue(typedValue instanceof Boolean);
                    assertFalse((Boolean)typedValue);
                }
                // Numbers may be cross-retrieved...
                else if (expected instanceof Number &&
                    (Integer.class.equals(randomType) ||
                     Long.class.equals(randomType) ||
                     Double.class.equals(randomType)))
                {
                    assertTrue(numbersEqual((Number)expected, (Number)typedValue));
                }
                // Double expects NaN...
                else if (Double.class.equals(randomType)) {
                    assertTrue(typedValue instanceof Double);
                    assertEquals(Double.valueOf(Double.NaN), typedValue);
                }
                // Numbers expect zero...
                else if (Integer.class.equals(randomType) || Long.class.equals(randomType)) {
                    assertTrue(typedValue instanceof Number);
                    assertEquals(0, ((Number)typedValue).longValue());
                }
                // byte[] expects an empty byte array...
                else if (byte[].class.equals(randomType)) {
                    assertTrue(typedValue instanceof byte[]);
                    assertArrayEquals(new byte[0], (byte[])typedValue);
                }
                // String expects the empty string...
                else if (String.class.equals(randomType)) {
                    assertTrue(typedValue instanceof String);
                    assertEquals("", typedValue);
                }
                // Everything else expects null.
                else {
                    assertNull(typedValue);
                }
            }
            
            // Verify opt functions with default value.
            assertTrue(mo.optBoolean("boolean", true));
            final byte[] b = new byte[10];
            random.nextBytes(b);
            assertArrayEquals(b, mo.optBytes("bytes", b));
            final Double d = random.nextDouble();
            assertEquals(d, Double.valueOf(mo.optDouble("double", d)));
            final Integer i = random.nextInt();
            assertEquals(i, Integer.valueOf(mo.optInt("integer", i)));
            assertNull(mo.optMslArray("array"));
            assertNull(mo.optMslObject("object", encoder));
            final Long l = random.nextLong();
            assertEquals(l, Long.valueOf(mo.optLong("long", l)));
            final String s = new String(b);
            assertEquals(s, mo.optString("string", s));
        }

        @Test
        public void createObjectFromMap() throws MslEncoderException {
            // Generate some values.
            final Map<String,Object> map = new HashMap<String,Object>();
            for (int i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                final String key = MSL_OBJECT_KEY + ":" + i;
                final Object value = createRandomValue();
                map.put(key, value);
            }

            // Create the object.
            final MslObject mo = encoder.createObject(map);
            assertNotNull(mo);

            // Verify object state.
            for (final String key : map.keySet()) {
                final Object expected = map.get(key);
                final Object value = mo.get(key);
                assertEquals(expected, value);
                final Object typedValue = getTypedField(key, expected.getClass(), mo);
                assertEquals(expected, typedValue);
            }
        }

        @Test
        public void createArray() throws MslEncoderException {
            // Create the array.
            final MslArray ma = encoder.createArray();
            assertNotNull(ma);

            // Populate it with some stuff.
            final List<Object> list = new ArrayList<Object>();
            for (int i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                final Object value = createRandomValue();
                list.add(value);
                ma.put(-1, value);
            }

            // Verify array state.
            for (int i = 0; i < list.size(); ++i) {
                final Object expected = list.get(i);
                final Object value = ma.get(i);
                assertEquals(expected, value);
                final Object typedValue = getTypedElement(i, expected.getClass(), ma);
                assertEquals(expected, typedValue);
            }
            
            // Verify opt functions.
            for (int i = 0; i < list.size(); ++i) {
                final Object expected = list.get(i);
                final Object value = ma.opt(i);
                assertEquals(expected, value);
                final Object typedValue = optTypedElement(i, expected.getClass(), ma);
                assertEquals(expected, typedValue);
            }
            
            // Verify opt functions with mismatched type.
            for (int i = 0; i < list.size(); ++i) {
                final Object expected = list.get(i);
                final Class<?> randomType = getRandomType();
                final Object typedValue = optTypedElement(i, randomType, ma);
                
                // opt function returns the value if the type is correct...
                if (expected.getClass().equals(randomType)) {
                    assertEquals(expected, typedValue);
                }
                // Boolean expects false...
                else if (Boolean.class.equals(randomType)) {
                    assertTrue(typedValue instanceof Boolean);
                    assertFalse((Boolean)typedValue);
                }
                // Numbers may be cross-retrieved...
                else if (expected instanceof Number &&
                    (Integer.class.equals(randomType) ||
                     Long.class.equals(randomType) ||
                     Double.class.equals(randomType)))
                {
                    assertTrue(numbersEqual((Number)expected, (Number)typedValue));
                }
                // Double expects NaN...
                else if (Double.class.equals(randomType)) {
                    assertTrue(typedValue instanceof Double);
                    assertEquals(Double.valueOf(Double.NaN), typedValue);
                }
                // Numbers expect zero...
                else if (Integer.class.equals(randomType) || Long.class.equals(randomType)) {
                    assertTrue(typedValue instanceof Number);
                    assertEquals(0L, ((Number)typedValue).longValue());
                }
                // byte[] expects an empty byte array...
                else if (byte[].class.equals(randomType)) {
                    assertTrue(typedValue instanceof byte[]);
                    assertArrayEquals(new byte[0], (byte[])typedValue);
                }
                // String expects the empty string...
                else if (String.class.equals(randomType)) {
                    assertTrue(typedValue instanceof String);
                    assertEquals("", typedValue);
                }
                // Everything else expects null.
                else {
                    assertNull(typedValue);
                }
            }
            
            // Verify opt functions with default value.
            ma.put(0, null);
            assertTrue(ma.optBoolean(0, true));
            final byte[] b = new byte[10];
            random.nextBytes(b);
            assertArrayEquals(b, ma.optBytes(0, b));
            final Double d = random.nextDouble();
            assertEquals(d, Double.valueOf(ma.optDouble(0, d)));
            final Integer i = random.nextInt();
            assertEquals(i, Integer.valueOf(ma.optInt(0, i)));
            assertNull(ma.optMslArray(0));
            assertNull(ma.optMslObject(0, encoder));
            final Long l = random.nextLong();
            assertEquals(l, Long.valueOf(ma.optLong(0, l)));
            final String s = new String(b);
            assertEquals(s, ma.optString(0, s));
        }

        @Test
        public void createArrayFromCollection() throws MslEncoderException {
            // Generate some elements.
            final List<Object> list = new ArrayList<Object>();
            for (int i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                final Object value = createRandomValue();
                list.add(value);
            }

            // Create the array.
            final MslArray ma = encoder.createArray(list);
            assertNotNull(ma);

            // Verify array state.
            for (int i = 0; i < list.size(); ++i) {
                final Object expected = list.get(i);
                final Object value = ma.get(i);
                assertEquals(expected, value);
                final Object typedValue = getTypedElement(i, expected.getClass(), ma);
                assertEquals(expected, typedValue);
            }
        }
    }
    
    /** Accessor unit tests. */
    @RunWith(Parameterized.class)
    public static class Accessor {
        @Rule
        public ExpectedException thrown = ExpectedException.none();
        
        @Parameters
        public static Collection<Object[]> data() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, IOException {
            DefaultMslEncoderFactorySuite.setup();
            
            // Parameters.
            return Arrays.asList(new Object[][] {
                { null },
                { Boolean.class },
                { byte[].class },
                { Double.class },
                { Integer.class },
                { MslArray.class },
                { MslObject.class },
                { Long.class },
                { String.class },
            });
        }
        
        /** Accessor type. May be null. */
        private final Class<?> type;
        
        /**
         * @param type value or element type.
         */
        public Accessor(final Class<?> type) {
            this.type = type;
        }
        
        @Test
        public void objectGetKeyNull() throws MslEncoderException {
            thrown.expect(IllegalArgumentException.class);
            
            final MslObject mo = encoder.createObject();
            getTypedField(null, type, mo);
        }
        
        @Test
        public void objectGetValueNull() throws MslEncoderException {
            thrown.expect(MslEncoderException.class);
            
            final MslObject mo = encoder.createObject();
            getTypedField(MSL_OBJECT_KEY, type, mo);
        }
        
        @Test
        public void objectOptKeyNull() {
            thrown.expect(IllegalArgumentException.class);
            
            final MslObject mo = encoder.createObject();
            optTypedField(null, type, mo);
        }
        
        @Test
        public void objectOptDefaultKeyNull() {
            thrown.expect(IllegalArgumentException.class);
            
            final MslObject mo = encoder.createObject();
            optDefaultTypedField(null, type, mo);
        }
        
        @Test
        public void objectPutKeyNull() {
            thrown.expect(IllegalArgumentException.class);
            
            final MslObject mo = encoder.createObject();
            final Object value = createTypedValue(type);
            putTypedField(null, type, value, mo);
        }
        
        @Test
        public void objectPutValueNull() {
            // Null value is incompatible with this test.
            if (type != null) {
                final MslObject mo = encoder.createObject();
                final Object value = createTypedValue(type);
                putTypedField(MSL_OBJECT_KEY, type, value, mo);
                assertTrue(mo.has(MSL_OBJECT_KEY));
                putTypedField(MSL_OBJECT_KEY, type, null, mo);
                assertFalse(mo.has(MSL_OBJECT_KEY));
            }
        }
        
        @Test
        public void arrayGetIndexNegative() throws MslEncoderException {
            thrown.expect(ArrayIndexOutOfBoundsException.class);
            
            final MslArray ma = encoder.createArray();
            getTypedElement(-1, type, ma);
        }
        
        @Test
        public void arrayGetElementNull() throws MslEncoderException {
            thrown.expect(MslEncoderException.class);
            
            final MslArray ma = encoder.createArray();
            putTypedElement(0, type, null, ma);
            assertEquals(1, ma.size());
            getTypedElement(0, type, ma);
        }
        
        @Test
        public void arrayOptIndexNegative() {
            thrown.expect(ArrayIndexOutOfBoundsException.class);
            
            final MslArray ma = encoder.createArray();
            optTypedElement(-1, type, ma);
        }
        
        @Test
        public void arrayOptDefaultIndexNegative() {
            thrown.expect(ArrayIndexOutOfBoundsException.class);
            
            final MslArray ma = encoder.createArray();
            optDefaultTypedElement(-1, type, ma);
        }

        @Test
        public void arrayGetIndexTooBig() throws MslEncoderException {
            thrown.expect(ArrayIndexOutOfBoundsException.class);
            
            final MslArray ma = encoder.createArray();
            getTypedElement(ma.size(), type, ma);
        }
        
        @Test
        public void arrayOptIndexTooBig() {
            thrown.expect(ArrayIndexOutOfBoundsException.class);
            
            final MslArray ma = encoder.createArray();
            optTypedElement(ma.size(), type, ma);
        }
        
        @Test
        public void arrayOptDefaultIndexTooBig() {
            thrown.expect(ArrayIndexOutOfBoundsException.class);
            
            final MslArray ma = encoder.createArray();
            optDefaultTypedElement(ma.size(), type, ma);
        }
        
        @Test
        public void arrayPutIndexNegative() {
            thrown.expect(ArrayIndexOutOfBoundsException.class);
            
            final MslArray ma = encoder.createArray();
            final Object value = createTypedValue(type);
            putTypedElement(-2, type, value, ma);
        }
    }
    
    /** Encoding unit tests. */
    @RunWith(Parameterized.class)
    public static class Encoding {
        @Rule
        public ExpectedException thrown = ExpectedException.none();

        @Parameters
        public static Collection<Object[]> data() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, IOException {
            DefaultMslEncoderFactorySuite.setup();
            
            // Parameters.
            return Arrays.asList(new Object[][] {
                { MslEncoderFormat.JSON },
            });
        }
        
        /** MSL encoder format. */
        private final MslEncoderFormat format;
        
        /**
         * @param format MSL encoder format.
         */
        public Encoding(final MslEncoderFormat format) {
            this.format = format;
        }

        @Test
        public void encodeAndParseObject() throws MslEncoderException {
            // Generate some values.
            final Map<String,Object> map = new HashMap<String,Object>();
            for (int i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                final String key = MSL_OBJECT_KEY + ":" + i;
                final Object value = createRandomValue();
                map.put(key, value);
            }

            // Create the object.
            final MslObject mo = encoder.createObject(map);
            assertNotNull(mo);

            // Encode.
            final byte[] encode = encoder.encodeObject(mo, format);
            assertNotNull(encode);
            
            // Parse.
            final MslObject parsedMo = encoder.parseObject(encode);
            assertTrue(MslEncoderUtils.equalObjects(mo, parsedMo));
        }

        @Test
        public void parseInvalidObject() throws MslEncoderException {
            thrown.expect(MslEncoderException.class);
            
            // Generate some values.
            final Map<String,Object> map = new HashMap<String,Object>();
            for (int i = 0; i < MAX_NUM_ELEMENTS; ++i) {
                final String key = MSL_OBJECT_KEY + ":" + i;
                final Object value = createRandomValue();
                map.put(key, value);
            }

            // Create the object.
            final MslObject mo = encoder.createObject(map);
            assertNotNull(mo);

            // Encode.
            final byte[] encode = encoder.encodeObject(mo, format);
            assertNotNull(encode);

            // Corrupt the encode.
            encode[0] = 0;
            encode[encode.length - 1] = 'x';
            
            // Parse.
            encoder.parseObject(encode);
        }
    }
}
