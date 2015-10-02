/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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

import java.util.Collection;
import java.util.Map;

/**
 * <p>A {@code MslObject} is an unordered collection of name/value pairs. It is
 * functionally equivalent to a JSON object, in that it encodes the pair data
 * without imposing any specific order and may contain more or less pairs than
 * explicitly defined.</p>
 * 
 * <p>The values can be any of these types: <code>Boolean</code>,
 * <code>Byte[]</code> <code>MslArray</code>, <code>MslObject</code>,
 * <code>Number</code>, or <code>String</code>.</p>
 * 
 * <p>The generic <code>get()</code> and <code>opt()</code> methods return
 * an object, which you can cast or query for type. There are also typed
 * <code>get</code> and <code>opt</code> methods that do type checking and type
 * coercion for you. The opt methods differ from the get methods in that they
 * do not throw. Instead, they return a specified value, such as null.</p>
 * 
 * <p>The <code>put</code> methods add or replace values in an object.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface MslObject {
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value or the value
     *         is {@code null}.
     */
    public Object get(final String key) throws MslEncoderException;
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public boolean getBoolean(final String key) throws MslEncoderException;
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public byte[] getBytes(final String key) throws MslEncoderException;
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public double getDouble(final String key) throws MslEncoderException;
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public int getInt(final String key) throws MslEncoderException;
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public MslArray getMslArray(final String key) throws MslEncoderException;
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public MslObject getMslObject(final String key) throws MslEncoderException;
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public long getLong(final String key) throws MslEncoderException;
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public String getString(final String key) throws MslEncoderException;

    /**
     * Return true if the specified key exists. The value may be {@code null}.
     * 
     * @param key the key.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public boolean has(final String key);

    /**
     * Return the value associated with the specified key or {@code null} if
     * the key is unknown.
     * 
     * @param key the key.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public Object opt(final String key);

    /**
     * Return the value associated with the specified key or {@code false} if
     * the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public boolean optBoolean(final String key);

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public boolean optBoolean(final String key, final boolean defaultValue);

    /**
     * Return the value associated with the specified key or an empty byte
     * array if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public byte[] optBytes(final String key);

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public byte[] optBytes(final String key, final byte[] defaultValue);

    /**
     * Return the value associated with the specified key or {@code NaN} if
     * the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public double optDouble(final String key);

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public double optDouble(final String key, final double defaultValue);

    /**
     * Return the value associated with the specified key or zero if
     * the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public int optInt(final String key);

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public int optInt(final String key, final int defaultValue);
    
    /**
     * Return the {@code MslArray} associated with the specified key or
     * {@code null} if the key is unknown or the value is not of the correct
     * type.
     * 
     * @param key the key.
     * @return the {@code MslArray}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslArray optMslArray(final String key);

    /**
     * Return the {@code MslObject} associated with the specified key or
     * {@code null} if the key unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the {@code MslObject}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject optMslObject(final String key);

    /**
     * Return the value associated with the specified key or zero if
     * the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public long optLong(final String key);

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public long optLong(final String key, final long defaultValue);

    /**
     * Return the value associated with the specified key or the empty string
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public String optString(final String key);

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public String optString(final String key, final String defaultValue);

    /**
     * Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null} or the
     *         value is of an unsupported type or value.
     */
    public MslObject put(final String key, final Object value);
    
    /**
     * Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putBoolean(final String key, final boolean value);

    /**
     * Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putBytes(final String key, final byte[] value);

    /**
     * Put a key/value pair into the {@code MslObject}. The collection of
     * elements will be transformed into a {@code MslArray}. If the value is
     * {@code null} the key will be removed.
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putCollection(final String key, final Collection<Object> value);

    /**
     * Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putDouble(final String key, final double value);

    /**
     * Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putInt(final String key, final int value);

    /**
     * Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putLong(final String key, final long value);

    /**
     * Put a key/value pair into the {@code MslObject}. The map of strings onto
     * objects will be transformed into a {@code MslObject}. If the value is
     * {@code null} the key will be removed.
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putMap(final String key, final Map<String,Object> value);
    
    /**
     * Remove a key and its associated value from the {@code MslObject}.
     * 
     * @param key the key.
     * @return the removed value. May be {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public Object remove(final String key);
    
    /**
     * Return a map of the {@code MslObject} contents.
     * 
     * @return the map of {@code MslObject} contents.
     */
    public Map<String,Object> getMap();
    
    /**
     * Encode the {@code MslObject} into its binary form.
     * 
     * @return the encoded form of the {@code MslObject}.
     * @throws MslEncoderException if there is an error generating the encoding.
     */
    public byte[] getEncoded() throws MslEncoderException;
}
