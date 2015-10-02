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
 * <p>A {@code MslArray} is an ordered sequence of values.</p>
 * 
 * <p>The values can be any of these types: <code>Boolean</code>,
 * <code>Byte[]</code> <code>MslArray</code>, <code>MslObject</code>,
 * <code>Number</code>, or <code>String</code>.</p>
 * 
 * <p>The generic <code>get()</code> and <code>opt()</code> methods return an
 * object, which you can cast or query for type. There are also typed
 * <code>get</code> and <code>opt</code> methods that do type checking and type
 * coercion for you. The opt methods differ from the get methods in that they
 * do not throw. Instead, they return a specified value, such as null.</p>
 * 
 * <p>The <code>put</code> methods add or replace values in an object.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface MslArray {
    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null}.
     */
    public Object get(final int index) throws MslEncoderException;

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null}.
     */
    public boolean getBoolean(final int index) throws MslEncoderException;

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null}.
     */
    public byte[] getBytes(final int index) throws MslEncoderException;

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null}.
     */
    public double getDouble(final int index) throws MslEncoderException;

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null}.
     */
    public int getInt(final int index) throws MslEncoderException;

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null}.
     */
    public MslArray getMslArray(final int index) throws MslEncoderException;

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null}.
     */
    public MslObject getMslObject(final int index) throws MslEncoderException;

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null}.
     */
    public long getLong(final int index) throws MslEncoderException;

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null}.
     */
    public String getString(final int index) throws MslEncoderException;

    /**
     * Return true if the value at the index is {@code null}.
     * 
     * @param index the index.
     * @return true if the value is null.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public boolean isNull(final int index);
    
    /**
     * Return the number of elements in the array, including {@code null}
     * values.
     * 
     * @return the array size.
     */
    public int length();
    
    /**
     * Return the value at the index.
     * 
     * @param index the index.
     * @return the value. May be {@code null}.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public Object opt(final int index);
    
    /**
     * Return the value at the index or {@code false} if the value is not of
     * the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public boolean optBoolean(final int index);
    
    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public boolean optBoolean(final int index, final boolean defaultValue);

    /**
     * Return the value at the index or an empty byte array if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public byte[] optBytes(final int index);

    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public byte[] optBytes(final int index, final byte[] defaultValue);
    
    /**
     * Return the value at the index or {@code NaN} if the value is not of
     * the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public double optDouble(final int index);
    
    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public double optDouble(final int index, final double defaultValue);

    /**
     * Return the value at the index or zero if the value is not of
     * the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public int optInt(final int index);
    
    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public int optInt(final int index, final int defaultValue);

    /**
     * Return the {@code MslArray} at the index or {@code null} if the value
     * is not of the correct type.
     * 
     * @param index the index.
     * @return the {@code MslArray}.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public MslArray optMslArray(final int index);

    /**
     * Return the {@code MslObject} at the index or {@code null} if the value
     * is not of the correct type.
     * 
     * @param index the index.
     * @return the {@code MslObject}.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public MslObject optMslObject(final int index);

    /**
     * Return the value at the index or zero if the value is not of
     * the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public long optLong(final int index);
    
    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public long optLong(final int index, final long defaultValue);

    /**
     * Return the value at the index or the empty string if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public String optString(final int index);
    
    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public String optString(final int index, final String defaultValue);
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray put(final int index, final Object value);
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putBoolean(final int index, final boolean value);
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putBytes(final int index, final byte[] value);
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. The
     * collection of elements will be transformed into a {@code MslArray}. If
     * the index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putCollection(final int index, final Collection<Object> value);
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putDouble(final int index, final double value);
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putInt(final int index, final int value);
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putLong(final int index, final long value);
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. The map of
     * strings onto objects will be transformed into a {@code MslObject}. If
     * the index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putMap(final int index, final Map<String,Object> value);
    
    /**
     * Remove an element at the index. This decreases the length by one.
     * 
     * @param index the index. -1 for the end of the array.
     * @return the removed value. May be {@code null}.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public Object remove(final int index);

    /**
     * Return a collection of the {@code MslArray} contents.
     * 
     * @return the collection of {@code MslArray} contents.
     */
    public Collection<Object> getCollection();
    
    /**
     * Encode the {@code MslArray} into its binary form.
     * 
     * @return the encoded form of the {@code MslArray}.
     * @throws MslEncoderException if there is an error generating the encoding.
     */
    public byte[] getEncoded() throws MslEncoderException;
}
