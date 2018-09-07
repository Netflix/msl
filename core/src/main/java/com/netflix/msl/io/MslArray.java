/**
 * Copyright (c) 2015-2018 Netflix, Inc.  All rights reserved.
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * <p>A {@code MslArray} is an ordered sequence of values.</p>
 * 
 * <p>The values can be any of these types: <code>Boolean</code>,
 * <code>Byte[]</code> <code>MslArray</code>, <code>MslObject</code>,
 * <code>Number</code>, or <code>String</code>. <code>Enum</code> is also
 * accepted and will be converted to a <code>String</code> using its
 * {@code name()} method.</p>
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
public class MslArray {
    /**
     * Create a new empty {@code MslArray}.
     */
    public MslArray() {
    }
    
    /**
     * Create a new {@code MslArray} from the given object array.
     * 
     * @param array the array of values. May be {@code null}.
     * @throws IllegalArgumentException if one of the values is of an
     *         unsupported type.
     */
    public MslArray(final Object[] array) {
        if (array != null) {
            for (final Object o : array)
                put(-1, o);
        }
    }

    /**
     * Create a new {@code MslArray} from the given collection.
     * 
     * @param collection the collection of values. May be {@code null}.
     * @throws IllegalArgumentException if one of the values is of an
     *         unsupported type.
     */
    public MslArray(final Collection<?> collection) {
        if (collection != null) {
            for (final Object o : collection)
                put(-1, o);
        }
    }
    
    /** Object list. */
    private final List<Object> list = new ArrayList<Object>();
    
    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    @SuppressWarnings("unchecked")
    public Object get(final int index) throws MslEncoderException {
        if (index < 0 || index >= list.size())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        final Object o = list.get(index);
        if (o == null)
            throw new MslEncoderException("MslArray[" + index + "] is null.");
        if (o instanceof Map)
            return new MslObject((Map<?,?>)o);
        if (o instanceof Collection)
            return new MslArray((Collection<Object>)o);
        if (o instanceof Object[])
            return new MslArray((Object[])o);
        return o;
    }

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    public boolean getBoolean(final int index) throws MslEncoderException {
        final Object o = get(index);
        if (o instanceof Boolean)
            return (Boolean)o;
        throw new MslEncoderException("MslArray[" + index + "] is not a boolean.");
    }

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    public byte[] getBytes(final int index) throws MslEncoderException {
        final Object o = get(index);
        if (o instanceof byte[])
            return (byte[])o;
        throw new MslEncoderException("MslArray[" + index + "] is not binary data.");
    }

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    public double getDouble(final int index) throws MslEncoderException {
        final Object o = get(index);
        if (o instanceof Number)
            return ((Number)o).doubleValue();
        throw new MslEncoderException("MslArray[" + index + "] is not a number.");
    }

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    public int getInt(final int index) throws MslEncoderException {
        final Object o = get(index);
        if (o instanceof Number)
            return ((Number)o).intValue();
        throw new MslEncoderException("MslArray[" + index + "] is not a number.");
    }

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    @SuppressWarnings("unchecked")
    public MslArray getMslArray(final int index) throws MslEncoderException {
        final Object o = get(index);
        if (o instanceof MslArray)
            return (MslArray)o;
        if (o instanceof Collection)
            return new MslArray((Collection<Object>)o);
        if (o instanceof Object[])
            return new MslArray((Object[])o);
        throw new MslEncoderException("MslArray[" + index + "] is not a MslArray.");
    }

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @param encoder the MSL encoder factory.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    public MslObject getMslObject(final int index, final MslEncoderFactory encoder) throws MslEncoderException {
        final Object o = get(index);
        if (o instanceof MslObject)
            return (MslObject)o;
        /* FIXME: How should we handle MslEncodable?
        if (o instanceof MslEncodable)
            return ((MslEncodable)o).toMslObject(encoder);
        */
        if (o instanceof Map)
            return new MslObject((Map<?,?>)o);
        if (o instanceof byte[]) {
            try {
                return encoder.parseObject((byte[])o);
            } catch (final MslEncoderException e) {
                throw new MslEncoderException("MslObject[" + index + "] is not a MslObject.", e);
            }
        }
        throw new MslEncoderException("MslArray[" + index + "] is not a MslObject.");
    }

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    public long getLong(final int index) throws MslEncoderException {
        final Object o = get(index);
        if (o instanceof Number)
            return ((Number)o).longValue();
        throw new MslEncoderException("MslArray[" + index + "] is not a number.");
    }

    /**
     * Return the value associated with an index.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    public String getString(final int index) throws MslEncoderException {
        final Object o = get(index);
        if (o instanceof String)
            return (String)o;
        throw new MslEncoderException("MslArray[" + index + "] is not a string.");
    }

    /**
     * Return true if the value at the index is {@code null}.
     * 
     * @param index the index.
     * @return true if the value is null.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public boolean isNull(final int index) {
        if (index < 0 || index >= list.size())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return list.get(index) == null;
    }
    
    /**
     * Return the number of elements in the array, including {@code null}
     * values.
     * 
     * @return the array size.
     */
    public int size() {
        return list.size();
    }
    
    /**
     * Return the value at the index, which may be {@code null}. {@code null}
     * will also be returned if the value is an unsupported type.
     * 
     * @param index the index.
     * @return the value. May be {@code null}.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    @SuppressWarnings("unchecked")
    public Object opt(final int index) {
        if (index < 0 || index >= list.size())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        final Object o = list.get(index);
        try {
            if (o instanceof Map)
                return new MslObject((Map<?,?>)o);
            if (o instanceof Collection)
                return new MslArray((Collection<Object>)o);
            if (o instanceof Object[])
                return new MslArray((Object[])o);
        } catch (final IllegalArgumentException e) {
            return null;
        }
        return o;
    }
    
    /**
     * Return the value at the index or {@code false} if the value is not of
     * the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public boolean optBoolean(final int index) {
        return optBoolean(index, false);
    }
    
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
    public boolean optBoolean(final int index, final boolean defaultValue) {
        final Object o = opt(index);
        if (o instanceof Boolean)
            return (Boolean)o;
        return defaultValue;
    }

    /**
     * Return the value at the index or an empty byte array if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public byte[] optBytes(final int index) {
        return optBytes(index, new byte[0]);
    }

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
    public byte[] optBytes(final int index, final byte[] defaultValue) {
        final Object o = opt(index);
        if (o instanceof byte[])
            return (byte[])o;
        return defaultValue;
    }
    
    /**
     * Return the value at the index or {@code NaN} if the value is not of
     * the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public double optDouble(final int index) {
        return optDouble(index, Double.NaN);
    }
    
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
    public double optDouble(final int index, final double defaultValue) {
        final Object o = opt(index);
        if (o instanceof Number)
            return ((Number)o).doubleValue();
        return defaultValue;
    }

    /**
     * Return the value at the index or zero if the value is not of
     * the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public int optInt(final int index) {
        return optInt(index, 0);
    }
    
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
    public int optInt(final int index, final int defaultValue) {
        final Object o = opt(index);
        if (o instanceof Number)
            return ((Number)o).intValue();
        return defaultValue;
    }

    /**
     * Return the {@code MslArray} at the index or {@code null} if the value
     * is not of the correct type.
     * 
     * @param index the index.
     * @return the {@code MslArray} or {@code null}.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    @SuppressWarnings("unchecked")
    public MslArray optMslArray(final int index) {
        final Object o = opt(index);
        if (o instanceof MslArray)
            return (MslArray)o;
        if (o instanceof Collection)
            return new MslArray((Collection<Object>)o);
        if (o instanceof Object[])
            return new MslArray((Object[])o);
        return null;
    }

    /**
     * Return the {@code MslObject} at the index or {@code null} if the value
     * is not of the correct type.
     * 
     * @param index the index.
     * @param encoder the MSL encoder factory.
     * @return the {@code MslObject} or {@code null}.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public MslObject optMslObject(final int index, final MslEncoderFactory encoder) {
        final Object o = opt(index);
        if (o instanceof MslObject)
            return (MslObject)o;
        /* FIXME: How should we handle MslEncodable?
        if (o instanceof MslEncodable) {
            try {
                return ((MslEncodable)o).toMslObject(encoder);
            } catch (final MslEncoderException e) {
                // Drop through.
            }
        }
        */
        try {
            if (o instanceof Map)
                return new MslObject((Map<?,?>)o);
        } catch (final IllegalArgumentException e) {
            return null;
        }
        if (o instanceof byte[]) {
            try {
                return encoder.parseObject((byte[])o);
            } catch (final MslEncoderException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Return the value at the index or zero if the value is not of
     * the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public long optLong(final int index) {
        return optLong(index, 0);
    }
    
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
    public long optLong(final int index, final long defaultValue) {
        final Object o = opt(index);
        if (o instanceof Number)
            return ((Number)o).longValue();
        return defaultValue;
    }

    /**
     * Return the value at the index or the empty string if the value is not
     * of the correct type.
     * 
     * @param index the index.
     * @return the value.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public String optString(final int index) {
        return optString(index, "");
    }
    
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
    public String optString(final int index, final String defaultValue) {
        final Object o = opt(index);
        if (o instanceof String)
            return (String)o;
        return defaultValue;
    }
    
    /**
     * <p>Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.</p>
     * 
     * <p>This method will call {@link #put(int, Object)}.</p>
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     * @throws IllegalArgumentException if the value is of an unsupported type.
     */
    @SuppressWarnings("unchecked")
    public MslArray put(final int index, final Object value) {
        if (index < -1)
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative.");
        
        // Convert appropriate values to MSL objects or MSL arrays.
        final Object element;
        if (value instanceof Boolean ||
            value instanceof byte[] ||
            value instanceof Number ||
            value instanceof MslObject ||
            value instanceof MslArray ||
            value instanceof String ||
            value instanceof MslEncodable)
        {
            element = value;
        }
        else if (value instanceof Map) {
            element = new MslObject((Map<?,?>)value);
        } else if (value instanceof Collection) {
            element = new MslArray((Collection<Object>)value);
        } else if (value instanceof Object[]) {
            element = new MslArray((Object[])value);
        } else if (value instanceof Enum) {
            element = ((Enum<?>)value).name();
        } else if (value == null) {
            element = null;
        } else {
            throw new IllegalArgumentException("Value [" + value.getClass() + "] is an unsupported type.");
        }
        
        // Fill with null elements as necessary.
        for (int i = list.size(); i < index; ++i)
            list.add(null);
        
        // Append if requested.
        if (index == -1 || index == list.size()) {
            list.add(element);
            return this;
        }
        
        // Otherwise replace.
        list.set(index, element);
        return this;
    }
    
    /**
     * <p>Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.</p>
     * 
     * <p>This method will call {@link #put(int, Object)}.</p>
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putBoolean(final int index, final Boolean value) {
        return put(index, value);
    }
    
    /**
     * <p>Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.</p>
     * 
     * <p>This method will call {@link #put(int, Object)}.</p>
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putBytes(final int index, final byte[] value) {
        return put(index, value);
    }
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. The
     * collection of elements will be transformed into a {@code MslArray}. If
     * the index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     * @throws IllegalArgumentException if the value contains an unsupported
     *         type.
     */
    public MslArray putCollection(final int index, final Collection<Object> value) {
        return put(index, value);
    }
    
    /**
     * <p>Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.</p>
     * 
     * <p>This method will call {@link #put(int, Object)}.</p>
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putDouble(final int index, final Double value) {
        return put(index, value);
    }
    
    /**
     * <p>Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.</p>
     * 
     * <p>This method will call {@link #put(int, Object)}.</p>
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putInt(final int index, final Integer value) {
        return put(index, value);
    }
    
    /**
     * <p>Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.</p>
     * 
     * <p>This method will call {@link #put(int, Object)}.</p>
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putLong(final int index, final Long value) {
        return put(index, value);
    }
    
    /**
     * Put or replace a value in the {@code MslArray} at the index. The map of
     * strings onto objects will be transformed into a {@code MslObject}. If
     * the index exceeds the length, null elements will be added as necessary.
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     * @throws IllegalArgumentException if one of the values is an unsupported
     *         type.
     */
    public MslArray putMap(final int index, final Map<String,Object> value) {
        return put(index, new MslObject(value));
    }

    /**
     * <p>Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.</p>
     * 
     * <p>This method will call {@link #put(int, Object)}.</p>
     * 
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws ArrayIndexOutOfBoundsException if the index is less than -1.
     */
    public MslArray putString(final int index, final String value) {
        return put(index, value);
    }
    
    /**
     * Remove an element at the index. This decreases the length by one.
     * 
     * @param index the index. -1 for the end of the array.
     * @return the removed value. May be {@code null}.
     * @throws ArrayIndexOutOfBoundsException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    public Object remove(final int index) {
        if (index < -1 || index >= list.size())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        final int i = (index == -1) ? list.size() - 1 : index;
        final Object value = opt(i);
        list.remove(i);
        return value;
    }

    /**
     * Return an unmodifiable collection of the {@code MslArray} contents.
     * 
     * @return the unmodifiable collection of {@code MslArray} contents.
     */
    public Collection<Object> getCollection() {
        return Collections.unmodifiableList(list);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MslArray)) return false;
        final MslArray that = (MslArray)obj;
        try {
            return MslEncoderUtils.equalArrays(this, that);
        } catch (final MslEncoderException e) {
            return false;
        }
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return MslEncoderUtils.hashArray(this);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        // This is based on the org.json {@code JSONArray.write()} code.
        final StringBuilder sb = new StringBuilder();
        boolean commanate = false;
        final int length = list.size();
        sb.append('[');

        if (length == 1) {
            sb.append(MslEncoderFactory.stringify(this.list.get(0)));
        } else if (length != 0) {
            for (int i = 0; i < length; i += 1) {
                if (commanate) {
                    sb.append(',');
                }
                sb.append(MslEncoderFactory.stringify(list.get(i)));
                commanate = true;
            }
        }
        sb.append(']');
        return sb.toString();
    }
}
