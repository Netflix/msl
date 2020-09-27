/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * <p>A {@code MslObject} is an unordered collection of name/value pairs. It is
 * functionally equivalent to a JSON object, in that it encodes the pair data
 * without imposing any specific order and may contain more or less pairs than
 * explicitly defined.</p>
 * 
 * <p>The values can be any of these types: <code>Boolean</code>,
 * <code>Byte[]</code> <code>MslArray</code>, <code>MslObject</code>,
 * <code>Number</code>, or <code>String</code>. <code>Enum</code> is also
 * accepted and will be converted to a <code>String</code> using its
 * {@code name()} method.</p>
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
public class MslObject {
    /**
     * Create a new empty {@code MslObject}.
     */
    public MslObject() {
    }
    
    /**
     * Create a new {@code MslObject} from the given map.
     * 
     * @param map the map of name/value pairs. This must be a map of
     *        {@code String}s onto values. May be {@code null}.
     * @throws IllegalArgumentException if one of the values is of an
     *         unsupported type.
     */
    public MslObject(final Map<?,?> map) {
        if (map != null) {
            for (final Map.Entry<?, ?> entry : map.entrySet()) {
                final Object key = entry.getKey();
                if (!(key instanceof String))
                    throw new IllegalArgumentException("Map key is not a string.");
                final Object value = entry.getValue();
                put((String)key, value);
            }
        }
    }
    
    /** Object map. */
    private final Map<String,Object> map = new HashMap<String,Object>();
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of a proper
     *         type or the value is {@code null}.
     */
    @SuppressWarnings("unchecked")
    public Object get(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final Object o = map.get(key);
        if (o == null)
            throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] not found.");
        if (o instanceof Map)
            return new MslObject((Map<?,?>)o);
        if (o instanceof Collection)
            return new MslArray((Collection<Object>)o);
        if (o instanceof Object[])
            return new MslArray((Object[])o);
        return o;
    }
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public boolean getBoolean(final String key) throws MslEncoderException {
        final Object o = get(key);
        if (o instanceof Boolean)
            return (Boolean)o;
        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a boolean.");
    }
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public byte[] getBytes(final String key) throws MslEncoderException {
        final Object o = get(key);
        if (o instanceof byte[])
            return (byte[])o;
        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not binary data.");
    }
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public double getDouble(final String key) throws MslEncoderException {
        final Object o = get(key);
        if (o instanceof Number)
            return ((Number)o).doubleValue();
        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a number.");
    }
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public int getInt(final String key) throws MslEncoderException {
        final Object o = get(key);
        if (o instanceof Number)
            return ((Number)o).intValue();
        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a number.");
    }
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public MslArray getMslArray(final String key) throws MslEncoderException {
        final Object o = get(key);
        if (o instanceof MslArray)
            return (MslArray)o;
        if (o instanceof Object[])
            return new MslArray((Object[])o);
        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a MslArray.");
    }
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @param encoder the MSL encoder factory.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public MslObject getMslObject(final String key, final MslEncoderFactory encoder) throws MslEncoderException {
        final Object o = get(key);
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
                throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a MslObject.");
            }
        }
        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a MslObject.");
    }
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public long getLong(final String key) throws MslEncoderException {
        final Object o = get(key);
        if (o instanceof Number)
            return ((Number)o).longValue();
        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a number.");
    }
    
    /**
     * Return the value associated with the specified key.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    public String getString(final String key) throws MslEncoderException {
        final Object o = get(key);
        if (o instanceof String)
            return (String)o;
        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not a string.");
    }

    /**
     * Return true if the specified key exists. The value may be {@code null}.
     * 
     * @param key the key.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public boolean has(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return map.containsKey(key);
    }

    /**
     * Return the value associated with the specified key or {@code null} if
     * the key is unknown or the value is an unsupported type.
     * 
     * @param key the key.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    @SuppressWarnings("unchecked")
    public Object opt(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final Object o = map.get(key);
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
     * Return the value associated with the specified key or {@code false} if
     * the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public boolean optBoolean(final String key) {
        return optBoolean(key, false);
    }

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public boolean optBoolean(final String key, final boolean defaultValue) {
        final Object o = opt(key);
        if (o instanceof Boolean)
            return (Boolean)o;
        return defaultValue;
    }

    /**
     * Return the value associated with the specified key or an empty byte
     * array if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public byte[] optBytes(final String key) {
        return optBytes(key, new byte[0]);
    }

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public byte[] optBytes(final String key, final byte[] defaultValue) {
        final Object o = opt(key);
        if (o instanceof byte[])
            return (byte[])o;
        return defaultValue;
    }

    /**
     * Return the value associated with the specified key or {@code NaN} if
     * the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public double optDouble(final String key) {
        return optDouble(key, Double.NaN);
    }

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public double optDouble(final String key, final double defaultValue) {
        final Object o = opt(key);
        if (o instanceof Number)
            return ((Number)o).doubleValue();
        return defaultValue;
    }

    /**
     * Return the value associated with the specified key or zero if
     * the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public int optInt(final String key) {
        return optInt(key, 0);
    }

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public int optInt(final String key, final int defaultValue) {
        final Object o = opt(key);
        if (o instanceof Number)
            return ((Number)o).intValue();
        return defaultValue;
    }
    
    /**
     * Return the {@code MslArray} associated with the specified key or
     * {@code null} if the key is unknown or the value is not of the correct
     * type.
     * 
     * @param key the key.
     * @return the {@code MslArray} or {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    @SuppressWarnings("unchecked")
    public MslArray optMslArray(final String key) {
        final Object o = opt(key);
        if (o instanceof MslArray)
            return (MslArray)o;
        try {
            if (o instanceof Collection)
                return new MslArray((Collection<Object>)o);
            if (o instanceof Object[])
                return new MslArray((Object[])o);
        } catch (final IllegalArgumentException e) {
            return null;
        }       
        return null;
    }

    /**
     * Return the {@code MslObject} associated with the specified key or
     * {@code null} if the key unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param encoder the MSL encoder factory.
     * @return the {@code MslObject} or {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject optMslObject(final String key, final MslEncoderFactory encoder) {
        final Object o = opt(key);
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
        if (o instanceof Map) {
            try {
                return new MslObject((Map<?,?>)o);
            } catch (final IllegalArgumentException e) {
                return null;
            }
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
     * Return the value associated with the specified key or zero if
     * the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public long optLong(final String key) {
        return optLong(key, 0);
    }

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public long optLong(final String key, final long defaultValue) {
        final Object o = opt(key);
        if (o instanceof Number)
            return ((Number)o).longValue();
        return defaultValue;
    }

    /**
     * Return the value associated with the specified key or the empty string
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public String optString(final String key) {
        return optString(key, "");
    }

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type.
     * 
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public String optString(final String key, final String defaultValue) {
        final Object o = opt(key);
        if (o instanceof String)
            return (String)o;
        return defaultValue;
    }

    /**
     * <p>Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.</p>
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null} or the
     *         value is of an unsupported type.
     */
    @SuppressWarnings("unchecked")
    public MslObject put(final String key, final Object value) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        
        // Remove if requested.
        if (value == null) {
            map.remove(key);
            return this;
        }
        
        // Otherwise set.
        if (value instanceof Boolean ||
            value instanceof byte[] ||
            value instanceof Number ||
            value instanceof MslObject ||
            value instanceof MslArray ||
            value instanceof String ||
            value instanceof MslEncodable)
        {
            map.put(key, value);
        }
        else if (value instanceof Map)
            map.put(key, new MslObject((Map<?,?>)value));
        else if (value instanceof Collection)
            map.put(key, new MslArray((Collection<Object>)value));
        else if (value instanceof Object[])
            map.put(key, new MslArray((Object[])value));
        else if (value instanceof Enum)
            map.put(key, ((Enum<?>)value).name());
        else
            throw new IllegalArgumentException("Value [" + value.getClass() + "] is an unsupported type.");
        return this;
    }
    
    /**
     * <p><p>Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.</p>
     * 
     * <p>This method will call {@link #put(String, Object)}.</p>
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putBoolean(final String key, final Boolean value) {
        return put(key, value);
    }

    /**
     * <p>Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.</p>
     * 
     * <p>This method will call {@link #put(String, Object)}.</p>
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putBytes(final String key, final byte[] value) {
        return put(key, value);
    }

    /**
     * Put a key/value pair into the {@code MslObject}. The collection of
     * elements will be transformed into a {@code MslArray}. If the value is
     * {@code null} the key will be removed.
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null} or the value
     *         contains an unsupported type.
     */
    public MslObject putCollection(final String key, final Collection<Object> value) {
        return put(key, value);
    }

    /**
     * <p>Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.</p>
     * 
     * <p>This method will call {@link #put(String, Object)}.</p>
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putDouble(final String key, final Double value) {
        return put(key, value);
    }

    /**
     * <p>Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.</p>
     * 
     * <p>This method will call {@link #put(String, Object)}.</p>
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putInt(final String key, final Integer value) {
        return put(key, value);
    }

    /**
     * <p>Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.</p>
     * 
     * <p>This method will call {@link #put(String, Object)}.</p>
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putLong(final String key, final Long value) {
        return put(key, value);
    }

    /**
     * <p>Put a key/value pair into the {@code MslObject}. The map of strings
     * onto objects will be transformed into a {@code MslObject}. If the value
     * is {@code null} the key will be removed.</p>
     * 
     * <p>This method will call {@link #put(String, Object)}.</p>
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null} or one of
     *         the values in the map is an unsupported type.
     */
    public MslObject putMap(final String key, final Map<String,Object> value) {
        return put(key, value);
    }

    /**
     * <p>Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.</p>
     * 
     * <p>This method will call {@link #put(String, Object)}.</p>
     * 
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public MslObject putString(final String key, final String value) {
        return put(key, value);
    }
    
    /**
     * Remove a key and its associated value from the {@code MslObject}.
     * 
     * @param key the key.
     * @return the removed value. May be {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    public Object remove(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final Object value = opt(key);
        map.remove(key);
        return value;
    }
    
    /**
     * Return an unmodifiable set of the {@code MslObject} keys.
     * 
     * @return the unmodifiable set of the {@code MslObject} keys.
     */
    public Set<String> getKeys() {
        return Collections.unmodifiableSet(map.keySet());
    }
    
    /**
     * Return an unmodifiable map of the {@code MslObject} contents.
     * 
     * @return the unmodifiable map of {@code MslObject} contents.
     */
    public Map<String,Object> getMap() {
        return Collections.unmodifiableMap(map);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MslObject)) return false;
        final MslObject that = (MslObject)obj;
        try {
            return MslEncoderUtils.equalObjects(this, that);
        } catch (final MslEncoderException e) {
            return false;
        }
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return MslEncoderUtils.hashObject(this);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        // This is based on the org.json {@code MslObject.write()} code.
        final StringBuilder sb = new StringBuilder();
        boolean commanate = false;
        final int length = map.size();
        final Iterator<String> keys = map.keySet().iterator();
        sb.append('{');

        if (length == 1) {
            final String key = keys.next();
            sb.append(MslEncoderFactory.quote(key));
            sb.append(':');
            sb.append(MslEncoderFactory.stringify(this.map.get(key)));
        } else if (length != 0) {
            while (keys.hasNext()) {
                final String key = keys.next();
                if (commanate) {
                    sb.append(',');
                }
                sb.append(MslEncoderFactory.quote(key));
                sb.append(':');
                sb.append(MslEncoderFactory.stringify(this.map.get(key)));
                commanate = true;
            }
        }
        sb.append('}');
        return sb.toString();
    }
}
