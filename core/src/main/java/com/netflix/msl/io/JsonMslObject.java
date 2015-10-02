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
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslConstants;

/**
 * <p>A {@code MslObject} that encodes its data as JSON.</p>
 * 
 * <p>This implementation is backed by {@code org.json}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonMslObject implements MslObject, JSONString {
    /**
     * Create a new empty {@code MslObject}. 
     */
    public JsonMslObject() {
        this.jo = new JSONObject();
    }
    
    /**
     * Create a new {@code MslObject} from the given map.
     * 
     * @param map the map of name/value pairs.
     */
    public JsonMslObject(final Map<String,Object> map) {
        this.jo = new JSONObject(map);
    }
    
    /**
     * Create a new {@code MslObject} from its encoded representation.
     * 
     * @param encoding the encoded data.
     * @throws MslEncoderException if the data is malformed or invalid.
     * @see #getEncoded()
     */
    public JsonMslObject(final byte[] encoding) throws MslEncoderException {
        try {
            final String json = new String(encoding, MslConstants.DEFAULT_CHARSET);
            this.jo = new JSONObject(json);
        } catch (final JSONException e) {
            throw new MslEncoderException("Invalid JSON object encoding.", e);
        }
    }
    
    /**
     * Create a new {@code MslObject} from the given {@code JSONObject}.
     * 
     * @param o the {@code JSONObject}.
     */
    protected JsonMslObject(final JSONObject o) {
        final Map<String,Object> map = new HashMap<String,Object>();
        for (final Object ko : o.keySet()) {
            final String key = (String)ko;
            map.put(key, o.opt(key));
        }
        this.jo = new JSONObject(map);
    }
    
    @Override
    public Object get(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        try {
            final Object o = jo.get(key);
            if (o instanceof JSONObject)
                return new JsonMslObject((JSONObject)o);
            if (o instanceof JSONArray)
                return new JsonMslArray((JSONArray)o);
            return o;
        } catch (final JSONException e) {
            throw new MslEncoderException("MslObject[" + JSONObject.quote(key) + "] not found.", e);
        }
    }

    @Override
    public boolean getBoolean(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        try {
            return jo.getBoolean(key);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslObject[" + JSONObject.quote(key) + "] is not a boolean.", e);
        }
    }
    
    @Override
    public byte[] getBytes(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        try {
            final String b64 = jo.getString(key);
            return DatatypeConverter.parseBase64Binary(b64);
        } catch (final JSONException | IllegalArgumentException e) {
            throw new MslEncoderException("MslObject[" + JSONObject.quote(key) + "] is not binary data.", e);
        }
    }

    @Override
    public double getDouble(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        try {
            return jo.getDouble(key);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslObject[" + JSONObject.quote(key) + "] is not a number.", e);
        }
    }

    @Override
    public int getInt(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        try {
            return jo.getInt(key);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslObject[" + JSONObject.quote(key) + "] is not a number.", e);
        }
    }

    @Override
    public MslArray getMslArray(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        try {
            final JSONArray a = jo.getJSONArray(key);
            return new JsonMslArray(a);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslObject[" + JSONObject.quote(key) + "] is not a MslArray.", e);
        }
    }

    @Override
    public MslObject getMslObject(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        try {
            final JSONObject o = jo.getJSONObject(key);
            return new JsonMslObject(o);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslObject[" + JSONObject.quote(key) + "] is not a MslObject.", e);
        }
    }

    @Override
    public long getLong(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        try {
            return jo.getLong(key);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslObject[" + JSONObject.quote(key) + "] is not a number.", e);
        }
    }

    @Override
    public String getString(final String key) throws MslEncoderException {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        try {
            return jo.getString(key);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslObject[" + JSONObject.quote(key) + "] is not a string.", e);
        }
    }

    @Override
    public boolean has(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.has(key);
    }

    @Override
    public Object opt(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final Object o = jo.opt(key);
        if (o instanceof JSONObject)
            return new JsonMslObject((JSONObject)o);
        if (o instanceof JSONArray)
            return new JsonMslArray((JSONArray)o);
        return o;
    }

    @Override
    public boolean optBoolean(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optBoolean(key);
    }

    @Override
    public boolean optBoolean(final String key, final boolean defaultValue) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optBoolean(key, defaultValue);
    }
    
    @Override
    public byte[] optBytes(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final String b64 = jo.optString(key);
        try {
            return DatatypeConverter.parseBase64Binary(b64);
        } catch (final IllegalArgumentException e) {
            return new byte[0];
        }
    }
    
    @Override
    public byte[] optBytes(final String key, final byte[] defaultValue) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final Object o = jo.opt(key);
        if (!(o instanceof String))
            return defaultValue;
        final String b64 = (String)o;
        try {
            return DatatypeConverter.parseBase64Binary(b64);
        } catch (final IllegalArgumentException e) {
            return defaultValue;
        }
    }

    @Override
    public double optDouble(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optDouble(key);
    }

    @Override
    public double optDouble(final String key, final double defaultValue) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optDouble(key, defaultValue);
    }

    @Override
    public int optInt(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optInt(key);
    }

    @Override
    public int optInt(final String key, final int defaultValue) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optInt(key, defaultValue);
    }

    @Override
    public MslArray optMslArray(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final JSONArray a = jo.optJSONArray(key);
        return (a != null) ? new JsonMslArray(a) : null;
    }

    @Override
    public MslObject optMslObject(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final JSONObject o = jo.optJSONObject(key);
        return (o != null) ? new JsonMslObject(o) : null;
    }

    @Override
    public long optLong(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optLong(key);
    }

    @Override
    public long optLong(final String key, final long defaultValue) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optLong(key, defaultValue);
    }

    @Override
    public String optString(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optString(key);
    }

    @Override
    public String optString(final String key, final String defaultValue) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        return jo.optString(key, defaultValue);
    }

    @Override
    public MslObject put(final String key, final Object value) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        put(key, value);
        return this;
    }

    @Override
    public MslObject putBoolean(final String key, final boolean value) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        jo.put(key, value);
        return this;
    }
    
    @Override
    public MslObject putBytes(final String key, final byte[] value) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final String b64 = (value != null) ? DatatypeConverter.printBase64Binary(value) : null;
        jo.put(key, b64);
        return this;
    }

    @Override
    public MslObject putCollection(final String key, final Collection<Object> value) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        jo.put(key, value);
        return this;
    }

    @Override
    public MslObject putDouble(final String key, final double value) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        jo.put(key, value);
        return this;
    }

    @Override
    public MslObject putInt(final String key, final int value) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        jo.put(key, value);
        return this;
    }

    @Override
    public MslObject putLong(final String key, final long value) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        jo.put(key, value);
        return this;
    }

    @Override
    public MslObject putMap(final String key, final Map<String, Object> value) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        jo.put(key, value);
        return this;
    }

    @Override
    public Object remove(final String key) {
        if (key == null)
            throw new IllegalArgumentException("Null key.");
        final Object o = opt(key);
        jo.remove(key);
        return o;
    }

    @Override
    public Map<String,Object> getMap() {
        final Map<String,Object> map = new HashMap<String,Object>();
        for (final Object ko : jo.keySet()) {
            final String key = (String)ko;
            map.put(key, jo.get(key));
        }
        return map;
    }

    @Override
    public byte[] getEncoded() {
        return jo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
    }
    
    @Override
    public String toJSONString() {
        return jo.toString();
    }
    
    /** JSON object. */
    private final JSONObject jo;
}
