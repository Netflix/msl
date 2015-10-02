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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslConstants;

/**
 * <p>A {@code MslArray} that encodes its data as JSON.</p>
 * 
 * <p>This implementation is backed by {@code org.json}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonMslArray implements MslArray, JSONString {
    /**
     * Create a new empty {@code MslArray}.
     */
    public JsonMslArray() {
        this.ja = new JSONArray();
    }
    
    /**
     * Create a new {@code MslArray} from the given collection.
     * 
     * @param collection the collection of values.
     */
    public JsonMslArray(final Collection<Object> collection) {
        this.ja = new JSONArray(collection);
    }
    
    /**
     * Create a new {@code MslArray} from its encoded representation.
     * 
     * @param encoding the encoded data.
     * @throws MslEncoderException if the data is malformed or invalid.
     * @see #getEncoded()
     */
    public JsonMslArray(final byte[] encoding) throws MslEncoderException {
        try {
            final String json = new String(encoding, MslConstants.DEFAULT_CHARSET);
            this.ja = new JSONArray(json);
        } catch (final JSONException e) {
            throw new MslEncoderException("Invalid JSON array encoding.", e);
        }
    }
    
    /**
     * Create a new {@code MslArray} from the given {@code JSONArray}.
     * 
     * @param a the {@code JSONArray}.
     */
    protected JsonMslArray(final JSONArray a) {
        final Collection<Object> collection = new ArrayList<Object>();
        for (int i = 0; i < a.length(); ++i)
            collection.add(a.opt(i));
        this.ja = new JSONArray(collection);
    }
    
    @Override
    public Object get(final int index) throws MslEncoderException {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        try {
            final Object o = ja.get(index);
            if (o instanceof JSONObject)
                return new JsonMslObject((JSONObject)o);
            if (o instanceof JSONArray)
                return new JsonMslArray((JSONArray)o);
            return o;
        } catch (final JSONException e) {
            throw new MslEncoderException("MslArray[" + index + "] not found.", e);
        }
    }
    
    @Override
    public boolean getBoolean(final int index) throws MslEncoderException {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        try {
            return ja.getBoolean(index);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslArray[" + index + "] is not a boolean.", e);
        }
    }
    
    @Override
    public byte[] getBytes(final int index) throws MslEncoderException {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        try {
            final String b64 = ja.getString(index);
            return DatatypeConverter.parseBase64Binary(b64);
        } catch (final JSONException | IllegalArgumentException e) {
            throw new MslEncoderException("MslArray[" + index + "] is not binary data.", e);
        }
    }

    @Override
    public double getDouble(final int index) throws MslEncoderException {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        try {
            return ja.getDouble(index);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslArray[" + index + "] is not a number.", e);
        }
    }

    @Override
    public int getInt(final int index) throws MslEncoderException {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        try {
            return ja.getInt(index);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslArray[" + index + "] is not a number.", e);
        }
    }

    @Override
    public MslArray getMslArray(final int index) throws MslEncoderException {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        try {
            final JSONArray a = ja.getJSONArray(index);
            return new JsonMslArray(a);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslArray[" + index + "] is not a MslArray.", e);
        }
    }

    @Override
    public MslObject getMslObject(final int index) throws MslEncoderException {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        try {
            final JSONObject o = ja.getJSONObject(index);
            return new JsonMslObject(o);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslArray[" + index + "] is not a MslObject.", e);
        }
    }

    @Override
    public long getLong(final int index) throws MslEncoderException {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        try {
            return ja.getLong(index);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslArray[" + index + "] is not a number.", e);
        }
    }

    @Override
    public String getString(final int index) throws MslEncoderException {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        try {
            return ja.getString(index);
        } catch (final JSONException e) {
            throw new MslEncoderException("MslArray[" + index + "] is not a string.", e);
        }
    }

    @Override
    public boolean isNull(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.isNull(index);
    }

    @Override
    public int length() {
        return ja.length();
    }

    @Override
    public Object opt(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        final Object o = ja.opt(index);
        if (o instanceof JSONObject)
            return new JsonMslObject((JSONObject)o);
        if (o instanceof JSONArray)
            return new JsonMslArray((JSONArray)o);
        return o;
    }

    @Override
    public boolean optBoolean(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optBoolean(index);
    }

    @Override
    public boolean optBoolean(final int index, final boolean defaultValue) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optBoolean(index, defaultValue);
    }
    
    @Override
    public byte[] optBytes(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        final String b64 = ja.optString(index);
        try {
            return DatatypeConverter.parseBase64Binary(b64);
        } catch (final IllegalArgumentException e) {
            return new byte[0];
        }
    }
    
    @Override
    public byte[] optBytes(final int index, final byte[] defaultValue) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        final Object o = ja.opt(index);
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
    public double optDouble(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optDouble(index);
    }

    @Override
    public double optDouble(final int index, final double defaultValue) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optDouble(index, defaultValue);
    }

    @Override
    public int optInt(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optInt(index);
    }

    @Override
    public int optInt(final int index, final int defaultValue) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optInt(index, defaultValue);
    }

    @Override
    public MslArray optMslArray(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        final JSONArray a = ja.optJSONArray(index);
        return (a != null) ? new JsonMslArray(a) : null;
    }

    @Override
    public MslObject optMslObject(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        final JSONObject o = ja.getJSONObject(index);
        return (o != null) ? new JsonMslObject(o) : null;
    }

    @Override
    public long optLong(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optLong(index);
    }

    @Override
    public long optLong(final int index, final long defaultValue) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optLong(index, defaultValue);
    }

    @Override
    public String optString(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optString(index);
    }

    @Override
    public String optString(final int index, final String defaultValue) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        return ja.optString(index, defaultValue);
    }

    @Override
    public MslArray put(final int index, final Object value) {
        if (index < -1)
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative.");
        ja.put((index == -1) ? ja.length() : index, value);
        return this;
    }

    @Override
    public MslArray putBoolean(final int index, final boolean value) {
        if (index < -1)
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative.");
        ja.put((index == -1) ? ja.length() : index, value);
        return this;
    }
    
    @Override
    public MslArray putBytes(final int index, final byte[] value) {
        if (index < -1)
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative.");
        final String b64 = (value != null) ? DatatypeConverter.printBase64Binary(value) : null;
        ja.put((index == -1) ? ja.length() : index, b64);
        return this;
    }

    @Override
    public MslArray putCollection(final int index, final Collection<Object> value) {
        if (index < -1)
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative.");
        ja.put((index == -1) ? ja.length() : index, value);
        return this;
    }

    @Override
    public MslArray putDouble(final int index, final double value) {
        if (index < -1)
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative.");
        ja.put((index == -1) ? ja.length() : index, value);
        return this;
    }

    @Override
    public MslArray putInt(final int index, final int value) {
        if (index < -1)
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative.");
        ja.put((index == -1) ? ja.length() : index, value);
        return this;
    }

    @Override
    public MslArray putLong(final int index, final long value) {
        if (index < -1)
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative.");
        ja.put((index == -1) ? ja.length() : index, value);
        return this;
    }

    @Override
    public MslArray putMap(final int index, final Map<String, Object> value) {
        if (index < -1)
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative.");
        ja.put((index == -1) ? ja.length() : index, value);
        return this;
    }

    @Override
    public Object remove(final int index) {
        if (index < 0 || index >= ja.length())
            throw new ArrayIndexOutOfBoundsException("MslArray[" + index + "] is negative or exceeds array length.");
        final Object o = opt(index);
        ja.remove(index);
        return o;
    }

    @Override
    public Collection<Object> getCollection() {
        final Collection<Object> collection = new ArrayList<Object>();
        for (int i = 0; i < ja.length(); ++i)
            collection.add(ja.get(i));
        return collection;
    }

    @Override
    public byte[] getEncoded() throws MslEncoderException {
        return ja.toString().getBytes(MslConstants.DEFAULT_CHARSET);
    }

    @Override
    public String toJSONString() {
        return ja.toString();
    }

    /** JSON array. */
    private final JSONArray ja;
}
