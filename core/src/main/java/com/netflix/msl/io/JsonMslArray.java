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

import java.nio.charset.Charset;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslInternalException;
import com.netflix.msl.util.Base64;

/**
 * <p>A {@code MslArray} that encodes its data as UTF-8 JSON.</p>
 * 
 * <p>This implementation is backed by {@code org.json}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonMslArray extends MslArray implements JSONString {
    /** UTF-8 charset. */
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    
    /**
     * Create a new {@code JsonMslArray} from the given {@code MslArray}.
     * 
     * @param encoder the encoder factory.
     * @param a the {@code MslArray}.
     * @throws MslEncoderException if the MSL array contains an unsupported
     *         type.
     */
    public JsonMslArray(final MslEncoderFactory encoder, final MslArray a) throws MslEncoderException {
        this.encoder = encoder;
        try {
            for (int i = 0; i < a.size(); ++i)
                put(i, a.opt(i));
        } catch (final IllegalArgumentException e) {
            throw new MslEncoderException("Invalid MSL array encoding.", e);
        }
    }
    
    /**
     * Create a new {@code JsonMslArray} from the given {@code JSONArray}.
     * 
     * @param encoder the encoder factory.
     * @param ja the {@code JSONArray}.
     * @throws MslEncoderException if the JSON array contains an unsupported
     *         type.
     */
    public JsonMslArray(final MslEncoderFactory encoder, final JSONArray ja) throws MslEncoderException {
        this.encoder = encoder;
        try {
            for (int i = 0; i < ja.length(); ++i)
                put(-1, ja.opt(i));
        } catch (final JSONException e) {
            throw new MslEncoderException("Invalid JSON array encoding.", e);
        } catch (final IllegalArgumentException e) {
            throw new MslEncoderException("Invalid MSL array encoding.", e);
        }
    }
    /**
     * Create a new {@code JsonMslArray} from its encoded representation.
     * 
     * @param encoder the encoder factory.
     * @param encoding the encoded data.
     * @throws MslEncoderException if the data is malformed or invalid.
     */
    public JsonMslArray(final MslEncoderFactory encoder, final byte[] encoding) throws MslEncoderException {
        this.encoder = encoder;
        try {
            final String json = new String(encoding, UTF_8);
            final JSONArray ja = new JSONArray(json);
            for (int i = 0; i < ja.length(); ++i)
                put(-1, ja.opt(i));
        } catch (final JSONException e) {
            throw new MslEncoderException("Invalid JSON array encoding.", e);
        } catch (final IllegalArgumentException e) {
            throw new MslEncoderException("Invalid MSL array encoding.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslArray#put(int, java.lang.Object)
     */
    @Override
    public MslArray put(final int index, final Object value) {
        final Object o;
        try {
            // Convert JSONObject to MslObject.
            if (value instanceof JSONObject)
                o = new JsonMslObject(encoder, (JSONObject)value);
            // Convert JSONarray to a MslArray.
            else if (value instanceof JSONArray)
                o = new JsonMslArray(encoder, (JSONArray)value);
            // All other types are OK as-is.
            else
                o = value;
        } catch (final MslEncoderException e) {
            throw new IllegalArgumentException("Unsupported JSON object or array representation.", e);
        }
        return super.put(index, o);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslArray#getBytes(int)
     */
    @Override
    public byte[] getBytes(final int index) throws MslEncoderException {
        // When a JsonMslArray is decoded, there's no way for us to know if a
        // value is supposed to be a String to byte[]. Therefore interpret
        // Strings as Base64-encoded data consistent with the toJSONString()
        // and getEncoded().
        final Object value = get(index);
        if (value instanceof byte[])
            return (byte[])value;
        if (value instanceof String) {
            try {
                return Base64.decode((String)value);
            } catch (final IllegalArgumentException e) {
                // Fall through.
            }
        }
        throw new MslEncoderException("MslArray[" + index + "] is not binary data.");
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslArray#optBytes(int)
     */
    @Override
    public byte[] optBytes(final int index) {
        return optBytes(index, new byte[0]);
    }
    
    public byte[] optBytes(final int index, final byte[] defaultValue) {
        // When a JsonMslArray is decoded, there's no way for us to know if a
        // value is supposed to be a String to byte[]. Therefore interpret
        // Strings as Base64-encoded data consistent with the toJSONString()
        // and getEncoded().
        final Object value = opt(index);
        if (value instanceof byte[])
            return (byte[])value;
        if (value instanceof String) {
            try {
                return Base64.decode((String)value);
            } catch (final IllegalArgumentException e) {
                // Fall through.
            }
        }
        return defaultValue;
    }

    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        try {
            final JSONArray ja = new JSONArray();
            final int size = size();
            for (int i = 0; i < size; ++i) {
                final Object value = opt(i);
                if (value instanceof byte[]) {
                    ja.put(i, Base64.encode((byte[])value));
                } else if (value instanceof JsonMslObject || value instanceof JsonMslArray) {
                    ja.put(i, value);
                } else if (value instanceof MslObject) {
                    final JsonMslObject jsonValue = new JsonMslObject(encoder, (MslObject)value);
                    ja.put(i, jsonValue);
                } else if (value instanceof MslArray) {
                    final JsonMslArray jsonValue = new JsonMslArray(encoder, (MslArray)value);
                    ja.put(i, jsonValue);
                } else if (value instanceof MslEncodable) {
                    final byte[] json = ((MslEncodable)value).toMslEncoding(encoder, MslEncoderFormat.JSON);
                    final JsonMslObject jsonValue = new JsonMslObject(encoder, json);
                    ja.put(i, jsonValue);
                } else {
                    ja.put(i, value);
                }
            }
            return ja.toString();
        } catch (final IllegalArgumentException e) {
            throw new MslInternalException("Error encoding MSL object as JSON.", e);
        } catch (final MslEncoderException e) {
            throw new MslInternalException("Error encoding MSL object as JSON.", e);
        } catch (final JSONException e) { 
            throw new MslInternalException("Error encoding MSL object as JSON.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslArray#toString()
     */
    @Override
    public String toString() {
        return toJSONString();
    }

    /** MSL encoder factory. */
    private final MslEncoderFactory encoder;
}
