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

import java.nio.charset.Charset;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslInternalException;
import com.netflix.msl.util.Base64;

/**
 * <p>A {@code MslObject} that encodes its data as UTF-8 JSON.</p>
 * 
 * <p>This implementation is backed by {@code org.json}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonMslObject extends MslObject implements JSONString {
    /** UTF-8 charset. */
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    
    /**
     * Returns a JSON MSL encoding of provided MSL object.
     * 
     * @param encoder the encoder factory.
     * @param object the MSL object.
     * @return the encoded data.
     * @throws MslEncoderException if there is an error encoding the data.
     */
    public static byte[] getEncoded(final MslEncoderFactory encoder, final MslObject object) throws MslEncoderException {
        if (object instanceof JsonMslObject)
            return ((JsonMslObject)object).toJSONString().getBytes(UTF_8);
        
        final JsonMslObject jsonObject = new JsonMslObject(encoder, object);
        return jsonObject.toJSONString().getBytes(UTF_8);
    }
    
    /**
     * Create a new {@code JsonMslObject} from the given {@code MslObject}.
     * 
     * @param encoder the encoder factory.
     * @param o the {@code MslObject}.
     * @throws MslEncoderException if the MSL object contains an unsupported
     *         type.
     */
    public JsonMslObject(final MslEncoderFactory encoder, final MslObject o) throws MslEncoderException {
        this.encoder = encoder;
        try {
            for (final String key : o.getKeys())
                put(key, o.opt(key));
        } catch (final IllegalArgumentException e) {
            throw new MslEncoderException("Invalid MSL object encoding.", e);
        }
    }
    
    /**
     * Create a new {@code JsonMslObject} from the given {@code JSONObject}.
     * 
     * @param encoder the encoder factory.
     * @param jo the {@code JSONObject}.
     * @throws MslEncoderException if the JSON object contains an unsupported
     *         type.
     */
    public JsonMslObject(final MslEncoderFactory encoder, final JSONObject jo) throws MslEncoderException {
        this.encoder = encoder;
        try {
            for (final Object key : jo.keySet()) {
                if (!(key instanceof String))
                    throw new MslEncoderException("Invalid JSON object encoding.");
                put((String)key, jo.opt((String)key));
            }
        } catch (final JSONException e) {
            throw new MslEncoderException("Invalid JSON object encoding.", e);
        } catch (final IllegalArgumentException e) {
            throw new MslEncoderException("Invalid MSL object encoding.", e);
        }
    }
    
    /**
     * Create a new {@code JsonMslObject} from its encoded representation.
     * 
     * @param encoder the encoder factory.
     * @param encoding the encoded data.
     * @throws MslEncoderException if the data is malformed or invalid.
     */
    public JsonMslObject(final MslEncoderFactory encoder, final byte[] encoding) throws MslEncoderException {
        this.encoder = encoder;
        try {
            final String json = new String(encoding, UTF_8);
            final JSONObject jo = new JSONObject(json);
            for (final Object key : jo.keySet()) {
                if (!(key instanceof String))
                    throw new MslEncoderException("Invalid JSON object encoding.");
                put((String)key, jo.opt((String)key));
            }
        } catch (final JSONException e) {
            throw new MslEncoderException("Invalid JSON object encoding.", e);
        } catch (final IllegalArgumentException e) {
            throw new MslEncoderException("Invalid MSL object encoding.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslObject#put(java.lang.String, java.lang.Object)
     */
    @Override
    public MslObject put(final String key, final Object value) {
        final Object o;
        try {
            // Convert JSONObject to MslObject.
            if (value instanceof JSONObject)
                o = new JsonMslObject(encoder, (JSONObject)value);
            // Convert JSONArray to a MslArray.
            else if (value instanceof JSONArray)
                o = new JsonMslArray(encoder, (JSONArray)value);
            // All other types are OK as-is.
            else
                o = value;
        } catch (final MslEncoderException e) {
            throw new IllegalArgumentException("Unsupported JSON object or array representation.", e);
        }
        return super.put(key, o);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslObject#getBytes(java.lang.String)
     */
    @Override
    public byte[] getBytes(final String key) throws MslEncoderException {
        // When a JsonMslObject is decoded, there's no way for us to know if a
        // value is supposed to be a String to byte[]. Therefore interpret
        // Strings as Base64-encoded data consistent with the toJSONString()
        // and getEncoded().
        final Object value = get(key);
        if (value instanceof byte[])
            return (byte[])value;
        if (value instanceof String) {
            try {
                return Base64.decode((String)value);
            } catch (final IllegalArgumentException e) {
                // Fall through.
            }
        }
        throw new MslEncoderException("MslObject[" + MslEncoderFactory.quote(key) + "] is not binary data.");
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslObject#optBytes(java.lang.String)
     */
    @Override
    public byte[] optBytes(final String key) {
        return optBytes(key, new byte[0]);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslObject#optBytes(java.lang.String, byte[])
     */
    @Override
    public byte[] optBytes(final String key, final byte[] defaultValue) {
        // When a JsonMslObject is decoded, there's no way for us to know if a
        // value is supposed to be a String to byte[]. Therefore interpret
        // Strings as Base64-encoded data consistent with the toJSONString()
        // and getEncoded().
        final Object value = opt(key);
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
            final JSONObject jo = new JSONObject();
            final Set<String> keys = getKeys();
            for (final String key : keys) {
                final Object value = opt(key);
                if (value instanceof byte[]) {
                    jo.put(key, Base64.encode((byte[])value));
                } else if (value instanceof JsonMslObject || value instanceof JsonMslArray) {
                    jo.put(key, value);
                } else if (value instanceof MslObject) {
                    final JsonMslObject jsonValue = new JsonMslObject(encoder, (MslObject)value);
                    jo.put(key, jsonValue);
                } else if (value instanceof MslArray) {
                    final JsonMslArray jsonValue = new JsonMslArray(encoder, (MslArray)value);
                    jo.put(key, jsonValue);
                } else if (value instanceof MslEncodable) {
                    final byte[] json = ((MslEncodable)value).toMslEncoding(encoder, MslEncoderFormat.JSON);
                    final JsonMslObject jsonValue = new JsonMslObject(encoder, json);
                    jo.put(key, jsonValue);
                } else {
                    jo.put(key, value);
                }
            }
            return jo.toString();
        } catch (final IllegalArgumentException e) {
            throw new MslInternalException("Error encoding MSL object as JSON.", e);
        } catch (final MslEncoderException e) {
            throw new MslInternalException("Error encoding MSL object as JSON.", e);
        } catch (final JSONException e) { 
            throw new MslInternalException("Error encoding MSL object as JSON.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslObject#toString()
     */
    @Override
    public String toString() {
        return toJSONString();
    }

    /** MSL encoder factory. */
    private final MslEncoderFactory encoder;
}
