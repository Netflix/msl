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

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import com.netflix.msl.MslConstants;

/**
 * <p>Create a new {@link MslTokenizer} that parses JSON-encoded MSL
 * messages.</p>
 * 
 * <p>This implementation is backed by {@code org.json}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonMslTokenizer extends MslTokenizer {
    /**
     * <p>Create a new JSON MSL tokenzier that will read data off the provided
     * input stream.</p>
     * 
     * @param encoder MSL encoder factory.
     * @param source JSON input stream.
     */
    public JsonMslTokenizer(final MslEncoderFactory encoder, final InputStream source) {
        this.encoder = encoder;
        final Reader reader = new InputStreamReader(source, MslConstants.DEFAULT_CHARSET);
        this.tokenizer = new JSONTokener(reader);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslTokenizer#next(int)
     */
    @Override
    protected MslObject next(final int timeout) throws MslEncoderException {
        try {
            if (!tokenizer.more())
                return null;
            final Object o = tokenizer.nextValue();
            if (o instanceof JSONObject)
                return new JsonMslObject(encoder, (JSONObject)o);
            throw new MslEncoderException("JSON value is not a JSON object.");
        } catch (final JSONException e) {
            throw new MslEncoderException("JSON syntax error.", e);
        }
    }

    /** MSL encoder factory. */
    private final MslEncoderFactory encoder;
    /** JSON tokenizer. */
    private final JSONTokener tokenizer;
}
