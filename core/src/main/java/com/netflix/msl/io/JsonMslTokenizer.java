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

import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslInternalException;

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
        // We cannot use the standard {@code InputStreamReader} to support
        // UTF-8 decoding because it makes use of {@code StreamDecoder} which
        // will read {@code StreamDecoder.DEFAULT_BYTE_BUFFER_SIZE} bytes by
        // default, and enforces a minimum of
        // {@code StreamDecoder.MIN_BYTE_BUFFER_SIZE}. This will consume extra
        // bytes and prevent the input stream from being used for future MSL
        // messages.
        //
        // {@code JSONTokener} will consume one character at a time, but will
        // default to a {@code BufferedReader} with the default buffer size if
        // an {@code InputStream} or {@code Reader} is provided that does not
        // support mark, which will also consume extra bytes and prevent reuse
        // of the input stream.
        //
        // Ensure none of that occurs and that only the minimum number of bytes
        // are consumed by explicitly using the {@code ThriftyUtf8Reader} which
        // reads characters one at a time and also supports mark.
        //
        // Make sure we're trying to parse UTF-8 data.
        if (StandardCharsets.UTF_8 != MslConstants.DEFAULT_CHARSET)
            throw new MslInternalException("Charset " + MslConstants.DEFAULT_CHARSET + " unsupported.");
        final Reader reader = new ThriftyUtf8Reader(source);
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
