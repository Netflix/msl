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

/**
 * <p>Create a new {@link MslTokenizer} that parses JSON-encoded MSL
 * messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var JsonMslTokenizer;

(function() {
    "use strict";
    
    function parse(data) {
        var json = textEncoding$getString(data, MslConstants$DEFAULT_CHARSET);
        var parser = new ClarinetParser(json);
        var value = parser.nextValue();
        var values = [];
        while (value !== undefined) {
            values.push(value);
            value = parser.nextValue();
        }
        return values;
    }
    
    function read(is, timeout, callback) {
        is.read(-1, timeout, {
            result: function(data) {
                AsyncExecutor(callback, function() {
                    // Return null on end of stream. This should never return
                    // zero bytes but handle it just in case.
                    if (!data || data.length == 0)
                        return null;
                    
                    // If the input stream is a special JSON stream return the
                    // JSON directly.
                    if (typeof is.getJSON === 'function')
                        return is.getJSON();
                    
                    // Parse the raw data as JSON.
                    return parse(data);
                });
            },
            timeout: function(data) {
                AsyncExecutor(callback, function() {
                    // If no data was returned then really timeout.
                    if (!data || data.length == 0)
                        callback.timeout(data);
                    
                    // If the input stream is a special JSON stream return the
                    // JSON directly.
                    if (typeof is.getJSON === 'function')
                        return is.getJSON();
                    
                    // Parse the raw data as JSON.
                    return parse(data);
                });
            },
            error: callback.error,
        });
    }
    
    JsonMslTokenizer = MslTokenizer.extend({
        init: function init(source) {
            // The properties.
            var props = {
                /** @type {InputStream} */
                source: { value: source, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
            
            // Need a way to roll back and re-parse any data that wasn't consumed.
        },
        
        /** @inheritDoc */
        next: function next(timeout, callback) {
            read(this.source, timeout, {
                result: function(values) {
                    
                },
                timeout: function() {
                    
                },
                error: function(e) {
                    callback.error(new MslEncoderException("Error reading next "))
                }
            })
        },
    });
})();

public class JsonMslTokenizer extends MslTokenizer {
    public JsonMslTokenizer(final InputStream source) {
        final Reader reader = new InputStreamReader(source, MslConstants.DEFAULT_CHARSET);
        tokenizer = new JSONTokener(reader);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslTokenizer#next()
     */
    @Override
    protected MslObject next() throws MslEncoderException {
        try {
            final Object o = tokenizer.nextValue();
            if (o instanceof JSONObject)
                return new JsonMslObject((JSONObject)o);
            throw new MslEncoderException("JSON value is not a JSON object.");
        } catch (final JSONException e) {
            throw new MslEncoderException("JSON syntax error.", e);
        }
    }

    /** JSON tokenizer. */
    private final JSONTokener tokenizer;
}
