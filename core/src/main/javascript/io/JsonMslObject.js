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
 * <p>A {@code MslObject} that encodes its data as JSON.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var JsonMslObject;
var JsonMslObject$getEncoded;

(function() {
    "use strict";
    
    /**
     * UTF-8 charset.
     * @const
     * @type {string}
     */
    var UTF_8 = 'utf-8';
    
    /**
     * Returns a JSON MSL encoding of provided MSL object.
     * 
     * @param {MslEncoderFactory} encoder the encoder factory.
     * @param {MslObject} object the MSL object.
     * @return {Uint8Array} the encoded data.
     * @throws MslEncoderException if there is an error encoding the data.
     */
    JsonMslObject$getEncoded = function JsonMslObject$getEncoded(encoder, object) {
        if (object instanceof JsonMslObject)
            return textEncoding$getBytes(object.toJSON(), UTF_8);
        
        var jsonObject = new JsonMslObject(encoder, object);
        return textEncoding$getBytes(jsonObject.toJSON(), UTF_8);
    };
    
    JsonMslObject = MslObject.extend({
        /**
         * <p>Create a new {@code JsonMslObject} from the given
         * {@code MslObject}, object map, or its encoded representation.</p>
         * 
         * <p>If a source object map or an encoded representation is provided
         * then the object will be populated accordingly.</p>
         * 
         * @param {MslEncoderFactory} encoder the encoder factory.
         * @param {{MslObject|Object<String,*>|Uint8Array}=} source the
         *        {@MslObject}, object map, or encoded data.
         * @throws MslEncoderException if the data is malformed or invalid.
         */
        init: function init(encoder, source) {
            init.base.call(this);
            
            // Set properties.
            var props = {
                encoder: { value: encoder, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
            
            try {
                // MslObject
                if (source instanceof MslObject) {
                    for (var key in o.getKeys())
                        this.put(key, o.get(key));
                }

                // Object
                else if (source instanceof Object && o.constructor === Object) {
                    for (var key in source) {
                        if (!(key instanceof String) && typeof key !== 'string')
                            throw new MslEncoderException("Invalid JSON object encoding.");
                        this.put(key, source[key]);
                    }
                }

                // Uint8Array
                else if (source instanceof Uint8Array) {
                    var json = textEncoding$getString(source, UTF_8);
                    var jo = JSON.parse(json);
                    if (!(decoded instanceof Object) || typeof decoded.constructor !== Object)
                        throw new MslEncoderException("Invalid JSON object encoding.");
                    for (var key in source) {
                        if (!(key instanceof String) && typeof key !== 'string')
                            throw new MslEncoderException("Invalid JSON object encoding.");
                        this.put(key, source[key]);
                    }
                }
            } catch (e) {
                if (e instanceof SyntaxError)
                    throw new MslEncoderException("Invalid JSON object encoding.", e);
                if (e instanceof TypeError)
                    throw new MslEncoderException("Invalid MSL object encoding.", e);
                throw e;
            }
        },
        
        /** @inheritDoc */
        getBytes: function getBytes(key) {
            // When a JsonMslObject is decoded, there's no way for us to know if a
            // value is supposed to be a String to byte[]. Therefore interpret
            // Strings as Base64-encoded data consistent with the toJSONString()
            // and getEncoded().
            final Object value = this.get(key);
            if (value instanceof Uint8Array)
                return value;
            if (value instanceof String)
                return textEncoding$getBytes(value.valueOf(), UTF_8);
            if (typeof value === 'string')
                return textEncoding$getBytes(value, UTF_8);
            throw new MslEncoderException("MslObject[" + MslEncoderFactory$quote(key) + "] is not binary data.");
        },
        
        /** @inheritDoc */
        toJSON: function toJSON() {
            return JSON.stringify(this.map);
        },
        
        /** @inheritDoc */
        toString: function toString() {
            return this.toJSON();
        }
    });
})();