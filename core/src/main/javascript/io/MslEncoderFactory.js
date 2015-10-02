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
 * <p>A factory class for producing {@link MslTokener}, {@link MslObject},
 * and {@link MslArray} instances of various encoding formats.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MslEncoderFactory;

(function() {
    MslEncoderFactory = util.Class.Create({
        /**
         * <p>Create a new {@link MslTokenizer}.</p>
         * 
         * <p>If the encoding format is not provided, it will be determined by
         * inspecting the byte stream identifier located in the first byte.</p>
         * 
         * @param {InputStream} source the binary data to tokenize.
         * @param {MslEncodingFormat=} format the encoding format.
         * @param {number} timeout read timeout used to determine the encoding
         *        format or -1 for no timeout.
         * @param {{result: function(MslTokenizer), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the
         *        {@link MslTokenizer}, be notified of timeouts, or any thrown
         *        exceptions.
         * @throws MslEncoderException if there is a problem reading the byte
         *         stream identifier or if the encoding format is not supported.
         */
        createTokenizer: function createTokenizer(source, format, timeout, callback) {
            AsyncExecutor(callback, function() {
                // Identify the encoding format.
                if (!format) {
                    source.mark();
                    source.read(1, timeout, {
                        result: function(bytes) {
                            AsyncExecutor(callback, function() {
                                if (bytes == null || bytes.length < 1)
                                    throw new new MslEncoderException("Failure reading the byte stream identifier.");
                                var id = bytes[0];
                                format = MslEncodingFormat$getFormat(id);
                                source.reset();
                                generate(format);
                            });
                        },
                        timeout: callback.timeout,
                        error: function(e) {
                            callback.error(new MslEncoderException("Failure reading the byte stream identifier.", e));
                        }
                    });
                } else {
                    generate(format);
                }
                
                function generate(format) {
                    AsyncExecutor(callback, function() {
                        // JSON.
                        if (MslEncodingFormat.JSON === format) {
                            return new JsonMslTokenizer(source);
                        }
                        
                        // Unsupported encoding format.
                        throw new MslEncoderException("Unsupported encoding format: " + format + ".");
                    });
                }
            });
        },
        
        /**
         * Create a new {@link MslObject} of the specified encoding format.
         * 
         * @param {MslEncodingFormat} format the encoding format.
         * @return {MslObject} the {@link MslObject}.
         * @throws MslEncoderException if the encoding format is not supported.
         */
        createObject: function createObject(format) {
            // JSON.
            if (MslEncodingFormat.JSON === format) {
                return new JsonMslObject();
            }
            
            // Unsupported encoding format.
            throw new MslEncoderException("Unsupported encoding format: " + format + ".");
        },

        /**
         * Create a new {@link MslArray} of the specified encoding format.
         * 
         * @param {MslEncodingFormat} format the encoding format.
         * @return {MslArray} the {@link MslArray}.
         * @throws MslEncoderException if the encoding format is not supported.
         */
        createArray: function createArray(format) {
            // JSON.
            if (MslEncodingFormat.JSON === format) {
                return new JsonMslArray();
            }
            
            // Unsupported encoding format.
            throw new MslEncoderException("Unsupported encoding format: " + format + ".");
        },
    });
})();