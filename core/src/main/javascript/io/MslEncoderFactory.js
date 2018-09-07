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

/**
 * <p>An abstract factory class for producing {@link MslTokenizer},
 * {@link MslObject}, and {@link MslArray} instances of various encoder
 * formats.</p>
 * 
 * <p>A concrete implementations must identify its supported and preferred
 * encoder formats and provide implementations for encoding and decoding those
 * formats.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";

    var Base64 = require('../util/Base64.js');
    var MslObject = require('../io/MslObject.js');
    var MslArray = require('../io/MslArray.js');
    var Class = require('../util/Class.js');
    var MslEncoderFormat = require('../io/MslEncoderFormat.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var MslEncoderException = require('../io/MslEncoderException.js');
    var BufferedInputStream = require('../io/BufferedInputStream.js');

    /**
     * Escape a string to be output as a single line of text.
     * 
     * @param {?string} s the string. May be {@code null}.
     * @returns {string} the escaped string.
     */
    var MslEncoderFactory$quote = function MslEncoderFactory$quote(s) {
        var json = JSON.stringify(s);
        return json
            .replace(/[\"]/g, '\\"')
            .replace(/[\\]/g, '\\\\')
            .replace(/[\/]/g, '\\/')
            .replace(/[\b]/g, '\\b')
            .replace(/[\f]/g, '\\f')
            .replace(/[\n]/g, '\\n')
            .replace(/[\r]/g, '\\r')
            .replace(/[\t]/g, '\\t');
    };
    
    /**
     * Convert a value to a string for print purposes.
     * 
     * @param {?} value the value to convert to a string. May be {@code null}.
     * @return {string} the string.
     */
    var MslEncoderFactory$stringify = function MslEncoderFactory$stringify(v) {
        if (v instanceof MslObject || v instanceof MslArray) {
            return v.toString();
        } else if (v instanceof Uint8Array) {
            return Base64.encode(v);
        } else {
            var json = JSON.stringify(v);
            return json
                .replace(/[\"]/g, '\\"')
                .replace(/[\\]/g, '\\\\')
                .replace(/[\/]/g, '\\/')
                .replace(/[\b]/g, '\\b')
                .replace(/[\f]/g, '\\f')
                .replace(/[\n]/g, '\\n')
                .replace(/[\r]/g, '\\r')
                .replace(/[\t]/g, '\\t');
        }
    };
    
    var MslEncoderFactory = module.exports = Class.create({
        /**
         * Returns the most preferred encoder format from the provided set of
         * formats.
         * 
         * @param {Array<MslEncoderFormat>} formats the set of formats to choose from. May be {@code null} or
         *        empty.
         * @return {MslEncoderFormat} the preferred format from the provided set or the default format
         *         if format set is {@code null} or empty.
         */
        getPreferredFormat: function(formats) {},
        
        /**
         * <p>Create a new {@link MslTokenizer}.</p>
         * 
         * <p>If the encoding format is not provided, it will be determined by
         * inspecting the byte stream identifier located in the first byte.</p>
         * 
         * @param {InputStream} source the binary data to tokenize.
         * @param {?MslEncoderFormat} format the encoding format. May be
         *        {@code null}.
         * @param {number} timeout read timeout used to determine the encoding
         *        format or -1 for no timeout.
         * @param {{result: function(MslTokenizer), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the
         *        {@link MslTokenizer}, be notified of timeouts, or any thrown
         *        exceptions.
         * @throws IOException if there is a problem reading the byte stream
         *         identifier.
         * @throws MslEncoderException if the encoder format is not recognized or
         *         is not supported.
         */
        createTokenizer: function createTokenizer(source, format, timeout, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                // If the format was provided, return the tokenizer directly.
                if (format)
                    return this.generateTokenizer(source, format);
                
                // Read the byte stream identifier.
                var bufferedSource = source.markSupported() ? source : new BufferedInputStream(source);
                bufferedSource.mark(1);
                bufferedSource.read(1, timeout, {
                    result: function(bytes) {
                        AsyncExecutor(callback, function() {
                            if (bytes == null || bytes.length < 1)
                                throw new MslEncoderException("End of stream reached when attempting to read the byte stream identifier.");
                            var id = bytes[0];
                            identify(bufferedSource, id);
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);
            
            function identify(bufferedSource, id) {
                AsyncExecutor(callback, function() {
                    format = MslEncoderFormat.getFormat(id);
                    if (!format)
                        throw new MslEncoderException("Unidentified encoder format ID: (byte)" + id + ".");
                    
                    // Reset the input stream and return the tokenizer.
                    bufferedSource.reset();
                    return this.generateTokenizer(bufferedSource, format);
                }, self);
            }
        },

        /**
         * Create a new {@link MslTokenizer} of the specified encoder format.
         * 
         * @param source the binary data to tokenize.
         * @param format the encoder format.
         * @return the {@link MslTokenizer}.
         * @throws MslEncoderException if the encoder format is not supported.
         */
        generateTokenizer: function generateTokenizer(source, format) {},
        
        /**
         * <p>Create a new {@link MslObject}.</p>
         * 
         * <p>If a map is provided the object will be populated with the map
         * data.</p>
         * 
         * @param {Object=} map the map of name/value pairs. This must be a map of
         *        {@code string}s onto values. May be {@code null}.
         * @return {MslObject} the {@link MslObject}.
         * @throws TypeError if one of the values is of an
         *         unsupported type.
         */
        createObject: function createObject(map) {
            return new MslObject(map);
        },
        
        /**
         * Identify the encoder format of the {@link MslObject} of the encoded
         * data. The format will be identified by inspecting the byte stream
         * identifier located in the first byte.
         * 
         * @param {Uint8Array} encoding the encoded data.
         * @return {MslEncoderFormat} the encoder format.
         * @throws MslEncoderException if the encoder format cannot be identified
         *         or there is an error parsing the encoder format ID.
         */
        parseFormat: function parseFormat(encoding) {
            // Fail if the encoding is too short.
            if (encoding.length < 1)
                throw new MslEncoderException("No encoding identifier found.");
            
            // Identify the encoder format.
            var id = encoding[0];
            var format = MslEncoderFormat.getFormat(id);
            if (!format)
                throw new MslEncoderException("Unidentified encoder format ID: (byte)" + id + ".");
            return format;
        },

        /**
         * Parse a {@link MslObject} from encoded data. The encoder format will be
         * determined by inspecting the byte stream identifier located in the first
         * byte.
         * 
         * @param {Uint8Array} encoding the encoded data to parse.
         * @return {MslObject} the {@link MslObject}.
         * @throws MslEncoderException if the encoder format is not supported or
         *         there is an error parsing the encoded data.
         */
        parseObject: function(encoding) {},
        
        /**
         * Encode a {@link MslObject} into the specified encoder format.
         * 
         * @param {MslObject} object the {@link MslObject} to encode.
         * @param {MslEncoderFormat} format the encoder format.
         * @param {{result: function(Uint8Array), error: function(Error)}}
         *        callback the callback that will receive the encoded data or
         *        any thrown exceptions.
         * @throws MslEncoderException if the encoder format is not supported or
         *         there is an error encoding the object.
         */
        encodeObject: function(object, format, callback) {},

        /**
         * <p>Create a new {@link MslArray}.</p>
         * 
         * <p>If a collection of values is provided the array will be populated
         * with the collection data.<p>
         * 
         * @param {Array<*>} collection the collection of values. May be {@code null}.
         * @return {MslArray} the {@link MslArray}.
         * @throws TypeError if one of the values is of an
         *         unsupported type.
         */
        createArray: function createArray(collection) {
            return new MslArray(collection);
        },
    });
    
    // Exports.
    module.exports.quote = MslEncoderFactory$quote;
    module.exports.stringify = MslEncoderFactory$stringify;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslEncoderFactory'));