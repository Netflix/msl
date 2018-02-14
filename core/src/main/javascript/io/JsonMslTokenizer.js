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
 * <p>Create a new {@link MslTokenizer} that parses JSON-encoded MSL
 * messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var MslTokenizer = require('../io/MslTokenizer.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var ClarinetParser = require('../io/ClarinetParser.js');
	var JsonMslObject = require('../io/JsonMslObject.js');
	var MslConstants = require('../MslConstants.js');
	var TextEncoding = require('../util/TextEncoding.js');

    /**
     * Delay time between read attempts in milliseconds.
     *
     * @const
     * @type {number}
     */
//    var READ_DELAY = 0;

    /**
     * Maximum JSON value size in characters (10MB).
     *
     * @const
     * @type {number}
     */
    var MAX_CHARACTERS = 10 * 1024 * 1024;
    
    /**
     * Closing curly brace character code.
     * 
     * @const
     * @type {number}
     */
    var CLOSING_BRACE = 125;
    
    var JsonMslTokenizer = module.exports = MslTokenizer.extend({
        /**
         * <p>Create a new JSON MSL tokenizer that will read tokens off the
         * provided input stream.</p>
         * 
         * @param {MslEncoderFactory} encoder MSL encoder factory.
         * @param {InputStream} source JSON input stream.
         */
        init: function init(encoder, source) {
            init.base.call(this);
            
            // The properties.
            var props = {
                /** @type {MslEncoderFactory} */
                _encoder: { value: encoder, writable: false, enumerable: false, configurable: false },
                /** @type {InputStream} */
                _source: { value: source, writable: false, enumerable: false, configurable: false },
                /** @type {string} */
                _charset: { value: TextEncoding.Encoding.UTF_8, writable: false, enumerable: false, configurable: false },
                /** @type {Array<Uint8Array>} */
                _remainingData: { value: [], writable: true, enumerable: false, configurable: false },
                /** @type {ClarinetParser} */
                _parser: { value: undefined, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        abort: function abort() {
            abort.base.call(this);
            this._source.abort();
        },
        
        /**
         * @param {number} read timeout in milliseconds.
         * @param {{result: function(ClarinetParser), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the new Clarinet JSON
         *        parser or any thrown exceptions.
         * @throws MslEncoderException if a JSON object exceeds the maximum
         *         permitted size or there is an error reading from the source
         *         input stream.
         */
        nextParser: function nextParser(timeout, callback) {
            var self = this;
            
            // Read one character at a time to avoid consuming data from the
            // input stream that may not be part of this MSL message.
            this._source.read(1, timeout, {
                result: function(data) {
                    AsyncExecutor(callback, function() {
                        // On end of stream return null for the parser.
                        if (!data) return null;
    
                        // Aborted responses send valid but empty data, treat
                        // it as end of stream.
                        if (!data.length) return null;

                        // Append the new data to the previous data.
                        this._remainingData.push(data[0]);
                        
                        // If the new data is not a closing brace, read the
                        // next character.
                        if (data[0] != CLOSING_BRACE) {
                            self.nextParser(timeout, callback);
                            return;
                        }
                        
                        // Otherwise convert the collected bytes to a string.
                        // It should be safe to do so irrespective of the
                        // charset since the last byte was a closing brace.
                        var json;
                        try {
                            var bytes = new Uint8Array(this._remainingData);
                            json = TextEncoding.getString(bytes, this._charset);
                        } catch (e) {
                            throw new MslEncoderException("Invalid JSON text encoding.", e);
                        }
    
                        // If the new data size exceeds the maximum allowed
                        // then error.
                        if (json.length > MAX_CHARACTERS)
                            throw new MslEncoderException("No JSON parsed after receiving " + json.length + " characters.");
                        
                        // Attempt to parse the JSON.
                        var parser = new ClarinetParser(json);

                        // If we got something then return the parser and
                        // update the remaining data.
                        var lastIndex = parser.lastIndex();
                        if (lastIndex > 0) {
                            this._remainingData = Array.from(TextEncoding.getBytes(json.substring(lastIndex), this._charset));
                            return parser;
                        }
    
                        // Otherwise retry.
                        self.nextParser(timeout, callback);
                    }, self);
                },
                timeout: callback.timeout,
                error: function(e) {
                    callback.error(new MslEncoderException("Error reading from the source input stream.", e));
                },
            });
        },
        
        /** @inheritDoc */
        next: function next(timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                var value = (this._parser) ? this._parser.nextValue() : undefined;
                if (value !== undefined)
                    return new JsonMslObject(this._encoder, value);

                this.nextParser(this._timeout, {
                    result: function(parser) {
                        InterruptibleExecutor(callback, function() {
                            // If aborted then return null.
                            if (this._aborted)
                                return null;

                            this._parser = parser;

                            // If we've reached the end of the stream then
                            // return null.
                            if (!this._parser)
                                return null;

                            // Grab the next value.
                            var value = this._parser.nextValue();
                            if (typeof value !== 'object')
                                throw new MslEncoderException("Malformed MSL message. Parsed " + typeof value + " instead of object.");
                            return new JsonMslObject(this._encoder, value);
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('JsonMslTokenizer'));