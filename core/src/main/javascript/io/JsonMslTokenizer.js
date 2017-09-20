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

/**
 * <p>Create a new {@link MslTokenizer} that parses JSON-encoded MSL
 * messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	const MslTokenizer = require('../io/MslTokenizer.js');
	const AsyncExecutor = require('../util/AsyncExecutor.js');
	const InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
	const MslEncoderException = require('../io/MslEncoderException.js');
	const ClarinetParser = require('../io/ClarinetParser.js');
	const JsonMslObject = require('../io/JsonMslObject.js');
	const MslConstants = require('../MslConstants.js');
	const textEncoding = require('../lib/textEncoding.js');

    /**
     * Delay time between read attempts in milliseconds.
     *
     * @const
     * @type {number}
     */
    var READ_DELAY = 10;

    /**
     * Maximum JSON value size in characters (10MB).
     *
     * @const
     * @type {number}
     */
    var MAX_CHARACTERS = 10 * 1024 * 1024;
    
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
                _charset: { value: MslConstants.DEFAULT_CHARSET, writable: false, enumerable: false, configurable: false },
                /** @type {string} */
                _remainingData: { value: '', writable: true, enumerable: false, configurable: false },
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
         * @param {{result: function(ClarinetParser), error: function(Error)}}
         *        callback the callback that will receive the new Clarinet JSON
         *        parser or any thrown exceptions.
         * @throws MslEncoderException if a JSON object exceeds the maximum
         *         permitted size or there is an error reading from the source
         *         input stream.
         */
        nextParser: function nextParser(timeout, callback) {
            var self = this;
            
            this._source.read(-1, timeout, {
                result: function(data) {
                    AsyncExecutor(callback, function() {
                        // On end of stream return null for the parser.
                        if (!data) return null;
    
                        // Aborted responses send valid but empty data, treat
                        // it as end of stream.
                        if (!data.length) return null;
                        
                        // Append the new data to the previous data and attempt
                        // to parse the JSON.
                        var json;
                        try {
                        	json = this._remainingData.concat(textEncoding.getString(data, this._charset));
                        } catch (e) {
                        	throw new MslEncoderException("Invalid JSON text encoding.", e);
                        }
                        var parser = new ClarinetParser(json);
    
                        // If we got something then return the parser and
                        // remaining data.
                        var lastIndex = parser.lastIndex();
                        if (lastIndex > 0) {
                            this._remainingData = json.substring(lastIndex);
                            return parser;
                        }
    
                        // If the new data size exceeds the maximum allowed
                        // then error.
                        if (json.length > MAX_CHARACTERS)
                            throw new MslEncoderException("No JSON parsed after receiving " + json.length + " characters.");
    
                        // Otherwise schedule a retry.
                        this._remainingData = json;
                        setTimeout(function() {
                            self.nextParser(timeout, callback);
                        }, READ_DELAY);
                    }, self);
                },
                timeout: function(data) {
                    AsyncExecutor(callback, function() {
                        // If we didn't get any data notify the caller and stop.
                        if (!data || data.length == 0) {
                            callback.timeout(this._remainingData);
                            return;
                        }
    
                        // Append the new data to the previous data and attempt
                        // to parse the JSON.
                        var json;
                        try {
                        	json = this._remainingData.concat(textEncoding.getString(data, this._charset));
                        } catch (e) {
                        	throw new MslEncoderException("Invalid JSON text encoding.");
                        }
                        var parser = new ClarinetParser(json);
    
                        // If we got something then return the parser and
                        // remaining data.
                        var lastIndex = parser.lastIndex();
                        if (lastIndex > 0) {
                            this._remainingData = json.substring(lastIndex);
                            return parser;
                        }
    
                        // Otherwise notify the caller of the timeout and stop.
                        this._remainingData = json;
                        callback.timeout(this._remainingData);
                    }, self);
                },
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
                    timeout: function(remainingData) {
                        self._remainingData = remainingData;
                        callback.timeout();
                    },
                    error: callback.error,
                });
            }, self);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('JsonMslTokenizer'));