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
	 * Source input stream read size in bytes (64KiB). The larger the read
	 * size, the shorter the recursive call stack.
	 * 
	 * @const
	 * @type {number}
	 */
	var READ_SIZE = 64 * 1024;

    /**
     * Maximum JSON value size in characters (10MiB).
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
                /** @type {string} */
                _remainingData: { value: '', writable: true, enumerable: false, configurable: false },
                /** @type {ClarinetParser} */
                _parser: { value: undefined, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        close: function close(timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                // If there is no remaining data then there is nothing to clean up.
                if (this._remainingData.length == 0)
                    return true;
                
                // Otherwise reset the source input stream and skip bytes equal
                // to the remaining data length in encoded bytes. This will
                // allow the input stream to be used again by a different MSL
                // tokenizer.
                //
                // If we did the right thing in this class' other functions,
                // calling reset() should not throw an exception.
                this._source.reset();
                var encodedData = TextEncoding.getBytes(this._remainingData, this._charset);
                this._source.skip(encodedData.length, timeout, {
                    result: function(count) {
                        AsyncExecutor(callback, function() {
                            if (count != encodedData.length)
                                throw new MslEncoderException("Only skipped " + count + " of " + encodedData.length + " bytes. Source input stream may not be reusable for additional MSL messages.");
                            return true;
                        }, self);
                    },
                    timeout: function(count) {
                        AsyncExecutor(callback, function() {
                            if (count != encodedData.length)
                                throw new MslEncoderException("Only skipped " + count + " of " + encodedData.length + " bytes. Source input stream may not be reusable for additional MSL messages.");
                            return true;
                        }, self);
                    },
                    error: callback.error,
                });
            }, self);
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
            
            // Mark the source input stream. We will need to return to this
            // position when we suceed in parsing the JSON.
            this._source.mark(READ_SIZE);
            
            // Read the next chunk of data.
            this._source.read(READ_SIZE, timeout, {
                result: function(data) {
                    AsyncExecutor(callback, function() {
                        // On end of stream return null for the parser.
                        if (!data) return null;
    
                        // Aborted responses send valid but empty data, treat
                        // it as end of stream.
                        if (!data.length) return null;
                        
                        // Convert the collected bytes to a string and append
                        // it to the pending JSON.
                        try {
                            this._remainingData += TextEncoding.getString(data, this._charset);
                        } catch (e) {
                            throw new MslEncoderException("Invalid JSON text encoding.", e);
                        }
    
                        // If the new data size exceeds the maximum allowed
                        // then error.
                        if (this._remainingData.length > MAX_CHARACTERS)
                            throw new MslEncoderException("No JSON parsed after receiving " + this._remainingData.length + " characters.");
                        
                        // Attempt to parse the JSON.
                        var parser = new ClarinetParser(this._remainingData);

                        // If we got something then return the parser and
                        // update the remaining data.
                        var lastIndex = parser.lastIndex();
                        if (lastIndex > 0) {
                            this._remainingData = this._remainingData.substring(lastIndex);
                            return parser;
                        }
    
                        // Otherwise retry. This will discard the current mark
                        // position which is okay as we definitely need to read
                        // past the read limit.
                        self.nextParser(timeout, callback);
                    }, self);
                },
                timeout: callback.timeout,
                error: function(e) {
                    AsyncExecutor(callback, function() {
                        throw new MslEncoderException("Error reading from the source input stream.", e);
                    }, self);
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