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
                _lastJson: { value: 0, writable: true, enumerable: false, configurable: false },
                /** @type {ClarinetParser} */
                _parser: { value: new ClarinetParser(), writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        close: function close(timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                // If there is no unparsed data then there is nothing to clean
                // up.
                if (this._parser.unparsedCount() == 0)
                    return true;
                
                // Otherwise reset the source input stream and skip bytes equal
                // to the parsed data length in encoded bytes. This will allow
                // the input stream to be used again by a different MSL
                // tokenizer.
                //
                // If we did the right thing in this class' other functions,
                // calling reset() should not throw an exception.
                var parsedCount = this._lastJson.length - this._parser.unparsedCount();
                var parsedJson = this._lastJson.substring(0, parsedCount);
                var encodedData = TextEncoding.getBytes(parsedJson, this._charset);
                this._source.reset();
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
         * <p>Feed more data from the source input stream into the parser until
         * another value has been found. This value is returned.</p>
         * 
         * @param {number} read timeout in milliseconds.
         * @param {{result: function(*), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the next parsed
         *        value, be notified of timeout, or any thrown exceptions.
         * @throws MslEncoderException if a JSON object exceeds the maximum
         *         permitted size or there is an error reading from the source
         *         input stream.
         */
        parseData: function parseData(timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                // Mark the source input stream. We will need to return to this
                // position when we suceed in parsing the JSON.
                this._source.mark(READ_SIZE);
                
                // Read the next chunk of data.
                this._source.read(READ_SIZE, timeout, {
                    result: function(data) {
                        InterruptibleExecutor(callback, function() {
                            // On end of stream return null for the value.
                            if (!data) return null;
        
                            // Aborted responses send valid but empty data, treat
                            // it as end of stream.
                            if (!data.length) return null;
                            
                            // Convert the collected bytes to a string.
                            this._lastJson = TextEncoding.getString(data, this._charset);
                            
                            // If the new unparsed data size exceeds the maximum
                            // allowed then error.
                            var unparsedCount = this._parser.unparsedCount() + this._lastJson.length;
                            if (unparsedCount > MAX_CHARACTERS)
                                throw new MslEncoderException("JSON parsing stopped after reaching " + unparsedCount + " unparsed characters.");
                            
                            // Attempt to parse the JSON.
                            this._parser.write(this._lastJson);
    
                            // If we got something then return the value.
                            var value = this._parser.nextValue();
                            if (value !== undefined)
                                return value;
        
                            // Otherwise retry. This will discard the current
                            // mark position which is okay as we definitely
                            // need to read past the read limit.
                            //
                            // Use setTimeout to avoid blowing the stack, which
                            // is also faster.
                            setTimeout(function() {
                                self.parseData(timeout, callback);
                            }, 0);
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            throw new MslEncoderException("Error reading from the source input stream.", e);
                        }, self);
                    },
                });
            }, self);
        },
        
        /** @inheritDoc */
        next: function next(timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                // Ask the parser for the next value.
                var value = this._parser.nextValue();
                
                // If we received a value, wrap it.
                if (value !== undefined) {
                    wrapValue(value);
                    return;
                }

                // Otherwise try to parse more data.
                this.parseData(this._timeout, {
                    result: function(value) {
                        InterruptibleExecutor(callback, function() {
                            // If aborted then return null.
                            if (this._aborted)
                                return null;

                            // If we've reached the end of the stream then
                            // return null.
                            if (!value)
                                return null;

                            // Wrap the value.
                            wrapValue(value);
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);
            
            function wrapValue(value) {
                InterruptibleExecutor(callback, function() {
                    // Error if the value is not an object.
                    if (typeof value !== 'object')
                        throw new MslEncoderException("Malformed MSL message. Parsed " + typeof value + " instead of object.");
                    return new JsonMslObject(this._encoder, value);
                }, self);
            }
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('JsonMslTokenizer'));