/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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

(function(require, module) {
    "use strict";

    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var FilterStreamFactory = require('msl-core/msg/FilterStreamFactory.js');
    var InputStream = require('msl-core/io/InputStream.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MslIoException = require('msl-core/MslIoException.js');
    var OutputStream = require('msl-core/io/OutputStream.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');

    /**
     * <p>A filter input stream that appends read data to a text HTML DOM
     * element.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var TextInputStream = InputStream.extend({
        /**
         * Create a new text input stream backed by the provided input stream.
         *
         * @param {Element} target target text HTML DOM element.
         * @param {InputStream} in the backing input stream.
         */
        init: function init(target, input) {
            // The properties.
            var props = {
                _target: { value: target, writable: false, enumerable: false, configurable: false },
                _input: { value: input, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        close: function close(timeout, callback) {
            this._input.close(timeout, callback);
        },

        /** @inheritDoc */
        mark: function mark(readlimit) {
            this._input.mark(readlimit);
        },

        /** @inheritDoc */
        reset: function reset() {
            this._input.reset();
        },

        /** @inheritDoc */
        markSupported: function markSupported() {
            return this._input.markSupported();
        },

        /** @inheritDoc */
        read: function read(len, timeout, callback) {
            var self = this;

            this._input.read(len, timeout, {
                result: function(data) {
                    AsyncExecutor(callback, function() {
                        try {
                            if (data)
                                self._target.innerHTML += TextEncoding.getString(data, MslConstants.DEFAULT_CHARSET);
                            return data;
                        } catch (e) {
                            throw new MslIoException("Error encoding data into string.", e);
                        }
                    }, self);
                },
                timeout: function(data) {
                    AsyncExecutor(callback, function() {
                        try {
                            if (data)
                                self._target.innerHTML += TextEncoding.getString(data, MslConstants.DEFAULT_CHARSET);
                            return data;
                        } catch (e) {
                            throw new MslIoException("Error encoding data into string.", e);
                        }
                    }, self);
                },
                error: callback.error,
            });
        },
        
        /** @inheritDoc */
        skip: function skip(n, timeout, callback) {
            this._input.skip(n, timeout, callback);
        }
    });

    /**
     * <p>A filter output stream that appends written data to a text HTML DOM
     * element.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var TextOutputStream = OutputStream.extend({
        /**
         * Create a new text output stream backed by the provided output stream.
         *
         * @param {Element} target target text HTML DOM element.
         * @param {OutputStream} output the backing output stream.
         */
        init: function init(target, output) {
            // The properties.
            var props = {
                _target: { value: target, writable: false, enumerable: false, configurable: false },
                _output: { value: output, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        close: function close(timeout, callback) {
            this._output.close(timeout, callback);
        },

        /** @inheritDoc */
        write: function write(data, off, len, timeout, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                try {
                    this._target.innerHTML += TextEncoding.getString(data.subarray(off, off + len), MslConstants.DEFAULT_CHARSET);
                } catch (e) {
                    throw new MslIoException("Error encoding data into string.", e);
                }
                this._output.write(data, off, len, timeout, callback);
            }, self);
        },

        /** @inheritDoc */
        flush: function flush(timeout, callback) {
            this._output.flush(timeout, callback);
        },
    });

    /**
     * <p>This filter stream factory will append stream data to provided text
     * HTML DOM elements.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var SimpleFilterStreamFactory = module.exports = FilterStreamFactory.extend({
        /**
         * <p>Create a new filter stream factory that is tied to the provided
         * HTML text elements.</p>
         *
         * @param {Element} sentText sent text HTML DOM element.
         * @param {Element} receivedText received text HTML DOM element.
         */
        init: function init(sentText, receivedText) {
            // Set properties.
            var props = {
                _sent: { value: sentText, writable: false, enumerable: false, configurable: false },
                _received: { value: receivedText, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getInputStream: function getInputStream(input) {
            return new TextInputStream(this._received, input);
        },

        /** @inheritDoc */
        getOutputStream: function getOutputStream(output) {
            return new TextOutputStream(this._sent, output);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleFilterStreamFactory'));
