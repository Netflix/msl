/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
 * The console filter stream factory will output the wrapped streams data to
 * console.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var InputStream = require('../io/InputStream.js');
    var OutputStream = require('../io/OutputStream.js');
    var FilterStreamFactory = require('../msg/FilterStreamFactory.js');
    
    /**
     * A filter input stream that outputs read data to stdout. A new line is
     * output when the stream is closed.
     */
    var ConsoleInputStream = InputStream.extend({
        /**
         * Create a new console input stream backed by the provided input
         * stream.
         * 
         * @param {InputStream} in the backing input stream.
         */
        init: function init(input) {
            // The properties.
            var props = {
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
            this._input.read(len, timeout, {
                result: function(data) {
                    console.log(data);
                    callback.result(data);
                },
                timeout: function(data) {
                    console.log(data);
                    callback.timeout(data);
                },
                error: callback.error,
            });
        },
        
        /** @inheritDoc */
        skip: function skip(n, timeout, callback) {
            this._input.skip(n, timeout, callback);
        },
    });
    
    /**
     * A filter output stream that outputs written data to stdout. A newline is
     * output when the stream is closed.
     */
    var ConsoleOutputStream = OutputStream.extend({
        /**
         * Create a new console output stream backed by the provided output
         * stream.
         * 
         * @param {OutputStream} output the backing output stream.
         */
        init: function init(output) {
            // The properties.
            var props = {
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
            console.log(data.subarray(off, off + len));
            this._output.write(data, off, len, timeout, callback);
        },

        /** @inheritDoc */
        flush: function flush(timeout, callback) {
            this._output.flush(timeout, callback);
        },
    });
    
    var ConsoleFilterStreamFactory = module.exports = FilterStreamFactory.extend({
        /** @inheritDoc */
        getInputStream: function getInputStream(input) {
            return new ConsoleInputStream(input);
        },
    
        /** @inheritDoc */
        getOutputStream: function getOutputStream(output) {
            return new ConsoleOutputStream(output);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('ConsoleFilterStreamFactory'));
