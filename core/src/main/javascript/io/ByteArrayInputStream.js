/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
 * Reads data from a byte array.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var InputStream = require('../io/InputStream.js');
    var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
    var MslIoException = require("../MslIoException.js");
        
    var ByteArrayInputStream = module.exports = InputStream.extend({
        /**
         * Create a new byte array input stream from the provided data.
         *
         * @param {Uint8Array} data the data.
         */
        init: function init(data) {
            // The properties.
            var props = {
                _data: { value: data, writable: false, enumerable: false, configurable: false },
                _closed: { value: false, writable: true, enumerable: false, configurable: false },
                _currentPosition: { value: 0, writable: true, enumerable: false, configurable: false },
                _mark: { value: -1, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    
        /** @inheritDoc */
        abort: function abort() {},
    
        /** @inheritDoc */
        close: function close(timeout, callback) {
            InterruptibleExecutor(callback, function() {
                this._closed = true;
                return true;
            }, this);
        },

        /** @inheritDoc */
        mark: function mark(readlimit) {
            this._mark = this._currentPosition;
        },
    
        /** @inheritDoc */
        reset: function reset() {
            if (this._mark == -1)
                throw new MslIoException("Cannot reset before input stream has been marked or if mark has been invalidated.");
            this._currentPosition = this._mark;
        },
    
        /** @inheritDoc */
        markSupported: function markSupported() {
            return true;
        },
    
        /**
         * Returns the requested number of bytes from the input stream. If -1
         * is specified for the length then this function returns any bytes
         * that are available but at least one unless the timeout is hit.
         *
         * If fewer bytes than requested are available then all available
         * bytes are returned. If zero bytes are available the method
         * blocks until at least one character is available or the timeout is hit.
         *
         * If there are no more bytes available (i.e. end of stream is hit)
         * then null is returned.
         *
         * @param {number} len the number of bytes to read.
         * @param {number} timeout read timeout in milliseconds.
         * @param {{result: function(Uint8Array), timeout: function(Uint8Array), error: function(Error)}}
         *        callback the callback that will receive the bytes or null, be
         *        notified of timeouts, or any thrown exceptions.
         */
        read: function read(len, timeout, callback) {
            InterruptibleExecutor(callback, function() {
                if (this._closed)
                    throw new MslIoException("Stream is already closed.");
    
                if (this._currentPosition == this._data.length)
                    return null;
    
                if (len == -1)
                    len = this._data.length - this._currentPosition;
                var endPosition = this._currentPosition + len;
                var data = this._data.subarray(this._currentPosition, endPosition);
                this._currentPosition += data.length;
                return data;
            }, this);
        },
        
        /** @inheritDoc */
        skip: function(n, timeout, callback) {
            InterruptibleExecutor(callback, function() {
                var originalPosition = this._currentPosition;
                this._currentPosition = Math.min(this._currentPosition + n, this._data.length);
                return this._currentPosition - originalPosition;
            }, this);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('ByteArrayInputStream'));
