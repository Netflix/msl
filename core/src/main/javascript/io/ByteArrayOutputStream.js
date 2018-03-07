/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
 * Accumulates all received data into a byte array.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var OutputStream = require('../io/OutputStream.js');
	var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
	var MslIoException = require("../MslIoException.js");
		
	var ByteArrayOutputStream = module.exports = OutputStream.extend({
	    /**
	     * Create a new byte array output stream.
	     */
	    init: function init() {
	        // The properties.
	        var props = {
	            _closed: { value: false, writable: true, enumerable: false, configurable: false },
	            /** @type {Uint8Array} */
	            _result: { value: new Uint8Array(0), writable: true, enuemrable: false, configurable: false },
	            /** @type {Array.<{data: Uint8Array}>} */
	            _buffered: { value: [], writable: false, enumerable: false, configurable: false },
	        };
	        Object.defineProperties(this, props);
	    },
	
	    /** @inheritDoc */
	    abort: function abort() {},
	
	    /** @inheritDoc */
	    close: function close(timeout, callback) {
	        this._closed = true;
	        callback.result(true);
	    },
    	    
        /** @inheritDoc */
        write: function(data, off, len, timeout, callback) {
            try {
                if (this._closed)
                    throw new MslIoException("Stream is already closed.");

                if (off < 0)
                    throw new RangeError("Offset cannot be negative.");
                if (len < 0)
                    throw new RangeError("Length cannot be negative.");
                if (off + len > data.length)
                    throw new RangeError("Offset plus length cannot be greater than the array length.");

                var endpos = Math.min(data.length, off + len);
                var segment = data.subarray(off, endpos);
                this._buffered.push(segment);
                callback.result(segment.length);
            } catch (e) {
                callback.error(e);
            }
        },
    
        /** @inheritDoc */
        flush: function(timeout, callback) {
            try {
                while (this._buffered.length > 0) {
                    var segment = this._buffered.shift();
                    if (!this._result) {
                        this._result = new Uint8Array(segment);
                    } else {
                        var newResult = new Uint8Array(this._result.length + segment.length);
                        newResult.set(this._result);
                        newResult.set(segment, this._result.length);
                        this._result = newResult;
                    }
                }
                callback.result(true);
            } catch (e) {
                callback.error(e);
            }
        },

        /**
         * @return {number} the number of accumulated bytes.
         */
        size: function size() {
            this.flush(1, {result: function() {}});
            return this._result.length;
        },

        /**
         * @return {Uint8Array} a Uint8Array of the accumulated bytes.
         */
        toByteArray: function toByteArray() {
            this.flush(1, {result: function() {}});
            return this._result;
        },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('ByteArrayOutputStream'));
