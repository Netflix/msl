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
 * An output stream provides write capability of raw bytes.
 *
 * Timeouts are triggered if no character has been sent within the timeout
 * period. A slow operation that is able to write at least one character per
 * timeout period will not trigger a timeout.
 *
 * @interface
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	
	var OutputStream = module.exports = Class.create({
	    /**
	     * Abort any outstanding operations.
	     */
	    abort: function() {},
	
	    /**
	     * Closes this output stream and releases any resources associated with the
	     * stream.
	     *
	     * @param {number} timeout write timeout in milliseconds.
	     * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
	     *        callback the callback that will receive true upon completion or
	     *        false if aborted, be notified of a timeout, or any thrown
	     *        exceptions.
	     * @throws IOException if there is an error closing the stream.
	     */
	    close: function(timeout, callback) {},
	
	    /**
	     * Writes the specified portion of the byte array to the output stream.
	     *
	     * This is an asynchronous call and the callback should be returned as soon
	     * as the byte structure is no longer needed or the timeout is hit. If the
	     * timeout is hit then the number of bytes written will be less than
	     * the requested amount.
	     *
	     * @param {Uint8Array} data the data to write.
	     * @param {number} off offset into the data.
	     * @param {number} len number of bytes to write.
	     * @param {number} timeout write timeout in milliseconds or -1 for no
	     *        timeout.
	     * @param {{result: function(number), timeout: function(number), error: function(Error)}}
	     *        callback the callback that will receive the number of bytes
	     *        written which will be less than the length if aborted, be
	     *        notified of a timeout, or any thrown exceptions.
	     * @throws IOException if there is an error writing the data or the stream
	     *         is closed.
	     * @throws RangeError if the offset is negative, the length is negative, or
	     *         the offset plus length exceeds the data length.
	     */
	    write: function(data, off, len, timeout, callback) {},
	
	    /**
	     * Flushes this output stream so any buffered data is written out.
	     *
	     * @param {number} timeout write timeout in milliseconds or -1 for no
	     *        timeout.
	     * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
	     *        callback the callback that will receive true upon completion or
	     *        false if aborted, be notified of a timeout, or any thrown
	     *        exceptions.
	     * @throws IOException if there is an error flushing the data.
	     */
	    flush: function(timeout, callback) {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('OutputStream'));
