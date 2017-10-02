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
 * An input stream provides read capability of raw bytes.
 *
 * Timeouts are triggered if no character has been read within the timeout
 * period. A slow operation that is able to read at least one character per
 * timeout period will not trigger a timeout.
 *
 * @interface
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	
	var InputStream = module.exports = Class.create({
	    /**
	     * Aborts any outstanding operations.
	     */
	    abort: function() {},
	
	    /**
	     * Closes this input stream and releases any resources associated with the
	     * stream.
	     *
	     * @param {number} timeout write timeout in milliseconds.
	     * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
	     *        callback the callback that will receive true upon completion or
	     *        false if aborted, be notified of a timeout, or any thrown
	     *        exceptions.
	     */
	    close: function(timeout, callback) {},
	
	    /**
	     * Marks the current position in this input stream. A subsequent call to
	     * the reset method repositions this stream at the last marked position so
	     * that subsequent reads re-read the same bytes.
	     *
	     * @see #reset()
	     */
	    mark: function() {},
	
	    /**
	     * Repositions this stream to the position at the time the mark method was
	     * last called on this input stream.
	     *
	     * @throws IOException if this stream has not been marked.
	     * @see #mark()
	     */
	    reset: function() {},
	
	    /**
	     * @return {boolean} true if the mark and reset operations are supported.
	     */
	    markSupported: function() {},
	
	    /**
	     * <p>Returns some bytes from the input stream, which may be less than
	     * the number requested. If -1 is specified for the length then this
	     * function returns at least one byte unless the timeout is hit. If 0
	     * is specified for the length then zero bytes are returned.</p>
	     * 
	     * <p>Unless zero bytes are requested, this method will block until at
	     * least one byte is available or the timeout is hit. If the timeout is
	     * hit then whatever bytes that have been read will be returned.</p>
	     *
	     * <p>If there are no more bytes available (i.e. end of stream is hit)
	     * then null is returned. This is the only reliable indicator that no
	     * more data is available.</p>
	     *
	     * <p>If aborted whatever bytes that have been read will be
	     * returned.</p>
	     *
	     * @param {number} len the number of characters to read.
	     * @param {number} timeout read timeout in milliseconds or -1 for no
	     *        timeout.
	     * @param {{result: function(Uint8Array), timeout: function(Uint8Array), error: function(Error)}}
	     *        callback the callback that will receive the bytes or null, be
	     *        notified of timeouts, or any thrown exceptions.
	     * @throws IOException if there is an error reading the data or the stream
	     *         is closed.
	     */
	    read: function(len, timeout, callback) {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('InputStream'));
