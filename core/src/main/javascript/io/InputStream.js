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
	var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
	
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
         * <p> The <code>readlimit</code> arguments tells this input stream to
         * allow that many bytes to be read before the mark position gets
         * invalidated.
         *
         * <p> The general contract of <code>mark</code> is that, if the method
         * <code>markSupported</code> returns <code>true</code>, the stream somehow
         * remembers all the bytes read after the call to <code>mark</code> and
         * stands ready to supply those same bytes again if and whenever the method
         * <code>reset</code> is called.  However, the stream is not required to
         * remember any data at all if more than <code>readlimit</code> bytes are
         * read from the stream before <code>reset</code> is called.
	     *
	     * @param {number=} readlimit optional maximum limit of bytes that can
	     *                  be read before the mark position becomes invalid.
	     * @see #reset()
	     */
	    mark: function(readlimit) {},
	
	    /**
	     * Repositions this stream to the position at the time the mark method was
	     * last called on this input stream.
	     *
	     * @throws IOException if this stream has not been marked or if the
	     *         read limit has been exceeded.
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
	    
	    /**
	     * <p>Skips over and discards <code>n</code> bytes of data from this
	     * input stream. The <code>skip</code> method may, for a variety of
	     * reasons, end up skipping over some smaller number of bytes, possibly
	     * <code>0</code>.</p>
	     * 
	     * <p>Skipped bytes must still be accounted for by mark() and
	     * reset().</p>
	     * 
	     * <p>The default implementation calls read() with the requested number
	     * of bytes.</p>
	     * 
	     * @param {number} n the number of bytes to be skipped.
	     * @param {number} timeout skip timeout in milliseconds or -1 for no
	     *        timeout.
	     * @param {{result: function(number), timeout: function(number), error: function(Error)}}
	     *        callback the callback that will receive the actual number of
	     *        bytes skipped, be notified of timeouts, or any thrown
	     *        exceptions.
	     * @throws IOException if skip is not supported, if there is an error
	     *         skipping over the data, or if the stream is closed.
	     */
	    skip: function(n, timeout, callback) {
            this.read(n, timeout, {
                result: function(data) {
                    InterruptibleExecutor(callback, function() {
                        return (data) ? data.length : 0;
                    });
                },
                timeout: function(data) {
                    InterruptibleExecutor(callback, function() {
                        return (data) ? data.length : 0;
                    });
                },
                error: callback.error,
            });
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('InputStream'));
