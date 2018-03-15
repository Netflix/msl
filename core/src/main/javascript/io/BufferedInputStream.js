/**
 * Copyright (c) 2017-2018 Netflix, Inc.  All rights reserved.
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
 * <p>A {@code BufferedInputStream} adds support for the {@code mark()} and
 * {@code reset()} functions.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var InputStream = require('../io/InputStream.js');
    var ByteArrayOutputStream = require('../io/ByteArrayOutputStream.js');
    var MslIoException = require('../MslIoException.js');
    var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');

	var BufferedInputStream = module.exports = InputStream.extend({
		/**
		 * Create a new buffered input stream backed by the provided input
		 * stream.
		 * 
		 * @param {InputStream} source the backing input stream.
		 */
		init: function init(source) {
			// The properties.
			var props = {
			    _source: { value: source, writable: false, enumerable: false, configurable: false },
			    /**
			     * Buffer of data read since the last call to mark(). Null if
			     * mark() has not been called or if the read limit has been
			     * exceeded.
			     * 
			     * @type {?ByteArrayOutputStream}
			     */
			    _buffer: { value: null, writable: true, enumerable: false, configurable: false },
			    /**
			     * Current buffer read position.
			     * 
			     * @type {number}
			     */
			    _bufpos: { value: 0, writable: true, enumerable: false, configurable: false },
			    /**
			     * Requested maximum number of bytes to buffer. -1 for no
			     * maximum.
			     * 
			     * @type {number}
			     */
			    _readlimit: { value: -1, writable: true, enumerable: false, configurable: false },
			    /**
			     * True if stream is closed.
			     * 
			     * @type {boolean}
			     */
			    _closed: { value: false, writable: true, enumerable: false, configurable: false },
			};
			Object.defineProperties(this, props);
		},
		
		/** @inheritDoc */
		abort: function abort() {
			this._source.abort();
		},
		
		/** @inheritDoc */
		close: function close(timeout, callback) {
            this._closed = true;
            this._source.close(timeout, callback);
		},
		
		/** @inheritDoc */
		mark: function mark(readlimit) {
			// If there is no current mark, then start buffering.
			if (!this._buffer) {
				this._buffer = new ByteArrayOutputStream();
				this._bufpos = 0;
				this._readlimit = readlimit;
				return;
			}
			
			// If there is data buffered and the current mark position is not
			// zero (at the beginning) then truncate the buffer.
			if (this._bufpos > 0) {
				var data = this._buffer.toByteArray();
				this._buffer = new ByteArrayOutputStream();
				// ByteArrayOutputStream.write() is synchronous so we can get
				// away with this.
				this._buffer.write(data, this._bufpos, data.length - this._bufpos, -1, {
					result: function() {},
					timeout: function() {},
					error: function() {}
				});
				this._bufpos = 0;
			}
			
			// Otherwise the existing buffer contains the correct data.
			//
			// Set the new read limit.
			this._readlimit = readlimit;
		},
		
		/** @inheritDoc */
		reset: function reset() {
			if (!this._buffer)
				throw new MslIoException("Cannot reset before input stream has been marked or if mark has been invalidated.");
			
			// Start reading from the beginning of the buffer. 
			this._bufpos = 0;
		},
		
		/** @inheritDoc */
		markSupported: function markSupported() {
			return true;
		},
		
		/** @inheritDoc */
		read: function read(len, timeout, callback) {
			var self = this;
			
			InterruptibleExecutor(callback, function() {
	            if (this._closed)
	                throw new MslIoException("Stream is already closed.");
	            
				// If we have any data in the buffer, read it first.
				var bufferedData;
				if (this._buffer && this._buffer.size() > this._bufpos) {
					// If no length was specified, read everything remaining
					// in the buffer.
					var endpos;
					if (len == -1) {
						endpos = this._buffer.size();
					}
					// Otherwise read the amount requested but no more than
					// what remains in the buffer. 
					else {
						endpos = Math.min(this._buffer.size(), this._bufpos + len);
					}
					
					// Extract the buffered data.
					bufferedData = this._buffer.toByteArray().subarray(this._bufpos, endpos);
					this._bufpos += bufferedData.length;
					
					// If the data is of sufficient size, return it.
					if (bufferedData.length >= len)
						return bufferedData;
				} else {
					bufferedData = null;
				}
				
				// We were not able to read enough off the buffer.
				//
				// If a length was specified, read any remaining data off the
				// backing source.
				var remainingLength = -1;
				if (len != -1)
					remainingLength = len - ((bufferedData) ? bufferedData.length : 0);
				this._source.read(remainingLength, timeout, {
					result: function(data) {
						InterruptibleExecutor(callback, function() {
							var concatData = concatenate(bufferedData, data);
							return concatData;
						}, self);
					},
					timeout: function(data) {
						InterruptibleExecutor(callback, function() {
							var concatData = concatenate(bufferedData, data);
							callback.timeout(concatData);
						}, self);
					},
					error: callback.error,
				});
				
				function concatenate(bufferedData, sourceData) {
					// On end of stream, return the buffered data.
					if (!sourceData)
						return bufferedData;
					
					// Append to the buffer if we are buffering.
					if (self._buffer) {
					    // Stop buffering if a read limit is set and the
					    // additional data would exceed it.
					    if (self._readlimit != -1 && self._buffer.size() + sourceData.length > self._readlimit) {
					        self._buffer = null;
					        self._bufpos = 0;
					        self._readlimit = -1;
					    }
					    
					    // Otherwise append.
					    else {
					        // ByteArrayOutputStream.write() is synchronous so
					        // we can get away with this.
					        self._buffer.write(sourceData, 0, sourceData.length, -1, {
					            result: function() {},
					            timeout: function() {},
					            error: function() {}
					        });
					        self._bufpos += sourceData.length;
					        // The mark position should now be equal to the
					        // buffer length.
					    }
					}
					
					// If we didn't have any buffered data, return the
					// data directly.
					if (!bufferedData)
						return sourceData;
					
					// Otherwise return the buffered data and the read
					// data.
					var result = new Uint8Array(bufferedData.length + sourceData.length);
					result.set(bufferedData);
					result.set(sourceData, bufferedData.length);
					return result;
				}
			}, self);
		},
		
		/** @inheritDoc */
		skip: function skip(n, timeout, callback) {
		    var self = this;
		    
		    InterruptibleExecutor(callback, function() {
		        if (this._closed)
		            throw new MslIoException("Stream is already closed.");
		        
		        // If we have any data in the buffer, skip it first.
		        var skipcount = 0;
		        if (this._buffer && this._buffer.size() > this._bufpos) {
		            skipcount = Math.min(n, this._buffer.size() - this._bufpos);
		            this._bufpos += skipcount;
		            
		            // If we skipped as much as requested return immediately.
		            if (skipcount == n)
		                return skipcount;
		        }
		        
		        // We were not able to skip enough using just buffered data.
		        this._read(n - skipcount, timeout, {
		            result: function(data) {
		                InterruptibleExecutor(callback, function() {
		                    if (!data) return skipcount;
		                    return data.length + skipcount;
		                }, self);
		            },
		            timeout: function(data) {
                        InterruptibleExecutor(callback, function() {
                            if (!data) return skipcount;
                            return data.length + skipcount;
                        }, self);
		            },
		            error: callback.error,
		        });
		    }, self);
		},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('BufferedInputStream'));