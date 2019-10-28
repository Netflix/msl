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
 * <p>A MSL message consists of a single MSL header followed by one or more
 * payload chunks carrying application data. Each payload chunk is individually
 * packaged but sequentially ordered. The end of the message is indicated by a
 * payload with no data.</p>
 *
 * <p>No payload chunks may be included in an error message.</p>
 *
 * <p>Data is buffered until {@link #flush()} or {@link #close()} is called.
 * At that point a new payload chunk is created and written out. Closing a
 * {@code MessageOutputStream} does not close the destination output stream in
 * case additional MSL messages will be written.</p>
 * 
 * <p>A copy of the payload chunks is kept in-memory and can be retrieved by a
 * a call to {@code getPayloads()} until {@code stopCaching()} is called. This
 * is used to facilitate automatic re-sending of messages.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var OutputStream = require('../io/OutputStream.js');
    var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
    var MessageHeader = require('../msg/MessageHeader.js');
    var MessageCapabilities = require('../msg/MessageCapabilities.js');
    var PayloadChunk = require('../msg/PayloadChunk.js');
    var MslConstants = require('../MslConstants.js');
    var BlockingQueue = require('../util/BlockingQueue.js');
    var MslEncoderException = require('../io/MslEncoderException.js');
    var MslIoException = require('../MslIoException.js');
    var MslInternalException = require('../MslInternalException.js');
    var ErrorHeader = require('../msg/ErrorHeader.js');
    var MslException = require('../MslException.js');
    
    var MessageOutputStream = module.exports = OutputStream.extend({
        /**
         * <p>Construct a new message output stream. The header is output
         * immediately by calling {@code #flush()} on the destination output
         * stream.</p>
         *
         * <p>The most preferred compression algorithm and encoder format supported
         * by the message header will be used. If this is a response, the message
         * header capabilities will already consist of the intersection of the
         * local and remote entity capabilities.</p>
         *
         * @param {MslContext} ctx the MSL context.
         * @param {OutputStream} destination MSL output stream.
         * @param {MessageHeader|ErrorHeader} header message or error header.
         * @param {?ICryptoContext} cryptoContext payload data crypto context.
         *        Required if a message header is provided.
         * @param {?MslEncoderFormat} format MSL encoder format. Required if an
         *        error header is provided.
         * @param {number} timeout write timeout in milliseconds.
         * @param {{result: function(MessageOutputStream), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the message output
         *        stream, or any thrown exceptions.
         * @throws IOException if there is an error writing the header.
         */
        init: function init(ctx, destination, header, cryptoContext, format, timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                var encoder = ctx.getMslEncoderFactory();
                
                // The supported compression algorithms is the intersection of what the
                // local entity supports and what the remote entity supports.
                var capabilities;
                var compressionAlgo;
                var encoderFormat;
                if (header instanceof MessageHeader) {
                    capabilities = MessageCapabilities.intersection(ctx.getMessageCapabilities(), header.messageCapabilities);
                    if (capabilities) {
                        var compressionAlgos = capabilities.compressionAlgorithms;
                        compressionAlgo = MslConstants.CompressionAlgorithm.getPreferredAlgorithm(compressionAlgos);
                        var encoderFormats = capabilities.encoderFormats;
                        encoderFormat = encoder.getPreferredFormat(encoderFormats);
                    } else {
                        compressionAlgo = null;
                        encoderFormat = encoder.getPreferredFormat(null);
                    }
                } else {
                    capabilities = ctx.getMessageCapabilities();
                    compressionAlgo = null;
                    encoderFormat = format;
                }
                
                // Set properties.
                var props = {
                    _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                    _destination: { value: destination, writable: false, enumerable: false, configurable: false },
                    _encoderFormat: { value: encoderFormat, writable: false, enumerable: false, configurable: false },
                    _capabilities : { value: capabilities, writable: false, enumerable: false, configurable: false },
                    _header: { value: header, writable: false, enumerable: false, configurable: false },
                    _cryptoContext: { value: cryptoContext, writable: false, enumerable: false, configurable: false },
                    _compressionAlgo: { value: compressionAlgo, writable: true, enumerable: false, configurable: false },
                    _payloadSequenceNumber: { value: 1, writable: true, enumerable: false, configurable: false },
                    /** @type {Array.<Uint8Array>} */
                    _currentPayload: { value: [], writable: true, enumerable: false, configurable: false },
                    /** @type {boolean} */
                    _closed: { value: false, writable: true, enumerable: false, configurable: false },
                    /** @type {boolean} */
                    _closeDestination: { value: false, writable: true, enuemrable: false, configurable: false },
                    /** @type {boolean} */
                    _caching: { value: true, writable: true, enumerable: false, configurable: false },
                    /** @type {Array.<PayloadChunk>} */
                    _payloads: { value: [], writable: false, enumerable: false, configurable: false },
                    // Set true once the header has been sent and payloads may
                    // be written.
                    _ready: { value: false, writable: true, enumerable: false, configurable: false },
                    // Use a blocking queue as a semaphore.
                    _readyQueue: { value: new BlockingQueue(), writable: false, enumerable: false, configurable: false },
                    _aborted: { value: false, writable: true, enumerable: false, configurable: false },
                    // If timed out writing the header then deliver the timeout
                    // at the next operation.
                    _timedout: { value: false, writable: true, enumerable: false, configurable: false },
                    // If an error occurs while writing the header then deliver
                    // it at the next operation.
                    _errored: { value: null, writable: true, enumerable: false, configurable: false },
                };
                Object.defineProperties(this, props);

                function ready() {
                    self._ready = true;
                    self._readyQueue.add(true);
                }
                
                // Encode the header.
                header.toMslEncoding(encoder, encoderFormat, {
                    result: function(encoding) {
                        destination.write(encoding, 0, encoding.length, timeout, {
                            result: function(numWritten) {
                                try {
                                    // If aborted do nothing.
                                    if (self._aborted) {
                                        ready();
                                        return;
                                    }

                                    // Check if timed out.
                                    if (numWritten < encoding.length) {
                                        self._timedout = true;
                                        ready();
                                        return;
                                    }
                                    destination.flush(timeout, {
                                        result: function(success) {
                                            // If aborted do nothing.
                                            if (self._aborted) {
                                                ready();
                                                return;
                                            }
                                            self._timedout = !success;

                                            // Notify all that it is ready.
                                            ready();
                                        },
                                        timeout: function() {
                                            self._timedout = true;
                                            ready();
                                        },
                                        error: function(e) {
                                            self._errored = e;
                                            ready();
                                        }
                                    });
                                } catch (e) {
                                    self._errored = e;
                                    ready();
                                }
                            },
                            timeout: function() {
                                self._timedout = true;
                                ready();
                            },
                            error: function(e) {
                                self._errored = e;
                                ready();
                            }
                        });
                    },
                    error: function(e) {
                        if (e instanceof MslEncoderException)
                            self._errored = new MslIoException("Error encoding the message header.", e);
                        else
                            self._errored = e;
                        ready();
                    },
                });

                // Return this immediately instead of after writing the header
                // so the write can be aborted.
                return this;
            }, self);
        },

        /**
         * Block until the message output stream has successfully written the
         * message header and been fully initialized. The timeout callback will
         * be triggered based off the timeout value provided to the
         * constructor.
         *
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback will receive true once the message
         *        output stream is ready or false if it has been aborted,
         *        notified of timeout, or any exceptions thrown during the
         *        message initialization.
         */
        isReady: function isReady(callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                // If not ready wait until we are ready.
                if (!this._ready) {
                    this._readyQueue.poll(-1, {
                        result: function(elem) {
                            InterruptibleExecutor(callback, function() {
                                // If aborted return false.
                                if (elem === undefined) return false;
                                else perform();
                            }, self);
                        },
                        timeout: function() {
                            InterruptibleExecutor(callback, function() {
                                throw new MslInternalException("Timeout while waiting for MessageOutputStream.isReady() despite no timeout being specified.");
                            });
                        },
                        error: callback.error,
                    });
                } else {
                    perform();
                }
            }, self);
            
            function perform() {
                InterruptibleExecutor(callback, function() {
                    // Check if already aborted, timedout, or errored.
                    if (this._aborted)
                        return false;
                    if (this._timedout) {
                        callback.timeout();
                        return;
                    }
                    if (this._errored)
                        throw this._errored;

                    // Ready.
                    return true;
                }, self);
            }
        },

        /**
         * Set the payload chunk compression algorithm that will be used for all
         * future payload chunks. This function will flush any buffered data iff
         * the compression algorithm is being changed.
         *
         * @param {MslConstants.CompressionAlgorithm} compressionAlgo payload chunk
         *            compression algorithm. Null for no compression.
         * @param {number} timeout write timeout in milliseconds.
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive true if the
         *        compression algorithm is supported by the message, false if
         *        it is not, or any thrown exceptions.
         * @throws IOException if buffered data could not be flushed. The
         *         compression algorithm will be unchanged.
         * @throws MslInternalException if writing an error message.
         * @see #flush()
         */
        setCompressionAlgorithm: function setCompressionAlgorithm(compressionAlgo, timeout, callback) {
            var self = this;
            InterruptibleExecutor(callback, function() {
                // Make sure this is not an error message,
                var messageHeader = this.getMessageHeader();
                if (!messageHeader)
                    throw new MslInternalException("Cannot write payload data for an error message.");

                // Do nothing if the compression algorithm is not different.
                if (this._compressionAlgo == compressionAlgo)
                    return true;
                
                // Make sure the message is capable of using the compression algorithm.
                if (compressionAlgo) {
                    if (!this._capabilities)
                        return false;
                    var compressionAlgos = this._capabilities.compressionAlgorithms;
                    for (var i = 0; i < compressionAlgos.length; ++i) {
                        if (compressionAlgos[i] == compressionAlgo) {
                            flush();
                            return;
                        }
                    }
                    return false;
                } else {
                    flush();
                    return;
                }
            }, self);
            
            function flush() {
                self.flush(timeout, {
                    result: function(success) {
                        InterruptibleExecutor(callback, function() {
                            // If unsuccessful deliver an error.
                            if (!success)
                                throw new MslIoException("flush() aborted");
                            this._compressionAlgo = compressionAlgo;
                            return true;
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error
                });
            }
        },

        /**
         * @return {MessageHeader} the message header. Will be null for error messages.
         */
        getMessageHeader: function getMessageHeader() {
            if (this._header instanceof MessageHeader)
                return this._header;
            return null;
        },

        /**
         * @return {ErrorHeader} the error header. Will be null except for error messages.
         */
        getErrorHeader: function getErrorHeader() {
            if (this._header instanceof ErrorHeader)
                return this._header;
            return null;
        },
        
        /**
         * Returns true if the payload application data is encrypted. This will be
         * true if the entity authentication scheme provides encryption or if
         * session keys were used. Returns false for error messages which do not
         * have any payload chunks.
         * 
         * @return {boolean} true if the payload application data is encrypted. Will be false
         *         for error messages.
         */
        encryptsPayloads: function encryptsPayloads() {
            // Return false for error messages.
            var messageHeader = this.getMessageHeader();
            if (!messageHeader)
                return false;
            
            // If the message uses entity authentication data for an entity
            // authentication scheme that provides encryption, return true.
            var entityAuthData = messageHeader.entityAuthenticationData;
            if (entityAuthData && entityAuthData.scheme.encrypts)
                return true;
            
            // If the message uses a master token, return true.
            var masterToken = messageHeader.masterToken;
            if (masterToken)
                return true;
            
            // If the message includes key response data, return true.
            var keyResponseData = messageHeader.keyResponseData;
            if (keyResponseData)
                return true;
            
            // Otherwise return false.
            return false;
        },
        
        /**
         * Returns true if the payload application data is integrity protected.
         * This will be true if the entity authentication scheme provides integrity
         * protection or if session keys were used. Returns false for error
         * messages which do not have any payload chunks.
         * 
         * @return {boolean} true if the payload application data is integrity protected.
         *         Will be false for error messages.
         */
        protectsPayloadIntegrity: function protectsPayloadIntegrity() {
            // Return false for error messages.
            var messageHeader = this.getMessageHeader();
            if (!messageHeader)
                return false;
            
            // If the message uses entity authentication data for an entity
            // authentication scheme that provides integrity protection, return
            // true.
            var entityAuthData = messageHeader.entityAuthenticationData;
            if (entityAuthData && entityAuthData.scheme.protectsIntegrity)
                return true;
            
            // If the message uses a master token, return true.
            var masterToken = messageHeader.masterToken;
            if (masterToken)
                return true;
            
            // If the message includes key response data, return true.
            var keyResponseData = messageHeader.keyResponseData;
            if (keyResponseData)
                return true;
            
            // Otherwise return false.
            return false;
        },

        /**
         * Returns the payloads sent so far. Once payload caching is turned off
         * this list will always be empty.
         * 
         * @return {Array.<PayloadChunk>} an ordered list of the payloads sent so far.
         */
        getPayloads: function getPayloads() {
            return this._payloads;
        },
        
        /**
         * Turns off caching of any message data (e.g. payloads).
         */
        stopCaching: function stopCaching() {
            this._caching = false;
            this._payloads.length = 0;
        },

        /** @inheritDoc */
        abort: function abort() {
            this._aborted = true;
            this._destination.abort();
            this._readyQueue.cancelAll();
        },
        
        /**
         * By default the destination output stream is not closed when this message
         * output stream is closed. If it should be closed then this method can be
         * used to dictate the desired behavior.
         * 
         * @param {boolean} close true if the destination output stream should be closed,
         *        false if it should not.
         */
        closeDestination: function closeDestination(close) {
            this._closeDestination = close;
        },

        /** @inheritDoc */
        close: function close(timeout, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                // Check if already aborted, timedout, or errored.
                if (this._aborted)
                    return false;
                if (this._timedout) {
                    callback.timeout();
                    return;
                }
                if (this._errored)
                    throw this._errored;

                if (this._closed) return true;

                // Send a final payload that can be used to identify the end of data.
                // This is done by setting closed equal to true while the current
                // payload not null.
                this._closed = true;
                this.flush(timeout, {
                    result: function(success) {
                        InterruptibleExecutor(callback, function() {
                            // If successful the payload is sent.
                            if (success)
                                this._currentPayload = null;

                            // Only close the destination if instructed to do so because we might
                            // want to reuse the connection.
                            if (this._closeDestination)
                                this._destination.close(timeout, callback);
                            else
                                return success;
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);
        },

        /**
         * Flush any buffered data out to the destination. This creates a payload
         * chunk. If there is no buffered data or this is an error message this
         * function does nothing.
         *
         * @param {number} timeout write timeout in milliseconds.
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive true upon completion
         *        or false if aborted, be notified of a timeout, or any thrown
         *        exceptions.
         * @throws IOException if buffered data could not be flushed.
         * @throws MslInternalException if writing an error message.
         * @see java.io.OutputStream#flush()
         */
        flush: function flush(timeout, callback) {
            var self = this;
            
            self.isReady({
                result: function(ready) {
                    InterruptibleExecutor(callback, function() {
                        if (ready) perform();
                        else return false;
                    }, self);
                },
                timeout: callback.timeout,
                error: callback.error,
            });

            function perform() {
                InterruptibleExecutor(callback, function() {
                    // If the current payload is null, we are already closed.
                    if (!this._currentPayload) return true;

                    // If we are not closed, and there is no data then we have nothing to
                    // send.
                    if (!this._closed && this._currentPayload.length == 0) return true;

                    // This is a no-op for error messages and handshake messages.
                    var messageHeader = this.getMessageHeader();
                    if (!messageHeader || messageHeader.isHandshake()) return true;

                    // Otherwise we are closed and need to send any buffered data as the
                    // last payload. If there is no buffered data, we still need to send a
                    // payload with the end of message flag set.
                    //
                    // Convert the current payload to a single Uint8Array.
                    var length = 0;
                    this._currentPayload.forEach(function(segment) { length += segment.length; });
                    var data = new Uint8Array(length);
                    for (var offset = 0, i = 0; i < this._currentPayload.length; ++i) {
                        var segment = this._currentPayload[i];
                        data.set(segment, offset);
                        offset += segment.length;
                    }

                    // Write the payload chunk.
                    PayloadChunk.create(this._ctx, this._payloadSequenceNumber, messageHeader.messageId, this._closed, this._compressionAlgo, data, this._cryptoContext, {
                        result: function(chunk) {
                            InterruptibleExecutor(callback, function() {
                                if (this._caching) this._payloads.push(chunk);
                                var encoder = this._ctx.getMslEncoderFactory();
                                chunk.toMslEncoding(encoder, this._encoderFormat, {
                                    result: function(encoding) {
                                        InterruptibleExecutor(callback, function() {
                                            this._destination.write(encoding, 0, encoding.length, timeout, {
                                                result: function(numWritten) {
                                                    InterruptibleExecutor(callback, function() {
                                                        // If we were aborted then return false.
                                                        if (this._aborted) return false;

                                                        // If we timed out then notify the caller.
                                                        if (numWritten < chunk.length) {
                                                            callback.timeout();
                                                            return;
                                                        }

                                                        this._destination.flush(timeout, {
                                                            result: function(success) {
                                                                InterruptibleExecutor(callback, function() {
                                                                    // If we were aborted then return false.
                                                                    if (this._aborted) return false;

                                                                    // If we timed out then return false.
                                                                    if (!success) {
                                                                        callback.timeout();
                                                                        return;
                                                                    }

                                                                    // Increment the payload number.
                                                                    ++this._payloadSequenceNumber;

                                                                    // If we are closed, get rid of the current payload. This prevents
                                                                    // us from sending any more payloads. Otherwise reset it for reuse.
                                                                    if (this._closed)
                                                                        this._currentPayload = null;
                                                                    else
                                                                        this._currentPayload = [];
                                                                    return true;
                                                                }, self);
                                                            },
                                                            timeout: callback.timeout,
                                                            error: function(e) {
                                                                InterruptibleExecutor(callback, function() {
                                                                    if (e instanceof MslException)
                                                                        e = new MslIoException("Error encoding payload chunk [sequence number " + self._payloadSequenceNumber + "].", e);
                                                                    throw e;
                                                                }, self);
                                                            }
                                                        });
                                                    }, self);
                                                },
                                                timeout: function(numWritten) { callback.timeout(); },
                                                error: function(e) {
                                                    InterruptibleExecutor(callback, function() {
                                                        if (e instanceof MslException)
                                                            e = new MslIoException("Error encoding payload chunk [sequence number " + self._payloadSequenceNumber + "].", e);
                                                        throw e;
                                                    }, self);
                                                }
                                            });
                                        }, self);
                                    },
                                    error: function(e) {
                                        InterruptibleExecutor(callback, function() {
                                            if (e instanceof MslEncoderException)
                                                throw new MslIoException("Error encoding payload chunk [sequence number " + self._payloadSequenceNumber + "].", e);
                                            throw e;
                                        }, self);
                                    }
                                });
                            }, self);
                        },
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                if (e instanceof MslException)
                                    e = new MslIoException("Error encoding payload chunk [sequence number " + self._payloadSequenceNumber + "].", e);
                                throw e;
                            }, self);
                        }
                    });
                }, self);
            }
        },

        /* (non-Javadoc)
         * @see java.io.OutputStream#write(byte[], int, int)
         */
        write: function write(data, off, len, timeout, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                // Check if already aborted, timedout, or errored.
                if (this._aborted)
                    return false;
                if (this._timedout) {
                    callback.timeout();
                    return;
                }
                if (this._errored)
                    throw this._errored;

                // Fail if closed.
                if (this._closed)
                    throw new MslIoException("Message output stream already closed.");

                // Verify arguments.
                if (off < 0)
                    throw new RangeError("Offset cannot be negative.");
                if (len < 0)
                    throw new RangeError("Length cannot be negative.");
                if (off + len > data.length)
                    throw new RangeError("Offset plus length cannot be greater than the array length.");

                // Make sure this is not an error message or handshake message.
                var messageHeader = this.getMessageHeader();
                if (!messageHeader)
                    throw new MslInternalException("Cannot write payload data for an error message.");
                if (messageHeader.isHandshake())
                    throw new MslInternalException("Cannot write payload data for a handshake message.");

                // Append data.
                var bytes = data.subarray(off, off + len);
                this._currentPayload.push(bytes);
                return bytes.length;
            }, self);
        },
    });


    /**
     * Construct a new message output stream. The header is output
     * immediately by calling {@code #flush()} on the destination output
     * stream. The most preferred compression algorithm supported by the
     * local entity and message header will be used.
     *
     * @param {MslContext} ctx the MSL context.
     * @param {OutputStream} destination MSL output stream.
     * @param {string} charset output stream character set encoding.
     * @param {MessageHeader|ErrorHeader} header message or error header.
     * @param {?ICryptoContext} cryptoContext payload data crypto context.
     *        Required if a message header is provided.
     * @param {?MslEncoderFormat} format MSL encoder format. Required if an
     *        error header is provided.
     * @param {number} timeout write timeout in milliseconds.
     * @param {{result: function(MessageOutputStream), timeout: function(), error: function(Error)}}
     *        callback the callback that will receive the message output
     *        stream, or any thrown exceptions.
     * @throws IOException if there is an error writing the header.
     */
    var MessageOutputStream$create = function MessageOutputStream$create(ctx, destination, header, cryptoContext, format, timeout, callback) {
        new MessageOutputStream(ctx, destination, header, cryptoContext, format, timeout, callback);
    };
    
    // Exports.
    module.exports.create = MessageOutputStream$create;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MessageOutputStream'));
