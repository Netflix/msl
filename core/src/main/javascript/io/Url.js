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
 * The URL class provides access to an input stream and output stream tied to a
 * specific URL.
 *
 * This implementation supports single-shot HTTP requests and responses. The
 * output stream data is buffered and only sent when the input stream is first
 * read from. The output stream will not accept additional data once the input
 * stream is read from.
 */
(function(require, module) {
	"use strict";

	var Class = require('../util/Class.js');
	var OutputStream = require('../io/OutputStream.js');
	var InputStream = require('../io/InputStream.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslIoException = require('../MslIoException.js');
	var ByteArrayInputStream = require('../io/ByteArrayInputStream.js');
	var ByteArrayOutputStream = require('../io/ByteArrayOutputStream.js');
	var BlockingQueue = require('../util/BlockingQueue.js');
	var MslEncoderFormat = require('../io/MslEncoderFormat.js');
	var TextEncoding = require('../util/TextEncoding.js');
	var MslConstants = require('../MslConstants.js');

    /**
     * Interface for getting an HTTP response given a request.
     */
	var IHttpLocation = Class.create({
	    /**
	     * Given a request, gets the response.
	     *
	     * @param {{body: string}} request
	     * @param {number} timeout request response timeout in milliseconds or -1 for no timeout.
	     * @param {{result: function({=body: string, =content: Uint8Array}), timeout: function(), error: function(Error)}}
	     *        callback the callback that will receive the response data as
	     *        a string or bytes, be notified of timeout or any thrown
	     *        exceptions.
	     * @returns {{abort:Function})
	     */
	    getResponse: function(request, timeout, callback) {}
	});

    /**
     * An HTTP output stream buffers data and then sends it upon close. The
     * response is made available after being closed.
     */
    var HttpOutputStream = OutputStream.extend({
        /**
         * Create a new HTTP output stream that will send and receive an HTTP
         * request and response to the target location.
         *
         * @param {IHttpLocation} httpLocation target location.
         * @param {number=} timeout optional connect/read/write timeout in
         *        milliseconds. The default is defined by the http client
         *        configuration.
         */
        init: function init(httpLocation, timeout) {
            // The properties.
            var props = {
                _httpLocation: { value: httpLocation, writable: false, enumerable: false, configurable: false },
                _timeout: { value: timeout, writable: true, enumerable: false, configurable: false },
                _buffer: { value: new ByteArrayOutputStream(), writable: false, enumerable: false, configurable: false },
                _response: { value: undefined, writable: true, enumerable: false, configurable: false },
                _abortToken: { value: undefined, writable: true, enumerable: false, configurable: false },
                _aborted: { value: false, writable: true, enumerable: false, configurable: false },
                _responseQueue: { value: new BlockingQueue(), writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * Set the timeout.
         *
         * @param {number} timeout connect/read/write timeout in milliseconds.
         *        -1 for no timeout.
         */
        setTimeout: function setTimeout(timeout) {
            this._timeout = timeout;
        },

        /**
         * Return the response. This blocks until a response is available.
         *
         * @param {{result: function({=response: {=body: string, =content: Uint8Array, =headers: ?Array<string>}, =isTimeout: boolean, =isError: boolean}), error: function(Error)}}
         *        callback the callback will receive the HTTP response or
         *        undefined if the HTTP transaction was aborted and notified of
         *        any thrown exceptions.
         */
        getResponse: function getResponse(callback) {
            var self = this;
            this._responseQueue.poll(-1, {
                result: function(response) {
                    AsyncExecutor(callback, function() {
                        // If we received a response then stick it back onto the
                        // queue for the next requestor.
                        if (response)
                            this._responseQueue.add(response);
                        return response;
                    }, self);
                },
                timeout: function() {
                    AsyncExecutor(callback, function() {
                        // This should never happen but if it does inject an
                        // error response and abort the request as an attempt
                        // at cleanup.
                        this._response = { isError: true };
                        this._responseQueue.add(this._response);
                        this.abort();
                        throw new MslInternalException("Timeout while waiting for HttpOutputStream.getResponse() despite no timeout being specified.");
                    }, self);
                },
                error: function(e) {
                    AsyncExecutor(callback, function() {
                        this._response = { isError: true };
                        this._responseQueue.add(this._response);
                        throw e;
                    }, self);
                }
            });
        },

        /** @inheritDoc */
        abort: function abort() {
            if (this._abortToken)
                this._abortToken.abort();
            this._aborted = true;
        },

        /** @inheritDoc */
        close: function close(timeout, callback) {
            var self = this;
            InterruptibleExecutor(callback, function() {
                // Do nothing if we already got the response, if we
                // already initiated the request, or if the call was
                // aborted.
                if (this._response || this._abortToken || this._aborted)
                    return true;

                var data = this._buffer.toByteArray();
                if (data.length > 0) {
                    var request = {
                        body: data
                    };

                    this._abortToken = this._httpLocation.getResponse(request, this._timeout, {
                        result: function (response) {
                            self._response = { response: response };
                            self._responseQueue.add(self._response);
                        },
                        timeout: function () {
                            self._response = { isTimeout: true };
                            self._responseQueue.add(self._response);
                        },
                        error: function (e) {
                            self._response = { isError: true, error: e };
                            self._responseQueue.add(self._response);
                        }
                    });
                }

                return true;
            }, this);
        },

        /** @inheritDoc */
        write: function write(data, off, len, timeout, callback) {
            InterruptibleExecutor(callback, function() {
                if (this._response)
                    throw new MslIoException("HttpOutputStream already closed.");

                this._buffer.write(data, off, len, timeout, callback);
            }, this);
        },

        /** @inheritDoc */
        flush: function flush(timeout, callback) {
            InterruptibleExecutor(callback, function() {
                if (this._response)
                    return true;

                this._buffer.flush(timeout, callback);
            }, this);
        },
    });

    /**
     * An HTTP input stream buffers data received from an HTTP output stream
     * for later consumption.
     */
    var HttpInputStream = InputStream.extend({
        /**
         * Create a new HTTP input stream that is linked to the provided HTTP
         * output stream.
         *
         * @param {HttpOutputStream} out the linked HTTP output stream.
         */
        init: function init(out) {
            // The properties.
            var props = {
                _out: { value: out, writable: false, enumerable: false, configurable: false },
                _buffer: { value: undefined, writable: true, enumerable: false, configurable: false },
                _readlimit: { value: -1, writable: true, enumerable: false, configurable: false },
                _exception: { value: undefined, writable: true, enumerable: false, configurable: false },
                _timedout: { value: false, writable: true, enumerable: false, configurable: false },
                _aborted: { value: false, writable: true, enumerable: false, configurable: false },
                _json: { value: undefined, writable: true, enumerable: false, configurable: false },
                _headers: { value: [], writable: true, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        abort: function abort() {
            this._out.abort();
        },

        /** @inheritDoc */
        close: function close(timeout, callback) {
            InterruptibleExecutor(callback, function() {
                if (this._buffer)
                    this._buffer.close(timeout, callback);
                else
                	return true;
            }, this);
        },

        /** @inheritDoc */
        mark: function mark(readlimit) {
            if (this._buffer)
                this._buffer.mark(readlimit);
            // If the buffer doesn't exist yet, we must remember to mark it
            // after it is created.
            else
                this._readlimit = readlimit;
        },

        /** @inheritDoc */
        reset: function reset() {
            if (this._buffer)
                this._buffer.reset();
        },

        /** @inheritDoc */
        markSupported: function markSupported() {
            // ByteArrayInputStream supports mark, and we must support mark for
            // the JSON hack to work.
            return true;
        },

        /**
         * <p>Returns the already-parsed JSON if it exists. This function will
         * return undefined until read() is first called, and may still return
         * undefined afterwards if the JSON cannot be accessed in this
         * manner.</p>
         *
         * <p>If read() does result in JSON becoming available via this method,
         * then read() will return zero bytes of data.</p>
         *
         * @return {?Array{*}} an array of JSON values or undefined.
         */
        getJSON: function getJSON() {
            return this._json;
        },

        /**
        * <p>Returns an array of HTTP response headers.</p>
        *
        * @return {Array{string}} an array of HTTP response headers.
        */
        getHttpHeaders: function getHttpHeaders() {
            return this._headers;
        },

        /** @inheritDoc */
        read: function read(len, timeout, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                // Throw any HTTP exception.
                if (this._exception)
                    throw this._exception;

                // Notify of timeouts.
                if (this._timedout) {
                    callback.timeout();
                    return;
                }

                // If aborted return the empty array.
                if (this._aborted)
                    return new Uint8Array(0);

                // If we don't have the buffer then get it.
                if (!this._buffer) {
                    this._out.close(timeout, {
                        result: function(success) { processResponse(success); },
                        timeout: callback.timeout,
                        error: callback.error,
                    });
                }

                // Otherwise read from it.
                else {
                    this._buffer.read(len, timeout, callback);
                }
            }, self);

            function processResponse(closed) {
                InterruptibleExecutor(callback, function() {
                    // If aborted return the empty array.
                    if (!closed) return new Uint8Array(0);

                    // Otherwise grab the response.
                    this._out.getResponse({
                        result: function(result) {
                            InterruptibleExecutor(callback, function() {
                                var content;

                                if (result.isTimeout) {
                                    this._timedout = true;
                                    callback.timeout();
                                    return;
                                }

                                // Handle errors.
                                if (result.isError) {
                                    this._exception = result.error || new MslIoException("Unknown HTTP exception.");
                                    throw this._exception;
                                }

                                if (!result.response) {
                                    this._exception = new MslIoException("Missing HTTP response.");
                                    throw this._exception;
                                }

                                // Capture headers
                                this._headers = result.response.headers;

                                // This is a platform hack that allows the
                                // stream to return already-parsed JSON.
                                //
                                // Use the JSON byte stream identifier as the
                                // content to imply JSON is available. If the
                                // caller knows about this hack, it will not
                                // try to read additional bytes and check for
                                // the JSON instead.
                                if (result.response.json !== undefined) {
                                    this._json = result.response.json;
                                    content = new Uint8Array([MslEncoderFormat.JSON.identifier]);
                                }

                                // Retrieve the raw bytes if available,
                                // otherwise convert the string value to bytes.
                                else if (result.response.content instanceof Uint8Array)
                                    content = result.response.content;
                                else if (typeof result.response.body === 'string')
                                    content = TextEncoding.getBytes(result.response.body, MslConstants.DEFAULT_CHARSET);
                                else
                                    throw new MslIoException("Missing HTTP response content.");

                                // Read from the response.
                                this._buffer = new ByteArrayInputStream(content);
                                if (this._readlimit != -1)
                                    this._buffer.mark(this._readlimit);
                                this._buffer.read(len, timeout, callback);
                            }, self);
                        },
                        error: callback.error,
                    });
                }, self);
            }
        },
    });

    var Url = module.exports = Class.create({
        /**
         * Create a new URL that points at the provided location.
         *
         * @param {IHttpLocation} httpEndpoint the target location.
         * @param {number=} timeout optional connect/read/write timeout in
         *        milliseconds. The default is defined by the http client
         *        configuration.
         */
        init: function init(httpLocation, timeout) {

            // The properties.
            var props = {
                _httpLocation: { value: httpLocation, writable: false, enumerable: false, configurable: false },
                _timeout: { value: timeout, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * Set the timeout.
         *
         * @param {number} timeout connect/read/write timeout in milliseconds.
         */
        setTimeout: function setTimeout(timeout) {
            this._timeout = timeout;
        },

        /**
         * <p>Open a new connection to the target location.</p>
         *
         * <p>The returned input stream must support
         * {@link InputStream#mark(int)}, {@link InputStream#reset()}, and
         * {@link InputStream#skip(long)} if you wish to use it for more than
         * one MSL message.</p>
         *
         * @return {{input: InputStream, output: OutputStream}} the input and
         *         output streams.
         */
        openConnection: function openConnection() {
            // The output stream will send the data either when it is closed or
            // when the input stream is read from.
            var output = new HttpOutputStream(this._httpLocation, this._timeout);

            // Buffer the input data after it is received to provide it when
            // requested from the input stream.
            var input = new HttpInputStream(output);

            return {input: input, output: output};
        },
    });

    // Exports.
    module.exports.IHttpLocation = IHttpLocation;
})(require, (typeof module !== 'undefined') ? module : mkmodule('Url'));
