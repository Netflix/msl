/**
 * Copyright (c) 2012-2015 Netflix, Inc.  All rights reserved.
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
var Url;

var IHttpLocation = util.Class.create({

    /**
     * Given a request, gets the response.
     *
     * @param {{body:string}} request
     * @param {number} timeout request response timeout in milliseconds or -1 for no timeout.
     * @param {{result: function({body:string}), timeout: function(), error: function(Error)}}
     *        callback the callback will receive the response
     * @returns {{abort:Function})
     */
    getResponse: function getResponse(request, timeout, callback) { }

});

(function () {

    /**
     * An HTTP output stream buffers data and then sends it upon close. The
     * response is made available
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
         * @param {{result: function({success: boolean, content: Uint8Array, errorHttpCode: number, errorSubCode: number}), error: function(Error)}}
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
        },

        /** @inheritDoc */
        close: function close(timeout, callback) {
            var self = this;
            InterruptibleExecutor(callback, function() {
                if (this._response)
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
                _exception: { value: undefined, writable: true, enumerable: false, configurable: false },
                _timedout: { value: false, writable: true, enumerable: false, configurable: false },
                _aborted: { value: false, writable: true, enumerable: false, configurable: false },
                _json: { value: undefined, writable: true, enumerable: false, configurable: false }
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
                    this._buffer.close();
                return true;
            });
        },

        /** @inheritDoc */
        mark: function mark() {
            if (!this._buffer)
                this._buffer.mark();
        },

        /** @inheritDoc */
        reset: function reset() {
            if (this._buffer)
                this._buffer.reset();
        },

        /** @inheritDoc */
        markSupported: function markSupported() {
            if (this._buffer)
                return this._buffer.markSupported();
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
                        timeout: function() { callback.timeout(); },
                        error: function(e) { callback.error(e); }
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

                                // this allows the stream to return already-parsed JSON
                                if (result.response.json !== undefined) {
                                    this._json = result.response.json;
                                    this.getJSON = function () { return self._json };
                                }

                                content = result.response.content || utf8$getBytes(typeof result.response.body === 'string' ? result.response.body : JSON.stringify(this._json));
                                this._buffer = new ByteArrayInputStream(content);
                                this._buffer.read(len, timeout, callback);
                            }, self);
                        },
                        error: function(e) { callback.error(e); }
                    });
                }, self);
            }
        },
    });

    Url = util.Class.create({
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
         * Open a new connection to the target location.
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
})();
