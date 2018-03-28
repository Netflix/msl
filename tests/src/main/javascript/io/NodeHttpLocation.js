/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
 * <p>An HTTP location that is implemented using Node HTTP.</p>
 * 
 * @author Wesley Miaw <wmiaw@netlix.com>
 */
(function(require, module) {
    "use strict";
    
    var Url = require('msl-core/io/Url.js');
    var MslIoException = require('msl-core/MslIoException.js');
    var InterruptibleExecutor = require('msl-core/util/InterruptibleExecutor.js');
    
    var http = require('http');
    var url = require('url');
    
    /**
     * Interface for getting an HTTP response given a request.
     */
    var NodeHttpLocation = module.exports = Url.IHttpLocation.extend({
        /**
         * <p>Create a new Node HTTP location pointing at the specified
         * endpoint.</p>
         * 
         * @param {string} endpoint the URL to send the request to.
         */
        init: function(endpoint) {
            // Set properties.
            var props = {
                _endpoint: { value: endpoint, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
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
        /** @inheritDoc */
        getResponse: function(request, timeout, callback) {
            var self = this;
            
            // Declare the http.ClientRequest reference here to provide the
            // abort function.
            var req;
        
            InterruptibleExecutor(callback, function() {
                // Convert the endpoint to HTTP request options.
                var options = url.parse(this._endpoint);
                options.method = 'POST';
                options.timeout = timeout;
                
                // Issue the request asynchronously.
                //
                // Only allow the callback to be triggered once, in case events
                // keep arriving after the data has been delivered or after an
                // error has occurred.
                var delivered = false;
                req = http.request(options);
                req.on('response', function(message) {
                    InterruptibleExecutor(callback, function() {
                        // Check for an error.
                        if (message.statusCode < 200 || message.statusCode >= 300)
                            throw new MslIoException("HTTP " + message.statusCode + ": " + message.statusMessage);
                        
                        // Buffer and then deliver the accumulated data. 
                        var buffers = [];
                        message.on('data', function(chunk) {
                            try {
                                if (typeof chunk === 'string') {
                                    var buffer = Buffer.from(chunk);
                                    buffers.push(buffer);
                                } else {
                                    buffers.push(chunk);
                                }
                            } catch (e) {
                                if (!delivered)
                                    callback.error(e);
                                delivered = true;
                            }
                        });
                        message.on('end', function() {
                            try {
                                if (!delivered) {
                                    var data = Buffer.concat(buffers);
                                    var content = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
                                    callback.result({ content: content });
                                }
                                delivered = true;
                            } catch (e) {
                                if (!delivered)
                                    callback.error(e);
                                delivered = true;
                            }
                        });
                    }, self);
                });
                req.on('timeout', function() {
                    if (!delivered)
                        callback.timeout();
                    delivered = true;
                });
                req.on('error', function(e) {
                    if (!delivered)
                        callback.error(e);
                    delivered = true;
                });
                var postdata = Buffer.from(request.body.buffer);
                req.end(postdata);
            }, self);

            // Return the abort function.
            return { abort: function() { req.abort(); } };
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('NodeHttpLocation'));
