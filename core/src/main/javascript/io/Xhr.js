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
 * <p>An HTTP location that is implemented using XMLHttpRequest.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var Url = require('../io/Url.js');
    var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    
    var Xhr = module.exports = Url.IHttpLocation.extend({
        /**
         * <p>Create a new XHR pointing at the specified endpoint.</p>
         * 
         * @param {string} endpoint the url to send the request to.
         */
        init: function(endpoint) {
            // Set properties.
            var props = {
                _endpoint: { value: endpoint, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        getResponse: function getResponse(request, timeout, callback) {
            var self = this;
            
            // We need to declare the XMLHttpRequest reference here to provide
            // the abort function.
            var xhr;
            
            // Deliver the XMLHttpRequest result asynchronously.
            InterruptibleExecutor(callback, function() {
                /* globals XMLHttpRequest: false */
                xhr = new XMLHttpRequest();
                xhr.responseType = "arraybuffer";
                xhr.onload = function onload() {
                    AsyncExecutor(callback, function() {
                        return { content: new Uint8Array(this.response) };
                    }, xhr);
                };
                xhr.ontimeout = callback.timeout;
                xhr.onerror = callback.error;
                xhr.open("POST", this._endpoint);
                xhr.timeout = timeout;
                xhr.send(request.body);
            }, self);
            
            // Define the abort function to dereference the XMLHttpRequest
            // after being called.
            return { abort: function() { xhr.abort(); } };
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('Xhr'));