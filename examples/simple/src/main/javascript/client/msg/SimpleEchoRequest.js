/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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

(function(require, module) {
    "use strict";

    var SimpleRequest = require('../msg/SimpleRequest.js');

    /** JSON key message. */
    var KEY_MESSAGE = "message";

    /**
     * <p>Request to echo the request message. The requesting entity identity and
     * user (if any) is also echoed.</p>
     *
     * <p>The request data object is defined as:
     * {@code
     * data = {
     *   "#mandatory" : [ "message" ],
     *   "message" : "string"
     * }} where:
     * <ul>
     * <li>{@code message} is the message to echo.</li>
     * </ul></p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var SimpleEchoRequest = module.exports = SimpleRequest.extend({
        /**
         * <p>Create a new echo request.</p>
         *
         * @param {string} message the message to echo.
         */
        init: function init(message) {
            init.base.call(this, SimpleRequest.Type.ECHO);

            // Properties.
            var props = {
                message: { value: message, writable: false, enumerable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getData: function getData() {
            var jo = {};
            jo[KEY_MESSAGE] = this.message;
            return jo;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleEchoRequest'));
