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

/**
 * <p>Example request type and parser.</p>
 *
 * <p>Requests are represented as JSON as follows:
 * {@code {
 * request = {
 *   "#mandatory" : [ "type", "data" ],
 *   "type" : "string",
 *   "data" : "object",
 * }
 * }} where:
 * <ul>
 * <li>{@code type} is the request type.</li>
 * <li>{@code data} is the request data.</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";

    var Class = require('msl-core/util/Class.js');

    /** JSON key type. */
    var KEY_TYPE = "type";
    /** JSON key data. */
    var KEY_DATA = "data";

    /** Request type. */
    var Type = {
        /** Echo request data. */
        ECHO: "ECHO",
        /** Query for data. */
        QUERY: "QUERY",
        /** Provide log data. */
        LOG: "LOG",
        /** Return user profile. */
        USER_PROFILE: "USER_PROFILE",
        /** Terminate server execution. */
        QUIT: "QUIT",
    };

    var SimpleRequest = module.exports = Class.create({
        /**
         * <p>Create a simple request.</p>
         *
         * @param {Type} type request type.
         */
        init: function init(type) {
            // Set properties.
            var props = {
                type: { value: type, writable: false, enumerable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {object} the request data object.
         */
        getData: function() {},

        /** @inheritDoc */
        toJSON: function toJSON() {
            var jo = {};
            jo[KEY_TYPE] = this.type;
            jo[KEY_DATA] = this.getData();
            return jo;
        },
    });
    
    // Exports.
    module.exports.Type = Type;
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleRequest'));
