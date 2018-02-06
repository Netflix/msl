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

    /** JSON key key. */
    var KEY_KEY = "key";

    /**
     * <p>Query for a data value. Some data values require a user identity for
     * access.</p>
     *
     * <p>The request data object is defined as:
     * {@code
     * data = {
     *   "#mandatory" : [ "key" ],
     *   "key" : "string"
     * }} where:
     * <ul>
     * <li>{@code key} is the data key identifying the value.</li>
     * </ul></p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var SimpleQueryRequest = module.exports = SimpleRequest.extend({

        /**
         * <p>Create a new query request.</p>
         *
         * @param {string} key the data key.
         */
        init: function init(key) {
            init.base.call(this, SimpleRequest.Type.QUERY);

            // Set properties.
            var props = {
                key: { value: key, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getData: function getData() {
            var jo = {};
            jo[KEY_KEY] = this.key;
            return jo;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleQueryRequest'));
