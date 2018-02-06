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

    /** JSON key timestamp. */
    var KEY_TIMESTAMP = "timestamp";
    /** JSON key severity. */
    var KEY_SEVERITY = "severity";
    /** JSON key message. */
    var KEY_MESSAGE = "message";

    /** Log message severity. */
    var Severity = module.exports.Severity = {
        ERROR: "ERROR",
        WARN: "WARN",
        INFO: "INFO"
    };

    /**
     * <p>Request to log a message.</p>
     *
     * <p>The request data object is defined as:
     * {@code
     * data = {
     *   "#mandatory" : [ "timestamp", "severity", "message" ],
     *   "timestamp" : "number",
     *   "severity" : enum(ERROR|WARN|INFO),
     *   "message" : "string",
     * }} where:
     * <ul>
     * <li>{@code timestamp} is the log message time in seconds since the UNIX epoch.</li>
     * <li>{@code severity} is the log message severity.</li>
     * <li>{@code message} is the log message text.</li>
     * </ul></p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var SimpleLogRequest = module.exports = SimpleRequest.extend({
        /**
         * <p>Create a new log request.</p>
         *
         * @param {number} timestamp the log message time in seconds since the UNIX
         *                 epoch.
         * @param {Severity} severity the log message severity.
         * @param {string} message the log message text.
         */
        init: function init(timestamp, severity, message) {
            init.base.call(this, SimpleRequest.Type.LOG);

            // Set properties.
            var props = {
                timestamp: { value: timestamp, writable: false, enumerable: true, configurable: false },
                severity: { value: severity, writable: false, enumerable: true, configurable: false },
                message: { value: message, writable: false, enumerable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getData: function getData() {
            var jo = {};
            jo[KEY_TIMESTAMP] = this.timestamp;
            jo[KEY_SEVERITY] = this.severity;
            jo[KEY_MESSAGE] = this.message;
            return jo;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleLogRequest'));
