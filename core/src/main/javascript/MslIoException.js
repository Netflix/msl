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
 * Thrown when an I/O exception occurs.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('./util/Class.js');
	
    var MslIoException = module.exports = Class.create(new Error());

    var proto = {
        /**
         * Construct a new MSL I/O exception with the specified detail message
         * and cause.
         *
         * @param {string} message the detail message.
         * @param {Error} cause the cause.
         * @constructor
         */
        init: function init(message, cause) {
            // Fix my stack trace.
            if (Error.captureStackTrace)
                Error.captureStackTrace(this, this.constructor);

            // Construct a better stack trace.
            var originalStack = this.stack;
            function getStack() {
                var trace = this.toString();
                if (originalStack)
                    trace += "\n" + originalStack;
                if (cause && cause.stack)
                    trace += "\nCaused by " + cause.stack;
                return trace;
            }

            // The properties.
            var props = {
                message: { value: message, writable: false, configurable: false },
                cause: { value: cause, writable: false, configurable: false },
                name: { value: "MslIoException", writable: false, configurable: true },
                stack: { get: getStack, configurable: true },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return a string containing the exception type and message.
         */
        toString: function toString() {
            return this.name + ': ' + this.message;
        }
    };

    // Attach methods.
    MslIoException.mixin(proto);
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslIoException'));
