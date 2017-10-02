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
 * <p>Thrown when an exception occurs while attempting to create and send an
 * automatically generated error response.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('./util/Class.js');
	
    var MslErrorResponseException = module.exports = Class.create(new Error());

    var proto = {
        /**
         * <p>Construct a new MSL error response exception with the specified detail
         * message, cause, and the original exception thrown by the request that
         * prompted an automatic error response.</p>
         * 
         * <p>The detail message should describe the error that triggered the
         * automatically generated error response.</p>
         *
         * @param message the detail message.
         * @param cause the cause.
         * @param requestCause the original request exception.
         */
        init: function init(message, cause, requestCause) {
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
                requestCause: { value: requestCause, writable: false, configurable: false},
                name: { value: "MslErrorResponseException", writable: false, configurable: true },
                stack: { get: getStack, configurable: true },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return a string containing the exception type and message.
         */
        toString: function toString() {
            return this.name + ': ' + this.message;
        },
    };

    // Attach methods.
    MslErrorResponseException.mixin(proto);
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslErrorResponseException'));
