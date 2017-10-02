/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
 * <p>A MSL encoder exception is thrown by the MSL encoding abstraction classes
 * when there is a problem.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	
    var MslEncoderException = module.exports = Class.create(new Error());
    
    var proto = {
        /**
         * <p>Construct a new MSL encoder exception with the provided message.</p>
         * 
         * @param {string} details the details text. May be null or undefined.
         * @param {Error} cause the cause. May be null or undefined.
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
                message: { value: message, writable: false, configurable: true },
                cause: { value: cause, writable: false, configurable: true },
                name: { value: "MslEncoderException", writable: false, configurable: true },
                stack: { get: getStack, configurable: true }
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
    MslEncoderException.mixin(proto);
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslEncoderException'));
