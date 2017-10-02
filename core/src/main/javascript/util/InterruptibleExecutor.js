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
 * <p>Executes a function (synchronously) that may timeout.</p>
 *
 * <p>This is identical to AsyncExecutor except it also enforces the existence
 * of a timeout callback.</p>
 *
 * @param {{result: function(*), timeout: function(), error:function(Error)}}
 *        callback the callback functions that will receive the result, be
 *        notified of timeout, or any thrown errors.
 * @param {function({result: function(*), error: function(Error)}): *=} func
 *        the function to execute.
 * @param {Object=} thisArg object to use as this when executing the function.
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var AsyncExecutor = require('../util/AsyncExecutor.js');
		
	var InterruptibleExecutor = module.exports = function InterruptibleExecutor(callback, func, thisArg) {
	    // Make sure the callback is correct.
	    if (typeof callback !== 'object' ||
	        typeof callback.timeout !== 'function')
	    {
	        throw new TypeError("callback must be an object with function properties 'result', 'timeout', and 'error'.");
	    }
	    AsyncExecutor(callback, func, thisArg);
	};
})(require, (typeof module !== 'undefined') ? module : mkmodule('InterruptibleExecutor'));