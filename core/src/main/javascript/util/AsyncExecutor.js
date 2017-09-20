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
 * <p>Executes a function (synchronously).</p>
 *
 * <p>If the function returns anything other than undefined the return value is
 * delivered to the callback's result function. Any errors thrown by the
 * function are delivered to the callback's error function.</p>
 *
 * <p>If the function returns undefined and does not throw any error, the
 * callback is not used; it is the function's responsibility to ensure the
 * callback receives a result. The callback is passed as an argument to the
 * function for this purpose.</p>
 *
 * <p>For example:
 * {@code
 * function syncOp() {
 *   return 5;
 * }
 *
 * function asyncOp(callback) {
 *   setTimeout(function() { AsyncExecutor(callback, function() { return 7; }); }, 1000);
 * }
 *
 * function noOp() {}
 *
 * var x = 0;
 * var callback = {
 *   result: function(num) { x = num; },
 *   error: function(err) { alert(err); },
 * };
 *
 * AsyncExecutor(callback, noOp); // x is still zero
 * AsyncExecutor(callback, syncOp); // x is now 5
 * AsyncExecutor(callback, asyncOp); // x is still 5
 * setTimeout(function() { // x is now 7 }, 2000);
 * </p>
 *
 * @param {{result: function(*), error: function(Error)}} callback the callback
 *        functions that will receive the result or any thrown errors.
 * @param {function({result: function(*), error: function(Error)}): *=} func
 *        the function to execute.
 * @param {Object=} thisArg object to use as this when executing the function.
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var AsyncExecutor = module.exports = function AsyncExecutor(callback, func, thisArg) {
	    var T;
	    if (thisArg)
	        T = thisArg;
	
	    // Make sure the callback is correct.
	    if (typeof callback !== 'object' ||
	        typeof callback.result !== 'function' ||
	        typeof callback.error !== 'function')
	    {
	        throw new TypeError("callback must be an object with function properties 'result' and 'error'.");
	    }
	
	    // Wrap the function in a try/catch block to catch any thrown errors.
	    try {
	        var result = func.call(T, callback);
	
	        // Only deliver the result if it was not undefined. It's possible the
	        // function is itself asynchronous and is not returning any result.
	        if (result !== undefined)
	            callback.result(result);
	    } catch (e) {
	        // Don't propagate exceptions from the callback
	        try {
	            callback.error(e);
	        } catch (f) {
	        }
	    }
	};
})(require, (typeof module !== 'undefined') ? module : mkmodule('AsyncExecutor'));
