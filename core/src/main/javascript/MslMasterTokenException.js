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
 * Thrown when there is a problem with a master token, but the token was
 * successfully parsed.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var MslException = require('./MslException.js');
		
	var MslMasterTokenException = module.exports = MslException.extend({
	    /**
	     * Construct a new MSL master token exception with the specified error and
	     * master token.
	     *
	     * @param {MslError} error the error.
	     * @param {MasterToken} masterToken the master token. May be null or undefined.
	     */
	    init: function init(error, masterToken) {
	        init.base.call(this, error);
	
	        // The properties.
	        var props = {
	            masterToken: { value: masterToken, writable: false, configurable: false},
	            name: { value: "MslMasterTokenException", writable: false, configurable: true }
	        };
	        Object.defineProperties(this, props);
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslMasterTokenException'));