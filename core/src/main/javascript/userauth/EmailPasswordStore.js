/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
 * An email/password store contains user credentials.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
		
	var EmailPasswordStore = module.exports = Class.create({    
	    /**
	     * Return the user if the email/password combination is valid.
	     * 
	     * @param {string} email email address.
	     * @param {string} password password.
	     * @return {MslUser} the MSL user or null if there is no such user.
	     */
	    isUser: function(email, password) {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('EmailPasswordStore'));