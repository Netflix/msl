/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
 * <p>An authentication utilities implementation where all operations are
 * permitted.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var AuthenticationUtils = require('../util/AuthenticationUtils.js');
		
	var NullAuthenticationUtils = module.exports = AuthenticationUtils.extend({
		/** @inheritDoc */
		isEntityRevoked: function isEntityRevoked(identity) {
			return false;
		},
	
		/** @inheritDoc */
		isSchemePermitted: function isSchemePermitted() {
			return true;
		},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('NullAuthenticationUtils'));