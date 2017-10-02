/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
 * <p>The error message registry is used to provide localized user-consumable
 * messages for specific MSL errors.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
		
	var ErrorMessageRegistry = module.exports = Class.create({
	    /**
	     * Returns the user-consumable message associated with the given MSL error
	     * or non-MSL error, localized according to the list of preferred
	     * languages.
	     * 
	     * @param {MslError|Error} err MSL error or non-MSL error.
	     * @param {Array.<String>} languages preferred languages as BCP-47 codes in descending
	     *        order. May be {@code null}.
	     * @return {String} the localized user message or {@code null} if there is none.
	     */
	    getUserMessage: function(err, languages) {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('ErrorMessageRegistry'));