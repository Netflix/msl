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
 * Diffie-Hellman parameters by parameter ID.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";

	var Class = require('../util/Class.js');
		
	var DiffieHellmanParameters = module.exports = Class.create({
	    /**
	     * @return {Object.<string,DHParameterSpec>} the map of Diffie-Hellman parameters by parameter ID.
	     * @throws MslKeyExchangeException if there is an error accessing the
	     *         parameters.
	     */
	    getParameterSpecs: function() {},
	    
	    /**
	     * Returns the Diffie-Hellman parameter specification identified by the
	     * parameters ID.
	     * 
	     * @param {string} id the parameters ID.
	     * @return {DHParameterSpec} the parameter specification or null if the parameters ID is
	     *         not recognized.
	     * @throws MslKeyExchangeException if there is an error accessing the
	     *         parameter specification.
	     */
	    getParameterSpec: function(id) {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('DiffieHellmanParameters'));