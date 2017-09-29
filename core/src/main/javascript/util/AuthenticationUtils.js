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
 * Authentication utility functions.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 * @interface
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
		
	var AuthenticationUtils = module.exports = Class.create({
	    /**
	     * Returns true if the entity identity has been revoked.
	     * 
	     * @param {string} identity the entity identity.
	     * @return {boolean} true if the entity identity has been revoked.
	     */
	    isEntityRevoked: function(identity) {},
	    
	    /**
	     * <p>This method has two acceptable parameter lists.</p>
	     * 
	     * <p>The first form accepts an entity identity and an entity
	     * authentication, user authentication, or key exchange scheme.</p>
	     * 
	     * @param {string} identity the entity identity.
	     * @param {EntityAuthenticationScheme|UserAuthenticationScheme|KeyExchangeScheme}
	     *        scheme the entity authentication scheme.
	     * @return {boolean} true if the entity is permitted to use the scheme.
	     * 
	     * <hr>
	     * 
	     * <p>The second form accepts an entity identity, MSL user, and an entity
	     * authentication, user authentication, or key exchange scheme.</p>
	     * 
	     * @param {string} identity the entity identity.
	     * @param {MslUser} user the user.
	     * @param {UserAuthenticationScheme} scheme the user authentication scheme.
	     * @return {boolean} true if the entity and user are permitted to use the scheme.
	     * 
	     * <hr>
	     * 
	     * <p>In either case this method returns true if the identified entity (and
	     * user) is permitted to use the specified scheme.</p>
	     */
	    isSchemePermitted: function(identity /* variable arguments */) {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('AuthenticationUtils'));