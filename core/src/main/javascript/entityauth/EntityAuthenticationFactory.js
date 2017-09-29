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
 * <p>A entity authentication factory creates authentication data instances and
 * authenticators for a specific entity authentication scheme.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	
	var EntityAuthenticationFactory = module.exports = Class.create({
	    /**
	     * <p>Create a new entity authentication factory for the specified scheme.</p>
	     *
	     * @param {EntityAuthenticationScheme} scheme the entity authentication scheme.
	     * @constructor
	     * @interface
	     */
	    init: function init(scheme) {
	        // The properties.
	        var props = {
	            scheme: { value: scheme, writable: false, configurable: false },
	        };
	        Object.defineProperties(this, props);
	    },
	
	    /**
	     * Construct a new entity authentication data instance from the provided
	     * MSL object.
	     *
	     * @param {MslContext} ctx MSL context.
	     * @param {MslObject} entityAuthMo the MSL object.
	     * @param {{result: function(EntityAuthenticationData), error: function(Error)}}
	     *        callback the callback that will receive the entity authentication
	     *        data or any thrown exceptions.
	     * @throws MslEncodingException if there is an error parsing the JSON.
	     * @throws MslCryptoException if there is an error with the entity
	     *         authentication data cryptography.
	     * @throws MslEntityAuthException if there is an error creating the entity
	     *         authentication data.
	     */
	    createData: function(ctx, entityAuthMo, callback) {},
	
	    /**
	     * Create a crypto context that can be used to encrypt/decrypt and
	     * authenticate data from the entity. The implementation of this function
	     * must, by necessity, authenticate the entity authentication data.
	     *
	     * @param {MslContext} ctx MSL context.
	     * @param {EntityAuthenticationData} authdata the authentication data.
	     * @return {ICryptoContext} the entity crypto context.
	     * @throws MslCryptoException if there is an error instantiating the crypto
	     *         context.
	     * @throws MslEntityAuthException if there is an error with the entity
	     *         authentication data.
	     */
	    getCryptoContext: function(ctx, authdata) {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('EntityAuthenticationFactory'));