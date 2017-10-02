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
 * Preshared keys entity authentication factory.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var EntityAuthenticationFactory = require('../entityauth/EntityAuthenticationFactory.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var PresharedAuthenticationData = require('../entityauth/PresharedAuthenticationData.js');
    var MslInternalException = require('../MslInternalException.js');
    var MslEntityAuthException = require('../MslEntityAuthException.js');
    var MslError = require('../MslError.js');
    var SymmetricCryptoContext = require('../crypto/SymmetricCryptoContext.js');

    var PresharedAuthenticationFactory = module.exports = EntityAuthenticationFactory.extend({
    	/**
    	 * Construct a new preshared keys authentication factory instance.
    	 *
    	 * @param {KeySetStore} store key set store.
    	 * @param {AuthenticationUtils} authutils authentication utilities.
    	 */
    	init: function init(store, authutils) {
    		init.base.call(this, EntityAuthenticationScheme.PSK);

    		// The properties.
    		var props = {
    		    store: { value: store, writable: false, enumerable: false, configurable: false },
    		    authutils: { value: authutils, writable: false, enumerable: false, configurable: false },
    		};
    		Object.defineProperties(this, props);
    	},

    	/** @inheritDoc */
    	createData: function createData(ctx, entityAuthMo, callback) {
    		AsyncExecutor(callback, function() {
    			return PresharedAuthenticationData.parse(entityAuthMo);
    		});
    	},

    	/** @inheritDoc */
    	getCryptoContext: function getCryptoContext(ctx, authdata) {
    		// Make sure we have the right kind of entity authentication data.
    		if (!(authdata instanceof PresharedAuthenticationData))
    			throw new MslInternalException("Incorrect authentication data type " + authdata + ".");
    		var pad = authdata;

    		// Check for revocation.
    		var identity = pad.getIdentity();
    		if (this.authutils.isEntityRevoked(identity))
    			throw new MslEntityAuthException(MslError.ENTITY_REVOKED, "psk " + identity).setEntityAuthenticationData(pad);

    		// Verify the scheme is permitted.
    		if (!this.authutils.isSchemePermitted(identity, this.scheme))
    			throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication scheme for entity " + identity + " not supported:" + this.scheme).setEntityAuthenticationData(pad);

            // Load keys set.
            var keys = this.store.getKeys(identity);
            if (!keys)
                throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "psk " + identity).setEntityAuthenticationData(pad);

    		// Return the crypto context.
    		return new SymmetricCryptoContext(ctx, identity, keys.encryptionKey, keys.hmacKey, keys.wrappingKey);
    	},
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('PresharedAuthenticationFactory'));
