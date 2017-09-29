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
 * <p>Unauthenticated entity authentication factory.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var EntityAuthenticationFactory = require('../entityauth/EntityAuthenticationFactory.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var UnauthenticatedAuthenticationData = require('../entityauth/UnauthenticatedAuthenticationData.js');
    var MslEntityAuthException = require('../MslEntityAuthException.js');
    var MslError = require('../MslError.js');
    var MslInternalException = require('../MslInternalException.js');
    var NullCryptoContext = require('../crypto/NullCryptoContext.js');

    var UnauthenticatedAuthenticationFactory = module.exports = EntityAuthenticationFactory.extend({
    	/**
    	 * Construct a new unauthenticated authentication factory instance.
    	 * 
    	 * @param {AuthenticationUtils} authutils authentication utilities.
    	 */
    	init: function init(authutils) {
    		init.base.call(this, EntityAuthenticationScheme.NONE);
            
            // The properties.
            var props = {
                authutils: { value: authutils, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
    	},

    	/** @inheritDoc */
    	createData: function createData(ctx, entityAuthMo, callback) {
    		AsyncExecutor(callback, function() {
    			return UnauthenticatedAuthenticationData.parse(entityAuthMo);
    		});
    	},

    	/** @inheritDoc */
    	getCryptoContext: function getCryptoContext(ctx, authdata) {
    	    // Make sure we have the right kind of entity authentication data.
    	    if (!(authdata instanceof UnauthenticatedAuthenticationData))
    	        throw new MslInternalException("Incorrect authentication data type " + authdata + ".");
    	    var uad = authdata;

    	    // Check for revocation.
    	    var identity = uad.getIdentity();
    	    if (this.authutils.isEntityRevoked(identity))
    	        throw new MslEntityAuthException(MslError.ENTITY_REVOKED, "none " + identity).setEntityAuthenticationData(uad);

    	    // Verify the scheme is permitted.
    	    if (!this.authutils.isSchemePermitted(identity, this.scheme))
    	        throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication scheme for entity " + identity + " not supported:" + this.scheme).setEntityAuthenticationData(uad);

    	    // Return the crypto context.
    	    return new NullCryptoContext();
    	},
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('UnauthenticatedAuthenticationFactory'));