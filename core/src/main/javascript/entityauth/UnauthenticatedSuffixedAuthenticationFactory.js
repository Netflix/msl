/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
 * <p>Unauthenticated suffixed entity authentication factory.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";

    var EntityAuthenticationFactory = require('../entityauth/EntityAuthenticationFactory.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var UnauthenticatedSuffixedAuthenticationData = require('../entityauth/UnauthenticatedSuffixedAuthenticationData.js');
    var MslInternalException = require('../MslInternalException.js');
    var NullCryptoContext = require('../crypto/NullCryptoContext.js');
	
	var UnauthenticatedSuffixedAuthenticationFactory = module.exports = EntityAuthenticationFactory.extend({
	    /**
	     * Construct a new unauthenticated suffixed authentication factory instance.
	     */
	    init: function init() {
	        init.base.call(this, EntityAuthenticationScheme.NONE_SUFFIXED);
	    },
	
	    /** @inheritDoc */
	    createData: function createData(ctx, entityAuthMo, callback) {
	        AsyncExecutor(callback, function() {
	            return UnauthenticatedSuffixedAuthenticationData.parse(entityAuthMo);
	        });
	    },
	
	    /** @inheritDoc */
	    getCryptoContext: function getCryptoContext(ctx, authdata) {
	        // Make sure we have the right kind of entity authentication data.
	        if (!(authdata instanceof UnauthenticatedSuffixedAuthenticationData))
	            throw new MslInternalException("Incorrect authentication data type " + authdata + ".");
	
	        // Return the crypto context.
	        return new NullCryptoContext();
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('UnauthenticatedSuffixedAuthenticationFactory'));