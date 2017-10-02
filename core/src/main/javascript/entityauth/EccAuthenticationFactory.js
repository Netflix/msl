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
 * <p>ECC asymmetric keys entity authentication factory.</p>
 *
 * @implements {EntityAuthenticationFactory}
 */
(function(require, module) {
	"use strict";
	
	var EntityAuthenticationFactory = require('../entityauth/EntityAuthenticationFactory.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var EccAuthenticationData = require('../entityauth/EccAuthenticationData.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslEntityAuthException = require('../MslEntityAuthException.js');
	var MslError = require('../MslError.js');
	var EccCryptoContext = require('../crypto/EccCryptoContext.js');
	
	var EccAuthenticationFactory = module.exports = EntityAuthenticationFactory.extend({
	    /**
	     * <p>Construct a new ECC asymmetric keys authentication factory
	     * instance.</p>
	     * 
	     * <p>If a key pair ID is specified for the local entity the ECC key store
	     * must contain a matching private key (a public key is optional).</p>
	     *
	     * @param {?string} keyPairId local entity key pair ID.
	     * @param {EccStore} store ECC public key store.
	     * @constructor
	     */
	    init: function init(keyPairId, store) {
	        init.base.call(this, EntityAuthenticationScheme.ECC);
	
	        // The properties.
	        var props = {
	            keyPairId: { value: keyPairId, writable: false, enumerable: false, configurable: false },
	            store: { value: store, writable: false, enumerable: false, configurable: false }
	        };
	        Object.defineProperties(this, props);
	    },
	
	    /** @inheritDoc */
	    createData: function createData(ctx, entityAuthMo, callback) {
	        AsyncExecutor(callback, function() {
	            return EccAuthenticationData.parse(entityAuthMo);
	        });
	    },
	
	    /** @inheritDoc */
	    getCryptoContext: function getCryptoContext(ctx, authdata) {
	        // Make sure we have the right kind of entity authentication data.
	        if (!(authdata instanceof EccAuthenticationData))
	            throw new MslInternalException("Incorrect authentication data type " + authdata + ".");
	
	        // Extract ECC authentication data.
	        var identity = authdata.identity;
	        var pubkeyid = authdata.publicKeyId;
	        var publicKey = this.store.getPublicKey(pubkeyid);
	        var privateKey = this.store.getPrivateKey(pubkeyid);
	        
	        // The local entity must have a private key.
	        if (pubkeyid == this.keyPairId && !privateKey)
	            throw new MslEntityAuthException(MslError.ECC_PRIVATEKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(authdata);
	        
	        // Remote entities must have a public key.
	        else if (pubkeyid != this.keyPairId && !publicKey)
	            throw new MslEntityAuthException(MslError.ECC_PUBLICKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(authdata);
	
	        // Return the crypto context.
	        return new EccCryptoContext(ctx, privateKey, publicKey);
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('EccAuthenticationFactory'));
