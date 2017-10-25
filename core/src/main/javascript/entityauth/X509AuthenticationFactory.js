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
 * <p>X.509 asymmetric keys entity authentication factory.</p>
 *
 * <p>Construct a new X.509 asymmetric keys authentication factory instance.</p>
 *
 * @param store X.509 certificate authority store.
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var EntityAuthenticationFactory = require('../entityauth/EntityAuthenticationFactory.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var X509AuthenticationData = require('../entityauth/X509AuthenticationData.js');
    var MslInternalException = require('../MslInternalException.js');
    var MslEntityAuthException = require('../MslEntityAuthException.js');
    var MslError = require('../MslError.js');
    var MslException = require('../MslException.js');
    var RsaCryptoContext = require('../crypto/RsaCryptoContext.js');
    
	var X509AuthenticationFactory = module.exports = EntityAuthenticationFactory.extend({
	    /**
	     * Construct a new X.509 asymmetric keys authentication factory instance.
	     *
	     * @param {X509Store} X.509 certificate authority store.
	     */
	    init: function init(store) {
	        init.base.call(this, EntityAuthenticationScheme.X509);
	
	        // The properties.
	        var props = {
	            store: { value: store, writable: false, enumerable: false, configurable: false }
	        };
	        Object.defineProperties(this, props);
	    },
	
	    /** @inheritDoc */
	    createData: function createData(ctx, entityAuthMo, callback) {
	        AsyncExecutor(callback, function() {
	            return X509AuthenticationData.parse(entityAuthMo);
	        });
	    },
	
	    /** @inheritDoc */
	    getCryptoContext: function getCryptoContext(ctx, authdata) {
	        // Make sure we have the right kind of entity authentication data.
	        if (!(authdata instanceof X509AuthenticationData))
	            throw new MslInternalException("Incorrect authentication data type " + authdata + ".");
	
	        // Extract X.509 authentication data.
	        var cert = authdata.x509cert;
	        var identity = cert.getSubjectString();
	        var publicKey = cert.subjectPublicKeyRSA;
	
	        // Verify entity certificate.
	        try {
	            if (!this.store.verify(cert))
	                throw new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED, cert.hex).setEntityAuthenticationData(authdata);
	        } catch (e) {
	            if (!(e instanceof MslException))
	                throw new MslEntityAuthException(MslError.X509CERT_PARSE_ERROR, cert.hex, e).setEntityAuthenticationData(authdata);
	            else
	                e.setEntityAuthenticationData(authdata);
	            throw e;
	        }
	        
            // Grab the optional private key.
            var privkey = this.store.getPrivateKey(cert);
	
	        // Return the crypto context.
	        return new RsaCryptoContext(ctx, identity, privkey, publicKey, RsaCryptoContext.Mode.SIGN_VERIFY);
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('X509AuthenticationFactory'));
