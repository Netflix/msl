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
 * This is a convenience class for constructing a symmetric crypto context from
 * a MSL session master token.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function (require, module) {
    "use strict";
    
    var SymmetricCryptoContext = require('../crypto/SymmetricCryptoContext.js');
    var MslMasterTokenException = require('../MslMasterTokenException.js');
    var MslError = require('../MslError.js');
    
	var SessionCryptoContext = module.exports = SymmetricCryptoContext.extend({
	    /**
	     * <p>Construct a new session crypto context from the provided master
	     * token.</p>
	     *
	     * <p>If an identity, encryption key, and HMAC key are provided then they
	     * are assumed to be the same as what is inside the master token, which may
	     * be untrusted.</p>
	     *
	     * @param {MslContext} ctx MSL context.
	     * @param {MasterToken} masterToken the master token. May be untrusted if
	     *        the identity, encryption key, and HMAC key are provided.
	     * @param {?string=} identity entity identity. May be {@code null}.
	     * @param {SecretKey=} encryptionKey encryption key.
	     * @param {SecretKey=} signatureKey signature key.
	     * @throws MslMasterTokenException if the master token is not trusted.
	     * @throws MslCryptoException if the encryption key length is unsupported.
	     */
	    init: function init(ctx, masterToken, identity, encryptionKey, signatureKey) {
	        if (identity !== undefined || encryptionKey || signatureKey) {
	            var keyId = (identity) ? identity + '_' + masterToken.sequenceNumber : '' + masterToken.sequenceNumber;
	            init.base.call(this, ctx, keyId, encryptionKey, signatureKey, null);
	        } else {
	            if (!masterToken.isDecrypted())
	                throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
	            init.base.call(this, ctx, masterToken.identity + '_' + masterToken.sequenceNumber, masterToken.encryptionKey, masterToken.signatureKey, null);
	        }
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('SessionCryptoContext'));