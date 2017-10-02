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
(function(require, module) {
	"use strict";
	
	var ICryptoContext = require('../crypto/ICryptoContext.js');
	var MslInternalException = require('../MslInternalException.js');
	
	/**
	 * This class should be used by trusted network clients for the primary crypto
	 * context used for master tokens and user ID tokens. It always fails to verify
	 * and its other operations are no-ops.
	 *
	 * @author Wesley Miaw <wmiaw@netflix.com>
	 * @see com.netflix.msl.util.MslContext#getMslCryptoContext()
	 */
	var ClientMslCryptoContext = module.exports = ICryptoContext.extend({
	    /** @inheritDoc */
	    encrypt: function encrypt(data, encoder, format, callback) {
	        callback.result(data);
	    },
	
	    /** @inheritDoc */
	    decrypt: function decrypt(data, encoder, callback) {
	        callback.result(data);
	    },
	
	    /** @inheritDoc */
	    wrap: function wrap(key, encoder, format, callback) {
	        // This should never be called.
	        callback.error(new MslInternalException("Wrap is unsupported by the MSL token crypto context."));
	    },
	
	    /** @inheritDoc */
	    unwrap: function wrap(data, algo, usages, encoder, callback) {
	        // This should never be called.
	        callback.error(new MslInternalException("Unwrap is unsupported by the MSL token crypto context."));
	    },
	
	    /** @inheritDoc */
	    sign: function sign(data, encoder, format, callback) {
	        callback.result(new Uint8Array(0));
	    },
	
	    /** inheritDoc */
	    verify: function verify(data, signature, encoder, callback) {
	        callback.result(false);
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('ClientMslCryptoContext'));