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
 * A crypto context where encryption/decryption are no-ops, signatures are
 * empty, and verification always returns true.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 * @implements {ICryptoContext}
 */
(function(require, module) {
	"use strict";
	
	var ICryptoContext = require('../crypto/ICryptoContext.js');
	
	var NullCryptoContext = module.exports = ICryptoContext.extend({
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
	        callback.result(key);
	    },
	
	    /** @inheritDoc */
	    unwrap: function unwrap(data, algo, usages, encoder, callback) {
	        callback.result(data);
	    },
	
	    /** @inheritDoc */
	    sign: function sign(data, encoder, format, callback) {
	        callback.result(new Uint8Array(0));
	    },
	
	    /** @inheritDoc */
	    verify: function verify(data, signature, encoder, callback) {
	        callback.result(true);
	    },
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('NullCryptoContext'));
