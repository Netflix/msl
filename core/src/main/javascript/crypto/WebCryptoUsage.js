/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
 * MSL key usages mapped onto Web Crypto key usages.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
		
	var WebCryptoUsage = module.exports = {
	    /** encrypt/decrypt */
	    ENCRYPT_DECRYPT: [ 'encrypt', 'decrypt' ],
	    /** encrypt */
	    ENCRYPT: [ 'encrypt' ],
	    /** decrypt */
	    DECRYPT: [ 'decrypt' ],
	    /** wrap/unwrap */
	    WRAP_UNWRAP: [ 'wrap', 'unwrap' ],
	    /** wrap */
	    WRAP: [ 'wrap'],
	    /** unwrap */
	    UNWRAP: [ 'unwrap' ],
	    /** sign/verify */
	    SIGN_VERIFY: [ 'sign', 'verify' ],
	    /** sign */
	    SIGN: [ 'sign' ],
	    /** verify */
	    VERIFY: [ 'verify' ],
	    /** derive key */
	    DERIVE_KEY: [ 'deriveKey' ],
	};
})(require, (typeof module !== 'undefined') ? module : mkmodule('WebCryptoUsage'));