/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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

	/**
	 * MSL algorithms mapped onto Web Crypto algorithms.
	 *
	 * @author Wesley Miaw <wmiaw@netflix.com>
	 */
	var WebCryptoAlgorithm = module.exports = {
	    /** generate/wrap/unwrap */
	    A128KW: { 'name': 'AES-KW' },
	    /** generate/encrypt/decrypt */
	    AES_CBC: { 'name': 'AES-CBC' },
	    /** generate */
	    ECDH: { 'name': 'ECDH' },
	    /** generate */
	    DIFFIE_HELLMAN: { 'name': 'DH' },
	    /** generate/sign/verify */
	    HMAC_SHA256: { 'name': 'HMAC', 'hash': { 'name': 'SHA-256' } },
	    /** generate/encrypt/decrypt/wrap/unwrap */
	    RSA_OAEP: { 'name': 'RSA-OAEP', 'hash': { 'name': 'SHA-1' } },
	    /** generate/encrypt/decrypt */
	    RSAES: { 'name': 'RSAES-PKCS1-v1_5' },
	    /** generate */
	    RSASSA: { 'name': 'RSASSA-PKCS1-v1_5', 'hash': { 'name': 'SHA-1' } },
	    /** sign/verify */
	    AES_CMAC: { 'name': 'AES-CMAC' },
	    ECDSA_SHA256: { 'name': 'ECDSA', 'hash': { 'name': 'SHA-256' } },
	    RSASSA_SHA1: { 'name': 'RSASSA-PKCS1-v1_5', 'hash': { 'name': 'SHA-1' } },
	    RSASSA_SHA256: { 'name': 'RSASSA-PKCS1-v1_5', 'hash': { 'name': 'SHA-256' } },
	    /** deriveKey */
	    AUTHENTICATED_DH: { 'name' : 'NFLX-DH' },
	    /** digest */
	    SHA_256: { 'name': 'SHA-256' },
	    SHA_384: { 'name': 'SHA-384' },
	};
	
	/**
	 * @param {WebCryptoAlgorithm} algo the Web Crypto algorithm.
	 * @return {boolean} true if the algorithm is an HMAC.
	 */
	var WebCryptoAlgorithm$isHmac = function WebCryptoAlgorithm$isHmac(algo) {
	    // Assume all HMAC algorithms use the same base algorithm name.
	    return (algo['name'] == 'HMAC');
	};
	
	/**
	 * @param {WebCryptoAlgorithm} algo the Web Crypto algorithm.
	 * @return {boolean} true if the algorithm uses RSA keys.
	 */
	var WebCryptoAlgorithm$isRsa = function WebCryptoAlgorithm$isRsa(algo) {
	    // We must compare by name because Web Crypto algorithm objects are not
	    // strictly defined.
	    switch (algo['name']) {
	        case WebCryptoAlgorithm.RSA_OAEP['name']:
	        case WebCryptoAlgorithm.RSAES['name']:
	        case WebCryptoAlgorithm.RSASSA['name']:
	        case WebCryptoAlgorithm.RSASSA_SHA1['name']:
	        case WebCryptoAlgorithm.RSASSA_SHA256['name']:
	            return true;
	        default:
	            return false;
	    }
	};

    /**
     * @param {WebCryptoAlgorithm} algo the Web Crypto algorithm.
     * @return {boolean} true if the algorithm uses EC keys.
     */
	var WebCryptoAlgorithm$isEc = function WebCryptoAlgorithm$isEc(algo) {
	    // We must compare by name because Web Crypto algorithm objects are not
        // strictly defined.
        switch (algo['name']) {
            case WebCryptoAlgorithm.ECDH['name']:
            case WebCryptoAlgorithm.ECDSA_SHA256['name']:
                return true;
            default:
                return false;
        }
	};
	
	// Exports.
	Object.defineProperties(WebCryptoAlgorithm, {
	    isHmac: { value: WebCryptoAlgorithm$isHmac, writable: false, enumerable: false, configurable: false },
	    isRsa: { value: WebCryptoAlgorithm$isRsa, writable: false, enumerable: false, configurable: false },
	    isEc: { value: WebCryptoAlgorithm$isEc, writable: false, enumerable: false, configurable: false },
	});
	Object.freeze(WebCryptoAlgorithm);
})(require, (typeof module !== 'undefined') ? module : mkmodule('WebCryptoAlgorithm'));