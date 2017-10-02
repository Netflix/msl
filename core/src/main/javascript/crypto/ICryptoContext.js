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
	
	var Class = require('../util/Class.js');
	
	/**
	 * A generic cryptographic context suitable for encryption/decryption,
	 * wrap/unwrap, and sign/verify operations.
	 *
	 * @author Wesley Miaw <wmiaw@netflix.com>
	 * @interface
	 */
	var ICryptoContext = module.exports = Class.create({
	    /**
	     * Encrypts some data.
	     *
	     * @param {Uint8Array} data the plaintext.
	     * @param {MslEncoderFactory} encoder MSL encoder factory.
	     * @param {MslEncoderFormat} format MSL encoder format.
	     * @param {{result: function(Uint8Array), error: function(Error)}}
	     *        callback the callback functions that will receive the ciphertext
	     *        or any thrown exceptions.
	     * @throws MslCryptoException if there is an error encrypting the data.
	     */
	    encrypt: function(data, encoder, format, callback) {},
	
	    /**
	     * Decrypts some data.
	     *
	     * @param {Uint8Array} data the ciphertext.
	     * @param {MslEncoderFactory} encoder MSL encoder factory.
	     * @param {{result: function(Uint8Array), error: function(Error)}}
	     *        callback the callback functions that will receive the plaintext
	     *        or any thrown exceptions.
	     * @throws MslCryptoException if there is an error decrypting the data.
	     */
	    decrypt: function(data, encoder, callback) {},
	
	    /**
	     * Wraps a key.
	     *
	     * @param {SecretKey|PublicKey|PrivateKey} key the key to wrap.
	     * @param {MslEncoderFactory} encoder MSL encoder factory.
	     * @param {MslEncoderFormat} format MSL encoder format.
	     * @return {result: function(Uint8Array), error: function(Error)}
	     *         callback the callback functions that will receive the wrapped
	     *         data or any thrown exceptions.
	     * @throws MslCryptoException if there is an error wrapping the key.
	     */
	    wrap: function(key, encoder, format, callback) {},
	
	    /**
	     * Unwraps a key.
	     *
	     * @param {Uint8Array} data the wrapped data.
	     * @param {WebCryptoAlgorithm} algo for the wrapped key.
	     * @param {WebCryptoUsage} usages the key usages for the wrapped key.
	     * @param {MslEncoderFactory} encoder MSL encoder factory.
	     * @return {result: function({SecretKey|PublicKey|PrivateKey}), error: function(Error)}
	     *         callback the callback functions that will receive the unwrapped
	     *         key or any thrown exceptions.
	     * @throws MslCryptoException if there is an error unwrapping the key.
	     */
	    unwrap: function(data, algo, usages, encoder, callback) {},
	
	    /**
	     * Computes the signature for some data. The signature may not be a
	     * signature proper, but the name suits the concept.
	     *
	     * @param {Uint8Array} data the data.
	     * @param {MslEncoderFactory} encoder MSL encoder factory.
	     * @param {MslEncoderFormat} format MSL encoder format.
	     * @param {{result: function(Uint8Array), error: function(Error)}}
	     *        callback the callback functions that will receive the signature
	     *        or any thrown exceptions.
	     * @throws MslCryptoException if there is an error computing the signature.
	     */
	    sign: function(data, encoder, format, callback) {},
	
	    /**
	     * Verifies the signature for some data. The signature may not be a
	     * signature proper, but the name suits the concept.
	     *
	     * @param {Uint8Array} data the data.
	     * @param {Uint8Array} signature the signature.
	     * @param {MslEncoderFactory} encoder MSL encoder factory.
	     * @param {{result: function(boolean), error: function(Error)}}
	     *        callback the callback functions that will receive true if the
	     *        data is verified, false if validation fails, or any thrown
	     *        exceptions.
	     * @throws MslCryptoException if there is an error verifying the signature.
	     */
	    verify: function(data, signature, encoder, callback) {},
	});
})(require, (typeof module !== 'undefined') ? module : mkmodule('ICryptoContext'));