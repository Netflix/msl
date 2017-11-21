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
 * SecretKey unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("SecretKey", function() {
    var SecretKey = require('msl-core/crypto/SecretKey.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var Base64 = require('msl-core/util/Base64.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    
    /** 128-bit key. */
    var keydata128B64 = "rXIN3PgEoTjJzeqSD1SwDw==";
	var key128;

    /** 256-bit key. */
	var keydata256B64 = "Ii0NcXKk8Yy9XQeLWvjkN7sYfTltDAowNrFPONzZOHU=";
	var key256;

	var initialized = false;
	beforeEach(function () {
	    if (!initialized) {
	        runs(function () {
	            SecretKey.import(keydata128B64,WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
	                result: function (key) { key128 = key; },
	                error: function (e) { expect(function() { throw e; }).not.toThrow(); }
	            });
	            SecretKey.import(keydata256B64, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
	                result: function (key) { key256 = key; },
	                error: function (e) { expect(function() { throw e; }).not.toThrow(); }
	            });
	        });
	        waitsFor(function() { return key128 && key256; }, "keys", MslTestConstants.TIMEOUT);
	        runs(function() { initialized = true; });
	    }
	});
	
	it("toByteArray", function () {
	    expect(key128.toByteArray()).toEqual(Base64.decode(keydata128B64));
	    expect(key256.toByteArray()).toEqual(Base64.decode(keydata256B64));
	});
	
	it("toBase64", function () {
	    expect(key128.toBase64()).toEqual(keydata128B64);
	    expect(key256.toBase64()).toEqual(keydata256B64);
	});
});