/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
(function() {
	// Check if typed arrays are supported
    if (typeof ArrayBuffer != 'function' && typeof ArrayBuffer != 'object') {
        return;
    }

    // Reference original sign/verify and encrypt/decrypt methods.
    var $superSign = RSAKey.prototype.sign;
    var $superSignWithSHA1 = RSAKey.prototype.signWithSHA1;
    var $superSignWithSHA256 = RSAKey.prototype.signWithSHA256;
    var $superVerify = RSAKey.prototype.verify;
    var $superEncrypt = RSAKey.prototype.encrypt;
    var $superDecrypt = RSAKey.prototype.decrypt;

    //  Convert typed arrays to strings.
    function stringify(typedArray) {
    	// Convert buffers to data view
        if (typedArray instanceof ArrayBuffer) {
        	typedArray = new Uint8Array(typedArray);
        }

        // Convert array views to data view
        else if (
            typedArray instanceof Int8Array ||
            typedArray instanceof Uint8ClampedArray ||
            typedArray instanceof Int16Array ||
            typedArray instanceof Uint16Array ||
            typedArray instanceof Int32Array ||
            typedArray instanceof Uint32Array ||
            typedArray instanceof Float32Array ||
            typedArray instanceof Float64Array
        ) {
            typedArray = new Uint8Array(typedArray.buffer);
        }

        // Handle data views
        if (typedArray instanceof Uint8Array) {
        	return textEncoding$getString(typedArray, "utf-8");
        } else {
            // Else return what we got.
        	return typedArray;
        }
    };

    // Convert typed arrays to hex strings.
    function hexify(typedArray) {
    	// Convert buffers to data view
        if (typedArray instanceof ArrayBuffer) {
        	typedArray = new Uint8Array(typedArray);
        }

        // Convert array views to data view
        else if (
            typedArray instanceof Int8Array ||
            typedArray instanceof Uint8ClampedArray ||
            typedArray instanceof Int16Array ||
            typedArray instanceof Uint16Array ||
            typedArray instanceof Int32Array ||
            typedArray instanceof Uint32Array ||
            typedArray instanceof Float32Array ||
            typedArray instanceof Float64Array
        ) {
            typedArray = new Uint8Array(typedArray.buffer);
        }

        // Handle data views
        if (typedArray instanceof Uint8Array) {
        	var words = CryptoJS.lib.WordArray.create(typedArray);
        	return CryptoJS.enc.Hex.stringify(words);
        } else {
            // Else return what we got.
        	return typedArray;
        }
    };

    // Convert strings to typed arrays.
    function arrayify(str) {
    	if (typeof str === 'string') {
    		return textEncoding$getBytes(str, "utf-8");
    	}
    	return str;
    };

    // Convert hex strings to typed arrays.
    function hexArrayify(hex) {
    	if (typeof hex === 'string') {
    		var byteLength = hex.length / 2;
    		var typedArray = new Uint8Array(byteLength);
    		for (var i = 0; i < byteLength; ++i) {
    			typedArray[i] = parseInt(hex.substr(2 * i, 2), 16);
    		}
    		return typedArray;
    	}
    	return hex;
    }

    // Augment functions to handle typed arrays.
    RSAKey.prototype.sign = function(s, hashAlg) {
    	s = stringify(s);
    	var sig = $superSign.call(this, s, hashAlg);
    	return hexArrayify(sig);
    };
    RSAKey.prototype.signWithSHA1 = function(s) {
    	s = stringify(s);
    	var sig = $superSignWithSHA1.call(this, s);
    	return hexArrayify(sig);
    };
    RSAKey.prototype.signWithSHA256 = function(s) {
    	s = stringify(s);
    	var sig = $superSignWithSHA256.call(this, s);
    	return hexArrayify(sig);
    };
    RSAKey.prototype.verify = function(sMsg, hSig) {
    	sMsg = stringify(sMsg);
    	hSig = hexify(hSig);
    	return $superVerify.call(this, sMsg, hSig);
    };
    RSAKey.prototype.encrypt = function(text) {
    	var hex = $superEncrypt.call(this, text);
    	return hexArrayify(hex);
    };
    RSAKey.prototype.decrypt = function(ctext) {
    	ctext = hexify(ctext);
    	return $superDecrypt.call(this, ctext);
    };
})();