/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
 * <p>Key Format constants and utility methods.</p>
 *
 */
(function(require, module) {
    "use strict";
    
    const Base64 = require('../util/Base64.js');
    const MslCryptoException = require('../MslCryptoException.js');
    const MslError = require('../MslError.js');

    var KeyFormat = module.exports = {
        RAW : "raw",
        JWK : "jwk",
        SPKI: "spki",
        PKCS8: "pkcs8",
    };

    /**
     * Normalize public key input into expected WebCrypto format.
     *
     * @param {string|object|Uint8Array} input Base64-encoded or JSON object or ByteArray of key.
     * @param {KeyFormat} format key format type ("spki" | "jwk")
     * @return WebCrypto acceptable format of the public key.
     * @throws MslCryptoException if the key data is invalid.
     */
    var normalizePubkeyInput = function normalizePubkeyInput(input, format) {
        if (format == KeyFormat.SPKI) {
            try {
                input = (typeof input === "string") ? Base64.decode(input) : input;
            } catch (e) {
                throw new MslCryptoException(MslError.INVALID_PUBLIC_KEY, format + " " + input, e);
            }
        }
        else if (format == KeyFormat.JWK) {
            try {
                input = (typeof input === "string") ? JSON.parse(input) : input;
                /* input must be a JSON object */
                if (typeof input !== "object" || input.constructor !== Object) {
                    throw "JWK key is not JSON format";
                }
            } catch (e) {
                throw new MslCryptoException(MslError.INVALID_PUBLIC_KEY, format + " " + input, e);
            }
        }
        else {
            throw new MslCryptoException(MslError.INVALID_PUBLIC_KEY, "Invalid format '" + format + "'", e);
        }

        return input;
    };

    /**
     * Normalize private key input into expected WebCrypto format.
     *
     * @param {string|object|Uint8Array} input Base64-encoded or JSON object or ByteArray of key.
     * @param {KeyFormat} format key format type ("pkcs8" | "jwk")
     * @return WebCrypto acceptable format of the private key.
     * @throws MslCryptoException if the key data is invalid.
     */
    var normalizePrivkeyInput = function normalizePrivkeyInput(input, format) {
        if (format == KeyFormat.PKCS8) {
            try {
                input = (typeof input === "string") ? Base64.decode(input) : input;
            } catch (e) {
                throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, format + " " + input, e);
            }
        }
        else if (format == KeyFormat.JWK) {
            try {
                input = (typeof input === "string") ? JSON.parse(input) : input;
                /* input must be a JSON object */
                if (typeof input !== "object" || input.constructor !== Object) {
                    throw "JWK key is not JSON format";
                }
            } catch (e) {
                throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, format + " " + input, e);
            }
        }
        else {
            throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, "Invalid format '" + format + "'", e);
        }

        return input;
    };
    
    // Exports.
    module.exports.normalizePubkeyInput = normalizePubkeyInput;
    module.exports.normalizePrivkeyInput = normalizePrivkeyInput;
})(require, (typeof module !== 'undefined') ? module : mkmodule('KeyFormat'));
