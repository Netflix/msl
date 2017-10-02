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
 * <p>An ECC, RSA, or Diffie-Hellman private key.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var Class = require('../util/Class.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var MslCryptoException = require('../MslCryptoException.js');
    var MslCrypto = require('../crypto/MslCrypto.js');
    var KeyFormat = require('../crypto/KeyFormat.js');
    var MslError = require('../MslError.js');
    var Base64 = require('../util/Base64.js');

    /**
     * Normalize private key input into expected Web Crypto API format.
     *
     * @param {string|Uint8Array|object} input Base64-encoded, raw or JSON key
     *        data (PKCS#8|JWK).
     * @param {KeyFormat} format provided key format (PKCS#8|JWK).
     * @return {Uint8Array|object} DER-encoded PCKS#8 or JSON Web Key object.
     * @throws MslCryptoException if the key data is invalid.
     */
    function normalizePrivkeyInput(input, format) {
        // PKCS#8 must be either a Base64-encoded string or the raw bytes.
        if (format == KeyFormat.PKCS8) {
            if (input instanceof Uint8Array)
                return input;
            if (typeof input === 'string') {
                try {
                    return Base64.decode(input);
                } catch (e) {
                    throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, format + " " + input, e);
                }
            }
            throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, format + " " + input);
        }
        
        // JWK must either be a JSON string or a JavaScript object.
        if (format == KeyFormat.JWK) {
            if (typeof input === 'string') {
                try {
                    input = JSON.parse(input);
                } catch (e) {
                    throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, format + " " + input, e);
                }
            }
            if (typeof input === 'object' && input.constructor === Object)
                return input;
            throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, format + " " + input);
        }
        
        // Invalid format.
        throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, "Invalid format '" + format + "'");
    }

    var PrivateKey = module.exports = Class.create({
        /**
         * Create a new private key from an original private key.
         *
         * If the raw key encoding is not provided the encoding will be
         * extracted if possible.
         *
         * @param rawKey {Object} the original crypto private key
         * @param {{result: function(PrivateKey), error: function(Error)}}
         *        callback the callback will receive the new private key
         *        or any thrown exceptions.
         * @param {Uint8Array=} encoded optional raw key encoding.
         * @throws MslCryptoException if the key is extractable but
         *         extraction fails.
         */
        init: function init(rawKey, callback, encoded) {
            var self = this;

            AsyncExecutor(callback, function () {
                if (typeof rawKey !== 'object' || rawKey.type != 'private')
                    throw new TypeError('Only original private crypto keys are supported.');

                if (!encoded && rawKey['extractable']) {
                    var oncomplete = function(result) {
                        createKey(new Uint8Array(result));
                    };
                    var onerror = function(e) {
                        callback.error(new MslCryptoException(MslError.KEY_EXPORT_ERROR, KeyFormat.PKCS8, e));
                    };
                    MslCrypto['exportKey'](KeyFormat.PKCS8, rawKey)
                        .then(oncomplete, onerror);
                } else {
                    createKey(encoded);
                }
            });

            function createKey(encoded) {
                AsyncExecutor(callback, function() {
                    // The properties.
                    var props = {
                        rawKey: { value: rawKey, writable: false, configurable: false },
                        encoded: { value: encoded, writable: false, configurable: false }
                    };
                    Object.defineProperties(self, props);
                    return this;
                }, self);
            }
        },

        /**
         * Returns the standard encoding of the private key.
         *
         * RSA keys are returned in pkcs#8 format.
         * ECC keys are not yet supported.
         * Diffie-Hellman keys are not yet supported.
         *
         * @return {Uint8Array} the encoded private key.
         */
        getEncoded: function getEncoded() {
            return this.encoded;
        },
    });

    /**
     * Create a new private key from an original private key.
     *
     * @param {Object} cryptoSubtle rawKey.
     * @param {{result: function(PrivateKey), error: function(Error)}}
     *        callback the callback will receive the new private key
     *        or any thrown exceptions.
     * @throws MslCryptoException if the key is extractable but
     *         extraction fails
     */
    var PrivateKey$create = function PrivateKey$create(rawKey, callback) {
        new PrivateKey(rawKey, callback);
    };

    /**
     * Creates a private key from the provided key data. The key's
     * byte encoding will be available.
     *
     * @param {string|Uint8Array|object} input Base64-encoded, raw or JSON key
     *        data (PKCS#8|JWK).
     * @param {WebCryptoAlgorithm} algo Web Crypto algorithm.
     * @param {WebCryptoUsage} usages Web Crypto key usages.
     * @param {KeyFormat} format format of the key to import.
     * @param {{result: function(PrivateKey), error: function(Error)}}
     *        callback the callback will receive the new public key
     *        or any thrown exceptions.
     * @throws MslCryptoException if the key data is invalid.
     */
    var PrivateKey$import = function PrivateKey$import(input, algo, usages, format, callback) {
        AsyncExecutor(callback, function() {
            var keydata = normalizePrivkeyInput(input, format);
            var oncomplete = function(result) {
                new PrivateKey(result, callback, keydata);
            };
            var onerror = function(e) {
                callback.error(new MslCryptoException(MslError.INVALID_PRIVATE_KEY, null, e));
            };
            MslCrypto["importKey"](format, keydata, algo, true, usages)
                .then(oncomplete, onerror);
        });
    };
    
    // Exports.
    module.exports.create = PrivateKey$create;
    module.exports.import = PrivateKey$import;
})(require, (typeof module !== 'undefined') ? module : mkmodule('PrivateKey'));
