/**
 * Copyright (c) 2012-2015 Netflix, Inc.  All rights reserved.
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
var PrivateKey;
var PrivateKey$create;
var PrivateKey$import;

(function () {
    "use strict";

    PrivateKey = util.Class.create({
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
         * @param {Uint8Array=} encopded optional raw key encoding.
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
                        callback.error(new MslCryptoException(MslError.KEY_EXPORT_ERROR, "pkcs8"));
                    };
                    mslCrypto['exportKey']("pkcs8", rawKey)
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
            };
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
    PrivateKey$create = function PrivateKey$create(rawKey, callback) {
        new PrivateKey(rawKey, callback);
    };

    /**
     * Creates a private key from the provided key data. The key's
     * byte encoding will be available.
     *
     * @param {string|Uint8Array} pkcs8 Base64-encoded or raw PKCS#8.
     * @param {WebCryptoAlgorithm} algo Web Crypto algorithm.
     * @param {WebCryptoUsage} usages Web Crypto key usages.
     * @param {{result: function(PrivateKey), error: function(Error)}}
     *        callback the callback will receive the new public key
     *        or any thrown exceptions.
     * @throws MslCryptoException if the key data is invalid.
     */
    PrivateKey$import = function PrivateKey$import(pkcs8, algo, usages, callback) {
        AsyncExecutor(callback, function() {
            try {
                pkcs8 = (typeof pkcs8 == "string") ? base64$decode(pkcs8) : pkcs8;
            } catch (e) {
                throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, "pkcs8 " + pkcs8, e);
            }
            var oncomplete = function(result) {
                new PrivateKey(result, callback, pkcs8);
            };
            var onerror = function(e) {
                callback.error(new MslCryptoException(MslError.INVALID_PRIVATE_KEY));
            };
            mslCrypto["importKey"]("pkcs8", pkcs8, algo, true, usages)
                .then(oncomplete, onerror);
        });
    };
})();
