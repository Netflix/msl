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
 * Symmetric crypto key.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var CipherKey;
var CipherKey$create;
var CipherKey$import;

(function () {
    "use strict";

    CipherKey = util.Class.create({
        /**
         * Create a new cipher key from an original symmetric key.
         *
         * If the raw key data is not provided the key data will be
         * extracted if possible.
         *
         * @param {Object} rawKey cryptoSubtle key.
         * @param {{result: function(CipherKey), error: function(Error)}}
         *        callback the callback will receive the new cipher key
         *        or any thrown exceptions.
         * @param {Uint8Array=} keyData optional raw key data.
         * @throws MslCryptoException if the key is extractable but
         *         extraction fails
         */
        init: function init(rawKey, callback, keyData) {
            var self = this;

            AsyncExecutor(callback, function () {
                if (typeof rawKey !== "object")
                    throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY);

                if (!keyData && rawKey['extractable']) {
                    var oncomplete = function(result) {
                        createKey(new Uint8Array(result));
                    };
                    var onerror = function(e) {
                        callback.error(new MslCryptoException(MslError.KEY_EXPORT_ERROR, "raw"));
                    };
                    mslCrypto.exportKey("raw", rawKey)
                        .then(oncomplete, onerror);

                } else {
                    createKey(keyData);
                }
            }, self);

            function createKey(keyData) {
                AsyncExecutor(callback, function() {
                    var keyDataB64 = (keyData) ? base64$encode(keyData) : undefined;

                    // The properties.
                    var props = {
                        algorithm: { value: rawKey.algorithm, writable: false, configurable: false },
                        rawKey: { value: rawKey, writable: false, configurable: false },
                        keyData: { value: keyData, writable: false, configurable: false },
                        keyDataB64: { value: keyDataB64, writable: false, configurable: false }
                    };
                    Object.defineProperties(self, props);
                    return this;
                }, self);
            }
        },

        /**
         * @return the key size in bytes.
         */
        size: function size() {
            return this.keyData.length;
        },

        /**
         * @return {Uint8Array} the raw key bytes.
         */
        toByteArray: function toByteArray() {
            return this.keyData;
        },

        /**
         * @return {string} the key Base64 encoded.
         */
        toBase64: function toBase64() {
            return this.keyDataB64;
        }
    });

    /**
     * Create a new cipher key from an original symmetric key.
     *
     * @param {Object} cryptoSubtle rawKey.
     * @param {{result: function(CipherKey), error: function(Error)}}
     *        callback the callback will receive the new cipher key
     *        or any thrown exceptions.
     * @throws MslCryptoException if the rawKey is invalid.
     */
    CipherKey$create = function CipherKey$create(rawKey, callback) {
        new CipherKey(rawKey, callback);
    };

    /**
     * Creates a cipher key from the provided key data. The key's byte
     * encoding will be available.
     *
     * @param {string|Uint8Array} keydata Base64-encoded or raw key data.
     * @param {WebCryptoAlgorithm} algo Web Crypto algorithm.
     * @param {WebCryptoUsage} usages Web Crypto key usages.
     * @param {{result: function(CipherKey), error: function(Error)}}
     *        callback the callback will receive the new cipher key
     *        or any thrown exceptions.
     * @throws MslCryptoException if the key data is invalid.
     */
    CipherKey$import = function CipherKey$import(keydata, algo, usages, callback) {
        AsyncExecutor(callback, function() {
            try {
                keydata = (typeof keydata == "string") ? base64$decode(keydata) : keydata;
            } catch (e) {
                throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, "keydata " + keydata, e);
            }

            var oncomplete = function(result) {
                new CipherKey(result, callback, keydata);
            };
            var onerror = function(e) {
                callback.error(new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY));
            };
            mslCrypto.importKey("raw", keydata, algo, true, usages)
                .then(oncomplete, onerror);
        });
    };
})();
