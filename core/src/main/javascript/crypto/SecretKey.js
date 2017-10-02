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
 * Symmetric crypto key.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function (require, module) {
    "use strict";
    
    var Class = require('../util/Class.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var MslCryptoException = require('../MslCryptoException.js');
    var MslError = require('../MslError.js');
    var MslCrypto = require('../crypto/MslCrypto.js');
    var KeyFormat = require('../crypto/KeyFormat.js');
    var Base64 = require('../util/Base64.js');

    var SecretKey = module.exports = Class.create({
        /**
         * Create a new cipher key from an original symmetric key.
         *
         * If the raw key data is not provided the key data will be
         * extracted if possible.
         *
         * @param {Object} rawKey cryptoSubtle key.
         * @param {{result: function(SecretKey), error: function(Error)}}
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
                        callback.error(new MslCryptoException(MslError.KEY_EXPORT_ERROR, KeyFormat.RAW, e));
                    };
                    MslCrypto.exportKey(KeyFormat.RAW, rawKey)
                        .then(oncomplete, onerror);

                } else {
                    createKey(keyData);
                }
            }, self);

            function createKey(keyData) {
                AsyncExecutor(callback, function() {
                    var keyDataB64 = (keyData) ? Base64.encode(keyData) : undefined;

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
         * @return {Uint8Array} the raw key bytes.
         */
        getEncoded: function getEncoded() {
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
     * @param {{result: function(SecretKey), error: function(Error)}}
     *        callback the callback will receive the new cipher key
     *        or any thrown exceptions.
     * @throws MslCryptoException if the rawKey is invalid.
     */
    var SecretKey$create = function SecretKey$create(rawKey, callback) {
        new SecretKey(rawKey, callback);
    };

    /**
     * Creates a cipher key from the provided key data. The key's byte
     * encoding will be available.
     *
     * @param {string|Uint8Array} keydata Base64-encoded or raw key data.
     * @param {WebCryptoAlgorithm} algo Web Crypto algorithm.
     * @param {WebCryptoUsage} usages Web Crypto key usages.
     * @param {{result: function(SecretKey), error: function(Error)}}
     *        callback the callback will receive the new cipher key
     *        or any thrown exceptions.
     * @throws MslCryptoException if the key data is invalid.
     */
    var SecretKey$import = function SecretKey$import(keydata, algo, usages, callback) {
        AsyncExecutor(callback, function() {
            try {
                keydata = (typeof keydata == "string") ? Base64.decode(keydata) : keydata;
            } catch (e) {
                throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, "keydata " + keydata, e);
            }

            var oncomplete = function(result) {
                new SecretKey(result, callback, keydata);
            };
            var onerror = function(e) {
                callback.error(new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, null, e));
            };
            MslCrypto.importKey(KeyFormat.RAW, keydata, algo, true, usages)
                .then(oncomplete, onerror);
        });
    };
    
    // Exports.
    module.exports.create = SecretKey$create;
    module.exports.import = SecretKey$import;
})(require, (typeof module !== 'undefined') ? module : mkmodule('SecretKey'));
