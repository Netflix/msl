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

/**
 * <p>This key exchange crypto context provides an implementation of the JSON
 * web encryption algorithm as defined in
 * <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-08">JSON Web Encryption</a>.
 * It supports a limited subset of the algorithms.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 * @implements {ICryptoContext}
 */
(function(require, module) {
    "use strict";
    
    var WebCryptoAlgorithm = require('../crypto/WebCryptoAlgorithm.js');
    var Class = require('../util/Class.js');
    var MslInternalException = require('../MslInternalException.js');
    var MslCryptoException = require('../MslCryptoException.js');
    var MslError = require('../MslError.js');
    var MslCrypto = require('../crypto/MslCrypto.js');
    var PrivateKey = require('../crypto/PrivateKey.js');
    var PublicKey = require('../crypto/PublicKey.js');
    var SecretKey = require('../crypto/SecretKey.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');

    /**
     * Supported content encryption key encryption algorithms. These are the
     * web crypto algorithm names.
     * @enum
     */
    var Algorithm = {
        /** RSAES-OAEP */
        RSA_OAEP: WebCryptoAlgorithm.RSA_OAEP['name'],
        /** AES-128 Key Wrap */
        A128KW: WebCryptoAlgorithm.A128KW['name'],
    };

    /**
     * Supported plaintext encryption algorithms. These are the JSON crypto
     * algorithm names.
     * @enum
     */
    var Encryption = {
        /** AES-128 GCM */
        A128GCM: "A128GCM",
        /** AES-256 GCM */
        A256GCM: "A256GCM",
    };

    var JsonWebEncryptionCryptoContext = module.exports = Class.create({
        /**
         * Create a new JSON web encryption crypto context with the specified
         * content encryption key and plaintext encryption algorithms.
         *
         * @param {MslContext} ctx MSL context.
         * @param {Algorithm} algo content encryption key encryption algorithm.
         * @param {Encryption} enc plaintext encryption algorithm.
         * @param {?PrivateKey|SecretKey} key content encryption key encryption
         *        private key for asymmetric encryption algorithms or secret key
         *        for symmetric encryption algorithms.
         * @param {PublicKey=} publicKey content encryption key encryption
         *        public key for asymmetric encryption algorithms.
         * @throws MslInternalException if the content encryption key encryption
         *         algorithm is unsupported.
         */
        init: function init(ctx, algo, enc, key, publicKey) {
            var transform, wrapKey, unwrapKey;
            switch (algo) {
                case Algorithm.RSA_OAEP:
                    transform = WebCryptoAlgorithm.RSA_OAEP;
                    wrapKey = publicKey && (publicKey.rawKey || publicKey);
                    unwrapKey = key && (key.rawKey || key);
                    break;
                case Algorithm.A128KW:
                    transform = WebCryptoAlgorithm.A128KW;
                    wrapKey = unwrapKey = key && (key.rawKey || key);
                    break;
                default:
                    throw new MslInternalException("Unsupported algorithm: " + algo);
            }

            // The properties.
            var props = {
                _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                _transform: { value: transform, writable: false, enumerable: false, configurable: false },
                _enc: {value: enc, writable: false, enumerable: false, configurable: false },
                _wrapKey: { value: wrapKey, writable: false, enumerable: false, configurable: false },
                _unwrapKey: { value: unwrapKey, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        encrypt: function encrypt(data, encoder, format, callback) {
            callback.error(new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED));
        },

        /** @inheritDoc */
        decrypt: function decrypt(data, encoder, callback) {
            callback.error(new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED));
        },

        /** @inheritDoc */
        wrap: function wrap(key, encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var oncomplete = function(result) {
                    callback.result(new Uint8Array(result));
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.WRAP_ERROR, null, e));
                };
                // Use the transform instead of the wrap key algorithm in case
                // the key algorithm is missing some fields.
                MslCrypto['wrapKey']('jwe+jwk', key.rawKey, this._wrapKey, this._transform)
                    .then(oncomplete, onerror);
            }, this);
        },

        /** @inheritDoc */
        unwrap: function unwrap(data, algo, usages, encoder, callback) {
            AsyncExecutor(callback, function() {
                var oncomplete = function(result) {
                    constructKey(result);
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.UNWRAP_ERROR, null, e));
                };
                // Use the transform instead of the wrap key algorithm in case
                // the key algorithm is missing some fields.
                MslCrypto['unwrapKey']('jwe+jwk', data, this._unwrapKey, this._transform, algo, false, usages)
                    .then(oncomplete, onerror);
            }, this);

            function constructKey(rawKey) {
                AsyncExecutor(callback, function() {
                    switch (rawKey["type"]) {
                        case "secret":
                            SecretKey.create(rawKey, callback);
                            break;
                        case "public":
                            PublicKey.create(rawKey, callback);
                            break;
                        case "private":
                            PrivateKey.create(rawKey, callback);
                            break;
                        default:
                            throw new MslCryptoException(MslError.UNSUPPORTED_KEY, "type: " + rawKey["type"]);
                    }
                });
            }
        },

        /** @inheritDoc */
        sign: function sign(data, encoder, format, callback) {
            callback.error(new MslCryptoException(MslError.SIGN_NOT_SUPPORTED));
        },

        /** @inheritDoc */
        verify: function verify(data, signature, encoder, callback) {
            callback.error(new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED));
        },
    });
    
    // Exports.
    module.exports.Algorithm = Algorithm;
    module.exports.Encryption = Encryption;
})(require, (typeof module !== 'undefined') ? module : mkmodule('JsonWebEncryptionCryptoContext'));
