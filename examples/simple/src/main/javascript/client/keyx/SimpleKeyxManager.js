/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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

    var AsymmetricWrappedExchange = require('msl-core/keyx/AsymmetricWrappedExchange.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var Class = require('msl-core/util/Class.js');
    var MslCrypto = require('msl-core/crypto/MslCrypto.js');
    var PrivateKey = require('msl-core/crypto/PrivateKey.js');
    var PublicKey = require('msl-core/crypto/PublicKey.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');

    /**
     * <p>A key pair holds a public and private key pair.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var KeyPair = Class.create({
        /**
         * <p>Create a new key pair.</p>
         *
         * @param {PublicKey} publicKey the public key.
         * @param {PrivateKey} privateKey the private key.
         */
        init: function init(publicKey, privateKey) {
            // Set properties.
            var props = {
                publicKey: { value: publicKey, writable: false, enumerable: true, configurable: false },
                privateKey: { value: privateKey, writable: false, enumerable: true, configurable: false },
            };
            Object.defineProperties(this, props);
        }
    });

    /**
     * <p>This class manages the lifetime of generated asymmetric keys used for
     * asymmetric wrapped key exchange. It is more efficient to generate a key
     * pair and use it multiple times until a key exchange occurs at which
     * point new keys should be generated and used.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var SimpleKeyxManager = module.exports = Class.create({
        /**
         * <p>Create a new asymmetric wrapped key exchange manager. A pair of
         * initial keys will be generated.</p>
         *
         * @param {AsymmetricWrappedExchange.Mechanism} mechanism the key
         *        mechanism to use.
         * @param {{result: function(SimpleKeyxManager), error: function(Error)}}
         *        callback the callback that will receive the key manager or
         *        any thrown exceptions.
         */
        init: function init(mechanism, callback) {
            var self = this;

            AsyncExecutor(callback, function() {
                // Set properties.
                var props = {
                	_mechanism: { value: mechanism, writable: false, enumerable: false, configurable: false },
                    _pubkey: { value: null, writable: true, enumerable: false, configurable: false },
                    _privkey: { value: null, writable: true, enumerable: false, configurable: false },
                };
                Object.defineProperties(this, props);

                // Generate the initial keys.
                this.regenerate({
                    result: function(success) {
                        // Return the key manager.
                        callback.result(self);
                    },
                    error: callback.error,
                });
            }, self);
        },

        /**
         * <p>Return the key exchange mechanism.</p>
         *
         * @return {AsymmetricWrappedExchange.Mechanism} the key exchange
         *         mechanism.
         */
        getMechanism: function getMechanism() {
        	return this._mechanism;
        },

        /**
         * <p>Return the current key pair.</p>
         *
         * @return {KeyPair} the current key pair.
         */
        getKeyPair: function getKeyPair() {
            return new KeyPair(this._pubkey, this._privkey);
        },

        /**
         * <p>Regenerate the current key pair.</p>
         *
         * @param {{result: function(boolean), error: function(Error)}}
         *        callback the callback that will receive true on success or
         *        any thrown exceptions.
         */
        regenerate: function regenerate(callback) {
            var self = this;

            AsyncExecutor(callback, function() {
                var oncomplete = function(result) {
                    PrivateKey.create(result.privateKey, {
                        result: function(privateKey) {
                            PublicKey.create(result.publicKey, {
                                result: function(publicKey) {
                                    AsyncExecutor(callback, function() {
                                        this._pubkey = publicKey;
                                        this._privkey = privateKey;
                                        return true;
                                    }, self);
                                },
                                error: callback.error,
                            });
                        },
                        error: callback.error,
                    });
                };
                var onerror = function(e) {
                    AsyncExecutor(callback, function() {
                        throw new Error("error generating RSA keys.");
                    }, self);
                };
                MslCrypto["generateKey"]({
                    'name': WebCryptoAlgorithm.RSA_OAEP['name'],
                    'modulusLength': 2048,
                    'publicExponent': new Uint8Array([0x01, 0x00, 0x01]),
                    'hash': WebCryptoAlgorithm.RSA_OAEP['hash'],
                }, false, WebCryptoUsage.WRAP_UNWRAP)
                    .then(oncomplete, onerror);
            }, self);
        }
    });

    /**
     * <p>Create a new asymmetric wrapped key exchange manager. A pair of
     * initial keys will be generated.</p>
     *
     * @param {AsymmetricWrappedExchange.Mechanism} mechanism the key
     *        mechanism to use.
     * @param {{result: function(SimpleKeyxManager), error: function(Error)}}
     *        callback the callback that will receive the key manager or
     *        any thrown exceptions.
     */
    var SimpleKeyxManager$create = function SimpleKeyxManager$create(mechanism, callback) {
        new SimpleKeyxManager(mechanism, callback);
    };
    
    // Exports.
    module.exports.KeyPair = KeyPair;
    module.exports.create = SimpleKeyxManager$create;
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleKeyxManager'));
