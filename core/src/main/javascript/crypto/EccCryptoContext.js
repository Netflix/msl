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
 * <p>An ECC crypto context performs SHA-1 with ECDSA sign/verify using a
 * public/private ECC key pair.</p>
 *
 * @author Pablo Pissanetzky <ppissanetzky@netflix.com>
 * @implements {ICryptoContext}
 */
(function(require, module) {
    "use strict";
    
    var ICryptoContext = require('../crypto/ICryptoContext.js');
    var MslSignatureEnvelope = require('../crypto/MslSignatureEnvelope.js');
    var WebCryptoAlgorithm = require('../crypto/WebCryptoAlgorithm.js');
    var MslCrypto = require('../crypto/MslCrypto.js');
    var MslCryptoException = require('../MslCryptoException.js');
    var MslError = require('../MslError.js');
    var MslEncoderException = require('../io/MslEncoderException.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');

    var EccCryptoContext = module.exports = ICryptoContext.extend({
        /**
         * <p>Create a new ECC crypto context with the provided public and
         * private keys.</p>
         *
         * <p>If there is no private key, signing is unsupported.</p>
         *
         * <p>If there is no public key, verification is unsupported.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {PrivateKey} privateKey the private key used for signing.
         * @param {PublicKey} publicKey the public key used for verification.
         * @constructor
         */
        init: function init(ctx, privateKey, publicKey) {
            init.base.call(this);

            // Extract the RAW ECC keys
            if (privateKey)
                privateKey = privateKey.rawKey;
            if (publicKey)
                publicKey = publicKey.rawKey;

            // The properties.
            var props = {
                privateKey: { value: privateKey, writable: false, enumerable: false, configurable: false },
                publicKey: { value: publicKey, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        encrypt: function encrypt(data, encoder, format, callback) {
            AsyncExecutor(callback, function() {
                return data;
            }, this);
        },

        /** @inheritDoc */
        decrypt: function decrypt(data, encoder, callback) {
            AsyncExecutor(callback, function() {
                return data;
            }, this);
        },

        /** @inheritDoc */
        wrap: function wrap(key, encoder, format, callback) {
            AsyncExecutor(callback, function() {
                throw new MslCryptoException(MslError.WRAP_NOT_SUPPORTED, "ECC does not wrap");
            }, this);
        },

        /** @inheritDoc */
        unwrap: function unwrap(data, algo, usages, encoder, callback) {
            AsyncExecutor(callback, function() {
                throw new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED, "ECC does not unwrap");
            }, this);
        },

        /** @inheritDoc */
        sign: function sign(data, encoder, format, callback) {
            AsyncExecutor(callback, function() {
                if (!this.privateKey)
                    throw new MslCryptoException(MslError.SIGN_NOT_SUPPORTED, "no private key");
                var oncomplete = function(hash) {
                    // Return the signature envelope byte representation.
                    MslSignatureEnvelope.create(new Uint8Array(hash), {
                        result: function(envelope) {
                            envelope.getBytes(encoder, format, {
                                result: callback.result,
                                error: function(e) {
                                    if (e instanceof MslEncoderException)
                                        e = new MslCryptoException(MslError.SIGNATURE_ENVELOPE_ENCODE_ERROR, e);
                                    callback.error(e);
                                },
                            });
                        },
                        error: callback.error
                    });
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.SIGNATURE_ERROR, null, e));
                };
                MslCrypto['sign'](WebCryptoAlgorithm.ECDSA_SHA256, this.privateKey, data)
                    .then(oncomplete, onerror);
            }, this);
        },

        /** @inheritDoc */
        verify: function verify(data, signature, encoder, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                if (!this.publicKey)
                    throw new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED, "no public key");

                // Reconstitute the signature envelope.
                MslSignatureEnvelope.parse(signature, MslSignatureEnvelope.Version.V1, encoder, {
                    result: function(envelope) {
                        AsyncExecutor(callback, function() {
                            var oncomplete = callback.result;
                            var onerror = function(e) {
                                callback.error(new MslCryptoException(MslError.SIGNATURE_ERROR, null, e));
                            };
                            MslCrypto['verify'](WebCryptoAlgorithm.ECDSA_SHA256, this.publicKey, envelope.signature, data)
                                .then(oncomplete, onerror);
                        }, self);
                    },
                    error: callback.error
                });
            }, this);
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('EccCryptoContext'));
