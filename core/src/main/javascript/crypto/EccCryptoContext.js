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
 * <p>An ECC crypto context performs ECDSA sign/verify using a
 *    public/private ECC key pair.</p>
 *
 * @author Pablo Pissanetzky <ppissanetzky@netflix.com>
 * @implements {ICryptoContext}
 */
var EccCryptoContext;

(function() {
    "use strict";

    EccCryptoContext = ICryptoContext.extend({
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
        encrypt: function encrypt(data, callback) {
            AsyncExecutor(callback, function() {
                return data;
            }, this);
        },

        /** @inheritDoc */
        decrypt: function decrypt(data, callback) {
            AsyncExecutor(callback, function() {
                return data;
            }, this);
        },

        /** @inheritDoc */
        wrap: function wrap(key, callback) {
            AsyncExecutor(callback, function() {
                throw new MslCryptoException(MslError.WRAP_NOT_SUPPORTED, "ECC does not wrap");
            }, this);
        },

        /** @inheritDoc */
        unwrap: function unwrap(data, algo, usages, callback) {
            AsyncExecutor(callback, function() {
                throw new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED, "ECC does not unwrap");
            }, this);
        },

        /** @inheritDoc */
        sign: function sign(data, callback) {
            AsyncExecutor(callback, function() {
                if (!this.privateKey)
                    throw new MslCryptoException(MslError.SIGN_NOT_SUPPORTED, "no private key");
                var oncomplete = function(hash) {
                    // Return the signature envelope byte representation.
                    MslSignatureEnvelope$create(new Uint8Array(hash), {
                        result: function(envelope) {
                            callback.result(envelope.bytes);
                        },
                        error: callback.error
                    });
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.SIGNATURE_ERROR));
                };
                mslCrypto['sign'](WebCryptoAlgorithm.ECDSA_SHA256, this.privateKey, data)
                    .then(oncomplete, onerror);
            }, this);
        },

        /** @inheritDoc */
        verify: function verify(data, signature, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                if (!this.publicKey)
                    throw new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED, "no public key");

                // Reconstitute the signature envelope.
                MslSignatureEnvelope$parse(signature, MslSignatureEnvelope$Version.V1, {
                    result: function(envelope) {
                        AsyncExecutor(callback, function() {
                            var oncomplete = callback.result;
                            var onerror = function(e) {
                                callback.error(new MslCryptoException(MslError.SIGNATURE_ERROR));
                            };
                            mslCrypto['verify'](WebCryptoAlgorithm.ECDSA_SHA256, this.publicKey, envelope.signature, data)
                                .then(oncomplete, onerror);
                        }, self);
                    },
                    error: callback.error
                });
            }, this);
        }
    });
})();
