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
 * A symmetric crypto context performs AES-128 encryption/decryption, AES-128
 * key wrap/unwrap, and HMAC-SHA256 or AES-CMAC sign/verify.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var ICryptoContext = require('../crypto/ICryptoContext.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var MslError = require('../MslError.js');
	var MslCiphertextEnvelope = require('../crypto/MslCiphertextEnvelope.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslException = require('../MslException.js');
	var MslCrypto = require('../crypto/MslCrypto.js');
	var WebCryptoAlgorithm = require('../crypto/WebCryptoAlgorithm.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var SecretKey = require('../crypto/SecretKey.js');
	var PublicKey = require('../crypto/PublicKey.js');
	var PrivateKey = require('../crypto/PrivateKey.js');
	var MslSignatureEnvelope = require('../crypto/MslSignatureEnvelope.js');
	
    var SymmetricCryptoContext = module.exports = ICryptoContext.extend({
        /**
         * <p>Create a new symmetric crypto context using the provided keys.</p>
         * 
         * <p>If there is no encryption key, encryption and decryption is
         * unsupported.</p>
         * 
         * <p>If there is no signature key, signing and verification is
         * unsupported.</p>
         * 
         * <p>If there is no wrapping key, wrap and unwrap is unsupported.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {string} id the key set identity.
         * @param {SecretKey} encryptionKey the key used for encryption/decryption.
         * @param {SecretKey} signatureKey the key used for HMAC or CMAC computation.
         * @param {SecretKey} wrapKey the key used for wrap/unwrap.
         * @throws MslCryptoException if the encryption key length is unsupported.
         */
        init: function init(ctx, id, encryptionKey, signatureKey, wrapKey) {
            init.base.call(this);

            encryptionKey = encryptionKey && encryptionKey.rawKey;
            signatureKey = signatureKey && signatureKey.rawKey;
            wrapKey = wrapKey && wrapKey.rawKey;

            // The properties.
            var props = {
                ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                id: { value: id, writable: false, enumerable: false, configurable: false },
                encryptionKey: { value: encryptionKey, writable: false, enumerable: false, configurable: false },
                signatureKey: { value: signatureKey, writable: false, enumerable: false, configurable: false },
                wrapKey: { value: wrapKey, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        encrypt: function encrypt(data, encoder, format, callback) {
            var self = this;

            AsyncExecutor(callback, function() {
                if (!this.encryptionKey)
                    throw new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED, "no encryption/decryption key");
                if (data.length == 0)
                    return data;

                // Generate IV.
                var iv = new Uint8Array(16);
                this.ctx.getRandom().nextBytes(iv);

                var oncomplete = function(ciphertext) {
                    // Return ciphertext envelope byte representation.
                    MslCiphertextEnvelope.create(self.id, iv, new Uint8Array(ciphertext), {
                        result: function(envelope) {
                            envelope.toMslEncoding(encoder, format, {
                                result: callback.result,
                                error: function(e) {
                                    if (e instanceof MslEncoderException)
                                        e = new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_ENCODE_ERROR, null, e);
                                    callback.error(e);
                                },
                            });
                        },
                        error: function(e) {
                            if (!(e instanceof MslException))
                                e = new MslCryptoException(MslError.ENCRYPT_ERROR, null, e);
                            callback.error(e);
                        }
                    });
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.ENCRYPT_ERROR, null, e));
                };
                MslCrypto['encrypt']({ 'name': WebCryptoAlgorithm.AES_CBC['name'], 'iv': iv }, self.encryptionKey, data)
                    .then(oncomplete, onerror);
            }, this);
        },

        /** @inheritDoc */
        decrypt: function decrypt(data, encoder, callback) {
            var self = this;

            AsyncExecutor(callback, function() {
                if (!this.encryptionKey)
                    throw new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED, "no encryption/decryption key");
                if (data.length == 0)
                    return data;

                // Reconstitute ciphertext envelope.
                var encryptionEnvelopeMo;
                try {
                    encryptionEnvelopeMo = encoder.parseObject(data);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR, null, e);
                    throw new MslCryptoException(MslError.DECRYPT_ERROR, null, e);
                }

                MslCiphertextEnvelope.parse(encryptionEnvelopeMo, MslCiphertextEnvelope.Version.V1, {
                    result: function(envelope) {
                        try {
                            // Decrypt ciphertext.
                            var oncomplete = function(plaintext) {
                                callback.result(new Uint8Array(plaintext));
                            };
                            var onerror = function(e) {
                                callback.error(new MslCryptoException(MslError.DECRYPT_ERROR, null, e));
                            };
                            MslCrypto['decrypt']({ 'name': WebCryptoAlgorithm.AES_CBC['name'], 'iv': envelope.iv }, self.encryptionKey, envelope.ciphertext)
                                .then(oncomplete, onerror);
                        } catch (e) {
                            if (!(e instanceof MslException))
                                callback.error(new MslCryptoException(MslError.DECRYPT_ERROR, null, e));
                            else
                                callback.error(e);
                        }
                    },
                    error: function(e) {
                        if (e instanceof MslEncodingException)
                            e = new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_ENCODE_ERROR, null, e);
                        if (!(e instanceof MslException))
                            e = new MslCryptoException(MslError.DECRYPT_ERROR, null, e);
                        callback.error(e);
                    },
                });
            }, this);
        },

        /** @inheritDoc */
        wrap: function wrap(key, encoder, format, callback) {
            AsyncExecutor(callback, function() {
                if (!this.wrapKey)
                    throw new MslCryptoException(MslError.WRAP_NOT_SUPPORTED, "no wrap/unwrap key");

                var oncomplete = function(result) {
                    callback.result(new Uint8Array(result));
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.WRAP_ERROR, null, e));
                };
                MslCrypto['wrapKey']('raw', key.rawKey, this.wrapKey, this.wrapKey.algorithm)
                    .then(oncomplete, onerror);
            }, this);
        },

        /** @inheritDoc */
        unwrap: function unwrap(data, algo, usages, encoder, callback) {
            AsyncExecutor(callback, function() {
                if (!this.wrapKey)
                    throw new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED, "no wrap/unwrap key");
                var oncomplete = function(result) {
                    constructKey(result);
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.UNWRAP_ERROR, null, e));
                };
                MslCrypto['unwrapKey']('raw', data, this.wrapKey, this.wrapKey.algorithm, algo, false, usages)
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
            var self = this;
            AsyncExecutor(callback, function() {
                if (!this.signatureKey)
                    throw new MslCryptoException(MslError.SIGN_NOT_SUPPORTED, "no signature key.");
                
                // Compute the hash.
                var oncomplete = function(hash) {
                    AsyncExecutor(callback, function() {
                        // Return the signature envelope byte representation.
                        MslSignatureEnvelope.create(new Uint8Array(hash), {
                            result: function(envelope) {
                            	envelope.getBytes(encoder, format, {
                            		result: callback.result,
                            		error: function(e) {
                            			AsyncExecutor(callback, function() {
		                                    if (e instanceof MslEncoderException)
		                                        e = new MslCryptoException(MslError.SIGNATURE_ENVELOPE_ENCODE_ERROR, null, e);
		                                    callback.error(e);
                            			}, self);
                            		},
                                });
                            },
                            error: callback.error,
                        });
                    }, self);
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.HMAC_ERROR, null, e));
                };
                MslCrypto['sign'](this.signatureKey.algorithm, this.signatureKey, data)
                    .then(oncomplete, onerror);
            }, this);
        },

        /** inheritDoc */
        verify: function verify(data, signature, encoder, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                if (!this.signatureKey)
                    throw new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED, "no signature key.");

                // Reconstitute the signature envelope.
                MslSignatureEnvelope.parse(signature, MslSignatureEnvelope.Version.V1, encoder, {
                    result: function(envelope) {
                        AsyncExecutor(callback, function() {
                            // Verify the hash.
                            var oncomplete = callback.result;
                            var onerror = function(e) {
                                callback.error(new MslCryptoException(MslError.HMAC_ERROR, null, e));
                            };
                            MslCrypto['verify'](this.signatureKey.algorithm, this.signatureKey, envelope.signature, data)
                                .then(oncomplete, onerror);
                        }, self);
                    },
                    error: callback.error
                });
            }, this);
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SymmetricCryptoContext'));
