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
 * <p>An RSA crypto context supports RSA/ECB/OAEPPadding or RSA/ECB/PKCS#1
 * encryption/decryption or wrap/unwrap, or SHA-256 with RSA sign/verify.</p>
 * 
 * <p>The {@link OAEPParameterSpec#DEFAULT} parameters are used for OAEP
 * encryption and decryption.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 * @implements {ICryptoContext}
 */
(function(require, module) {
    "use strict";
    
    var ICryptoContext = require('../crypto/ICryptoContext.js');
    var WebCryptoAlgorithm = require('../crypto/WebCryptoAlgorithm.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var MslCryptoException = require('../MslCryptoException.js');
    var MslEncoderException = require('../io/MslEncoderException.js');
    var MslException = require('../MslException.js');
    var MslError = require('../MslError.js');
    var MslCrypto = require('../crypto/MslCrypto.js');
    var MslSignatureEnvelope = require('../crypto/MslSignatureEnvelope.js');
    var SecretKey = require('../crypto/SecretKey.js');
    var PublicKey = require('../crypto/PublicKey.js');
    var PrivateKey = require('../crypto/PrivateKey.js');
    var MslEncodingException = require('../MslEncodingException.js');
    var MslCiphertextEnvelope = require('../crypto/MslCiphertextEnvelope.js');

    /**
     * Null transform or algorithm.
     * @const
     * @type {String}
     */
    var NULL_OP = "nullOp";

    /**
     * RSA crypto context mode.
     * @enum
     */
    var Mode = {
        /** RSA-OAEP encrypt/decrypt */
        ENCRYPT_DECRYPT_OAEP: 1,
        /** RSA PKCS#1 encrypt/decrypt */
        ENCRYPT_DECRYPT_PKCS1: 2,
        /** RSA-OAEP wrap/unwrap */
        WRAP_UNWRAP_OAEP: 3,
        /** RSA PKCS#1 wrap/unwrap */
        WRAP_UNWRAP_PKCS1: 4,
        /** RSA-SHA256 sign/verify */
        SIGN_VERIFY: 5
    };

    var RsaCryptoContext = module.exports = ICryptoContext.extend({
        /**
         * <p>Create a new RSA crypto context for encrypt/decrypt and sign/verify
         * using the provided public and private keys. The crypto context mode
         * identifies the operations to enable. All other operations are no-ops and
         * return the data unmodified. (Wrap/unwrap cannot return the data
         * unmodified and instead throws a {@link MslCryptoException} indicating
         * the operation is unsupported.</p>
         *
         * <p>If there is no private key decryption, unwrapping, and signing is
         * unsupported.</p>
         *
         * <p>If there is no public key encryption, wrapping, and verification is
         * unsupported.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {String} id the key pair identity.
         * @param {PrivateKey} privateKey the private key. May be null.
         * @param {PublicKey} publicKey the public key. May be null.
         * @param {Mode} mode crypto context mode.
         * @constructor
         */
        init: function init(ctx, id, privateKey, publicKey, mode) {
            init.base.call(this);

            // Extract actual RSA keys.
            if (privateKey)
                privateKey = privateKey.rawKey;
            if (publicKey)
                publicKey = publicKey.rawKey;

            var transform;
            if (mode == Mode.ENCRYPT_DECRYPT_PKCS1) {
                transform = WebCryptoAlgorithm.RSAES;
            } else if (mode == Mode.ENCRYPT_DECRYPT_OAEP) {
                transform = WebCryptoAlgorithm.RSA_OAEP;
            } else {
                transform = NULL_OP;
            }
            var wrapTransform;
            if (mode == Mode.WRAP_UNWRAP_PKCS1) {
                wrapTransform = WebCryptoAlgorithm.RSAES;
            } else if (mode == Mode.WRAP_UNWRAP_OAEP) {
                wrapTransform = WebCryptoAlgorithm.RSA_OAEP;
            } else {
                wrapTransform = NULL_OP;
            }
            var algo = (mode == Mode.SIGN_VERIFY) ? WebCryptoAlgorithm.RSASSA_SHA256 : NULL_OP;

            // The properties.
            var props = {
                id: { value: id, writable: false, enumerable: false, configurable: false },
                privateKey: { value: privateKey, writable: false, enumerable: false, configurable: false },
                publicKey: { value: publicKey, writable: false, enumerable: false, configurable: false },
                transform: { value: transform, writable: false, enumerable: false, configurable: false },
                wrapTransform: { value: wrapTransform, writable: false, enumerable: false, configurable: false },
                algo: { value: algo, writable: false, enumerable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        encrypt: function encrypt(data, encoder, format, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                if (this.transform == NULL_OP)
                    return data;
                if (!this.publicKey)
                    throw new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED, "no public key");
                if (data.length == 0)
                    return data;

                var oncomplete = function(ciphertext) {
                    // Return ciphertext envelope byte representation.
                    MslCiphertextEnvelope.create(self.id, null, new Uint8Array(ciphertext), {
                        result: function (envelope) {
                            envelope.toMslEncoding(encoder, format, {
                                result: callback.result,
                                error: function(e) {
                                    if (e instanceof MslEncoderException)
                                        e = new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_ENCODE_ERROR, null, e);
                                    callback.error(e);
                                }
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
                MslCrypto['encrypt'](self.transform, self.publicKey, data)
                    .then(oncomplete, onerror);
            }, this);
        },

        /** @inheritDoc */
        decrypt: function decrypt(data, encoder, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                if (this.transform == NULL_OP)
                    return data;
                if (!this.privateKey)
                    throw new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED, "no private key");
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
                            MslCrypto['decrypt'](self.transform, self.privateKey, envelope.ciphertext)
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
                    }
                });
            }, this);
        },

        /** @inheritDoc */
        wrap: function wrap(key, encoder, format, callback) {
            AsyncExecutor(callback, function() {
                if (this.wrapTransform == NULL_OP || !this.publicKey)
                    throw new MslCryptoException(MslError.WRAP_NOT_SUPPORTED, "no public key");

                var oncomplete = function(result) {
                    callback.result(new Uint8Array(result));
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.WRAP_ERROR, null, e));
                };
                // Use the transform instead of the wrap key algorithm in case
                // the key algorithm is missing some fields.
                MslCrypto['wrapKey']('jwk', key.rawKey, this.publicKey, this.wrapTransform)
                    .then(oncomplete, onerror);
            }, this);
        },

        /** @inheritDoc */
        unwrap: function unwrap(data, algo, usages, encoder, callback) {
            AsyncExecutor(callback, function() {
                if (this.wrapTransform == NULL_OP || !this.privateKey)
                    throw new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED, "no private key");

                var oncomplete = constructKey;
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.UNWRAP_ERROR, null, e));
                };
                // Use the transform instead of the wrap key algorithm in case
                // the key algorithm is missing some fields.
                MslCrypto['unwrapKey']('jwk', data, this.privateKey, this.wrapTransform, algo, false, usages)
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
            AsyncExecutor(callback, function() {
                if (this.algo == NULL_OP)
                    return new Uint8Array(0);
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
                                        e = new MslCryptoException(MslError.SIGNATURE_ENVELOPE_ENCODE_ERROR, null, e);
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
                MslCrypto['sign'](this.algo, this.privateKey, data)
                    .then(oncomplete, onerror);
            }, this);
        },

        /** @inheritDoc */
        verify: function verify(data, signature, encoder, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                if (this.algo == NULL_OP)
                    return true;
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
                            MslCrypto['verify'](this.algo, this.publicKey, envelope.signature, data)
                                .then(oncomplete, onerror);
                        }, self);
                    },
                    error: callback.error
                });
            }, this);
        }
    });
    
    // Exports.
    module.exports.Mode = Mode;
})(require, (typeof module !== 'undefined') ? module : mkmodule('RsaCryptoContext'));
