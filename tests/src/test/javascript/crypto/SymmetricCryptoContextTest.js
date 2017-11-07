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
 * Symmetric crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("SymmetricCryptoContext", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var Random = require('msl-core/util/Random.js');
    var SecretKey = require('msl-core/crypto/SecretKey.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var SymmetricCryptoContext = require('msl-core/crypto/SymmetricCryptoContext.js');
    var MslCiphertextEnvelope = require('msl-core/crypto/MslCiphertextEnvelope.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
	/** Key set ID. */
    var KEYSET_ID = "keysetid";
    /** Key ciphertext. */
    var KEY_CIPHERTEXT = "ciphertext";
    
    /** Crypto context key ID. */
    var KEY_ID = "keyId";
    /** AES-128 CBC key. */
    var AES_128_KEY;
    /** AES-128 CMAC key. */
    var AES_CMAC_KEY;
    /** AES-128 symmetric crypto context. */
    var SYMMETRIC_CRYPTO_CONTEXT;
    
    /** MSL Context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Random. */
    var random = new Random();
    
    /** Plaintext data. */
    var data = new Uint8Array(128);
    random.nextBytes(data);
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                var aes128Bytes = new Uint8Array(16);
                random.nextBytes(aes128Bytes);
                SecretKey.import(aes128Bytes, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(k) { AES_128_KEY = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                /* TODO AES-CMAC is not supported by any browsers yet. We need to check
                 * based on the MslCrypto$WebCryptoVersion, once it is supported.
                SecretKey$import(aes128Bytes, WebCryptoAlgorithm.AES_CMAC, WebCryptoUsage.SIGN_VERIFY, {
                    result: function(k) { AES_CMAC_KEY = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                */
                AES_CMAC_KEY = true;
                
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return AES_128_KEY && AES_CMAC_KEY && ctx; }, "static initialization", MslTestConstants.TIMEOUT_CTX);
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                SYMMETRIC_CRYPTO_CONTEXT = new SymmetricCryptoContext(ctx, KEY_ID, AES_128_KEY, null, null);
                initialized = true;
            });
        }
    });
    
    function cryptoKeys() {
        var params = [];
        params.push([ 1 ]);
        /* TODO AES-CMAC is not supported by any browsers yet. We need to check
         * based on the MslCrypto$WebCryptoVersion, once it is supported.
        params.push([ 2 ]);
        */
        return params;
    }

    parameterize("Parameterized", cryptoKeys, function(keyset) {
        var cryptoContext;
        beforeEach(function() {
            if (!cryptoContext) {
                var encryptionKey, signatureKey, wrappingKey;
                switch (keyset) {
                    case 1:
                        encryptionKey = MockPresharedAuthenticationFactory.KPE;
                        signatureKey = MockPresharedAuthenticationFactory.KPH;
                        wrappingKey = MockPresharedAuthenticationFactory.KPW;
                        break;
                    case 2:
                        encryptionKey = MockPresharedAuthenticationFactory.KPE;
                        signatureKey = AES_CMAC_KEY;
                        wrappingKey = MockPresharedAuthenticationFactory.KPW;
                        break;
                    default:
                        throw new Error("Key set " + keyset + " is not configured.");
                }
                cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, encryptionKey, signatureKey, wrappingKey);
            }
        });

        it("encrypt/decrypt", function() {
            var messageA = new Uint8Array(32);
            random.nextBytes(messageA);

            var messageB = new Uint8Array(32);
            random.nextBytes(messageB);

            var ciphertextA, ciphertextB;
            runs(function() {
                cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertextA = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertextB = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ciphertextA && ciphertextB; }, "ciphertext", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(ciphertextA).not.toBeNull();
                expect(ciphertextA).not.toEqual(messageA);
                expect(ciphertextB).not.toBeNull();
                expect(ciphertextB).not.toEqual(messageB);
                expect(ciphertextA).not.toEqual(ciphertextB);
            });

            var plaintextA, plaintextB;
            runs(function() {
                cryptoContext.decrypt(ciphertextA, encoder, {
                    result: function(p) { plaintextA = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                cryptoContext.decrypt(ciphertextB, encoder, {
                    result: function(p) { plaintextB = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return plaintextA && plaintextB; }, "plaintext", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(plaintextA).not.toBeNull();
                expect(plaintextA).toEqual(messageA);
                expect(plaintextB).not.toBeNull();
                expect(plaintextB).toEqual(messageB);
            });
        });

        it("invalid ciphertext", function() {
            var message = new Uint8Array(32);
            random.nextBytes(message);

            var ciphertext;
            runs(function() {
                cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT);

            var envelope;
            runs(function() {
                var envelopeMo = encoder.parseObject(ciphertext);
                MslCiphertextEnvelope.parse(envelopeMo, null, {
                    result: function(e) { envelope = e; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var shortEnvelope;
            runs(function() {
                var ciphertext = envelope.ciphertext;
                ++ciphertext[ciphertext.length / 2];
                ++ciphertext[ciphertext.length - 1];
                MslCiphertextEnvelope.create(envelope.keyId, envelope.iv, ciphertext, {
                    result: function(e) { shortEnvelope = e; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return shortEnvelope; }, "short envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                shortEnvelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                cryptoContext.decrypt(encode, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; },
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.DECRYPT_ERROR));
            });
        });

        it("insufficient ciphertext", function() {
            var message = new Uint8Array(32);
            random.nextBytes(message);

            var ciphertext;
            runs(function() {
                cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT);

            var envelope;
            runs(function() {
                var envelopeMo = encoder.parseObject(ciphertext);
                MslCiphertextEnvelope.parse(envelopeMo, null, {
                    result: function(x) { envelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return envelope; }, "envelope", MslTestConstants.TIMEOUT);

            var shortEnvelope;
            runs(function() {
                var ciphertext = envelope.ciphertext;
                ciphertext = new Uint8Array(ciphertext.buffer, 0, ciphertext.length / 2);
                MslCiphertextEnvelope.create(envelope.keyId, envelope.iv, ciphertext, {
                    result: function(x) { shortEnvelope = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return shortEnvelope; }, "short envelope", MslTestConstants.TIMEOUT);
            
            var encode;
            runs(function() {
                shortEnvelope.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                cryptoContext.decrypt(encode, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.DECRYPT_ERROR));
            });
        });

        it("not envelope", function() {
            var message = new Uint8Array(32);
            random.nextBytes(message);

            var ciphertext;
            runs(function() {
                cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT);

            var encode;
            runs(function() {
                var envelopeMo = encoder.parseObject(ciphertext);
                envelopeMo.remove(KEY_CIPHERTEXT);
                encoder.encodeObject(envelopeMo, ENCODER_FORMAT, {
                	result: function(x) { encode = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                cryptoContext.decrypt(encode, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; },
                });
            });

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_ENCODE_ERROR));
            });
        });

        it("corrupt envelope", function() {
            var message = new Uint8Array(32);
            random.nextBytes(message);

            var ciphertext;
            runs(function() {
                cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                ciphertext[0] = 0;
                cryptoContext.decrypt(ciphertext, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR));
            });
        });

        it("encrypt/decrypt with null encryption key", function() {
            var cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, null, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPE_WRAP);

            var message = new Uint8Array(32);
            random.nextBytes(message);

            var exception;
            runs(function() {
                cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function() {},
                    error: function(e) { exception = e; },
                });
            });

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED));
            });
        });

        it("encrypt/decrypt with null keys", function() {
            var cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, null, null);

            var messageA = new Uint8Array(32);
            random.nextBytes(messageA);

            var messageB = new Uint8Array(32);
            random.nextBytes(messageB);

            var ciphertextA, ciphertextB;
            runs(function() {
                cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertextA = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertextB = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ciphertextA && ciphertextB; }, "ciphertext", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(ciphertextA).not.toBeNull();
                expect(ciphertextA).not.toEqual(messageA);
                expect(ciphertextB).not.toBeNull();
                expect(ciphertextB).not.toEqual(messageB);
                expect(ciphertextA).not.toEqual(ciphertextB);
            });

            var plaintextA, plaintextB;
            runs(function() {
                cryptoContext.decrypt(ciphertextA, encoder, {
                    result: function(p) { plaintextA = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                cryptoContext.decrypt(ciphertextB, encoder, {
                    result: function(p) { plaintextB = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintextA && plaintextB; }, "plaintext", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(plaintextA).not.toBeNull();
                expect(plaintextA).toEqual(messageA);
                expect(plaintextB).not.toBeNull();
                expect(plaintextB).toEqual(messageB);
            });
        });

        it("encrypt/decrypt with mismatched ID", function() {
            var cryptoContextA = new SymmetricCryptoContext(ctx, KEYSET_ID + "A", MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
            var cryptoContextB = new SymmetricCryptoContext(ctx, KEYSET_ID + "B", MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);

            var message = new Uint8Array(32);
            random.nextBytes(message);

            var ciphertext;
            runs(function() {
                cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT);

            var plaintext;
            runs(function() {
            	expect(ciphertext).not.toBeNull();
            	expect(ciphertext).not.toEqual(message);
            	
                cryptoContextB.decrypt(ciphertext, encoder, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

            runs(function() {
            	expect(plaintext).not.toBeNull();
            	expect(plaintext).toEqual(message);
            });
        });

        it("encrypt/decrypt keys mismatched", function() {
            var cryptoContextA = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
            var cryptoContextB = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE2, MockPresharedAuthenticationFactory.KPH2, MockPresharedAuthenticationFactory.KPW2);

            var message = new Uint8Array(32);
            random.nextBytes(message);

            var ciphertext;
            runs(function() {
                cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                cryptoContextB.decrypt(ciphertext, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; },
                });
            });
            waitsFor(function() { return exception; }, "exception", 200);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.DECRYPT_ERROR));
            });
        });

        it("wrap/unwrap", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped", MslTestConstants.TIMEOUT);

            var unwrapped;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(AES_128_KEY.toByteArray());
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
                    result: function(key) { unwrapped = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unwrapped; }, "unwrapped", MslTestConstants.TIMEOUT);

            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var wrapCryptoContext, refCiphertext, wrapCiphertext;
            runs(function() {
                wrapCryptoContext = new SymmetricCryptoContext(ctx, KEY_ID, unwrapped, null, null);
                SYMMETRIC_CRYPTO_CONTEXT.encrypt(data, encoder, ENCODER_FORMAT, {
                    result: function(x) { refCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.encrypt(data, encoder, ENCODER_FORMAT, {
                    result: function(x) { wrapCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refCiphertext && wrapCiphertext; }, "ciphertexts", MslTestConstants.TIMEOUT);
            var refPlaintext, wrapPlaintext;
            runs(function() {
                SYMMETRIC_CRYPTO_CONTEXT.decrypt(wrapCiphertext, encoder, {
                    result: function(x) { refPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.decrypt(refCiphertext, encoder, {
                    result: function(x) { wrapPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refPlaintext && wrapPlaintext; }, "plaintexts", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(wrapPlaintext).toEqual(refPlaintext);
            });
        });

        it("wrap/unwrap with mismatched contexts", function() {
            var cryptoContextA = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
            var cryptoContextB = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE2, MockPresharedAuthenticationFactory.KPH2, MockPresharedAuthenticationFactory.KPW2);

            var wrapped;
            runs(function() {
                cryptoContextA.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(AES_128_KEY.toByteArray());
                cryptoContextB.unwrap(wrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_ERROR));
            });
        });

        it("wrap with null wrap key", function() {
            var cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, null);

            var exception;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.WRAP_NOT_SUPPORTED));
            });
        });

        it("unwrap with null wrap key", function() {
            var cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, null);

            var exception;
            runs(function() {
                cryptoContext.unwrap(AES_128_KEY, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED));
            });
        });

        it("sign/verify", function() {
            var cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);

            var messageA = new Uint8Array(32);
            random.nextBytes(messageA);

            var messageB = new Uint8Array(32);
            random.nextBytes(messageB);

            var signatureA, signatureB;
            runs(function() {
                cryptoContext.sign(messageA, encoder, ENCODER_FORMAT, {
                    result: function(s) { signatureA = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                cryptoContext.sign(messageB, encoder, ENCODER_FORMAT, {
                    result: function(s) { signatureB = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signatureA && signatureB; }, "signature", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(signatureA).not.toBeNull();
                expect(signatureA.length).toBeGreaterThan(0);
                expect(signatureA).not.toEqual(messageA);
                expect(signatureB.length).toBeGreaterThan(0);
                expect(signatureB).not.toEqual(signatureA);
            });

            var verifiedAA, verifiedBB, verifiedBA;
            runs(function() {
                cryptoContext.verify(messageA, signatureA, encoder, {
                    result: function(v) { verifiedAA = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                cryptoContext.verify(messageB, signatureB, encoder, {
                    result: function(v) { verifiedBB = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                cryptoContext.verify(messageB, signatureA, encoder, {
                    result: function(v) { verifiedBA = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return verifiedAA !== undefined && verifiedBB !== undefined && verifiedBA !== undefined; }, "verified", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(verifiedAA).toBeTruthy();
                expect(verifiedBB).toBeTruthy();
                expect(verifiedBA).toBeFalsy();
            });
        });

        it("sign/verify with mismatched contexts", function() {
            var cryptoContextA = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
            var cryptoContextB = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE2, MockPresharedAuthenticationFactory.KPH2, MockPresharedAuthenticationFactory.KPW2);

            var message = new Uint8Array(32);
            random.nextBytes(message);

            var signature;
            runs(function() {
                cryptoContextA.sign(message, encoder, ENCODER_FORMAT, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);

            var verified;
            runs(function() {
                cryptoContextB.verify(message, signature, encoder, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(verified).toBeFalsy();
            });
        });

        it("sign/verify with null keys", function() {
            var cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, null, MockPresharedAuthenticationFactory.KPH, null);

            var messageA = new Uint8Array(32);
            random.nextBytes(messageA);

            var messageB = new Uint8Array(32);
            random.nextBytes(messageB);

            var signatureA, signatureB;
            runs(function() {
                cryptoContext.sign(messageA, encoder, ENCODER_FORMAT, {
                    result: function(s) { signatureA = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                cryptoContext.sign(messageB, encoder, ENCODER_FORMAT, {
                    result: function(s) { signatureB = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signatureA && signatureB; }, "signature", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(signatureA).not.toBeNull();
                expect(signatureA.length).toBeGreaterThan(0);
                expect(signatureA).not.toEqual(messageA);
                expect(signatureB.length).toBeGreaterThan(0);
                expect(signatureB).not.toEqual(signatureA);
            });

            var verifiedAA, verifiedBB, verifiedBA;
            runs(function() {
                cryptoContext.verify(messageA, signatureA, encoder, {
                    result: function(v) { verifiedAA = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                cryptoContext.verify(messageB, signatureB, encoder, {
                    result: function(v) { verifiedBB = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                cryptoContext.verify(messageB, signatureA, encoder, {
                    result: function(v) { verifiedBA = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return verifiedAA !== undefined && verifiedBB !== undefined && verifiedBA !== undefined; }, "verified", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(verifiedAA).toBeTruthy();
                expect(verifiedBB).toBeTruthy();
                expect(verifiedBA).toBeFalsy();
            });
        });

        it("sign with null HMAC key", function() {
            var cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, null, MockPresharedAuthenticationFactory.KPW);

            var messageA = new Uint8Array(32);
            random.nextBytes(messageA);

            var exception;
            runs(function() {
                cryptoContext.sign(messageA, encoder, ENCODER_FORMAT, {
                    result: function() {},
                    error: function(e) { exception = e; },
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.SIGN_NOT_SUPPORTED));
            });
        });
    });
});
