/**
 * Copyright (c) 2013-2018 Netflix, Inc.  All rights reserved.
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
 * JSON Web Encryption crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
// Do not run these tests unless using legacy Web Crypto.
describe("JsonWebEncryptionCryptoContext", function() {
    var MslCrypto = require('msl-core/crypto/MslCrypto.js');
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var JsonWebEncryptionCryptoContext = require('msl-core/crypto/JsonWebEncryptionCryptoContext.js');
    var Random = require('msl-core/util/Random.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var SecretKey = require('msl-core/crypto/SecretKey.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var SymmetricCryptoContext = require('msl-core/crypto/SymmetricCryptoContext.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslError = require('msl-core/MslError.js');
    var Base64 = require('msl-core/util/Base64.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    
// Do nothing unless executing in the legacy Web Crypto environment.
if (MslCrypto.getWebCryptoVersion() == MslCrypto.WebCryptoVersion.LEGACY) {
    /** Encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** JSON key recipients. */
    var KEY_RECIPIENTS = "recipients";
    /** JSON key header. */
    var KEY_HEADER = "header";
    /** JSON key encrypted key. */
    var KEY_ENCRYPTED_KEY = "encrypted_key";
    /** JSON key integrity value. */
    var KEY_INTEGRITY_VALUE = "integrity_value";
    /** JSON key initialization vector. */
    var KEY_INITIALIZATION_VECTOR = "initialization_vector";
    /** JSON key ciphertext. */
    var KEY_CIPHERTEXT = "ciphertext";
    
    /** JSON key wrap algorithm. */
    var KEY_ALGORITHM = "alg";
    /** JSON key encryption algorithm. */
    var KEY_ENCRYPTION = "enc";
    
    /**
     * Return the requested value of the provided JSON serialization.
     * 
     * @param {Uint8Array} serialization JSON serialization.
     * @param {string} key Key.
     * @return {string} the requested Base64-encoded value.
     * @throws JSONException if there is an error parsing the serialization.
     */
    function get(serialization, key) {
        var serializationJo = JSON.parse(TextEncoding.getString(serialization, TextEncoding.Encoding.UTF_8));
        var recipients = serializationJo[KEY_RECIPIENTS];
        var recipient = recipients[0];
        switch (key) {
            case KEY_HEADER:
            case KEY_ENCRYPTED_KEY:
            case KEY_INTEGRITY_VALUE:
                return recipient[key];
            case KEY_INITIALIZATION_VECTOR:
            case KEY_CIPHERTEXT:
                return serializationJo[key];
            default:
                throw new Error("Unknown Key: " + key);
        }
    }
    
    /**
     * Replace one part of the provided JSON serialization with a specified
     * value.
     * 
     * @param {Uint8Array} serialization JSON serialization.
     * @param {string} key Key.
     * @param {*} value replacement value.
     * @return {Uint8Array} the modified JSON serialization.
     * @throws JSONException if there is an error modifying the JSON
     *         serialization.
     */
    function replace(serialization, key, value) {
        var serializationJo = JSON.parse(TextEncoding.getString(serialization, TextEncoding.Encoding.UTF_8));
        var recipients = serializationJo[KEY_RECIPIENTS];
        var recipient = recipients[0];
        switch (key) {
            case KEY_RECIPIENTS:
                // Return immediately after replacing because this creates a
                // malformed serialization.
                serializationJo[KEY_RECIPIENTS] = value;
                return TextEncoding.getBytes(JSON.stringify(serializationJo), TextEncoding.Encoding.UTF_8);
            case KEY_HEADER:
                recipient[KEY_HEADER] = value;
                break;
            case KEY_ENCRYPTED_KEY:
                recipient[KEY_ENCRYPTED_KEY] = value;
                break;
            case KEY_INTEGRITY_VALUE:
                recipient[KEY_INTEGRITY_VALUE] = value;
                break;
            case KEY_INITIALIZATION_VECTOR:
                serializationJo[KEY_INITIALIZATION_VECTOR] = value;
                break;
            case KEY_CIPHERTEXT:
                serializationJo[KEY_CIPHERTEXT] = value;
                break;
            default:
                throw new Error("Unknown Key: " + key);
        }
        recipients[0] = recipient;
        serializationJo[KEY_RECIPIENTS] = recipients;
        return TextEncoding.getBytes(JSON.stringify(serializationJo), TextEncoding.Encoding.UTF_8);
    }
    
    /**
     * Remove one part of the provided JSON serialization.
     * 
     * @param {Uint8Array} serialization JSON serialization.
     * @param {String} key Key.
     * @return {Uint8Array} the modified JSON serialization.
     * @throws JSONException if there is an error modifying the JSON
     *         serialization.
     */
    function remove(serialization, key) {
        var serializationJo = JSON.parse(TextEncoding.getString(serialization, TextEncoding.Encoding.UTF_8));
        var recipients = serializationJo[KEY_RECIPIENTS];
        var recipient = recipients[0];
        switch (key) {
            case KEY_RECIPIENTS:
                // Return immediately after removing because this creates a
                // malformed serialization.
                delete serializationJo[KEY_RECIPIENTS];
                return TextEncoding.getBytes(JSON.stringify(serializationJo), TextEncoding.Encoding.UTF_8);
            case KEY_HEADER:
                delete recipient[KEY_HEADER];
                break;
            case KEY_ENCRYPTED_KEY:
                delete recipient[KEY_ENCRYPTED_KEY];
                break;
            case KEY_INTEGRITY_VALUE:
                delete recipient[KEY_INTEGRITY_VALUE];
                break;
            case KEY_INITIALIZATION_VECTOR:
                delete serializationJo[KEY_INITIALIZATION_VECTOR];
                break;
            case KEY_CIPHERTEXT:
                delete serializationJo[KEY_CIPHERTEXT];
                break;
            default:
                throw new Error("Unknown key: " + key);
        }
        recipients[0] = recipient;
        serializationJo[KEY_RECIPIENTS] = recipients;
        return TextEncoding.getBytes(JSON.stringify(serializationJo), TextEncoding.Encoding.UTF_8);
    }
    
    // Shortcuts.
    var Algorithm = JsonWebEncryptionCryptoContext.Algorithm;
    var Encryption = JsonWebEncryptionCryptoContext.Encryption;
    
    /** Crypto context key ID. */
    var KEY_ID = "keyId";
    /** AES-128 key. */
    var AES_128_KEY;
    /** HMAC-SHA256 key. */
    var HMAC_256_KEY;
    /** AES-128 HMAC-SHA256 AES-KW symmetric crypto context. */
    var SYMMETRIC_CRYPTO_CONTEXT;
    /** RSA-OAEP public key. */
    var RSA_PUBLIC_KEY;
    /** RSA-OAEP private key. */
    var RSA_PRIVATE_KEY;
    /** AES key wrap key. */
    var AES_WRAP_KEY;

    /** Random. */
    var random = new Random();
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Plaintext data. */
    var data = new Uint8Array(128);
    random.nextBytes(data);
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                
                var aes128Bytes = new Uint8Array(16);
                random.nextBytes(aes128Bytes);
                var hmac256Bytes = new Uint8Array(32);
                random.nextBytes(hmac256Bytes);
                SecretKey.import(aes128Bytes, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(k) { AES_128_KEY = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                SecretKey.import(hmac256Bytes, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function(k) { HMAC_256_KEY = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                
                MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSA_OAEP, WebCryptoUsage.WRAP_UNWRAP, 2048, {
                    result: function(publicKey, privateKey) {
                        RSA_PUBLIC_KEY = publicKey;
                        RSA_PRIVATE_KEY = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                
                var keydata = new Uint8Array(16);
                random.nextBytes(keydata);
                SecretKey.import(keydata, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                    result: function(key) { AES_WRAP_KEY = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx && AES_128_KEY && HMAC_256_KEY && RSA_PUBLIC_KEY && RSA_PRIVATE_KEY && AES_WRAP_KEY; }, "static initialization", MslTestConstants.TIMEOUT_CTX);
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                SYMMETRIC_CRYPTO_CONTEXT = new SymmetricCryptoContext(ctx, KEY_ID, AES_128_KEY, HMAC_256_KEY, null);
                initialized = true;
            });
        }
    });

    /** RSA-OAEP JSON serialization unit tests. */
    describe("RSA-OAEP JSON Serialization", function() {
        /** JWE crypto context. */
        var cryptoContext;
        beforeEach(function() {
            if (!cryptoContext)
                cryptoContext = new JsonWebEncryptionCryptoContext(ctx, Algorithm.RSA_OAEP, Encryption.A128GCM, RSA_PRIVATE_KEY, RSA_PUBLIC_KEY);
        });
        
        it("wrap/unwrap AES-128 key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var unwrapped;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(AES_128_KEY.toByteArray());
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
                    result: function(key) { unwrapped = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unwrapped; }, "unwrapped not received", MslTestConstants.TIMEOUT);
            
            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var wrapCryptoContext, refCiphertext, wrapCiphertext;
            runs(function() {
                wrapCryptoContext = new SymmetricCryptoContext(ctx, KEY_ID, unwrapped, null, null);
                SYMMETRIC_CRYPTO_CONTEXT.encrypt(data, {
                    result: function(x) { refCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.encrypt(data, {
                    result: function(x) { wrapCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refCiphertext && wrapCiphertext; }, "ciphertexts", MslTestConstants.TIMEOUT);
            var refPlaintext, wrapPlaintext;
            runs(function() {
                SYMMETRIC_CRYPTO_CONTEXT.decrypt(wrapCiphertext, {
                    result: function(x) { refPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.decrypt(refCiphertext, {
                    result: function(x) { wrapPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refPlaintext && wrapPlaintext; }, "plaintexts", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(wrapPlaintext).toEqual(refPlaintext);
            });
        });
        
        it("wrap/unwrap HMAC-SHA256 key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(HMAC_256_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            var unwrapped;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(HMAC_256_KEY.toByteArray());
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, encoder, {
                    result: function(key) { unwrapped = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unwrapped; }, "unwrapped not received", MslTestConstants.TIMEOUT);
         
            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var refHmac, wrapHmac;
            runs(function() {
                SYMMETRIC_CRYPTO_CONTEXT.sign(data, {
                    result: function(x) { refHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                var wrapCryptoContext = new SymmetricCryptoContext(ctx, KEY_ID, null, unwrapped, null);
                wrapCryptoContext.sign(data, {
                    result: function(x) { wrapHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refHmac && wrapHmac; }, "hmacs", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(wrapHmac).toEqual(refHmac);
            });
        });
        
        it("invalid serialization", function() {
            var exception;
            runs(function() {
                var wrapped = TextEncoding.getBytes("x", TextEncoding.Encoding.UTF_8);
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing recipients", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_RECIPIENTS);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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

        it("invalid recipients", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_RECIPIENTS, "x");
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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

        it("missing recipient", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_RECIPIENTS, []);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
        
        it("invalid recipient", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_RECIPIENTS, ['x']);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing header", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_HEADER);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid header", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing content encryption key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_ENCRYPTED_KEY);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid content encryption key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing initialization vector", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_INITIALIZATION_VECTOR);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid initialization vector", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing ciphertext", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_CIPHERTEXT);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid ciphertext", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_CIPHERTEXT, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing authentication tag", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_INTEGRITY_VALUE);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid authentication tag", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_INTEGRITY_VALUE, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 200);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_ERROR));
            });
        });
        
        it("wrong authentication tag", function() {
            var at = new Uint8Array(16);
            random.nextBytes(at);
            
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", 200);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_INTEGRITY_VALUE, Base64.encode(at, true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing algorithm", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT,{
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var headerB64 = get(wrapped, KEY_HEADER);
                var header = JSON.parse(TextEncoding.getString(Base64.decode(headerB64, true), TextEncoding.Encoding.UTF_8));
                expect(header[KEY_ALGORITHM]).not.toBeNull();
                delete header[KEY_ALGORITHM];
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode(header.toString(), true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid algorithm", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var headerB64 = get(wrapped, KEY_HEADER);
                var header = JSON.parse(TextEncoding.getString(Base64.decode(headerB64, true), TextEncoding.Encoding.UTF_8));
                header[KEY_ALGORITHM] = "x";
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode(TextEncoding.getBytes(header, TextEncoding.Encoding.UTF_8), true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing encryption", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var headerB64 = get(wrapped, KEY_HEADER);
                var header = JSON.parse(TextEncoding.getString(Base64.decode(headerB64, true), TextEncoding.Encoding.UTF_8));
                expect(header[KEY_ENCRYPTION]).not.toBeNull();
                delete header[KEY_ENCRYPTION];
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode(TextEncoding.getBytes(header, TextEncoding.Encoding.UTF_8), true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid encryption", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var headerB64 = get(wrapped, KEY_HEADER);
                var header = JSON.parse(TextEncoding.getString(Base64.decode(headerB64, true), TextEncoding.Encoding.UTF_8));
                header[KEY_ENCRYPTION] = "x";
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode(TextEncoding.getBytes(header, TextEncoding.Encoding.UTF_8), true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("bad content encryption key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var ecek = new Uint8Array(137);
                random.nextBytes(ecek);
                var badWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, Base64.encode(ecek, true));
                cryptoContext.unwrap(badWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("bad initialization vector", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var iv = new Uint8Array(31);
                random.nextBytes(iv);
                var badWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, Base64.encode(iv, true));
                cryptoContext.unwrap(badWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("wrong content encryption key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);

            var ecek;
            runs(function() {
                var cek = new Uint8Array(16);
                random.nextBytes(cek);
                SYMMETRIC_CRYPTO_CONTEXT.encrypt(cek, {
                    result: function(data) { ecek = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ecek; }, "ecek not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var wrongWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, Base64.encode(ecek, true));
                cryptoContext.unwrap(wrongWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("wrong initialization vector", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var iv = new Uint8Array(16);
                random.nextBytes(iv);
                var wrongWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, Base64.encode(iv, true));
                cryptoContext.unwrap(wrongWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    });
    
    /** AES key wrap JSON serialization unit tests. */
    describe("AES key wrap JSON serialization", function() {
        /** JWE crypto context. */
        var cryptoContext;
        beforeEach(function() {
            if (!cryptoContext)
                cryptoContext = new JsonWebEncryptionCryptoContext(ctx, Algorithm.A128KW, Encryption.A256GCM, AES_WRAP_KEY);
        });
        
        it("wrap/unwrap AES-128 key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            var unwrapped;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(AES_128_KEY.toByteArray());
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
                    result: function(key) { unwrapped = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unwrapped; }, "unwrapped not received", MslTestConstants.TIMEOUT);
         
            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var wrapCryptoContext, refCiphertext, wrapCiphertext;
            runs(function() {
                wrapCryptoContext = new SymmetricCryptoContext(ctx, KEY_ID, unwrapped, null, null);
                SYMMETRIC_CRYPTO_CONTEXT.encrypt(data, {
                    result: function(x) { refCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.encrypt(data, {
                    result: function(x) { wrapCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refCiphertext && wrapCiphertext; }, "ciphertexts", MslTestConstants.TIMEOUT);
            var refPlaintext, wrapPlaintext;
            runs(function() {
                SYMMETRIC_CRYPTO_CONTEXT.decrypt(wrapCiphertext, {
                    result: function(x) { refPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.decrypt(refCiphertext, {
                    result: function(x) { wrapPlaintext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refPlaintext && wrapPlaintext; }, "plaintexts", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(wrapPlaintext).toEqual(refPlaintext);
            });
        });
        
        it("wrap/unwrap HMAC-SHA256 key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(HMAC_256_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            var unwrapped;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(HMAC_256_KEY.toByteArray());
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
                    result: function(key) { unwrapped = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unwrapped; }, "unwrapped not received", MslTestConstants.TIMEOUT);
            
            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var refHmac, wrapHmac;
            runs(function() {
                SYMMETRIC_CRYPTO_CONTEXT.sign(data, {
                    result: function(x) { refHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                var wrapCryptoContext = new SymmetricCryptoContext(ctx, KEY_ID, null, unwrapped, null);
                wrapCryptoContext.sign(data, {
                    result: function(x) { wrapHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refHmac && wrapHmac; }, "hmacs", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(wrapHmac).toEqual(refHmac);
            });
        });
    
        it("invalid serialization", function() {
            var exception;
            runs(function() {
                var wrapped = TextEncoding.getBytes("x", TextEncoding.Encoding.UTF_8);
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
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
        
        it("missing recipients", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_RECIPIENTS);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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

        it("invalid recipients", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_RECIPIENTS, "x");
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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

        it("missing recipient", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_RECIPIENTS, []);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
        
        it("invalid recipient", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_RECIPIENTS, ['x']);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
        
        it("missing header", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_HEADER);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid header", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing content encryption key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);

            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_ENCRYPTED_KEY);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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

        it("invalid content encryption key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing initialization vector", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_INITIALIZATION_VECTOR);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid initialization vector", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing ciphertext", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_CIPHERTEXT);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid ciphertext", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_CIPHERTEXT, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing authentication tag", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = remove(wrapped, KEY_INTEGRITY_VALUE);
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid authentication tag", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_INTEGRITY_VALUE, Base64.encode("x", true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 200);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_ERROR));
            });
        });
        
        it("wrong authentication tag", function() {
            var at = new Uint8Array(16);
            random.nextBytes(at);
            
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", 200);
            
            var exception;
            runs(function() {
                var missingWrapped = replace(wrapped, KEY_INTEGRITY_VALUE, Base64.encode(at, true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing algorithm", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var headerB64 = get(wrapped, KEY_HEADER);
                var header = JSON.parse(TextEncoding.getString(Base64.decode(headerB64, true), TextEncoding.Encoding.UTF_8));
                expect(header[KEY_ALGORITHM]).not.toBeNull();
                delete header[KEY_ALGORITHM];
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode(TextEncoding.getBytes(header, TextEncoding.Encoding.UTF_8), true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid algorithm", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var headerB64 = get(wrapped, KEY_HEADER);
                var header = JSON.parse(TextEncoding.getString(Base64.decode(headerB64, true), TextEncoding.Encoding.UTF_8));
                header[KEY_ALGORITHM] = "x";
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode(TextEncoding.getBytes(header, TextEncoding.Encoding.UTF_8), true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("missing encryption", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var headerB64 = get(wrapped, KEY_HEADER);
                var header = JSON.parse(TextEncoding.getString(Base64.decode(headerB64, true), TextEncoding.Encoding.UTF_8));
                expect(header[KEY_ENCRYPTION]).not.toBeNull();
                delete header[KEY_ENCRYPTION];
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode(TextEncoding.getBytes(header, TextEncoding.Encoding.UTF_8), true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("invalid encryption", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var headerB64 = get(wrapped, KEY_HEADER);
                var header = JSON.parse(TextEncoding.getString(Base64.decode(headerB64, true), TextEncoding.Encoding.UTF_8));
                header[KEY_ENCRYPTION] = "x";
                var missingWrapped = replace(wrapped, KEY_HEADER, Base64.encode(TextEncoding.getBytes(header, TextEncoding.Encoding.UTF_8), true));
                cryptoContext.unwrap(missingWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("bad content encryption key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var ecek = new Uint8Array(137);
                random.nextBytes(ecek);
                var badWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, Base64.encode(ecek, true));
                cryptoContext.unwrap(badWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("bad initialization vector", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var iv = new Uint8Array(31);
                random.nextBytes(iv);
                var badWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, Base64.encode(iv, true));
                cryptoContext.unwrap(badWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("wrong content encryption key", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);

            var ecek;
            runs(function() {
                var cek = new Uint8Array(16);
                random.nextBytes(cek);
                SYMMETRIC_CRYPTO_CONTEXT.encrypt(cek, {
                    result: function(data) { ecek = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ecek; }, "ecek not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var wrongWrapped = replace(wrapped, KEY_ENCRYPTED_KEY, Base64.encode(ecek, true));
                cryptoContext.unwrap(wrongWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    
        it("wrong initialization vector", function() {
            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                var iv = new Uint8Array(16);
                random.nextBytes(iv);
                var wrongWrapped = replace(wrapped, KEY_INITIALIZATION_VECTOR, Base64.encode(iv, true));
                cryptoContext.unwrap(wrongWrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, encoder, {
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
    });

    /** JSON Web Encryption unit tests. */
    describe("JWE", function() {
        /** JWE crypto context. */
        var cryptoContext;
        
        var initialized = false;
        beforeEach(function() {
            if (!initialized) {
                var secretKey;
                runs(function() {
                    var keydata = new Uint8Array(16);
                    random.nextBytes(keydata);
                    SecretKey.import(keydata, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                        result: function(key) { secretKey = key; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return secretKey; }, "secretKey", MslTestConstants.TIMEOUT);
                runs(function() {
                    cryptoContext = new JsonWebEncryptionCryptoContext(ctx, Algorithm.RSA_OAEP, Encryption.A128GCM, secretKey);
                });
                waitsFor(function() { return cryptoContext; }, "crypto context", MslTestConstants.TIMEOUT);
                runs(function() { initialized = true; });
            }
        });
        
        it("encrypt", function() {
            var exception;
            runs(function() {
                cryptoContext.encrypt(new Uint8Array(0), {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED));
            });
        });

        it("decrypt", function() {
            var exception;
            runs(function() {
                cryptoContext.decrypt(new Uint8Array(0), {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED));
            });
        });

        it("sign", function() {
            var exception;
            runs(function() {
                cryptoContext.sign(new Uint8Array(0), {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.SIGN_NOT_SUPPORTED));
            });
        });

        it("verify", function() {
            var exception;
            runs(function() {
                cryptoContext.verify(new Uint8Array(0), new Uint8Array(0), {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED));
            });
        });

        it("algorithm mismatch", function() {
            var cryptoContextA = new JsonWebEncryptionCryptoContext(ctx, Algorithm.RSA_OAEP, Encryption.A128GCM, RSA_PRIVATE_KEY, RSA_PUBLIC_KEY);
            var cryptoContextB = new JsonWebEncryptionCryptoContext(ctx, Algorithm.A128KW, Encryption.A128GCM, AES_WRAP_KEY);

            var wrapped;
            runs(function() {
                cryptoContextA.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped not received", MslTestConstants.TIMEOUT);
            var exception;
            runs(function() {
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
    });
}
});