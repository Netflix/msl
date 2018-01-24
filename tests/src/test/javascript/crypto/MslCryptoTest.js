/**
 * Copyright (c) 2017-2018 Netflix, Inc.  All rights reserved.
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
 * MSL crypto unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MslCrypto", function() {
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var WebCryptoNamedCurve = require('msl-core/crypto/WebCryptoNamedCurve.js');
    var KeyFormat = require('msl-core/crypto/KeyFormat.js');
    var SecretKey = require('msl-core/crypto/SecretKey.js');
    var PrivateKey = require('msl-core/crypto/PrivateKey.js');
    var PublicKey = require('msl-core/crypto/PublicKey.js');
    var MslCrypto = require('msl-core/crypto/MslCrypto.js');
    var Arrays = require('msl-core/util/Arrays.js');
    var Base64 = require('msl-core/util/Base64.js');
    var Random = require('msl-core/util/Random.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    
    describe("AES-KW", function() {
        /** RFC 3394 encryption key. */
        var RFC_KEY = new Uint8Array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F ]);
        /** RFC 3394 plaintext (key data). */
        var RFC_PLAINTEXT = new Uint8Array([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF ]);
        /** RFC 3394 ciphertext. */
        var RFC_CIPHERTEXT = new Uint8Array([
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
            0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
            0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5 ]);
        
        var RFC_KEK, RFC_KEYDATA;
        
        var initialized = false;
        beforeEach(function() {
            if (!initialized) {
                runs(function() {
                    SecretKey.import(RFC_KEY, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                        result: function(x) { RFC_KEK = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    SecretKey.import(RFC_PLAINTEXT, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                        result: function(x) { RFC_KEYDATA = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return RFC_KEK && RFC_KEYDATA; }, "initialization", MslTestConstants.TIMEOUT);
                
                runs(function() {
                    initialized = true;
                });
            }
        });
        
        it("RFC wrap/unwrap", function() {
            var ciphertext;
            runs(function() {
                var oncomplete = function(result) {
                    ciphertext = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['wrapKey'](KeyFormat.RAW, RFC_KEYDATA.rawKey, RFC_KEK.rawKey, WebCryptoAlgorithm.A128KW)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return ciphertext; }, "wrap", MslTestConstants.TIMEOUT);
            
            var key;
            runs(function() {
                expect(ciphertext).toEqual(RFC_CIPHERTEXT);
                
                var oncomplete = function(result) {
                    key = result;
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['unwrapKey'](KeyFormat.RAW, ciphertext, RFC_KEK.rawKey, WebCryptoAlgorithm.A128KW, WebCryptoAlgorithm.AES_CBC, true, WebCryptoUsage.ENCRYPT_DECRYPT)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return key; }, "unwrap", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(key).not.toBeNull();
                expect(key['type']).toEqual('secret');
                expect(key['algorithm']).toEqual(WebCryptoAlgorithm.AES_CBC);
                expect(key['extractable']).toEqual(true);
                expect(key['usages']).toEqual(WebCryptoUsage.ENCRYPT_DECRYPT);
            });
        });
    });
    
    describe("AES-CBC", function() {
        /** RFC 3602 encryption key. */
        var RFC_KEY = new Uint8Array([
            0x56, 0xe4, 0x7a, 0x38, 0xc5, 0x59, 0x89, 0x74,
            0xbc, 0x46, 0x90, 0x3d, 0xba, 0x29, 0x03, 0x49 ]);
        /** RFC 3602 initialization vector. */
        var RFC_IV = new Uint8Array([
            0x8c, 0xe8, 0x2e, 0xef, 0xbe, 0xa0, 0xda, 0x3c,
            0x44, 0x69, 0x9e, 0xd7, 0xdb, 0x51, 0xb7, 0xd9 ]);
        /** RFC 3602 plaintext. */
        var RFC_PLAINTEXT = new Uint8Array([
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
            0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf ]);
        /** RFC 3602 ciphertext (padded). */
        var RFC_CIPHERTEXT = new Uint8Array([
            0xc3, 0x0e, 0x32, 0xff, 0xed, 0xc0, 0x77, 0x4e, 0x6a, 0xff, 0x6a, 0xf0, 0x86, 0x9f, 0x71, 0xaa,
            0x0f, 0x3a, 0xf0, 0x7a, 0x9a, 0x31, 0xa9, 0xc6, 0x84, 0xdb, 0x20, 0x7e, 0xb0, 0xef, 0x8e, 0x4e,
            0x35, 0x90, 0x7a, 0xa6, 0x32, 0xc3, 0xff, 0xdf, 0x86, 0x8b, 0xb7, 0xb2, 0x9d, 0x3d, 0x46, 0xad,
            0x83, 0xce, 0x9f, 0x9a, 0x10, 0x2e, 0xe9, 0x9d, 0x49, 0xa5, 0x3e, 0x87, 0xf4, 0xc3, 0xda, 0x55,
            0x78, 0xb8, 0xd0, 0x47, 0x31, 0x04, 0x1a, 0xa2, 0xd9, 0x78, 0x7c, 0xa4, 0xa4, 0xfa, 0x3e, 0xef ]);

        var RFC_K;
        
        var initialized = false;
        beforeEach(function() {
            if (!initialized) {
                runs(function() {
                    SecretKey.import(RFC_KEY, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                        result: function(x) { RFC_K = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return RFC_K; }, "initialization", MslTestConstants.TIMEOUT);
                
                runs(function() {
                    initialized = true;
                });
            }
        });
        
        it("RFC encrypt/decrypt", function() {
            var algo = { 'name': WebCryptoAlgorithm.AES_CBC['name'], 'iv': RFC_IV };
            
            var ciphertext;
            runs(function() {
                var oncomplete = function(result) {
                    ciphertext = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['encrypt'](algo, RFC_K.rawKey, RFC_PLAINTEXT)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return ciphertext; }, "encrypt", MslTestConstants.TIMEOUT);
            
            var plaintext;
            runs(function() {
                expect(ciphertext).toEqual(RFC_CIPHERTEXT);

                var oncomplete = function(result) {
                    plaintext = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['decrypt'](algo, RFC_K.rawKey, RFC_CIPHERTEXT)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return plaintext; }, "decrypt", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(plaintext).toEqual(RFC_PLAINTEXT);
            });
        });
    });
    
    describe("HMAC", function() {
        /** RFC 4868 HMAC key. */
        var RFC_KEY = new Uint8Array([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 ]);
        /** RFC 4868 data. */
        var RFC_DATA = new Uint8Array([
            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
            0xcd, 0xcd ]);
        /** RFC 4868 HMAC. */
        var RFC_HMAC = new Uint8Array([
            0x37, 0x2e, 0xfc, 0xf9, 0xb4, 0x0b, 0x35, 0xc2, 0x11, 0x5b, 0x13, 0x46, 0x90, 0x3d, 0x2e, 0xf4,
            0x2f, 0xce, 0xd4, 0x6f, 0x08, 0x46, 0xe7, 0x25, 0x7b, 0xb1, 0x56, 0xd3, 0xd7, 0xb3, 0x0d, 0x3f ]);

        var RFC_K;
        
        var initialized = false;
        beforeEach(function() {
            if (!initialized) {
                runs(function() {
                    SecretKey.import(RFC_KEY, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                        result: function(x) { RFC_K = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return RFC_K; }, "initialization", MslTestConstants.TIMEOUT);
                
                runs(function() {
                    initialized = true;
                });
            }
        });
        
        it ("RFC sign/verify", function() {
            var signature;
            runs(function() {
                var oncomplete = function(result) {
                    signature = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['sign'](WebCryptoAlgorithm.HMAC_SHA256, RFC_K.rawKey, RFC_DATA)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return signature; }, "sign", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(signature).toEqual(RFC_HMAC);
            });
        });
    });
    
    describe("RSA-OAEP", function() {
        /** RSA private key. */
        var RSA_PRIVKEY_B64 =
            "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAyAhBM5zheXUIyMug" +
            "rAgRoZ/ZARTicsurf3RMtMNygfpqlbJMmac7r89wACXqFbbDh2hMUgmjZnylNt14" +
            "Fg1mywIDAQABAkBna70qTkZVYak1B/L+fv1+rwKniIC8EYmN0DeIjjS59jAgqX7A" +
            "Pf46/RfCvWgPCTBuNS6Ps1nTeP/Ink/zG56hAiEA9pLVM6JMH3352kOFb1hx/YOr" +
            "VZ8fBZE6OhaEq+NpwbUCIQDPre5bpnrDRx1mHDTP3itsHMdqC3qjGbAn172j16XW" +
            "fwIhANHcSQ+IS+flzZjCLTiGe4Z84X+fTcTsRTWZYtP1W1adAiA0n1/MPUzR+k0K" +
            "uI7xNNxP0qL8zdfPSA0Iq3PT9iqBRQIhAKZGuAGtVwsfjhMWkRP4VswTPR7hqAUz" +
            "NDNvJ46TaIvM";
        /** RSA public key. */
        var RSA_PUBKEY_B64 =
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMgIQTOc4Xl1CMjLoKwIEaGf2QEU4nLL" +
            "q390TLTDcoH6apWyTJmnO6/PcAAl6hW2w4doTFIJo2Z8pTbdeBYNZssCAwEAAQ==";
        /** Plaintext. */
        var PLAINTEXT = new Uint8Array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f ]);
        
        var PRIVKEY, PUBKEY;
        
        var initialized = false;
        beforeEach(function() {
            if (!initialized) {
                runs(function() {
                    PrivateKey.import(RSA_PRIVKEY_B64, WebCryptoAlgorithm.RSA_OAEP, WebCryptoUsage.DECRYPT, KeyFormat.PKCS8, {
                        result: function(x) { PRIVKEY = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    PublicKey.import(RSA_PUBKEY_B64, WebCryptoAlgorithm.RSA_OAEP, WebCryptoUsage.ENCRYPT, KeyFormat.SPKI, {
                        result: function(x) { PUBKEY = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return PRIVKEY && PUBKEY; }, "initialization", MslTestConstants.TIMEOUT);
                
                runs(function() {
                    initialized = true;
                });
            }
        });
        
        it("encrypt/decrypt", function() {
            var ciphertext;
            runs(function() {
                var oncomplete = function(result) {
                    ciphertext = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['encrypt'](WebCryptoAlgorithm.RSA_OAEP, PUBKEY.rawKey, PLAINTEXT)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return ciphertext; }, "encrypt", MslTestConstants.TIMEOUT);
            
            var plaintext;
            runs(function() {
                expect(ciphertext).not.toEqual(PLAINTEXT);
                
                var oncomplete = function(result) {
                    plaintext = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['decrypt'](WebCryptoAlgorithm.RSA_OAEP, PRIVKEY.rawKey, ciphertext)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return plaintext; }, "decrypt", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(plaintext).toEqual(PLAINTEXT);
            });
        });
        
        it("wrap/unwrap AES-128 key", function() {
            var aes128Key;
            runs(function() {
                var keydata = new Uint8Array(16);
                var random = new Random();
                random.nextBytes(keydata);
                SecretKey.import(keydata, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(x) { aes128Key = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return aes128Key; }, "AES key", MslTestConstants.TIMEOUT);
            
            var ciphertext;
            runs(function() {
                var oncomplete = function(result) {
                    ciphertext = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['wrapKey'](KeyFormat.RAW, aes128Key.rawKey, PUBKEY.rawKey, WebCryptoAlgorithm.RSA_OAEP)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return ciphertext; }, "wrap", MslTestConstants.TIMEOUT);
            
            var unwrappedKey;
            runs(function() {
                expect(ciphertext.length).toBeGreaterThan(0);
                
                var oncomplete = function(result) {
                    SecretKey.create(result, {
                        result: function(x) { unwrappedKey = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['unwrapKey'](KeyFormat.RAW, ciphertext, PRIVKEY.rawKey, WebCryptoAlgorithm.RSA_OAEP, WebCryptoAlgorithm.AES_CBC, true, WebCryptoUsage.ENCRYPT_DECRYPT)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return unwrappedKey; }, "unwrap", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(unwrappedKey.rawKey).toEqual(aes128Key.rawKey);
            });
        });
        
        it("wrap/unwrap HMAC-SHA256 key", function() {
            var hmacSha256Key;
            runs(function() {
                var keydata = new Uint8Array(16);
                var random = new Random();
                random.nextBytes(keydata);
                SecretKey.import(keydata, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function(x) { hmacSha256Key = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return hmacSha256Key; }, "HMAC-SHA256 key", MslTestConstants.TIMEOUT);
            
            var ciphertext;
            runs(function() {
                var oncomplete = function(result) {
                    ciphertext = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['wrapKey'](KeyFormat.RAW, hmacSha256Key.rawKey, PUBKEY.rawKey, WebCryptoAlgorithm.RSA_OAEP)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return ciphertext; }, "wrap", MslTestConstants.TIMEOUT);
            
            var unwrappedKey;
            runs(function() {
                expect(ciphertext.length).toBeGreaterThan(0);
                
                var oncomplete = function(result) {
                    SecretKey.create(result, {
                        result: function(x) { unwrappedKey = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['unwrapKey'](KeyFormat.RAW, ciphertext, PRIVKEY.rawKey, WebCryptoAlgorithm.RSA_OAEP, WebCryptoAlgorithm.HMAC_SHA256, true, WebCryptoUsage.SIGN_VERIFY)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return unwrappedKey; }, "unwrap", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(unwrappedKey.rawKey).toEqual(hmacSha256Key.rawKey);
            });
        });
    });
    
    describe("ECDSA", function() {
        /** RFC 6979 256b private key. */
        var RFC_PRIVKEY = {
            x: new Uint8Array([
                0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
                0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21 ]),
        };
        /** RFC 6979 256b public key. */
        var RFC_PUBKEY = {
            ux: new Uint8Array([
                0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
                0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6 ]),
            uy: new Uint8Array([
                0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
                0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51, 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99 ]),
        };
        /** RFC 6979 plaintext. */
        var RFC_PLAINTEXT = TextEncoding.getBytes("message");
        
        var PRIVKEY, PUBKEY;
        
        var initialized = false;
        beforeEach(function() {
            if (!initialized) {
                runs(function() {
                    var privkeyJwk = {
                        'kty': 'EC',
                        'crv': WebCryptoNamedCurve.P_256,
                        'd': Base64.encode(RFC_PRIVKEY.x),
                        'x': Base64.encode(RFC_PUBKEY.ux),
                        'y': Base64.encode(RFC_PUBKEY.uy),
                    };
                    var pubkeyJwk = {
                        'kty': 'EC',
                        'crv': WebCryptoNamedCurve.P_256,
                        'x': Base64.encode(RFC_PUBKEY.ux),
                        'y': Base64.encode(RFC_PUBKEY.uy),
                    };
                    var algo = WebCryptoAlgorithm.ECDSA_SHA256;
                    algo['namedCurve'] = WebCryptoNamedCurve.P_256;
                    
                    PrivateKey.import(privkeyJwk, algo, WebCryptoUsage.SIGN, KeyFormat.JWK, {
                        result: function(x) { PRIVKEY = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    PublicKey.import(pubkeyJwk, algo, WebCryptoUsage.VERIFY, KeyFormat.JWK, {
                        result: function(x) { PUBKEY = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return PRIVKEY && PUBKEY; }, "initialization", MslTestConstants.TIMEOUT);
                runs(function() { initialized = true; });
            }
        });
        
        it("sign/verify", function() {
            var signature;
            runs(function() {
                var oncomplete = function(result) {
                    signature = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['sign'](WebCryptoAlgorithm.ECDSA_SHA256, PRIVKEY.rawKey, RFC_PLAINTEXT)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return signature; }, "sign", MslTestConstants.TIMEOUT);
            
            var verified;
            runs(function() {
                expect(signature).not.toEqual(RFC_PLAINTEXT);
                
                var oncomplete = function(result) {
                    verified = result;
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['verify'](WebCryptoAlgorithm.ECDSA_SHA256, PUBKEY.rawKey, signature, RFC_PLAINTEXT)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return verified !== undefined; }, "verify", MslTestConstants.TIMEOUT);
            
            var notVerified;
            runs(function() {
                expect(verified).toBeTruthy();
                
                var notSignature = Arrays.copyOf(signature);
                notSignature[notSignature.length / 2] ^= 0xab;
                var oncomplete = function(result) {
                    notVerified = result;
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['verify'](WebCryptoAlgorithm.ECDSA_SHA256, PUBKEY.rawKey, notSignature, RFC_PLAINTEXT)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return notVerified !== undefined; }, "notVerified", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(notVerified).toBeFalsy();
            });
        });
    });

    function rsassaData() {
        var PLAINTEXT_B64 = "VEvgpARO3NwSQPIYIQn4JteE6mE0ht/VIh07pE0VJak0wTxagfiF85VdqNFo410bkJEhqJ+DLR2yMqhWR/UcCE/HJ6SFSnN+/QznLgAJHzYXchrmZq0zfTudU5HnI2SxzeUJSLhOjMRy1hj4koMov5WvP+MwDdo95eeiHdWp5+w=";
        var plaintext = Base64.decode(PLAINTEXT_B64);
        
        return [
            [ WebCryptoAlgorithm.RSASSA_SHA1, plaintext ],
            [ WebCryptoAlgorithm.RSASSA_SHA256, plaintext ],
        ];
    }
    
    parameterize("RSASSA", rsassaData, function(algo, plaintext) {
        /** Private key. */
        var PRIVKEY_B64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDm0BtwBF5IMXWkeYVoDunO9MBTwNrKp0jfzxM4Ue0PHuEGoh+3mhty90xl0/EFCQCkKYiU99f5kr77hsYitNPU35xIPcZICLhfHQQPN+qw6G+9YuUfzABfEIsZOhSRYDXtZUfjta/cqFArtJLZV4nkdQMEjgoseFOsMiiNc78+qYfFehZzZTwmTBgelfIiZqj+CZeGRF0mduBkbbPYxlmCIpGSET68WAB1fiA3HjevFUHbdu7oyjydYyb9HEZcvZfqLA0W0XNcNtVrxXuu2wqNi5HdOaN7LCh3Oqs1BQvK6i3Qe52ZQtlBUBth5Oa1poGoylK60Y73owYkMJKO2uyBAgMBAAECggEAFhe7WJiCccSSLyEWnOQ4iv+wXRPrnVQvzIRkoZJt73GUNm9UO927XODA5kpIGqRG9G+pTCEBAjmCoE7BLldCo3CX4+5NyV1UUH5VgiNnCnHlKCqMJeP/8RmDRvHhQB0GbGeyXuBoKeXObrCFEdqoLz7oAAqcfK8zyxqt+QQoPRYMfrjndToFpot1K4Nuv/G6ZdcNMIolAJP3Vn3dXPxzQpijkpzwjAlWLGKVV9VsboAOXipITXM7Q9mmNsM9MKk9TPAmvs5seAwdtlRvgp39X75AwWPPn1BfKctdjML8TeIpbaKmje4QrKNlHBoYvK4w8mPdvERdylLceSlMWSVNwQKBgQD9aOjl/EKZoVEFLrAokAGTbF59DPia70In51PbG9sPCJPLYRJdeU8dJkTfiZiLHXWvkYVJAFday1BtUVgv2V7rVyYO6ueJYXnV36ESlbcx0UpytC60KfVrBYUeguD+IPXe+f7y5qNO/aHUiXup9HHM4o3feoubAGU7YTmSxTHsOQKBgQDpLBGcR5J/47ybFHBJAWs7ii6M9khj3+o/BRygq95DNXNC780qwuWJvkbvXh2jmAK0MVmSVIg8vdXAttkGep52IHOpaUjoc0RAdSkHUNM074bYaSG/PPjvObJPwvkzS78J1jK2LrNZWHM8NusPV6yzxW11KefC90FusZbUl8OSiQKBgDMt4Pux+vF0NxzI1SMcEnVnyZ2P5RXFhKLygWkbMx7SKKdGr6LZQTUt6XMMIxbVmFMhHL4lp37a2R968kiXqif1reYNYz3Hxgd/5tQOELWrA1IvOc+BOeOndb83x6ELnxyteOQt2IW3i9uU+LjWebVbfDPKWC+x4MAhXrNZyD9hAoGAK7Ry6JQRxZ7uLzM5iLWXX+WarBlNoErMIVvX7dXJJ1fRbu57ylQVqifcK+m8LHnFp/jIDUGC97+tXR3ot+or4YBbrZlqbQeN93b+Zbykmft7jvzFso6/KjfqUED/bLn56OIZR0ShoVGO5+5zSMDqQhfzWE6ufkDSJulqmBaKNeECgYEAyvDuspGzJ2v6EKlQgS+0VxEKAGAtubllgEuyNZDPAui2FEG/RxAfLzQXZtV1zHmIIKH09Ty3PqCRq4Hz3YcNf50bOITqIxHAGPBPaGG/GWopIg3WElwP8ZDl5uqb67cagZh3tSEA7tKtOijqLgGzGfU4u7ZxzWmQ0ivZSFGGqHI=";
        /** Public key. */
        var PUBKEY_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5tAbcAReSDF1pHmFaA7pzvTAU8DayqdI388TOFHtDx7hBqIft5obcvdMZdPxBQkApCmIlPfX+ZK++4bGIrTT1N+cSD3GSAi4Xx0EDzfqsOhvvWLlH8wAXxCLGToUkWA17WVH47Wv3KhQK7SS2VeJ5HUDBI4KLHhTrDIojXO/PqmHxXoWc2U8JkwYHpXyImao/gmXhkRdJnbgZG2z2MZZgiKRkhE+vFgAdX4gNx43rxVB23bu6Mo8nWMm/RxGXL2X6iwNFtFzXDbVa8V7rtsKjYuR3TmjeywodzqrNQULyuot0HudmULZQVAbYeTmtaaBqMpSutGO96MGJDCSjtrsgQIDAQAB";
        
        /** SHA-1 signature. */
        var SHA1_SIG_B64 = "Yxo9PYJeu+PdJ6flyVgXymwYNF4jTpLnISfknGCysEW4djcUypYl2KtJa05LJZl+SKCGBvEz4xebnmGSpBl0GLYfPXnPODJ+kb4lQsmXW6SAehcGguGqCuwIXCIG5d0QZSbAWwqZNjX65d8/jvKeEQo0wMQ86sDIgaq+zxQr76FeSdvOai7rqjglgwdzIIrbha0+Vt8tl2l2Oit/CPsvh56OdfGKMqRN+Lq1dDWzObDy6+rSdFNFrKRrBGZi9kTnqXza7bnIXIgYWYgWtGsuedbaIcLgYp5isZvU0Xa+/nskHOXAf1FF9+aHEXBKK4Ryquhj+xwjn29IP//+iQjI3w==";
        
        /** SHA-256 signature. */
        var SHA256_SIG_B64 = "M2E7LE9hms3EzEcVK02/9eDO6wflYSgWsr0vA1ahNXKrueoE4bPtNtZ9Ex78UmfncJbrYF/BX0JCXovxPOCLhkqgoAdVZ6z14I22eFa+mf7t04Fa8ZxjbqZq39HpL7Y4wjxAIu5GBOzZik81QGrF7TDzEXgt+oL6oNifejn2THYQveIyk9rd2kkmYqhX5txQG39w8ILDJdtnDocphKHjQKiPZCBiWrSqk0nybmCuZtqpIRWi4qjcVq4x28vUtMnM403ev2fW/Ha6dJl3HF3TfKPdNpI2vKf8SvRKsjmI6afpdSt7hPEXsPbvIVr3y07lFFJMOGRNVivb0Sfo/YOhEA==";

        var privateKey, publicKey;

        var initialized = false;
        beforeEach(function() {
            if (initialized) return;

            runs(function() {
                PrivateKey.import(PRIVKEY_B64, algo, WebCryptoUsage.SIGN, KeyFormat.PKCS8, {
                    result: function(x) { privateKey = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                PublicKey.import(PUBKEY_B64, algo, WebCryptoUsage.VERIFY, KeyFormat.SPKI, {
                    result: function(x) { publicKey = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return privateKey && publicKey; }, "keys", MslTestConstants.TIMEOUT);

            runs(function() { initialized = true; });
        });

        it("sign/verify", function() {
            var signature;
            runs(function() {
                var oncomplete = function(result) {
                    signature = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['sign'](algo, privateKey.rawKey, plaintext)
                .then(oncomplete, onerror);
            });
            waitsFor(function() { return signature; }, "sign", MslTestConstants.TIMEOUT);

            var verified;
            runs(function() {
                expect(signature).not.toEqual(plaintext);

                var oncomplete = function(result) {
                    verified = result;
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['verify'](algo, publicKey.rawKey, signature, plaintext)
                .then(oncomplete, onerror);
            });
            waitsFor(function() { return verified !== undefined; }, "verify", MslTestConstants.TIMEOUT);

            var notVerified;
            runs(function() {
                expect(verified).toBeTruthy();

                var notSignature = Arrays.copyOf(signature);
                notSignature[notSignature.length / 2] ^= 0xab;
                var oncomplete = function(result) {
                    notVerified = result;
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['verify'](algo, publicKey.rawKey, notSignature, plaintext)
                .then(oncomplete, onerror);
            });
            waitsFor(function() { return notVerified !== undefined; }, "notVerified", MslTestConstants.TIMEOUT);

            runs(function() {
                expect(notVerified).toBeFalsy();
            });
        });
    });

    function shaData() {
        var PLAINTEXT_B64 = "VEvgpARO3NwSQPIYIQn4JteE6mE0ht/VIh07pE0VJak0wTxagfiF85VdqNFo410bkJEhqJ+DLR2yMqhWR/UcCE/HJ6SFSnN+/QznLgAJHzYXchrmZq0zfTudU5HnI2SxzeUJSLhOjMRy1hj4koMov5WvP+MwDdo95eeiHdWp5+w=";
        var plaintext = Base64.decode(PLAINTEXT_B64);

        var sha256 = new Uint8Array([
            0x1b, 0xf7, 0x26, 0x3d, 0xa0, 0x25, 0x6f, 0xf4, 0xc2, 0x03, 0xd3, 0xc5, 0x0c, 0xe6, 0xa6, 0x10,
            0x70, 0xb6, 0x5a, 0x40, 0x5e, 0x9c, 0x0d, 0xcd, 0xce, 0x67, 0x7b, 0x92, 0x3e, 0x00, 0xa7, 0x2d ]);
        
        var sha384 = new Uint8Array([
            0x65, 0xc8, 0x0e, 0x3a, 0xbb, 0xc2, 0x46, 0x16, 0xed, 0xff, 0xbb, 0xd3, 0x1f, 0xde, 0xd5, 0x3e,
            0x00, 0x44, 0x30, 0xa7, 0x2b, 0x8f, 0x9b, 0x3e, 0x23, 0x2d, 0x66, 0xa4, 0x07, 0xc2, 0xca, 0x9d,
            0x54, 0x58, 0x65, 0x33, 0x45, 0xf1, 0x10, 0x2e, 0x97, 0x53, 0xde, 0xd6, 0x2d, 0xca, 0xe5, 0xe4 ]);
        
        return [
            [ WebCryptoAlgorithm.SHA_256, plaintext, sha256 ],
            [ WebCryptoAlgorithm.SHA_384, plaintext, sha384 ],
        ];
    }
    
    function toHexString(byteArray) {
        return Array.from(byteArray, function(byte) {
          return '0x' + ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join(', ');
      }
    
    parameterize("SHA", shaData, function(algo, plaintext, sha) {
        it("digest", function() {
            var digest;
            runs(function() {
                var oncomplete = function(result) {
                    digest = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['digest'](algo, plaintext)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return digest; }, "digest", MslTestConstants.TIMEOUT);
            
            var badDigest;
            runs(function() {
                expect(Arrays.equal(digest, sha)).toBeTruthy();

                var badPlaintext = Arrays.copyOf(plaintext);
                badPlaintext[badPlaintext.length / 2] ^= 0x1;
                var oncomplete = function(result) {
                    badDigest = new Uint8Array(result);
                };
                var onerror = function(e) {
                    expect(function() { throw e; }).not.toThrow();
                };
                MslCrypto['digest'](algo, badPlaintext)
                    .then(oncomplete, onerror);
            });
            waitsFor(function() { return badDigest; }, "bad digest", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(Arrays.equal(badDigest, sha)).toBeFalsy();
            });
        });
    });
});