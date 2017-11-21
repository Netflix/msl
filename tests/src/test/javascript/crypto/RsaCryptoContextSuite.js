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
 * RSA crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("RsaCryptoContext", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var Random = require('msl-core/util/Random.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var SecretKey = require('msl-core/crypto/SecretKey.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var SymmetricCryptoContext = require('msl-core/crypto/SymmetricCryptoContext.js');
    var MslCrypto = require('msl-core/crypto/MslCrypto.js');
    var RsaCryptoContext = require('msl-core/crypto/RsaCryptoContext.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
	
    /** Key pair ID. */
    var KEYPAIR_ID = "keypairid";
    /** Crypto context key ID. */
    var KEY_ID = "keyId";
    /** AES-128 key. */
    var AES_128_KEY;
    /** HMAC-SHA256 key. */
    var HMAC_256_KEY;
    /** AES-128 HMAC-SHA256 AES-KW symmetric crypto context. */
    var SYMMETRIC_CRYPTO_CONTEXT;

    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Random. */
    var random = new Random();
    /** Message. */
    var message = new Uint8Array(32);
    random.nextBytes(message);
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    
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
            });
            waitsFor(function() { return ctx && AES_128_KEY && HMAC_256_KEY; }, "static initialization", MslTestConstants.TIMEOUT_CTX);
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                SYMMETRIC_CRYPTO_CONTEXT = new SymmetricCryptoContext(ctx, KEY_ID, AES_128_KEY, HMAC_256_KEY, null);
                initialized = true;
            });
        }
    });
    
    function encryptDecryptData() {
        var params = [];
        var webCryptoVersion = MslCrypto.getWebCryptoVersion();
        if (webCryptoVersion == MslCrypto.WebCryptoVersion.V2014_01) {
            params.push([ WebCryptoAlgorithm.RSAES, RsaCryptoContext.Mode.ENCRYPT_DECRYPT_PKCS1, 32 ]);
        }
        return params;
    }

    parameterize("encrypt/decrypt", encryptDecryptData, function(algorithm, mode, messageSize) {
        var publicKeyA;
        var privateKeyA;
        var publicKeyB;
        var privateKeyB;

        var loading;
        beforeEach(function () {
            if (loading) return;
            loading = true;
            
            runs(function () {
                MslTestUtils.generateRsaKeys(algorithm, WebCryptoUsage.ENCRYPT_DECRYPT, 2048, {
                    result: function(publicKey, privateKey) {
                        publicKeyA = publicKey;
                        privateKeyA = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return publicKeyA && privateKeyA; }, "did not create publicKeyA && privateKeyA", MslTestConstants.TIMEOUT_CRYPTO);

            runs(function() {
                MslTestUtils.generateRsaKeys(algorithm, WebCryptoUsage.ENCRYPT_DECRYPT, 2048, {
                    result: function(publicKey, privateKey) {
                        publicKeyB = publicKey;
                        privateKeyB = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function () { return publicKeyB && privateKeyB; }, "did not create publicKeyB && privateKeyB", MslTestConstants.TIMEOUT_CRYPTO);
        });
        
    	it("encrypt/decrypt", function() {
    		var messageA = new Uint8Array(messageSize);
    		random.nextBytes(messageA);
            
            var messageB = new Uint8Array(messageSize);
            random.nextBytes(messageB);
    		
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
    		var ciphertextA, ciphertextB;
    		runs(function() {
    			cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertextA = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    			cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertextB = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertextA && ciphertextB; }, "did not receive ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		runs(function() {
	    		expect(ciphertextA).not.toBeNull();
	    		expect(ciphertextA).not.toEqual(messageA);
	
	            expect(ciphertextB).not.toBeNull();
	            expect(ciphertextB).not.toEqual(messageB);
	            expect(ciphertextB).not.toEqual(ciphertextA);
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
    		waitsFor(function() { return plaintextA && plaintextB; }, "did not receive plaintext", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		runs(function() {
	            expect(plaintextA).not.toBeNull();
	            expect(plaintextA).toEqual(messageA);
	            
	            expect(plaintextB).not.toBeNull();
	            expect(plaintextB).toEqual(messageB);
    		});
    	});
    	
    	it("encrypt with null public key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
    		
    		var exception;
    		runs(function() {
    			cryptoContext.encrypt(message, {
    				result: function() {},
    				error: function(err) { exception = err; }
    			});
    		});
    		waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		runs(function() {
    			var f = function() { throw exception; };
    			expect(f).toThrow(new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED));
    		});
    	});
    	
    	it("decrypt with null private key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
    		var ciphertext;
    		runs(function() {
    			cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		var exception;
    		runs(function() {
	    		cryptoContext.decrypt(ciphertext, encoder, {
	    			result: function() {},
	    			error: function(err) { exception = err; }
	    		});
    		});
			waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
			
			runs(function() {
				var f = function() { throw exception; };
				expect(f).toThrow(new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED));
			});
    	});
    	
    	it("encrypt/decrypt with mismatched key ID", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID + 'A', privateKeyA, publicKeyA, mode);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID + 'B', privateKeyA, publicKeyA, mode);
    			
    		var ciphertext;
    		runs(function() {
    			cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		var plaintext;
    		runs(function() {
    			expect(ciphertext).not.toBeNull();
    			expect(ciphertext).not.toEqual(message);
    			
    			cryptoContextB.decrypt(ciphertext, encoder, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		runs(function() {
    			expect(plaintext).not.toBeNull();
    			expect(plaintext).toEqual(message);
    		});
    	});

    	it("encrypt/decrypt with mismatched keys", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, mode);

    		var ciphertext;
    		runs(function() {
    			cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		var exception;
    		runs(function() {
    			cryptoContextB.decrypt(ciphertext, encoder, {
    				result: function() {},
    				error: function(err) { exception = err; }
    			});
    		});
    		waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		runs(function() {
    			var f = function() { throw exception; };
    			expect(f).toThrow(new MslCryptoException(MslError.DECRYPT_ERROR));
    		});
    	});
    	
    	it("wrap", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            
            var keyA;
            runs(function() {
                var keydataA = new Uint8Array(16);
                random.nextBytes(keydataA);
                SecretKey.import(keydataA, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(k) { keyA = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyA; }, "keyA", MslTestConstants.TIMEOUT_CRYPTO);
            
            var exception;
            runs(function() {
                cryptoContext.wrap(keyA, encoder, ENCODER_FORMAT, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.WRAP_NOT_SUPPORTED));
            });
        });
        
        it("unwrap", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            
            var exception;
            runs(function() {
                cryptoContext.unwrap(message, null, null, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED));
            });
        });
    	
    	it("sign/verify", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
    		var signature;
    		runs(function() {
    			cryptoContext.sign(message, encoder, ENCODER_FORMAT, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		runs(function() {
	    		expect(signature).not.toBeNull();
	    		expect(signature.length).toEqual(0);
    		});
    		
    		var verified;
    		runs(function() {
    			cryptoContext.verify(message, signature, encoder, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		runs(function() {
	    		expect(verified).toBeTruthy();
    		});
    	});
    	
    	it("sign/verify with mismatched contexts", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, mode);
    		var signature;
    		runs(function() {
    			cryptoContextA.sign(message, encoder, ENCODER_FORMAT, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);
    		var verified;
    		runs(function() {
    			cryptoContextB.verify(message, signature, encoder, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
    			expect(verified).toBeTruthy();
    		});
    	});
    	
    	it("sign with null private key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
    		var signature;
    		runs(function() {
    			cryptoContext.sign(message, encoder, ENCODER_FORMAT, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	    		expect(signature).not.toBeNull();
	    		expect(signature.length).toEqual(0);
    		});
    		var verified;
    		runs(function() {
    			cryptoContext.verify(message, signature, encoder, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
    			expect(verified).toBeTruthy();
    		});
    	});
    	
    	it("verify with null public key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
    		var signature;
    		runs(function() {
    			cryptoContext.sign(message, encoder, ENCODER_FORMAT, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	    		expect(signature).not.toBeNull();
	    		expect(signature.length).toEqual(0);
    		});
    		var verified;
    		runs(function() {
    			cryptoContext.verify(message, signature, encoder, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
    			expect(verified).toBeTruthy();
    		});
    	});
    });
    
    function wrapUnwrapData() {
        var params = [];
        var webCryptoVersion = MslCrypto.getWebCryptoVersion();
        if (webCryptoVersion == MslCrypto.WebCryptoVersion.LEGACY) {
        } else if (webCryptoVersion == MslCrypto.WebCryptoVersion.V2014_01) {
            params.push([ WebCryptoAlgorithm.RSA_OAEP, RsaCryptoContext.Mode.WRAP_UNWRAP_OAEP ]);
            params.push([ WebCryptoAlgorithm.RSAES, RsaCryptoContext.Mode.WRAP_UNWRAP_PKCS1 ]);
        } else {
            params.push([ WebCryptoAlgorithm.RSA_OAEP, RsaCryptoContext.Mode.WRAP_UNWRAP_OAEP ]);
        }
        return params;
    }

    parameterize("wrap/unwrap", wrapUnwrapData, function(algorithm, mode) {
        var publicKeyA;
        var privateKeyA;
        var publicKeyB;
        var privateKeyB;

        var initialized = false;
        beforeEach(function () {
            if (initialized) return;

            runs(function () {
                // TODO: read from RSA_KEYPAIR_A.publicKey
                // TODO: read from RSA_KEYPAIR_A.privateKey
                MslTestUtils.generateRsaKeys(algorithm, WebCryptoUsage.WRAP_UNWRAP, 2048, {
                    result: function(publicKey, privateKey) {
                        publicKeyA = publicKey;
                        privateKeyA = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return publicKeyA && privateKeyA; }, "publicKeyA && privateKeyA", 5000);

            runs(function() {
                // TODO: read from RSA_KEYPAIR_B.publicKey
                // TODO: read from RSA_KEYPAIR_B.privateKey
                MslTestUtils.generateRsaKeys(algorithm, WebCryptoUsage.WRAP_UNWRAP, 2048, {
                    result: function(publicKey, privateKey) {
                        publicKeyB = publicKey;
                        privateKeyB = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function () { return publicKeyB && privateKeyB; }, "publicKeyB && privateKeyB", 5000);

            runs(function() { initialized = true; });
        });

        it("encrypt/decrypt", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            var ciphertext;
            runs(function() {
                cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContext.decrypt(ciphertext, encoder, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(plaintext).not.toBeNull();
                expect(plaintext).toEqual(message);
            });
        });

        it("encrypt with null public key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
            var ciphertext;
            runs(function() {
                cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContext.decrypt(ciphertext, encoder, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(plaintext).not.toBeNull();
                expect(plaintext).toEqual(message);
            });
        });

        it("decrypt with null private key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
            var ciphertext;
            runs(function() {
                cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContext.decrypt(ciphertext, encoder, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(plaintext).not.toBeNull();
                expect(plaintext).toEqual(message);
            });
        });

        it("encrypt/decrypt with mismatched key ID", function() {
            var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID + 'A', privateKeyA, publicKeyA, mode);
            var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID + 'B', privateKeyA, publicKeyA, mode);

            var ciphertext;
            runs(function() {
                cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContextB.decrypt(ciphertext, encoder, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(plaintext).not.toBeNull();
                expect(plaintext).toEqual(message);
            });
        });

        it("encrypt/decrypt with mismatched keys", function() {
            var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, mode);

            var ciphertext;
            runs(function() {
                cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContextB.decrypt(ciphertext, encoder, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(plaintext).not.toBeNull();
                expect(plaintext).toEqual(message);
            });
        });

        it("wrap/unwrap AES-128 key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);

            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped", MslTestConstants.TIMEOUT_CRYPTO);

            var unwrapped;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(AES_128_KEY.toByteArray());
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
                    result: function(key) { unwrapped = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unwrapped; }, "unwrapped", MslTestConstants.TIMEOUT_CRYPTO);

            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var wrapCryptoContext, refCiphertext, wrapCiphertext;
            runs(function() {
                wrapCryptoContext = new SymmetricCryptoContext(ctx, KEY_ID, unwrapped, null, null);
                SYMMETRIC_CRYPTO_CONTEXT.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(x) { refCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
                    result: function(x) { wrapCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refCiphertext && wrapCiphertext; }, "ciphertexts", MslTestConstants.TIMEOUT_CRYPTO);
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
            waitsFor(function() { return refPlaintext && wrapPlaintext; }, "plaintexts", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(wrapPlaintext).toEqual(refPlaintext);
            });
        });

        it("wrap/unwrap HMAC-SHA256 key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);

            var wrapped;
            runs(function() {
                cryptoContext.wrap(HMAC_256_KEY, encoder, ENCODER_FORMAT, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped", MslTestConstants.TIMEOUT_CRYPTO);
            var unwrapped;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(HMAC_256_KEY.toByteArray());
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, encoder, {
                    result: function(key) { unwrapped = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unwrapped; }, "unwrapped", MslTestConstants.TIMEOUT_CRYPTO);

            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var refHmac, wrapHmac;
            runs(function() {
                SYMMETRIC_CRYPTO_CONTEXT.sign(message, encoder, ENCODER_FORMAT, {
                    result: function(x) { refHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                var wrapCryptoContext = new SymmetricCryptoContext(ctx, KEY_ID, null, unwrapped, null);
                wrapCryptoContext.sign(message, encoder, ENCODER_FORMAT, {
                    result: function(x) { wrapHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refHmac && wrapHmac; }, "hmacs", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(wrapHmac).toEqual(refHmac);
            });
        });

        it("sign/verify", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            var signature;
            runs(function() {
                cryptoContext.sign(message, encoder, ENCODER_FORMAT, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);

            runs(function() {
                expect(signature).not.toBeNull();
                expect(signature.length).toEqual(0);
            });

            var verified;
            runs(function() {
                cryptoContext.verify(message, signature, encoder, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);

            runs(function() {
                expect(verified).toBeTruthy();
            });
        });

        it("sign/verify with mismatched contexts", function() {
            var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, mode);
            var signature;
            runs(function() {
                cryptoContextA.sign(message, encoder, ENCODER_FORMAT, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);
            var verified;
            runs(function() {
                cryptoContextB.verify(message, signature, encoder, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(verified).toBeTruthy();
            });
        });

        it("sign with null private key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
            var signature;
            runs(function() {
                cryptoContext.sign(message, encoder, ENCODER_FORMAT, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(signature).not.toBeNull();
                expect(signature.length).toEqual(0);
            });
            var verified;
            runs(function() {
                cryptoContext.verify(message, signature, encoder, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(verified).toBeTruthy();
            });
        });

        it("verify with null public key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
            var signature;
            runs(function() {
                cryptoContext.sign(message, encoder, ENCODER_FORMAT, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(signature).not.toBeNull();
                expect(signature.length).toEqual(0);
            });
            var verified;
            runs(function() {
                cryptoContext.verify(message, signature, encoder, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                expect(verified).toBeTruthy();
            });
        });
    });

    describe("sign/verify", function() {
        // RSASSA-PKCS1-v1_5 keys.
        var publicKeyA;
        var privateKeyA;
        var publicKeyB;
        var privateKeyB;

        var initialized = false;
        beforeEach(function () {
            if (initialized) return;
            
            runs(function () {
                // TODO: read from RSA_KEYPAIR_A.publicKey
                // TODO: read from RSA_KEYPAIR_A.privateKey
                MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSASSA, WebCryptoUsage.SIGN_VERIFY, 2048, {
                    result: function(publicKey, privateKey) {
                        publicKeyA = publicKey;
                        privateKeyA = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return publicKeyA && privateKeyA; }, "publicKeyA && privateKeyA", 1200);

            runs(function() {
                // TODO: read from RSA_KEYPAIR_B.publicKey
                // TODO: read from RSA_KEYPAIR_B.privateKey
                MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSASSA, WebCryptoUsage.SIGN_VERIFY, 2048, {
                    result: function(publicKey, privateKey) {
                        publicKeyB = publicKey;
                        privateKeyB = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function () { return publicKeyB && privateKeyB; }, "publicKeyB && privateKeyB", 1200);
            
            runs(function() { initialized = true; });
        });
        
    	it("encrypt/decrypt", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext.Mode.SIGN_VERIFY);
    		var ciphertext;
    		runs(function() {
    			cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});
    		
    		var plaintext;
    		runs(function() {
    			cryptoContext.decrypt(ciphertext, encoder, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
    	
    	it("encrypt with null public key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, RsaCryptoContext.Mode.SIGN_VERIFY);
    		var ciphertext;
    		runs(function() {
    			cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});
    		
    		var plaintext;
    		runs(function() {
    			cryptoContext.decrypt(ciphertext, encoder, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
    	
    	it("decrypt with null private key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, RsaCryptoContext.Mode.SIGN_VERIFY);
    		var ciphertext;
    		runs(function() {
    			cryptoContext.encrypt(message, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});
    		
    		var plaintext;
    		runs(function() {
    			cryptoContext.decrypt(ciphertext, encoder, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
    	
    	it("encrypt/decrypt with mismatched key ID", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID + 'A', privateKeyA, publicKeyA, RsaCryptoContext.Mode.SIGN_VERIFY);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID + 'B', privateKeyA, publicKeyA, RsaCryptoContext.Mode.SIGN_VERIFY);
    			
    		var ciphertext;
    		runs(function() {
    			cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});
    		
    		var plaintext;
    		runs(function() {
    			cryptoContextB.decrypt(ciphertext, encoder, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
    	
    	it("encrypt/decrypt with mismatched keys", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext.Mode.SIGN_VERIFY);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, RsaCryptoContext.Mode.SIGN_VERIFY);
    			
    		var ciphertext;
    		runs(function() {
    			cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});

    		var plaintext;
    		runs(function() {
    			cryptoContextB.decrypt(ciphertext, encoder, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
        
        it("wrap", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext.Mode.ENCRYPT_DECRYPT);
            
            var keyA;
            runs(function() {
                var keydataA = new Uint8Array(16);
                random.nextBytes(keydataA);
                SecretKey.import(keydataA, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(k) { keyA = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyA; }, "keyA", MslTestConstants.TIMEOUT_CRYPTO);
            
            var exception;
            runs(function() {
                cryptoContext.wrap(keyA, encoder, ENCODER_FORMAT, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.WRAP_NOT_SUPPORTED));
            });
        });
        
        it("unwrap", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext.Mode.ENCRYPT_DECRYPT);
            
            var exception;
            runs(function() {
                cryptoContext.unwrap(message, null, null, encoder, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED));
            });
        });
    	
    	it("sign/verify", function() {
    		var messageA = new Uint8Array(32);
    		random.nextBytes(messageA);
    		
    		var messageB = new Uint8Array(32);
    		random.nextBytes(messageB);
    		
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext.Mode.SIGN_VERIFY);
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
    		waitsFor(function() { return signatureA && signatureB; }, "signatures", MslTestConstants.TIMEOUT_CRYPTO);
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
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
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
    		waitsFor(function() { return verifiedAA !== undefined && verifiedBB !== undefined && verifiedBA !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	    		expect(verifiedAA).toBeTruthy();
	    		expect(verifiedBB).toBeTruthy();
	    		expect(verifiedBA).toBeFalsy();
    		});
    	});
    	
    	it("sign/verify with mismatched contexts", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext.Mode.SIGN_VERIFY);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, RsaCryptoContext.Mode.SIGN_VERIFY);
    		var signature;
    		runs(function() {
    			cryptoContextA.sign(message, encoder, ENCODER_FORMAT, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);
    		var verified;
    		runs(function() {
    			cryptoContextB.verify(message, signature, encoder, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
    			expect(verified).toBeFalsy();
    		});
    	});
    	
    	it("sign with null private key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, RsaCryptoContext.Mode.SIGN_VERIFY);
	    	var exception;
	    	runs(function() {
	    		cryptoContext.sign(message, encoder, ENCODER_FORMAT, {
	    			result: function() {},
	    			error: function(err) { exception = err; }
	    		});
    		});
	    	waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT_CRYPTO);
    		runs(function() {
	    		var f = function() { throw exception; };
	    		expect(f).toThrow(new MslCryptoException(MslError.SIGN_NOT_SUPPORTED));
    		});
    	});
    	
    	it("verify with null public key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, RsaCryptoContext.Mode.SIGN_VERIFY);
    		
    		var signature;
    		runs(function() {
    			cryptoContext.sign(message, encoder, ENCODER_FORMAT, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		var exception;
    		runs(function() {
    			cryptoContext.verify(message, signature, encoder, {
    				result: function() {},
    				error: function(err) { exception = err; }
    			});
    		});
    		runs(function() {
	    		var f = function() { throw exception; };
	    		expect(f).toThrow(new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED));
    		});
    	});
    });
});
