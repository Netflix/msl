/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
	/** RSA keypair A. */
	var RSA_KEYPAIR_A = {
		privateKey:
			"-----BEGIN RSA PRIVATE KEY-----\n" +
			"MIICWwIBAAKBgQCeZQW2kdq8pTi+v+z0ACkAQtVz5ohv/2cZOOXAEiGnEhHMR1jT\n" +
			"/O2uUDsVnpY8Y+qDAE0rJVV6NJnB+txzA13Yd5MAGRfnkCyDKCkpmd29BzmgN1/A\n" +
			"YNvL99DbFdEZnZSzzxT4dYUoJ3xx2fnmV7E4Vh8kJMJfbusw2a+d/yRD0wIDAQAB\n" +
			"AoGAQpM/lX80qzne4f4VgHFYym1M/owVKM327ZkGqHZ2gpyLsosCgQe8dxnt26Zu\n" +
			"iy+L8Ef+J3ZnuRfG0Mu6QPVXSe2hS/wzvFlEcEidI/97fOUWRHRmZn0WKmDnYqzq\n" +
			"4trC+0VTTzvnUpVtS5rHj6Xn15rLN1kqxRsP0LR6FftRZmECQQDJ5oz/MyyWU83s\n" +
			"L7KQ5mXhmuHQdZP4pPV7O5duGb7RydYJY55RydGVlRPFR8tysO89Tudmz1Dx4smI\n" +
			"I0oUiN6ZAkEAyNYpoYtu0Ll8Xdhy2N4YfAoNIXcl9k5yy000vte3h8PlVZaxaczJ\n" +
			"cyStPhjQN3CJm1fKpp8dYNPg7mDw9tyVSwJALM8XQdhIsABfdmjLl68as2xda5d8\n" +
			"xLVPqg76t7vNBuBluWW7kGlbM3iHj8Q0Wfr8zb2CS+X9EAIGOkmiulX6GQJAYAA3\n" +
			"UDgVVYKEl1tispWfgJNRaYDJza38I4AZSWxWF3ilhD8POTKhzP9oLHmx9f4+WNoj\n" +
			"TXhbk7BUIb6HEImqdwJACY4w5EpkWXquA2EJu/MpTIzROi1bDD0hNToKbTPKWtw8\n" +
			"pXmFVRGmEZmcJIEnPfu9y7TMgRjCPIz4CswGOu2zbg==\n" +
			"-----END RSA PRIVATE KEY-----",
		// PKCS#1 RSA Public Key Format
		publicKey:
			"-----BEGIN PUBLIC KEY-----\n" +
			"MIGJAoGBAJ5lBbaR2rylOL6/7PQAKQBC1XPmiG//Zxk45cASIacSEcxHWNP87a5Q\n" +
			"OxWeljxj6oMATSslVXo0mcH63HMDXdh3kwAZF+eQLIMoKSmZ3b0HOaA3X8Bg28v3\n" +
			"0NsV0RmdlLPPFPh1hSgnfHHZ+eZXsThWHyQkwl9u6zDZr53/JEPTAgMBAAE=\n" +
			"-----END PUBLIC KEY-----",
	};
	/** RSA keypair B. */
	var RSA_KEYPAIR_B = {
		privateKey:
			"-----BEGIN RSA PRIVATE KEY-----\n" +
			"MIICWwIBAAKBgQDmFkuuushqzchxoO5v4HYKAbg17PqTCHiqjTsHiI8rDK8SDsYJ\n" +
			"Syqg+iHme6dQWzxMV1yZLGOIEjQu9AngAQ0OxKKm13tA/U0zTfyTEZyK3p3rveXK\n" +
			"us2tMeVlrJLyhzt62lPcBKf2BEu5lLJIq2TQPhUzE2fdnEl82P5NEOnXuwIDAQAB\n" +
			"AoGALxcfFDrMK/fD72WVhzY0UmX5sqe2vQL910Iic69CRfhJmHOHmn1U0y9+YrKq\n" +
			"EqspkyJKJFtOX5oCLh3qK3trlVfVwvqrswNqZIQI3Lm3jmzMdoEBTJV44hwV4QPn\n" +
			"dupmozSsKXScJzphNSM+fjRTZHqdZmfSDa9mwwxLzlnTpbkCQQD1RycQazPDnV5s\n" +
			"daDFaEoKiJKKF24TnKTey+l3SaBLgJM9nfV6ZMQM0fhu5AO6FWMGKK8PJy2VWf0+\n" +
			"jsHszzs1AkEA8CUlVw2nIeD/kW9rBj+p91s8RzhkbOnGBURoWAOCGn2qVx25ybFO\n" +
			"IJ3a8XqlKI1/dujtWQr4VcpKlNPFSKw1LwJABqxL5Md13hGO+xZsLFK9CPJUQkuG\n" +
			"5COz3Jfhnywynzs9RkTg49aP+uVPg/zSGSLx0b4TnS7sr46GNEiAAChXLQJAJDP1\n" +
			"ZSJRx/G7lZlOcSq33OqMM9B0k1bK25Bsipg8zPGU9H0uvRFVzeT+VNlAfNSYGr0S\n" +
			"yxG0Tnqos7cZTtNnUQJARrojuTuWPTsLzoTVNZqkiw7mmVNxUPVF1cIarffN1vqP\n" +
			"QaITNTUkBgbo3b04YyHgdgtS5O+hvpxa+mCPOmQzcg==\n" +
			"-----END RSA PRIVATE KEY-----",
		// PKCS#1 RSA Public Key Format
		publicKey:
			"-----BEGIN PUBLIC KEY-----\n" +
			"MIGJAoGBAOYWS666yGrNyHGg7m/gdgoBuDXs+pMIeKqNOweIjysMrxIOxglLKqD6\n" +
			"IeZ7p1BbPExXXJksY4gSNC70CeABDQ7EoqbXe0D9TTNN/JMRnIreneu95cq6za0x\n" +
			"5WWskvKHO3raU9wEp/YES7mUskirZNA+FTMTZ92cSXzY/k0Q6de7AgMBAAE=\n" +
			"-----END PUBLIC KEY-----",
	};

	
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
    
    /** Random. */
    var random = new Random();
    /** Message. */
    var message = new Uint8Array(32);
    random.nextBytes(message);
    /** MSL context. */
    var ctx;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                
                var aes128Bytes = new Uint8Array(16);
                random.nextBytes(aes128Bytes);
                var hmac256Bytes = new Uint8Array(32);
                random.nextBytes(hmac256Bytes);
                CipherKey$import(aes128Bytes, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(k) { AES_128_KEY = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                CipherKey$import(hmac256Bytes, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function(k) { HMAC_256_KEY = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx && AES_128_KEY && HMAC_256_KEY; }, "static initialization", 300);
            runs(function() {
                SYMMETRIC_CRYPTO_CONTEXT = new SymmetricCryptoContext(ctx, KEY_ID, AES_128_KEY, HMAC_256_KEY, null);
                initialized = true;
            });
        }
    });
    
    function encryptDecryptData() {
        var params = [];
        var webCryptoVersion = MslCrypto$getWebCryptoVersion();
        if (webCryptoVersion == MslCrypto$WebCryptoVersion.V2014_01) {
            params.push([ WebCryptoAlgorithm.RSAES, RsaCryptoContext$Mode.ENCRYPT_DECRYPT_PKCS1, 32 ]);
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
                // TODO: read from RSA_KEYPAIR_A.publicKey
                // TODO: read from RSA_KEYPAIR_A.privateKey
                MslTestUtils.generateRsaKeys(algorithm, WebCryptoUsage.ENCRYPT_DECRYPT, 512, {
                    result: function(publicKey, privateKey) {
                        publicKeyA = publicKey;
                        privateKeyA = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return publicKeyA && privateKeyA; }, "did not create publicKeyA && privateKeyA", 300);

            runs(function() {
                // TODO: read from RSA_KEYPAIR_B.publicKey
                // TODO: read from RSA_KEYPAIR_B.privateKey
                MslTestUtils.generateRsaKeys(algorithm, WebCryptoUsage.ENCRYPT_DECRYPT, 512, {
                    result: function(publicKey, privateKey) {
                        publicKeyB = publicKey;
                        privateKeyB = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function () { return publicKeyB && privateKeyB; }, "did not create publicKeyB && privateKeyB", 300);
        });
        
    	it("encrypt/decrypt", function() {
    		var messageA = new Uint8Array(messageSize);
    		random.nextBytes(messageA);
            
            var messageB = new Uint8Array(messageSize);
            random.nextBytes(messageB);
    		
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
    		var ciphertextA = undefined, ciphertextB;
    		runs(function() {
    			cryptoContext.encrypt(messageA, {
    				result: function(c) { ciphertextA = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    			cryptoContext.encrypt(messageB, {
    				result: function(c) { ciphertextB = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertextA && ciphertextB; }, "did not receive ciphertext", 300);
    		
    		runs(function() {
	    		expect(ciphertextA).not.toBeNull();
	    		expect(ciphertextA).not.toEqual(messageA);
	
	            expect(ciphertextB).not.toBeNull();
	            expect(ciphertextB).not.toEqual(messageB);
	            expect(ciphertextB).not.toEqual(ciphertextA);
    		});
    		
    		var plaintextA = undefined, plaintextB;
    		runs(function() {
    			cryptoContext.decrypt(ciphertextA, {
    				result: function(p) { plaintextA = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    			cryptoContext.decrypt(ciphertextB, {
    				result: function(p) { plaintextB = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return plaintextA && plaintextB; }, "did not receive plaintext", 300);
    		
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
    		waitsFor(function() { return exception; }, "exception", 300);
    		
    		runs(function() {
    			var f = function() { throw exception; };
    			expect(f).toThrow(new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED));
    		});
    	});
    	
    	it("decrypt with null private key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
    		var ciphertext;
    		runs(function() {
    			cryptoContext.encrypt(message, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});;
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", 300);
    		
    		var exception;
    		runs(function() {
	    		cryptoContext.decrypt(ciphertext, {
	    			result: function() {},
	    			error: function(err) { exception = err; }
	    		});
    		});
			waitsFor(function() { return exception; }, "exception", 300);
			
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
    			cryptoContextA.encrypt(message, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", 300);
    		
    		var exception;
    		runs(function() {
    			cryptoContextB.decrypt(ciphertext, {
    				result: function() {},
    				error: function(err) { exception = err; }
    			});
    		});
    		waitsFor(function() { return exception; }, "exception", 300);
    		
    		runs(function() {
    			var f = function() { throw exception; };
    			expect(f).toThrow(new MslCryptoException(MslError.ENVELOPE_KEY_ID_MISMATCH));
    		});
    	});

    	it("encrypt/decrypt with mismatched keys", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, mode);

    		var ciphertext;
    		runs(function() {
    			cryptoContextA.encrypt(message, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", 300);
    		
    		var exception;
    		runs(function() {
    			cryptoContextB.decrypt(ciphertext, {
    				result: function() {},
    				error: function(err) { exception = err; }
    			});
    		});
    		waitsFor(function() { return exception; }, "exception", 300);
    		
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
                CipherKey$import(keydataA, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(k) { keyA = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyA; }, "keyA", 300);
            
            var exception;
            runs(function() {
                cryptoContext.wrap(keyA, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 300);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.WRAP_NOT_SUPPORTED));
            });
        });
        
        it("unwrap", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            
            var exception;
            runs(function() {
                cryptoContext.unwrap(message, null, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 300);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.UNWRAP_NOT_SUPPORTED));
            });
        });
    	
    	it("sign/verify", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
    		var signature;
    		runs(function() {
    			cryptoContext.sign(message, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", 300);
    		
    		runs(function() {
	    		expect(signature).not.toBeNull();
	    		expect(signature.length).toEqual(0);
    		});
    		
    		var verified;
    		runs(function() {
    			cryptoContext.verify(message, signature, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", 300);
    		
    		runs(function() {
	    		expect(verified).toBeTruthy();
    		});
    	});
    	
    	it("sign/verify with mismatched contexts", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, mode);
    		var signature;
    		runs(function() {
    			cryptoContextA.sign(message, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", 300);
    		var verified;
    		runs(function() {
    			cryptoContextB.verify(message, signature, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", 300);
    		runs(function() {
    			expect(verified).toBeTruthy();
    		});
    	});
    	
    	it("sign with null private key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
    		var signature;
    		runs(function() {
    			cryptoContext.sign(message, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", 300);
    		runs(function() {
	    		expect(signature).not.toBeNull();
	    		expect(signature.length).toEqual(0);
    		});
    		var verified;
    		runs(function() {
    			cryptoContext.verify(message, signature, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", 300);
    		runs(function() {
    			expect(verified).toBeTruthy();
    		});
    	});
    	
    	it("verify with null public key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
    		var signature;
    		runs(function() {
    			cryptoContext.sign(message, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", 300);
    		runs(function() {
	    		expect(signature).not.toBeNull();
	    		expect(signature.length).toEqual(0);
    		});
    		var verified;
    		runs(function() {
    			cryptoContext.verify(message, signature, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", 300);
    		runs(function() {
    			expect(verified).toBeTruthy();
    		});
    	});
    });
    
    function wrapUnwrapData() {
        var params = [];
        var webCryptoVersion = MslCrypto$getWebCryptoVersion();
        if (webCryptoVersion == MslCrypto$WebCryptoVersion.LEGACY) {
        } else if (webCryptoVersion == MslCrypto$WebCryptoVersion.V2014_01) {
            params.push([ WebCryptoAlgorithm.RSA_OAEP, RsaCryptoContext$Mode.WRAP_UNWRAP_OAEP ]);
            params.push([ WebCryptoAlgorithm.RSAES, RsaCryptoContext$Mode.WRAP_UNWRAP_PKCS1 ]);
        } else {
            params.push([ WebCryptoAlgorithm.RSA_OAEP, RsaCryptoContext$Mode.WRAP_UNWRAP_OAEP ]);
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
                cryptoContext.encrypt(message, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", 300);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContext.decrypt(ciphertext, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", 300);
            runs(function() {
                expect(plaintext).not.toBeNull();
                expect(plaintext).toEqual(message);
            });
        });

        it("encrypt with null public key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
            var ciphertext;
            runs(function() {
                cryptoContext.encrypt(message, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", 300);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContext.decrypt(ciphertext, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", 300);
            runs(function() {
                expect(plaintext).not.toBeNull();
                expect(plaintext).toEqual(message);
            });
        });

        it("decrypt with null private key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
            var ciphertext;
            runs(function() {
                cryptoContext.encrypt(message, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", 300);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContext.decrypt(ciphertext, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", 300);
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
                cryptoContextA.encrypt(message, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", 300);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContextB.decrypt(ciphertext, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", 300);
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
                cryptoContextA.encrypt(message, {
                    result: function(c) { ciphertext = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ciphertext; }, "ciphertext", 300);
            runs(function() {
                expect(ciphertext).not.toBeNull();
                expect(ciphertext).toEqual(message);
            });

            var plaintext;
            runs(function() {
                cryptoContextB.decrypt(ciphertext, {
                    result: function(p) { plaintext = p; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return plaintext; }, "plaintext", 300);
            runs(function() {
                expect(plaintext).not.toBeNull();
                expect(plaintext).toEqual(message);
            });
        });

        it("wrap/unwrap AES-128 key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);

            var wrapped;
            runs(function() {
                cryptoContext.wrap(AES_128_KEY, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped", 300);

            var unwrapped;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(AES_128_KEY.toByteArray());
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(key) { unwrapped = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unwrapped; }, "unwrapped", 300);

            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var wrapCryptoContext, refCiphertext, wrapCiphertext;
            runs(function() {
                wrapCryptoContext = new SymmetricCryptoContext(ctx, KEY_ID, unwrapped, null, null);
                SYMMETRIC_CRYPTO_CONTEXT.encrypt(message, {
                    result: function(x) { refCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                wrapCryptoContext.encrypt(message, {
                    result: function(x) { wrapCiphertext = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refCiphertext && wrapCiphertext; }, "ciphertexts", 300);
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
            waitsFor(function() { return refPlaintext && wrapPlaintext; }, "plaintexts", 300);
            runs(function() {
                expect(wrapPlaintext).toEqual(refPlaintext);
            });
        });

        it("wrap/unwrap HMAC-SHA256 key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);

            var wrapped;
            runs(function() {
                cryptoContext.wrap(HMAC_256_KEY, {
                    result: function(data) { wrapped = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return wrapped; }, "wrapped", 300);
            var unwrapped;
            runs(function() {
                expect(wrapped).not.toBeNull();
                expect(wrapped).not.toEqual(HMAC_256_KEY.toByteArray());
                cryptoContext.unwrap(wrapped, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function(key) { unwrapped = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unwrapped; }, "unwrapped", 300);

            // We must verify the unwrapped key by performing a crypto
            // operation as the wrapped key is not exportable.
            var refHmac, wrapHmac;
            runs(function() {
                SYMMETRIC_CRYPTO_CONTEXT.sign(message, {
                    result: function(x) { refHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                var wrapCryptoContext = new SymmetricCryptoContext(ctx, KEY_ID, null, unwrapped, null);
                wrapCryptoContext.sign(message, {
                    result: function(x) { wrapHmac = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return refHmac && wrapHmac; }, "hmacs", 300);
            runs(function() {
                expect(wrapHmac).toEqual(refHmac);
            });
        });

        it("sign/verify", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            var signature;
            runs(function() {
                cryptoContext.sign(message, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return signature; }, "signature", 300);

            runs(function() {
                expect(signature).not.toBeNull();
                expect(signature.length).toEqual(0);
            });

            var verified;
            runs(function() {
                cryptoContext.verify(message, signature, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", 300);

            runs(function() {
                expect(verified).toBeTruthy();
            });
        });

        it("sign/verify with mismatched contexts", function() {
            var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, mode);
            var signature;
            runs(function() {
                cryptoContextA.sign(message, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signature; }, "signature", 300);
            var verified;
            runs(function() {
                cryptoContextB.verify(message, signature, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", 300);
            runs(function() {
                expect(verified).toBeTruthy();
            });
        });

        it("sign with null private key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
            var signature;
            runs(function() {
                cryptoContext.sign(message, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signature; }, "signature", 300);
            runs(function() {
                expect(signature).not.toBeNull();
                expect(signature.length).toEqual(0);
            });
            var verified;
            runs(function() {
                cryptoContext.verify(message, signature, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", 300);
            runs(function() {
                expect(verified).toBeTruthy();
            });
        });

        it("verify with null public key", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
            var signature;
            runs(function() {
                cryptoContext.sign(message, {
                    result: function(s) { signature = s; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return signature; }, "signature", 300);
            runs(function() {
                expect(signature).not.toBeNull();
                expect(signature.length).toEqual(0);
            });
            var verified;
            runs(function() {
                cryptoContext.verify(message, signature, {
                    result: function(v) { verified = v; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return verified !== undefined; }, "verified", 300);
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
                MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSASSA, WebCryptoUsage.SIGN_VERIFY, 512, {
                    result: function(publicKey, privateKey) {
                        publicKeyA = publicKey;
                        privateKeyA = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return publicKeyA && privateKeyA; }, "publicKeyA && privateKeyA", 300);

            runs(function() {
                // TODO: read from RSA_KEYPAIR_B.publicKey
                // TODO: read from RSA_KEYPAIR_B.privateKey
                MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSASSA, WebCryptoUsage.SIGN_VERIFY, 512, {
                    result: function(publicKey, privateKey) {
                        publicKeyB = publicKey;
                        privateKeyB = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function () { return publicKeyB && privateKeyB; }, "publicKeyB && privateKeyB", 300);
            
            runs(function() { initialized = true; });
        });
        
    	it("encrypt/decrypt", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext$Mode.SIGN_VERIFY);
    		var ciphertext;
    		runs(function() {
    			cryptoContext.encrypt(message, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", 300);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});
    		
    		var plaintext;
    		runs(function() {
    			cryptoContext.decrypt(ciphertext, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", 300);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
    	
    	it("encrypt with null public key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, RsaCryptoContext$Mode.SIGN_VERIFY);
    		var ciphertext;
    		runs(function() {
    			cryptoContext.encrypt(message, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", 300);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});
    		
    		var plaintext;
    		runs(function() {
    			cryptoContext.decrypt(ciphertext, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", 300);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
    	
    	it("decrypt with null private key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, RsaCryptoContext$Mode.SIGN_VERIFY);
    		var ciphertext;
    		runs(function() {
    			cryptoContext.encrypt(message, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", 300);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});
    		
    		var plaintext;
    		runs(function() {
    			cryptoContext.decrypt(ciphertext, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", 300);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
    	
    	it("encrypt/decrypt with mismatched key ID", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID + 'A', privateKeyA, publicKeyA, RsaCryptoContext$Mode.SIGN_VERIFY);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID + 'B', privateKeyA, publicKeyA, RsaCryptoContext$Mode.SIGN_VERIFY);
    			
    		var ciphertext;
    		runs(function() {
    			cryptoContextA.encrypt(message, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", 300);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});
    		
    		var plaintext;
    		runs(function() {
    			cryptoContextB.decrypt(ciphertext, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", 300);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
    	
    	it("encrypt/decrypt with mismatched keys", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext$Mode.SIGN_VERIFY);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, RsaCryptoContext$Mode.SIGN_VERIFY);
    			
    		var ciphertext;
    		runs(function() {
    			cryptoContextA.encrypt(message, {
    				result: function(c) { ciphertext = c; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ciphertext; }, "ciphertext", 300);
    		runs(function() {
	    		expect(ciphertext).not.toBeNull();
	    		expect(ciphertext).toEqual(message);
    		});

    		var plaintext;
    		runs(function() {
    			cryptoContextB.decrypt(ciphertext, {
    				result: function(p) { plaintext = p; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return plaintext; }, "plaintext", 300);
    		runs(function() {
	            expect(plaintext).not.toBeNull();
	            expect(plaintext).toEqual(message);
    		});
    	});
        
        it("wrap", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext$Mode.ENCRYPT_DECRYPT);
            
            var keyA;
            runs(function() {
                var keydataA = new Uint8Array(16);
                random.nextBytes(keydataA);
                CipherKey$import(keydataA, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(k) { keyA = k; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyA; }, "keyA", 300);
            
            var exception;
            runs(function() {
                cryptoContext.wrap(keyA, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 300);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslCryptoException(MslError.WRAP_NOT_SUPPORTED));
            });
        });
        
        it("unwrap", function() {
            var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext$Mode.ENCRYPT_DECRYPT);
            
            var exception;
            runs(function() {
                cryptoContext.unwrap(message, null, null, {
                    result: function() {},
                    error: function(e) { exception = e; }
                });
            });
            waitsFor(function() { return exception; }, "exception", 300);
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
    		
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext$Mode.SIGN_VERIFY);
    		var signatureA = undefined, signatureB;
    		runs(function() {
    			cryptoContext.sign(messageA, {
    				result: function(s) { signatureA = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    			cryptoContext.sign(messageB, {
    				result: function(s) { signatureB = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return signatureA && signatureB; }, "signatures", 300);
    		runs(function() {
	    		expect(signatureA).not.toBeNull();
	    		expect(signatureA.length).toBeGreaterThan(0);
	    		expect(signatureA).not.toEqual(messageA);
	    		
	    		expect(signatureB.length).toBeGreaterThan(0);
	    		expect(signatureB).not.toEqual(signatureA);
    		}); 
    		
    		var verifiedAA = undefined, verifiedBB = undefined, verifiedBA;
    		runs(function() {
    			cryptoContext.verify(messageA, signatureA, {
    				result: function(v) { verifiedAA = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    			cryptoContext.verify(messageB, signatureB, {
    				result: function(v) { verifiedBB = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    			cryptoContext.verify(messageB, signatureA, {
    				result: function(v) { verifiedBA = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return verifiedAA !== undefined && verifiedBB !== undefined && verifiedBA !== undefined; }, "verified", 300);
    		runs(function() {
	    		expect(verifiedAA).toBeTruthy();
	    		expect(verifiedBB).toBeTruthy();
	    		expect(verifiedBA).toBeFalsy();
    		});
    	});
    	
    	it("sign/verify with mismatched contexts", function() {
    		var cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext$Mode.SIGN_VERIFY);
    		var cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, RsaCryptoContext$Mode.SIGN_VERIFY);
    		var signature;
    		runs(function() {
    			cryptoContextA.sign(message, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", 300);
    		var verified;
    		runs(function() {
    			cryptoContextB.verify(message, signature, {
    				result: function(v) { verified = v; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return verified !== undefined; }, "verified", 300);
    		runs(function() {
    			expect(verified).toBeFalsy();
    		});
    	});
    	
    	it("sign with null private key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, RsaCryptoContext$Mode.SIGN_VERIFY);
	    	var exception;
	    	runs(function() {
	    		cryptoContext.sign(message, {
	    			result: function() {},
	    			error: function(err) { exception = err; }
	    		});
    		});
	    	waitsFor(function() { return exception; }, "exception", 300);
    		runs(function() {
	    		var f = function() { throw exception; };
	    		expect(f).toThrow(new MslCryptoException(MslError.SIGN_NOT_SUPPORTED));
    		});
    	});
    	
    	it("verify with null public key", function() {
    		var cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, RsaCryptoContext$Mode.SIGN_VERIFY);
    		
    		var signature;
    		runs(function() {
    			cryptoContext.sign(message, {
    				result: function(s) { signature = s; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
    			});
    		});
    		waitsFor(function() { return signature; }, "signature", 300);
    		
    		var exception;
    		runs(function() {
    			cryptoContext.verify(message, signature, {
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
