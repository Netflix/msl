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
 * Asymmetric wrapped key exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("AsymmetricWrappedExchangeSuite", function() {
    /** EC curve q. */
    var EC_Q = new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839");
    /** EC coefficient a. */
    var EC_A = new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16);
    /** EC coefficient b. */
    var EC_B = new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16);
    
    /** EC base point g. */
    var EC_G = new BigInteger("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf", 16);
    /** EC generator order n. */
    var EC_N = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");
    
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
	
    /** JSON key key exchange scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key key request data. */
    var KEY_KEYDATA = "keydata";
    
    /** JSON key key pair ID. */
    var KEY_KEY_PAIR_ID = "keypairid";
    /** JSON key encrypted encryption key. */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /** JSON key encrypted HMAC key. */
    var KEY_HMAC_KEY = "hmackey";
    
    /** MSL context. */
    var ctx;
    
    var KEYPAIR_ID = "keypairId";
    var ECC_PUBLIC_KEY;
    var ECC_PRIVATE_KEY;
    var RSA_OAEP_PUBLIC_KEY;
    var RSA_OAEP_PRIVATE_KEY;
    var RSAES_PUBLIC_KEY;
    var RSAES_PRIVATE_KEY;
    
    var IDENTITY = MockPresharedAuthenticationFactory.PSK_ESN;
    var MASTER_TOKEN;
    var ENCRYPTION_KEY;
    var HMAC_KEY;
    
    var initialized = false;
    beforeEach(function() {
    	if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return "ctx"; }, "ctx", 300);
            
            runs(function() {
                MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSA_OAEP, WebCryptoUsage.WRAP_UNWRAP, 2048, {
                    result: function(publicKey, privateKey) {
                        RSA_OAEP_PUBLIC_KEY = publicKey;
                        RSA_OAEP_PRIVATE_KEY = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return RSA_OAEP_PUBLIC_KEY && RSA_OAEP_PRIVATE_KEY; }, "RSA-OAEP keys", 2500);
            
            runs(function() {
                if (MslCrypto$getWebCryptoVersion() != MslCrypto$WebCryptoVersion.V2014_01) {
                    // These keys will not be used in the legacy unit tests.
                    RSAES_PUBLIC_KEY = true;
                    RSAES_PRIVATE_KEY = true;
                } else {
                    MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSAES, WebCryptoUsage.WRAP_UNWRAP, 2048, {
                        result: function(publicKey, privateKey) {
                            RSAES_PUBLIC_KEY = publicKey;
                            RSAES_PRIVATE_KEY = privateKey;
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                }
            });
            waitsFor(function() { return RSAES_PUBLIC_KEY && RSAES_PRIVATE_KEY; }, "RSAES keys", 2500);
            
    		runs(function() {
    			MslTestUtils.getMasterToken(ctx, 1, 1, {
    				result: function(masterToken) {
    					MASTER_TOKEN = masterToken;
    					ENCRYPTION_KEY = MASTER_TOKEN.encryptionKey.toByteArray();
    					HMAC_KEY = MASTER_TOKEN.signatureKey.toByteArray();
    				},
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return MASTER_TOKEN && ENCRYPTION_KEY && HMAC_KEY; }, "static intialization", 300);
    		
    		runs(function() { initialized = true; });
    	}
    });
    
    // Shortcuts.
    var Mechanism = AsymmetricWrappedExchange$Mechanism;
    var RequestData = AsymmetricWrappedExchange$RequestData;
    var RequestData$parse = AsymmetricWrappedExchange$RequestData$parse;
    var ResponseData = AsymmetricWrappedExchange$ResponseData;
    var ResponseData$parse = AsymmetricWrappedExchange$ResponseData$parse;
    
    /** Request data unit tests. */
    describe("RequestData", function() {
        /** JSON key key pair ID. */
        var KEY_KEY_PAIR_ID = "keypairid";
        /** JSON key mechanism. */
        var KEY_MECHANISM = "mechanism";
        /** JSON key public key. */
        var KEY_PUBLIC_KEY = "publickey";

        function keyxRequestData() {
            var params = [];
            var webCryptoVersion = MslCrypto$getWebCryptoVersion();
            if (webCryptoVersion == MslCrypto$WebCryptoVersion.LEGACY) {
                params.push([ Mechanism.JWE_RSA ]);
                params.push([ Mechanism.JWEJS_RSA ]);
            } else if (webCryptoVersion == MslCrypto$WebCryptoVersion.V2014_01) {
                params.push([ Mechanism.JWK_RSA ]);
                params.push([ Mechanism.JWK_RSAES ]);
            } else {
                params.push([ Mechanism.JWK_RSA ]);
            }
            return params;
        }
        
        parameterize("Parameterized", keyxRequestData, function(mechanism) {
            var publicKey, privateKey;
            beforeEach(function() {
                switch (mechanism) {
                    case Mechanism.JWE_RSA:
                    case Mechanism.JWEJS_RSA:
                    case Mechanism.JWK_RSA:
                        publicKey = RSA_OAEP_PUBLIC_KEY;
                        privateKey = RSA_OAEP_PRIVATE_KEY;
                        break;
                    case Mechanism.JWK_RSAES:
                        publicKey = RSAES_PUBLIC_KEY;
                        privateKey = RSAES_PRIVATE_KEY;
                        break;
                    default:
                        throw new Error("Unsupported key exchange mechanism " + mechanism + ".");
                }
            });
            
            it("ctors", function() {
                var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                expect(req.keyExchangeScheme).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
                expect(req.keyPairId).toEqual(KEYPAIR_ID);
                expect(req.mechanism).toEqual(mechanism);
                expect(req.privateKey.getEncoded()).toEqual(privateKey.getEncoded());
                expect(req.publicKey.getEncoded()).toEqual(publicKey.getEncoded());
                var keydata = req.getKeydata();
                expect(keydata).not.toBeNull();

                var joReq;
                runs(function() {
                    RequestData$parse(keydata, {
                        result: function(data) { joReq = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return joReq; }, "joReq not received", 100);

                runs(function() {
                    expect(joReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
                    expect(joReq.keyPairId).toEqual(req.keyPairId);
                    expect(joReq.mechanism).toEqual(req.mechanism);
                    expect(joReq.privateKey).toBeNull();
                    expect(joReq.publicKey.getEncoded()).toEqual(req.publicKey.getEncoded());
                    var joKeydata = joReq.getKeydata();
                    expect(joKeydata).not.toBeNull();
                    expect(joKeydata).toEqual(keydata);
                });
            });

            it("json is correct", function() {
                var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                var jo = JSON.parse(JSON.stringify(req));
                expect(jo[KEY_SCHEME]).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
                var keydata = jo[KEY_KEYDATA];
                expect(keydata[KEY_KEY_PAIR_ID]).toEqual(KEYPAIR_ID);
                expect(keydata[KEY_MECHANISM]).toEqual(mechanism);
                expect(base64$decode(keydata[KEY_PUBLIC_KEY])).toEqual(publicKey.getEncoded());
            });

            it("create", function() {
                var data = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                var jsonString = JSON.stringify(data);
                var jo = JSON.parse(jsonString);
                var keyRequestData;
                runs(function() {
                    KeyRequestData$parse(ctx, jo, {
                        result: function(data) { keyRequestData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyRequestData; }, "keyRequestData not received", 100);

                runs(function() {
                    expect(keyRequestData).not.toBeNull();
                    expect(keyRequestData instanceof RequestData).toBeTruthy();

                    var joData = keyRequestData;
                    expect(joData.keyExchangeScheme).toEqual(data.keyExchangeScheme);
                    expect(joData.keyPairId).toEqual(data.keyPairId);
                    expect(joData.mechanism).toEqual(data.mechanism);
                    expect(joData.privateKey).toBeNull();
                    expect(joData.publicKey.getEncoded()).toEqual(data.publicKey.getEncoded());
                });
            });

            it("missing key pair ID", function() {
                var exception;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    var keydata = req.getKeydata();

                    expect(keydata[KEY_KEY_PAIR_ID]).not.toBeNull();
                    delete keydata[KEY_KEY_PAIR_ID];

                    RequestData$parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", 100);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
                });
            });

            it("missing mechanism", function() {
                var exception;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    var keydata = req.getKeydata();

                    expect(keydata[KEY_MECHANISM]).not.toBeNull();
                    delete keydata[KEY_MECHANISM];

                    RequestData$parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", 100);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
                });
            });

            it("invalid mechanism", function() {
                var exception;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    var keydata = req.getKeydata();

                    keydata[KEY_MECHANISM] = "x";

                    RequestData$parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", 100);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_MECHANISM));
                });
            });

            it("missing public key", function() {
                var exception;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    var keydata = req.getKeydata();

                    expect(keydata[KEY_PUBLIC_KEY]).not.toBeNull();
                    delete keydata[KEY_PUBLIC_KEY];

                    RequestData$parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", 100);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
                });
            });

            it("invalid public key", function() {
                var exception;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    var keydata = req.getKeydata();

                    var encodedKey = publicKey.getEncoded();
                    var shortKey = Arrays$copyOf(encodedKey, 0, encodedKey.length / 2);
                    keydata[KEY_PUBLIC_KEY] = base64$encode(shortKey);

                    RequestData$parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", 100);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslCryptoException(MslError.INVALID_PUBLIC_KEY));
                });
            });
        });
        
        it("equals key pair ID", function() {
            var dataA = new RequestData(KEYPAIR_ID + "A", Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, RSA_OAEP_PRIVATE_KEY);
            var dataB = new RequestData(KEYPAIR_ID + "B", Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, RSA_OAEP_PRIVATE_KEY);
            var dataA2;
            runs(function() {
                RequestData$parse(dataA.getKeydata(), {
                    result: function(data) { dataA2 = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return dataA2; }, "dataA2 not received", 300);
            
            runs(function() {
                expect(dataA.equals(dataA)).toBeTruthy();
                expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

                expect(dataA.equals(dataB)).toBeFalsy();
                expect(dataB.equals(dataA)).toBeFalsy();
                expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

                expect(dataA.equals(dataA2)).toBeFalsy();
                expect(dataA2.equals(dataA)).toBeFalsy();
                expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
            });
        });
        
        it("equals mechanism", function() {
            var dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, RSA_OAEP_PRIVATE_KEY);
            var dataB = new RequestData(KEYPAIR_ID, Mechanism.ECC, RSA_OAEP_PUBLIC_KEY, RSA_OAEP_PRIVATE_KEY);
            var dataA2;
            runs(function() {
                RequestData$parse(dataA.getKeydata(), {
                    result: function(data) { dataA2 = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return dataA2; }, "dataA2 not received", 300);
            
            runs(function() {
                expect(dataA.equals(dataA)).toBeTruthy();
                expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());
                
                expect(dataA.equals(dataB)).toBeFalsy();
                expect(dataB.equals(dataA)).toBeFalsy();
                expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());
                
                expect(dataA.equals(dataA2)).toBeFalsy();
                expect(dataA2.equals(dataA)).toBeFalsy();
                expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
            });
        });
        
        it("equals public key", function() {
        	var rsaPublicKey;
        	runs(function() {
        	    // FIXME: Read from RSA_KEYPAIR_B.
        	    MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSA_OAEP, WebCryptoUsage.WRAP_UNWRAP, 2048, {
        	        result: function(publicKey, privateKey) { rsaPublicKey = publicKey; },
        	        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	    });
        	});
        	waitsFor(function() { return rsaPublicKey; }, "RSA public key", 1200);
        	
        	var dataA = undefined, dataB = undefined, dataA2;
        	runs(function() {
        	    dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, RSA_OAEP_PRIVATE_KEY);
        	    dataB = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, rsaPublicKey, RSA_OAEP_PRIVATE_KEY);
        	    RequestData$parse(dataA.getKeydata(), {
        	        result: function(data) { dataA2 = data; },
        	        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	    });
        	});
        	waitsFor(function() { return dataA && dataB && dataA2; }, "data not received", 300);

        	runs(function() {
        	    expect(dataA.equals(dataA)).toBeTruthy();
        	    expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

        	    expect(dataA.equals(dataB)).toBeFalsy();
        	    expect(dataB.equals(dataA)).toBeFalsy();
        	    expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

        	    expect(dataA.equals(dataA2)).toBeFalsy();
        	    expect(dataA2.equals(dataA)).toBeFalsy();
        	    expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        	});
        });
        
        it("equals private key", function() {
            var rsaPrivateKey;
            runs(function() {
                // FIXME: Read from RSA_KEYPAIR_B.
                MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSA_OAEP, WebCryptoUsage.WRAP_UNWRAP, 2048, {
                    result: function(publicKey, privateKey) { rsaPrivateKey = privateKey; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return rsaPrivateKey; }, "RSA private key", 1200);

            var dataA = undefined, dataB = undefined, dataA2;
            runs(function() {
                dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, RSA_OAEP_PRIVATE_KEY);
                dataB = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, rsaPrivateKey);
                RequestData$parse(dataA.getKeydata(), {
                    result: function(data) { dataA2 = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return dataA2; }, "dataA2 not received", 300);

            runs(function() {    
                expect(dataA.equals(dataA)).toBeTruthy();
                expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

                // The private keys will not be used for equality.
                expect(dataA.equals(dataB)).toBeTruthy();
                expect(dataB.equals(dataA)).toBeTruthy();
                expect(dataB.uniqueKey()).toEqual(dataA.uniqueKey());

                expect(dataA.equals(dataA2)).toBeFalsy();
                expect(dataA2.equals(dataA)).toBeFalsy();
                expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
            });
        });
        
        it("equals object", function() {
            var data = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, RSA_OAEP_PRIVATE_KEY);
            expect(data.equals(null)).toBeFalsy();
            expect(data.equals(IDENTITY)).toBeFalsy();
        });
    });

    /** Response data unit tests. */
    describe("ResponseData", function() {
        /** JSON key master token. */
        var KEY_MASTER_TOKEN = "mastertoken";
        
        it("ctors", function() {
            var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            expect(resp.encryptionKey).toEqual(ENCRYPTION_KEY);
            expect(resp.hmacKey).toEqual(HMAC_KEY);
            expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            expect(resp.keyPairId).toEqual(KEYPAIR_ID);
            expect(resp.masterToken).toEqual(MASTER_TOKEN);
            var keydata = resp.getKeydata();
            expect(keydata).not.toBeNull();

            var joResp = ResponseData$parse(MASTER_TOKEN, keydata);
            expect(joResp.encryptionKey).toEqual(resp.encryptionKey);
            expect(joResp.hmacKey).toEqual(resp.hmacKey);
            expect(joResp.keyExchangeScheme).toEqual(resp.keyExchangeScheme);
            expect(joResp.keyPairId).toEqual(resp.keyPairId);
            expect(joResp.masterToken).toEqual(resp.masterToken);
            var joKeydata = resp.getKeydata();
            expect(joKeydata).not.toBeNull();
            expect(joKeydata).toEqual(keydata);
        });
        
        it("json is correct", function() {
            var masterToken = undefined, jo;
            runs(function() {
                var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
                jo = JSON.parse(JSON.stringify(resp));
                expect(jo[KEY_SCHEME]).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
                
            	MasterToken$parse(ctx, jo[KEY_MASTER_TOKEN], {
            		result: function(token) { masterToken = token; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return jo && masterToken; }, "json object and master token not received", 600);
            runs(function() {
	            expect(masterToken).toEqual(MASTER_TOKEN);
	            var keydata = jo[KEY_KEYDATA];
	            expect(keydata[KEY_KEY_PAIR_ID]).toEqual(KEYPAIR_ID);
	            expect(base64$decode(keydata[KEY_ENCRYPTION_KEY])).toEqual(ENCRYPTION_KEY);
	            expect(base64$decode(keydata[KEY_HMAC_KEY])).toEqual(HMAC_KEY);
            });
        });
        
        it("create", function() {
            var data = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            
            var keyResponseData;
            runs(function() {
                var jsonString = JSON.stringify(data);
                var jo = JSON.parse(jsonString);
                KeyResponseData$parse(ctx, jo, {
                    result: function(data) { keyResponseData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyResponseData; }, "keyResponseData not received", 300);;
            runs(function() {
	            expect(keyResponseData).not.toBeNull();
	            expect(keyResponseData instanceof ResponseData).toBeTruthy();
	            
	            var joData = keyResponseData;
	            expect(joData.encryptionKey).toEqual(data.encryptionKey);
	            expect(joData.hmacKey).toEqual(data.hmacKey);
	            expect(joData.keyExchangeScheme).toEqual(data.keyExchangeScheme);
	            expect(joData.keyPairId).toEqual(data.keyPairId);
	            expect(joData.masterToken).toEqual(data.masterToken);
            });
        });

        it("missing key pair ID", function() {
            var f = function() {
            	var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            	var keydata = resp.getKeydata();

            	expect(keydata[KEY_KEY_PAIR_ID]).not.toBeNull();
            	delete keydata[KEY_KEY_PAIR_ID];

            	ResponseData$parse(MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });

        it("missing encryption key", function() {
            var f = function() {
            	var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            	var keydata = resp.getKeydata();

            	expect(keydata[KEY_ENCRYPTION_KEY]).not.toBeNull();
            	delete keydata[KEY_ENCRYPTION_KEY];

            	ResponseData$parse(MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });

        it("missing HMAC key", function() {
            var f = function() {
            	var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            	var keydata = resp.getKeydata();

            	expect(keydata[KEY_HMAC_KEY]).not.toBeNull();
            	delete keydata[KEY_HMAC_KEY];

            	ResponseData$parse(MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
        
        it("equals master token", function() {
        	var masterTokenA = undefined, masterTokenB;
            runs(function() {
            	MslTestUtils.getMasterToken(ctx, 1, 1, {
            		result: function(token) { masterTokenA = token; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            	});
            	MslTestUtils.getMasterToken(ctx, 1, 2, {
            		result: function(token) { masterTokenB = token; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            	});
            });
            waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 300);
            
            runs(function() {
            	var dataA = new ResponseData(masterTokenA, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            	var dataB = new ResponseData(masterTokenB, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            	var dataA2 = ResponseData$parse(masterTokenA, dataA.getKeydata());
            	
	            expect(dataA.equals(dataA)).toBeTruthy();
	            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());
	            
	            expect(dataA.equals(dataB)).toBeFalsy();
	            expect(dataB.equals(dataA)).toBeFalsy();
	            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());
	            
	            expect(dataA.equals(dataA2)).toBeTruthy();
	            expect(dataA2.equals(dataA)).toBeTruthy();
	            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
            });
        });
        
        it("equals key pair ID", function() {
            var dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID + "A", ENCRYPTION_KEY, HMAC_KEY);
            var dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID + "B", ENCRYPTION_KEY, HMAC_KEY);
            var dataA2 = ResponseData$parse(MASTER_TOKEN, dataA.getKeydata());
 
            expect(dataA.equals(dataA)).toBeTruthy();
            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        });
        
        it("equals encryption key", function() {
            var encryptionKeyA = Arrays$copyOf(ENCRYPTION_KEY);
            var encryptionKeyB = Arrays$copyOf(ENCRYPTION_KEY);
            ++encryptionKeyB[0];
            var dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyA, HMAC_KEY);
            var dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyB, HMAC_KEY);
            var dataA2 = ResponseData$parse(MASTER_TOKEN, dataA.getKeydata());
            
            expect(dataA.equals(dataA)).toBeTruthy();
            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        });
        
        it("equals HMAC key", function() {
            var hmacKeyA = Arrays$copyOf(HMAC_KEY);
            var hmacKeyB = Arrays$copyOf(HMAC_KEY);
            ++hmacKeyB[0];
            var dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyA);
            var dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyB);
            var dataA2 = ResponseData$parse(MASTER_TOKEN, dataA.getKeydata());
            
            expect(dataA.equals(dataA)).toBeTruthy();
            expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA2.uniqueKey()).toEqual(dataA.uniqueKey());
        });
        
        it("equals object", function() {
            var data = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            expect(data.equals(null)).toBeFalsy();
            expect(data.equals(IDENTITY)).toBeFalsy();
        });
    });
    
    /** Key exchange factory unit tests. */
    describe("KeyExchangeFactory", function() {
        /**
         * Fake key request data for the asymmetric wrapped key exchange
         * scheme.
         */
        var FakeKeyRequestData = KeyRequestData.extend({
            /** Create a new fake key request data. */
            init: function init() {
                init.base.call(this, KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            },

            /** @inheritDoc */
            getKeydata: function getKeydata() {
                return null;
            },
        });
        
        /**
         * Fake key response data for the asymmetric wrapped key exchange
         * scheme.
         */
        var FakeKeyResponseData = KeyResponseData.extend({
            /** Create a new fake key response data. */
            init: function init() {
                init.base.call(this, MASTER_TOKEN, KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            },

            /** @inheritDoc */
            getKeydata: function getKeydata() {
                return null;
            },
        });
        
        /** Random. */
        var random = new Random();
        /** Key exchange factory. */
        var factory = new AsymmetricWrappedExchange();
        /** Entity authentication data. */
        var entityAuthData = new PresharedAuthenticationData(IDENTITY);
        
        beforeEach(function() {
            ctx.getMslStore().clearCryptoContexts();
            ctx.getMslStore().clearServiceTokens();
        });
        
        it("factory", function() {
            expect(factory.scheme).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
        });
        
        it("generate initial response with wrong request type", function() {
            var exception;
            runs(function() {
                var keyRequestData = new FakeKeyRequestData();
                factory.generateResponse(ctx, keyRequestData, entityAuthData, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", 300);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        it("generate subsequent response with wrong request type", function() {
            var keyRequestData = new FakeKeyRequestData();
            var exception;
            runs(function() {
                factory.generateResponse(ctx, keyRequestData, MASTER_TOKEN, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", 300);
            
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        function keyxFactoryData() {
            var params = [];
            var webCryptoVersion = MslCrypto$getWebCryptoVersion();
            if (webCryptoVersion == MslCrypto$WebCryptoVersion.LEGACY) {
                params.push([ Mechanism.JWE_RSA ]);
                params.push([ Mechanism.JWEJS_RSA ]);
            } else if (webCryptoVersion == MslCrypto$WebCryptoVersion.V2014_01) {
                params.push([ Mechanism.JWK_RSA ]);
                params.push([ Mechanism.JWK_RSAES ]);
            } else {
                params.push([ Mechanism.JWK_RSA ]);
            }
            return params;
        }
        
        parameterize("Parameterized", keyxFactoryData, function(mechanism) {
            var publicKey, privateKey;
            beforeEach(function() {
                switch (mechanism) {
                    case Mechanism.JWE_RSA:
                    case Mechanism.JWEJS_RSA:
                    case Mechanism.JWK_RSA:
                        publicKey = RSA_OAEP_PUBLIC_KEY;
                        privateKey = RSA_OAEP_PRIVATE_KEY;
                        break;
                    case Mechanism.JWK_RSAES:
                        publicKey = RSAES_PUBLIC_KEY;
                        privateKey = RSAES_PRIVATE_KEY;
                        break;
                    default:
                        throw new Error("Unsupported key exchange mechanism " + mechanism + ".");
                }
            });
            
            it("generate initial response", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", 300);
                runs(function() {
                    expect(keyxData).not.toBeNull();
                    expect(keyxData.cryptoContext).not.toBeNull();
                    expect(keyxData.keyResponseData).not.toBeNull();

                    var keyResponseData = keyxData.keyResponseData;
                    expect(keyResponseData.keyExchangeScheme).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
                    var masterToken = keyResponseData.masterToken;
                    expect(masterToken).not.toBeNull();
                    expect(masterToken.identity).toEqual(IDENTITY);
                });
            });

            it("generate subsequent response", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, keyRequestData, MASTER_TOKEN, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", 300);
                runs(function() {
                    expect(keyxData).not.toBeNull();
                    expect(keyxData.cryptoContext).not.toBeNull();
                    expect(keyxData.keyResponseData).not.toBeNull();

                    var keyResponseData = keyxData.keyResponseData;
                    expect(keyResponseData.keyExchangeScheme).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
                    var masterToken = keyResponseData.masterToken;
                    expect(masterToken).not.toBeNull();
                    expect(masterToken.identity).toEqual(MASTER_TOKEN.identity);
                    expect(masterToken.serialNumber).toEqual(MASTER_TOKEN.serialNumber);
                    expect(masterToken.sequenceNumber).toEqual(MASTER_TOKEN.sequenceNumber + 1);
                });
            });

            it("generate subsequent response with untrusted master token", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);

                var masterToken;
                runs(function() {
                    MslTestUtils.getUntrustedMasterToken(ctx, {
                        result: function(token) { masterToken = token; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                });
                waitsFor(function() { return masterToken; }, "master token not received", 300);

                var exception;
                runs(function() {
                    factory.generateResponse(ctx, keyRequestData, masterToken, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not received", 300);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslMasterTokenException(MslError.NONE));
                });
            });

            it("get crypto context", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", 300);

                var data = new Uint8Array(32);
                random.nextBytes(data);

                var requestCryptoContext = undefined, responseCryptoContext;
                runs(function() {
                    requestCryptoContext = keyxData.cryptoContext;
                    var keyResponseData = keyxData.keyResponseData;
                    factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null, {
                        result: function(cryptoContext) { responseCryptoContext = cryptoContext; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestCryptoContext && responseCryptoContext; }, "crypto contexts not received", 300);

                // Ciphertext won't always be equal depending on how it was
                // enveloped. So we cannot check for equality or inequality.
                var requestCiphertext = undefined, responseCiphertext;
                runs(function() {
                    expect(responseCryptoContext).not.toBeNull();

                    requestCryptoContext.encrypt(data, {
                        result: function(data) { requestCiphertext = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    responseCryptoContext.encrypt(data, {
                        result: function(data) { responseCiphertext = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestCiphertext && responseCiphertext; }, "ciphertexts not received", 300);
                runs(function() {
                    expect(requestCiphertext).not.toEqual(data);
                    expect(responseCiphertext).not.toEqual(data);
                });

                // Signatures should always be equal.
                var requestSignature = undefined, responseSignature;
                runs(function() {
                    requestCryptoContext.sign(data, {
                        result: function(data) { requestSignature = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    responseCryptoContext.sign(data, {
                        result: function(data) { responseSignature = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestSignature && responseSignature; }, "signatures not received", 300);
                runs(function() {
                    expect(requestSignature).not.toEqual(data);
                    expect(responseSignature).not.toEqual(data);
                    expect(responseSignature).toEqual(requestSignature);
                });

                // Plaintext should always be equal to the original message.
                var requestPlaintext = undefined, responsePlaintext;
                runs(function() {
                    requestCryptoContext.decrypt(responseCiphertext, {
                        result: function(data) { requestPlaintext = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    responseCryptoContext.decrypt(requestCiphertext, {
                        result: function(data) { responsePlaintext = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestPlaintext && responsePlaintext; }, "plaintexts not received", 300);
                runs(function() {
                    expect(requestPlaintext).not.toBeNull();
                    expect(requestPlaintext).toEqual(data);
                    expect(responsePlaintext).toEqual(requestPlaintext);
                });

                // Verification should always succeed.
                var requestVerified; responseVerified = undefined;
                runs(function() {
                    requestCryptoContext.verify(data, responseSignature, {
                        result: function(data) { requestVerified = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    responseCryptoContext.verify(data, requestSignature, {
                        result: function(data) { responseVerified = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestVerified && responseVerified; }, "verifieds not received", 300);
                runs(function() {
                    expect(requestVerified).toBeTruthy();
                    expect(responseVerified).toBeTruthy();
                });
            });

            it("get crypto context with wrong request type", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", 300);

                var exception;
                runs(function() {
                    var keyResponseData = keyxData.keyResponseData;

                    var fakeKeyRequestData = new FakeKeyRequestData();
                    factory.getCryptoContext(ctx, fakeKeyRequestData, keyResponseData, null, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", 300);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslInternalException(MslError.NONE));
                });
            });

            it("get crypto context with wrong response type", function() {
                var exception;
                runs(function() {
                    var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    var fakeKeyResponseData = new FakeKeyResponseData();
                    factory.getCryptoContext(ctx, keyRequestData, fakeKeyResponseData, null, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", 300);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslInternalException(MslError.NONE));
                });
            });

            it("get crypto context with mismatched key IDs", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID + "A", mechanism, publicKey, privateKey);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", 300);

                var exception;
                runs(function() {
                    var keyResponseData = keyxData.keyResponseData;
                    var masterToken = keyResponseData.masterToken;

                    var mismatchedKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID + "B", ENCRYPTION_KEY, HMAC_KEY);

                    factory.getCryptoContext(ctx, keyRequestData, mismatchedKeyResponseData, null, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", 300);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH));
                });
            });

            it("get crypto context with missing private key", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID + "B", mechanism, publicKey, null);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", 300);

                var exception;
                runs(function() {
                    var keyResponseData = keyxData.keyResponseData;

                    factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", 300);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_PRIVATE_KEY_MISSING));
                });
            });

            it("get crypto context with invalid wrapped encryption key", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", 300);

                var exception;
                runs(function() {
                    var keyResponseData = keyxData.keyResponseData;
                    var masterToken = keyResponseData.masterToken;

                    var keydata = keyResponseData.getKeydata();
                    var wrappedEncryptionKey = base64$decode(keydata[KEY_ENCRYPTION_KEY]);
                    //  I think I have to change length - 2 because of padding.
                    ++wrappedEncryptionKey[wrappedEncryptionKey.length-2];
                    keydata[KEY_ENCRYPTION_KEY] = base64$encode(wrappedEncryptionKey);
                    var wrappedHmacKey = base64$decode(keydata[KEY_HMAC_KEY]);

                    var invalidKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
                    factory.getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, null, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", 300);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslCryptoException(MslError.NONE));
                });
            });

            it("get crypto context with invalid wrapped HMAC key", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", 300);

                var exception;
                runs(function() {
                    var keyResponseData = keyxData.keyResponseData;
                    var masterToken = keyResponseData.masterToken;

                    var keydata = keyResponseData.getKeydata();
                    var wrappedHmacKey = base64$decode(keydata[KEY_HMAC_KEY]);
                    //  I think I have to change length - 2 because of padding.
                    ++wrappedHmacKey[wrappedHmacKey.length-2];
                    keydata[KEY_HMAC_KEY] = base64$encode(wrappedHmacKey);
                    var wrappedEncryptionKey = base64$decode(keydata[KEY_ENCRYPTION_KEY]);

                    var invalidKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
                    factory.getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, null, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", 300);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslCryptoException(MslError.NONE));
                });
            });
        });
    });
});
