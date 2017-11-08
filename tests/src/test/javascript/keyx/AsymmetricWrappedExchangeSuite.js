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
 * Asymmetric wrapped key exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("AsymmetricWrappedExchangeSuite", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var MslCrypto = require('msl-core/crypto/MslCrypto.js');
    var AsymmetricWrappedExchange = require('msl-core/keyx/AsymmetricWrappedExchange.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslKeyExchangeException = require('msl-core/MslKeyExchangeException.js');
    var MslError = require('msl-core/MslError.js');
    var MasterToken = require('msl-core/tokens/MasterToken.js');
    var KeyRequestData = require('msl-core/keyx/KeyRequestData.js');
    var KeyResponseData = require('msl-core/keyx/KeyResponseData.js');
    var Arrays = require('msl-core/util/Arrays.js');
    var Random = require('msl-core/util/Random.js');
    var PresharedAuthenticationData = require('msl-core/entityauth/PresharedAuthenticationData.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslMasterTokenException = require('msl-core/MslMasterTokenException.js');
    
    var BigInteger = require('jsrsasign').BigInteger;

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockAuthenticationUtils = require('msl-tests/util/MockAuthenticationUtils.js');
    
	/** MSL encoder format. */
	var ENCODER_FORMAT = MslEncoderFormat.JSON;
	
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
	
    /** Key key exchange scheme. */
    var KEY_SCHEME = "scheme";
    /** Key key request data. */
    var KEY_KEYDATA = "keydata";
    
    /** Key key pair ID. */
    var KEY_KEY_PAIR_ID = "keypairid";
    /** Key encrypted encryption key. */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /** Key encrypted HMAC key. */
    var KEY_HMAC_KEY = "hmackey";
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    
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
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
            
            runs(function() {
                MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSA_OAEP, WebCryptoUsage.WRAP_UNWRAP, 2048, {
                    result: function(publicKey, privateKey) {
                        RSA_OAEP_PUBLIC_KEY = publicKey;
                        RSA_OAEP_PRIVATE_KEY = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return RSA_OAEP_PUBLIC_KEY && RSA_OAEP_PRIVATE_KEY; }, "RSA-OAEP keys", MslTestConstants.TIMEOUT_CRYPTO);
            
            runs(function() {
                if (MslCrypto.getWebCryptoVersion() != MslCrypto.WebCryptoVersion.V2014_01) {
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
            waitsFor(function() { return RSAES_PUBLIC_KEY && RSAES_PRIVATE_KEY; }, "RSAES keys", MslTestConstants.TIMEOUT_CRYPTO);
            
    		runs(function() {
    			encoder = ctx.getMslEncoderFactory();
    			MslTestUtils.getMasterToken(ctx, 1, 1, {
    				result: function(masterToken) {
    					MASTER_TOKEN = masterToken;
    					ENCRYPTION_KEY = MASTER_TOKEN.encryptionKey.toByteArray();
    					HMAC_KEY = MASTER_TOKEN.signatureKey.toByteArray();
    				},
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return MASTER_TOKEN && ENCRYPTION_KEY && HMAC_KEY; }, "static intialization", MslTestConstants.TIMEOUT_CRYPTO);
    		
    		runs(function() { initialized = true; });
    	}
    });
    
    // Shortcuts.
    var Mechanism = AsymmetricWrappedExchange.Mechanism;
    var RequestData = AsymmetricWrappedExchange.RequestData;
    var ResponseData = AsymmetricWrappedExchange.ResponseData;
    
    /** Request data unit tests. */
    describe("RequestData", function() {
        /** Key key pair ID. */
        var KEY_KEY_PAIR_ID = "keypairid";
        /** Key mechanism. */
        var KEY_MECHANISM = "mechanism";
        /** Key public key. */
        var KEY_PUBLIC_KEY = "publickey";

        function keyxRequestData() {
            var params = [];
            var webCryptoVersion = MslCrypto.getWebCryptoVersion();
            if (webCryptoVersion == MslCrypto.WebCryptoVersion.LEGACY) {
                params.push([ Mechanism.RSA ]);
                params.push([ Mechanism.JWE_RSA ]);
                params.push([ Mechanism.JWEJS_RSA ]);
            } else if (webCryptoVersion == MslCrypto.WebCryptoVersion.V2014_01) {
                params.push([ Mechanism.RSA ]);
                params.push([ Mechanism.JWK_RSA ]);
                params.push([ Mechanism.JWK_RSAES ]);
            } else {
                params.push([ Mechanism.RSA ]);
                params.push([ Mechanism.JWK_RSA ]);
            }
            return params;
        }
        
        parameterize("Parameterized", keyxRequestData, function(mechanism) {
            var publicKey, privateKey;
            beforeEach(function() {
                switch (mechanism) {
                    case Mechanism.RSA:
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
                var keydata;
                runs(function() {
                    req.getKeydata(encoder, ENCODER_FORMAT, {
                        result: function(x) { keydata = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                });
                waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

                var moReq;
                runs(function() {
                    expect(keydata).not.toBeNull();
                    RequestData.parse(keydata, {
                        result: function(data) { moReq = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return moReq; }, "moReq not received", MslTestConstants.TIMEOUT);

                var moKeydata;
                runs(function() {
                    expect(moReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
                    expect(moReq.keyPairId).toEqual(req.keyPairId);
                    expect(moReq.mechanism).toEqual(req.mechanism);
                    expect(moReq.privateKey).toBeNull();
                    expect(moReq.publicKey.getEncoded()).toEqual(req.publicKey.getEncoded());
                    moReq.getKeydata(encoder, ENCODER_FORMAT, {
                        result: function(x) { moKeydata = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return moKeydata; }, "moKeydata", MslTestConstants.TIMEOUT);
                
                runs(function() {
                    expect(moKeydata).not.toBeNull();
                    expect(moKeydata).toEqual(keydata);
                });
            });

            it("mslobject is correct", function() {
                var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);

                var mo;
                runs(function() {
                    MslTestUtils.toMslObject(encoder, req, {
                        result: function(x) { mo = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

                runs(function() {
                    expect(mo.getString(KEY_SCHEME)).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
                    var keydata = mo.getMslObject(KEY_KEYDATA, encoder);
                    expect(keydata.getString(KEY_KEY_PAIR_ID)).toEqual(KEYPAIR_ID);
	                expect(keydata.getString(KEY_MECHANISM)).toEqual(mechanism);
	                expect(keydata.getBytes(KEY_PUBLIC_KEY)).toEqual(publicKey.getEncoded());
                });
            });

            it("create", function() {
                var data = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                var mo;
                runs(function() {
                    MslTestUtils.toMslObject(encoder, data, {
                        result: function(x) { mo = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
                
                var keyRequestData;
                runs(function() {
                    KeyRequestData.parse(ctx, mo, {
                        result: function(data) { keyRequestData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyRequestData; }, "keyRequestData not received", MslTestConstants.TIMEOUT);

                runs(function() {
                    expect(keyRequestData).not.toBeNull();
                    expect(keyRequestData instanceof RequestData).toBeTruthy();

                    var moData = keyRequestData;
                    expect(moData.keyExchangeScheme).toEqual(data.keyExchangeScheme);
                    expect(moData.keyPairId).toEqual(data.keyPairId);
                    expect(moData.mechanism).toEqual(data.mechanism);
                    expect(moData.privateKey).toBeNull();
                    expect(moData.publicKey.getEncoded()).toEqual(data.publicKey.getEncoded());
                });
            });

            it("missing key pair ID", function() {
            	var keydata;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    req.getKeydata(encoder, ENCODER_FORMAT, {
                        result: function(x) { keydata = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

                var exception;
                runs(function() {
                    keydata.remove(KEY_KEY_PAIR_ID);

                    RequestData.parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
                });
            });

            it("missing mechanism", function() {
            	var keydata;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    req.getKeydata(encoder, ENCODER_FORMAT, {
                        result: function(x) { keydata = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

                var exception;
                runs(function() {
                    keydata.remove(KEY_MECHANISM);

                    RequestData.parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
                });
            });

            it("invalid mechanism", function() {
            	var keydata;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    req.getKeydata(encoder, ENCODER_FORMAT, {
                        result: function(x) { keydata = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

                var exception;
                runs(function() {
                    keydata.put(KEY_MECHANISM, "x");

                    RequestData.parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_MECHANISM));
                });
            });

            it("missing public key", function() {
                var keydata;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    req.getKeydata(encoder, ENCODER_FORMAT, {
                        result: function(x) { keydata = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

                var exception;
                runs(function() {
                    keydata.remove(KEY_PUBLIC_KEY);

                    RequestData.parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
                });
            });

            it("invalid public key", function() {
                var keydata;
                runs(function() {
                    var req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                    req.getKeydata(encoder, ENCODER_FORMAT, {
                        result: function(x) { keydata = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

                var exception;
                runs(function() {
                    var encodedKey = publicKey.getEncoded();
                    var shortKey = Arrays.copyOf(encodedKey, 0, encodedKey.length / 2);
                    keydata.put(KEY_PUBLIC_KEY, shortKey);

                    RequestData.parse(keydata, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

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
                dataA.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(keydata) {
                        RequestData.parse(keydata, {
                            result: function(data) { dataA2 = data; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return dataA2; }, "dataA2 not received", MslTestConstants.TIMEOUT_CRYPTO);

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
                dataA.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(keydata) {
                        RequestData.parse(keydata, {
                            result: function(data) { dataA2 = data; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return dataA2; }, "dataA2 not received", MslTestConstants.TIMEOUT_CRYPTO);

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
            waitsFor(function() { return rsaPublicKey; }, "RSA public key", MslTestConstants.TIMEOUT_CTX);

            var dataA, dataB, dataA2;
            runs(function() {
                dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, RSA_OAEP_PRIVATE_KEY);
                dataB = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, rsaPublicKey, RSA_OAEP_PRIVATE_KEY);
                dataA.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(keydata) {
                        RequestData.parse(keydata, {
                            result: function(data) { dataA2 = data; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return dataA && dataB && dataA2; }, "data not received", MslTestConstants.TIMEOUT_CRYPTO);

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
            waitsFor(function() { return rsaPrivateKey; }, "RSA private key", MslTestConstants.TIMEOUT_CTX);

            var dataA, dataB, dataA2;
            runs(function() {
                dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, RSA_OAEP_PRIVATE_KEY);
                dataB = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_OAEP_PUBLIC_KEY, rsaPrivateKey);
                dataA.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(keydata) {
                        RequestData.parse(keydata, {
                            result: function(data) { dataA2 = data; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return dataA && dataB && dataA2; }, "data not received", MslTestConstants.TIMEOUT_CRYPTO);

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
        /** Key master token. */
        var KEY_MASTER_TOKEN = "mastertoken";

        it("ctors", function() {
            var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            expect(resp.encryptionKey).toEqual(ENCRYPTION_KEY);
            expect(resp.hmacKey).toEqual(HMAC_KEY);
            expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            expect(resp.keyPairId).toEqual(KEYPAIR_ID);
            expect(resp.masterToken).toEqual(MASTER_TOKEN);

            var keydata;
            runs(function() {
                resp.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(x) { keydata = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

            var moKeydata;
            runs(function() {
                expect(keydata).not.toBeNull();

                var moResp = ResponseData.parse(MASTER_TOKEN, keydata);
                expect(moResp.encryptionKey).toEqual(resp.encryptionKey);
                expect(moResp.hmacKey).toEqual(resp.hmacKey);
                expect(moResp.keyExchangeScheme).toEqual(resp.keyExchangeScheme);
                expect(moResp.keyPairId).toEqual(resp.keyPairId);
                expect(moResp.masterToken).toEqual(resp.masterToken);
                resp.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(x) { moKeydata = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return moKeydata; }, "moKeydata", MslTestConstants.TIMEOUT);

            runs(function() {
                expect(moKeydata).not.toBeNull();
                expect(moKeydata).toEqual(keydata);
            });
        });

        it("mslobject is correct", function() {
            var mo;
            runs(function() {
                var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
                MslTestUtils.toMslObject(encoder, resp, {
                    result: function(x) { mo = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

            var masterToken;
            runs(function() {
                expect(mo.getString(KEY_SCHEME)).toEqual(KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);

                MasterToken.parse(ctx, mo.getMslObject(KEY_MASTER_TOKEN, encoder), {
                    result: function(token) { masterToken = token; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT_CRYPTO);

            runs(function() {
                expect(masterToken).toEqual(MASTER_TOKEN);
                var keydata = mo.getMslObject(KEY_KEYDATA, encoder);
                expect(keydata.getString(KEY_KEY_PAIR_ID)).toEqual(KEYPAIR_ID);
                expect(keydata.getBytes(KEY_ENCRYPTION_KEY)).toEqual(ENCRYPTION_KEY);
                expect(keydata.getBytes(KEY_HMAC_KEY)).toEqual(HMAC_KEY);
            });
        });

        it("create", function() {
            var data = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);

            var keyResponseData;
            runs(function() {
                MslTestUtils.toMslObject(encoder, data, {
                    result: function(mo) {
                        KeyResponseData.parse(ctx, mo, {
                            result: function(data) { keyResponseData = data; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyResponseData; }, "keyResponseData not received", MslTestConstants.TIMEOUT_CRYPTO);

            runs(function() {
                expect(keyResponseData).not.toBeNull();
                expect(keyResponseData instanceof ResponseData).toBeTruthy();

                var moData = keyResponseData;
                expect(moData.encryptionKey).toEqual(data.encryptionKey);
                expect(moData.hmacKey).toEqual(data.hmacKey);
                expect(moData.keyExchangeScheme).toEqual(data.keyExchangeScheme);
                expect(moData.keyPairId).toEqual(data.keyPairId);
                expect(moData.masterToken).toEqual(data.masterToken);
                expect(moData.identity).toEqual(data.identity);
            });
        });

        it("missing key pair ID", function() {
            var keydata;
            runs(function() {
                var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
                resp.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(x) { keydata = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() {
                    keydata.remove(KEY_KEY_PAIR_ID);
                    ResponseData.parse(MASTER_TOKEN, keydata);
                };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });

        it("missing encryption key", function() {
            var keydata;
            runs(function() {
                var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
                resp.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(x) { keydata = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() {
                    keydata.remove(KEY_ENCRYPTION_KEY);
                    ResponseData.parse(MASTER_TOKEN, keydata);
                };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });

        it("missing HMAC key", function() {
            var keydata;
            runs(function() {
                var resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
                resp.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(x) { keydata = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() {
                    keydata.remove(KEY_HMAC_KEY);
                    ResponseData.parse(MASTER_TOKEN, keydata);
                };
                expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });

        it("equals master token", function() {
            var masterTokenA, masterTokenB;
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
            waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT_CRYPTO);

            var dataA, dataB, dataA2;
            runs(function() {
                dataA = new ResponseData(masterTokenA, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
                dataB = new ResponseData(masterTokenB, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
                dataA.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(keydata) {
                        dataA2 = ResponseData.parse(masterTokenA, keydata);
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return dataA && dataB && dataA2; }, "data", MslTestConstants.TIMEOUT);

            runs(function() {
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
            var dataA2;
            runs(function() {
                dataA.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(keydata) {
                        dataA2 = ResponseData.parse(MASTER_TOKEN, keydata);
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return dataA2; }, "dataA2", MslTestConstants.TIMEOUT);

            runs(function() {
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

        it("equals encryption key", function() {
            var encryptionKeyA = Arrays.copyOf(ENCRYPTION_KEY);
            var encryptionKeyB = Arrays.copyOf(ENCRYPTION_KEY);
            ++encryptionKeyB[0];
            var dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyA, HMAC_KEY);
            var dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyB, HMAC_KEY);
            var dataA2;
            runs(function() {
                dataA.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(keydata) {
                        dataA2 = ResponseData.parse(MASTER_TOKEN, keydata);
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return dataA2; }, "dataA2", MslTestConstants.TIMEOUT);

            runs(function() {
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

        it("equals HMAC key", function() {
            var hmacKeyA = Arrays.copyOf(HMAC_KEY);
            var hmacKeyB = Arrays.copyOf(HMAC_KEY);
            ++hmacKeyB[0];
            var dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyA);
            var dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyB);
            var dataA2;
            runs(function() {
                dataA.getKeydata(encoder, ENCODER_FORMAT, {
                    result: function(keydata) {
                        dataA2 = ResponseData.parse(MASTER_TOKEN, keydata);
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return dataA2; }, "dataA2", MslTestConstants.TIMEOUT);

            runs(function() {
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
        /** Authentication utilities. */
        var authutils = new MockAuthenticationUtils();
        /** Key exchange factory. */
        var factory = new AsymmetricWrappedExchange(authutils);
        /** Entity authentication data. */
        var entityAuthData = new PresharedAuthenticationData(IDENTITY);

        beforeEach(function() {
            authutils.reset();
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
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT_CRYPTO);
            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });

        it("generate subsequent response with wrong request type", function() {
            var keyRequestData = new FakeKeyRequestData();
            var exception;
            runs(function() {
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT_CRYPTO);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });

        function keyxFactoryData() {
            var params = [];
            var webCryptoVersion = MslCrypto.getWebCryptoVersion();
            if (webCryptoVersion == MslCrypto.WebCryptoVersion.LEGACY) {
                params.push([ Mechanism.RSA ]);
                params.push([ Mechanism.JWE_RSA ]);
                params.push([ Mechanism.JWEJS_RSA ]);
            } else if (webCryptoVersion == MslCrypto.WebCryptoVersion.V2014_01) {
                params.push([ Mechanism.RSA ]);
                params.push([ Mechanism.JWK_RSA ]);
                params.push([ Mechanism.JWK_RSAES ]);
            } else {
                params.push([ Mechanism.RSA ]);
                params.push([ Mechanism.JWK_RSA ]);
            }
            return params;
        }

        parameterize("Parameterized", keyxFactoryData, function(mechanism) {
            var publicKey, privateKey;
            beforeEach(function() {
                switch (mechanism) {
                    case Mechanism.RSA:
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
                    factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT_CRYPTO);
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
                    factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT_CRYPTO);
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
                waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT_CRYPTO);

                var exception;
                runs(function() {
                    factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, masterToken, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT_CRYPTO);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslMasterTokenException(MslError.NONE));
                });
            });

            it("get crypto context", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT_CRYPTO);

                var data = new Uint8Array(32);
                random.nextBytes(data);

                var requestCryptoContext, responseCryptoContext;
                runs(function() {
                    requestCryptoContext = keyxData.cryptoContext;
                    var keyResponseData = keyxData.keyResponseData;
                    factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null, {
                        result: function(cryptoContext) { responseCryptoContext = cryptoContext; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestCryptoContext && responseCryptoContext; }, "crypto contexts not received", MslTestConstants.TIMEOUT_CRYPTO);

                // Ciphertext won't always be equal depending on how it was
                // enveloped. So we cannot check for equality or inequality.
                var requestCiphertext, responseCiphertext;
                runs(function() {
                    expect(responseCryptoContext).not.toBeNull();

                    requestCryptoContext.encrypt(data, encoder, ENCODER_FORMAT, {
                        result: function(data) { requestCiphertext = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    responseCryptoContext.encrypt(data, encoder, ENCODER_FORMAT, {
                        result: function(data) { responseCiphertext = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestCiphertext && responseCiphertext; }, "ciphertexts not received", MslTestConstants.TIMEOUT_CRYPTO);
                runs(function() {
                    expect(requestCiphertext).not.toEqual(data);
                    expect(responseCiphertext).not.toEqual(data);
                });

                // Signatures should always be equal.
                var requestSignature, responseSignature;
                runs(function() {
                    requestCryptoContext.sign(data, encoder, ENCODER_FORMAT, {
                        result: function(data) { requestSignature = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    responseCryptoContext.sign(data, encoder, ENCODER_FORMAT, {
                        result: function(data) { responseSignature = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestSignature && responseSignature; }, "signatures not received", MslTestConstants.TIMEOUT_CRYPTO);
                runs(function() {
                    expect(requestSignature).not.toEqual(data);
                    expect(responseSignature).not.toEqual(data);
                    expect(responseSignature).toEqual(requestSignature);
                });

                // Plaintext should always be equal to the original message.
                var requestPlaintext, responsePlaintext;
                runs(function() {
                    requestCryptoContext.decrypt(responseCiphertext, encoder, {
                        result: function(data) { requestPlaintext = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    responseCryptoContext.decrypt(requestCiphertext, encoder, {
                        result: function(data) { responsePlaintext = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestPlaintext && responsePlaintext; }, "plaintexts not received", MslTestConstants.TIMEOUT_CRYPTO);
                runs(function() {
                    expect(requestPlaintext).not.toBeNull();
                    expect(requestPlaintext).toEqual(data);
                    expect(responsePlaintext).toEqual(requestPlaintext);
                });

                // Verification should always succeed.
                var requestVerified, responseVerified;
                runs(function() {
                    requestCryptoContext.verify(data, responseSignature, encoder, {
                        result: function(data) { requestVerified = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                    responseCryptoContext.verify(data, requestSignature, encoder, {
                        result: function(data) { responseVerified = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return requestVerified && responseVerified; }, "verifieds not received", MslTestConstants.TIMEOUT_CRYPTO);
                runs(function() {
                    expect(requestVerified).toBeTruthy();
                    expect(responseVerified).toBeTruthy();
                });
            });

            it("get crypto context with wrong request type", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT_CRYPTO);

                var exception;
                runs(function() {
                    var keyResponseData = keyxData.keyResponseData;

                    var fakeKeyRequestData = new FakeKeyRequestData();
                    factory.getCryptoContext(ctx, fakeKeyRequestData, keyResponseData, null, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT_CRYPTO);

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
                waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT_CRYPTO);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslInternalException(MslError.NONE));
                });
            });

            it("get crypto context with mismatched key IDs", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID + "A", mechanism, publicKey, privateKey);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT_CRYPTO);

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
                waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT_CRYPTO);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH));
                });
            });

            it("get crypto context with missing private key", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID + "B", mechanism, publicKey, null);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT_CRYPTO);

                var exception;
                runs(function() {
                    var keyResponseData = keyxData.keyResponseData;

                    factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null, {
                        result: function() {},
                        error: function(err) { exception = err; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT_CRYPTO);
                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_PRIVATE_KEY_MISSING));
                });
            });

            it("get crypto context with invalid wrapped encryption key", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT_CRYPTO);

                var masterToken, keydata;
                runs(function() {
                    var keyResponseData = keyxData.keyResponseData;
                    masterToken = keyResponseData.masterToken;

                    keyResponseData.getKeydata(encoder, ENCODER_FORMAT, {
                        result: function(x) { keydata = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

                var exception;
                runs(function() {
                    var wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);
                    //  I think I have to change length - 2 because of padding.
                    ++wrappedEncryptionKey[wrappedEncryptionKey.length-2];
                    keydata.put(KEY_ENCRYPTION_KEY, wrappedEncryptionKey);
                    var wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);

                    var invalidKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
                    factory.getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, null, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT_CRYPTO);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslCryptoException(MslError.NONE));
                });
            });

            it("get crypto context with invalid wrapped HMAC key", function() {
                var keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);

                var keyxData;
                runs(function() {
                    factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                        result: function(data) { keyxData = data; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT_CRYPTO);

                var masterToken, keydata;
                runs(function() {
                    var keyResponseData = keyxData.keyResponseData;
                    masterToken = keyResponseData.masterToken;

                    keyResponseData.getKeydata(encoder, ENCODER_FORMAT, {
                        result: function(x) { keydata = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
                waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

                var exception;
                runs(function() {
                    var wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);
                    //  I think I have to change length - 2 because of padding.
                    ++wrappedHmacKey[wrappedHmacKey.length-2];
                    keydata.put(KEY_HMAC_KEY, wrappedHmacKey);
                    var wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);

                    var invalidKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
                    factory.getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, null, {
                        result: function() {},
                        error: function(e) { exception = e; }
                    });
                });
                waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT_CRYPTO);

                runs(function() {
                    var f = function() { throw exception; };
                    expect(f).toThrow(new MslCryptoException(MslError.NONE));
                });
            });
        });
    });
});
