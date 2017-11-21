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
 * Symmetric wrapped key exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("SymmetricWrappedExchangeSuite", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var Random = require('msl-core/util/Random.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var SymmetricWrappedExchange = require('msl-core/keyx/SymmetricWrappedExchange.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslKeyExchangeException = require('msl-core/MslKeyExchangeException.js');
    var MslError = require('msl-core/MslError.js');
    var KeyRequestData = require('msl-core/keyx/KeyRequestData.js');
    var KeyResponseData = require('msl-core/keyx/KeyResponseData.js');
    var Arrays = require('msl-core/util/Arrays.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var MasterToken = require('msl-core/tokens/MasterToken.js');
    var PresharedAuthenticationData = require('msl-core/entityauth/PresharedAuthenticationData.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslMasterTokenException = require('msl-core/MslMasterTokenException.js');
    var MslEntityAuthException = require('msl-core/MslEntityAuthException.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockAuthenticationUtils = require('msl-tests/util/MockAuthenticationUtils.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
    
	/** MSL encoder format. */
	var ENCODER_FORMAT = MslEncoderFormat.JSON;
	
    /** Key key exchange scheme. */
    var KEY_SCHEME = "scheme";
    /** Key key request data. */
    var KEY_KEYDATA = "keydata";
    
    /** Key symmetric key ID. */
    var KEY_KEY_ID = "keyid";
    /** Key wrapped encryption key. */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /** Key wrapped HMAC key. */
    var KEY_HMAC_KEY = "hmackey";

    /** Random. */
    var random = new Random();
    /** Preshared keys entity context. */
    var pskCtx;
    /** MSL encoder factory. */
    var encoder;
    /** Unauthenticated (server) entity context. */
    var unauthCtx;

    var ENCRYPTION_KEY = new Uint8Array(16);
    random.nextBytes(ENCRYPTION_KEY);
    var HMAC_KEY = new Uint8Array(32);
    random.nextBytes(HMAC_KEY);
    
    var PSK_MASTER_TOKEN;

    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { pskCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MockMslContext.create(EntityAuthenticationScheme.NONE, false, {
                    result: function(c) { unauthCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return pskCtx && unauthCtx; }, "MSL contexts", MslTestConstants.TIMEOUT_CTX);

            runs(function() {
                encoder = pskCtx.getMslEncoderFactory();
                MslTestUtils.getMasterToken(pskCtx, 1, 1, {
                    result: function(masterToken) {
                        PSK_MASTER_TOKEN = masterToken;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return PSK_MASTER_TOKEN; }, "static initialization", MslTestConstants.TIMEOUT);
            runs(function() { initialized = true; });
        }
    });

    // Shortcuts
    var KeyId = SymmetricWrappedExchange.KeyId;
	var RequestData = SymmetricWrappedExchange.RequestData;
	var ResponseData = SymmetricWrappedExchange.ResponseData;
    
    /** Request data unit tests. */
    describe("RequestData", function() {
        it("ctor with PSK key ID", function() {
            var req = new RequestData(KeyId.PSK);
            expect(req.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
            expect(req.keyId).toEqual(KeyId.PSK);
            
            var keydata;
            runs(function() {
            	req.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(x) { keydata = x; },
		    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
            
            var moKeydata;
            runs(function() {
	            expect(keydata).not.toBeNull();
	
	            var moReq = RequestData.parse(keydata);
	            expect(moReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
	            expect(moReq.keyId).toEqual(req.keyId);
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
        
        it("ctor with SESSION key ID", function() {
            var req = new RequestData(KeyId.SESSION);
            expect(req.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
            expect(req.keyId).toEqual(KeyId.SESSION);
            
            var keydata;
            runs(function() {
            	req.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(x) { keydata = x; },
		    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

            var moKeydata;
            runs(function() {
	            expect(keydata).not.toBeNull();
	
	            var moReq = RequestData.parse(keydata);
	            expect(moReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
	            expect(moReq.keyId).toEqual(req.keyId);
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
            var req = new RequestData(KeyId.PSK);
            var mo;
            runs(function() {
            	MslTestUtils.toMslObject(encoder, req, {
            		result: function(x) { mo = x; },
		    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
            
            runs(function() {
	            expect(mo.getString(KEY_SCHEME)).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED.name);
	            var keydata = mo.getMslObject(KEY_KEYDATA, encoder);
	            expect(keydata.getString(KEY_KEY_ID)).toEqual(KeyId.PSK);
            });
        });
        
        it("create", function() {
            var data = new RequestData(KeyId.PSK);
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
                KeyRequestData.parse(pskCtx, mo, {
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
                expect(moData.keyId).toEqual(data.keyId);
            });
        });

        it("missing key ID", function() {
        	var keydata;
            runs(function() {
            	var req = new RequestData(KeyId.PSK);
            	req.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(x) { keydata = x; },
		    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
	
            runs(function() {
            	keydata.remove(KEY_KEY_ID);
            	var f = function() {
            		RequestData.parse(keydata);
            	};
            	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });

        it("invalid key ID", function() {
        	var keydata;
            runs(function() {
	            var req = new RequestData(KeyId.PSK);
            	req.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(x) { keydata = x; },
		    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
	
            runs(function() {
	            keydata.put(KEY_KEY_ID, "x");
	            var f = function() {
	            	RequestData.parse(keydata);
	            };
	            expect(f).toThrow(new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_KEY_ID));
            });
        });
        
        it("equals key ID", function() {
        	var dataA = new RequestData(KeyId.PSK);
            var dataB = new RequestData(KeyId.SESSION);
            var dataA2;
            runs(function() {
            	dataA.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(keydata) {
            			dataA2 = RequestData.parse(keydata);
            		},
		    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
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
            var data = new RequestData(KeyId.PSK);
            expect(data.equals(null)).toBeFalsy();
            expect(data.equals(KEY_KEY_ID)).toBeFalsy();
        });
    });

    /** Response data unit tests. */
    describe("ResponseData", function() {
        /** Key master token. */
        var KEY_MASTER_TOKEN = "mastertoken";
        
        it("ctors", function() {
            var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            expect(resp.encryptionKey).toEqual(ENCRYPTION_KEY);
            expect(resp.hmacKey).toEqual(HMAC_KEY);
            expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
            expect(resp.keyId).toEqual(KeyId.PSK);
            expect(resp.masterToken).toEqual(PSK_MASTER_TOKEN);
            var keydata;
            runs(function() {
            	resp.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(x) { keydata = x; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
            
            var moKeydata;
            runs(function() {
	            expect(keydata).not.toBeNull();
	
	            var joResp = ResponseData.parse(PSK_MASTER_TOKEN, keydata);
	            expect(joResp.encryptionKey).toEqual(resp.encryptionKey);
	            expect(joResp.hmacKey).toEqual(resp.hmacKey);
	            expect(joResp.keyExchangeScheme).toEqual(resp.keyExchangeScheme);
	            expect(joResp.keyId).toEqual(resp.keyId);
	            expect(joResp.masterToken).toEqual(resp.masterToken);
	            resp.getKeydata(encoder, ENCODER_FORMAT, {
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
        	var mo;
        	runs(function() {
        		var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
        		MslTestUtils.toMslObject(encoder, resp, {
        			result: function(x) { mo = x; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
        	
        	var masterToken;
        	runs(function() {
        		expect(mo.getString(KEY_SCHEME)).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED.name);
        		MasterToken.parse(pskCtx, mo.getMslObject(KEY_MASTER_TOKEN, encoder), {
        			result: function(token) { masterToken = token; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT);
        	
        	runs(function() {
	            expect(PSK_MASTER_TOKEN.equals(masterToken)).toBeTruthy();
	            var keydata = mo.getMslObject(KEY_KEYDATA, encoder);
	            expect(keydata.getString(KEY_KEY_ID)).toEqual(KeyId.PSK);
	            expect(keydata.getBytes(KEY_ENCRYPTION_KEY)).toEqual(ENCRYPTION_KEY);
	            expect(keydata.getBytes(KEY_HMAC_KEY)).toEqual(HMAC_KEY);
        	});
        });
        
        it("create", function() {
            var data = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            
            var mo;
            runs(function() {
            	MslTestUtils.toMslObject(encoder, data, {
            		result: function(x) { mo = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

            var keyResponseData;
            runs(function() {
            	KeyResponseData.parse(pskCtx, mo, {
            		result: function(data) { keyResponseData = data; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keyResponseData; }, "keyResponseData not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
            	expect(keyResponseData).not.toBeNull();
            	expect(keyResponseData instanceof ResponseData).toBeTruthy();

            	var moData = keyResponseData;
            	expect(moData.encryptionKey).toEqual(data.encryptionKey);
            	expect(moData.hmacKey).toEqual(data.hmacKey);
            	expect(moData.keyExchangeScheme).toEqual(data.keyExchangeScheme);
            	expect(moData.keyId).toEqual(data.keyId);
            	expect(data.masterToken.equals(moData.masterToken)).toBeTruthy();
            });
        });

        it("missing key ID", function() {
        	var keydata;
            runs(function() {
	            var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            	resp.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(x) { keydata = x; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
	
            runs(function() {
            	keydata.remove(KEY_KEY_ID);
            	var f = function() {
            		ResponseData.parse(PSK_MASTER_TOKEN, keydata);
            	};
            	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });

        it("missing encryption key", function() {
        	var keydata;
            runs(function() {
	            var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            	resp.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(x) { keydata = x; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
	
            runs(function() {
            	keydata.remove(KEY_ENCRYPTION_KEY);
            	var f = function() {
            		ResponseData.parse(PSK_MASTER_TOKEN, keydata);
            	};
            	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });

        it("missing HMAC key", function() {
        	var keydata;
            runs(function() {
	            var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            	resp.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(x) { keydata = x; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
	
            runs(function() {
            	keydata.remove(KEY_HMAC_KEY);
            	var f = function() {
            		ResponseData.parse(PSK_MASTER_TOKEN, keydata);
            	};
            	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });
        
        it("equals master token", function() {
        	var masterTokenA, masterTokenB;
            runs(function() {
            	MslTestUtils.getMasterToken(pskCtx, 1, 1, {
            		result: function(token) { masterTokenA = token; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            	});
            	MslTestUtils.getMasterToken(pskCtx, 1, 2, {
            		result: function(token) { masterTokenB = token; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            	});
            });
            waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);
            
            var dataA, dataB, dataA2;
            runs(function() {
	            dataA = new ResponseData(masterTokenA, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
	            dataB = new ResponseData(masterTokenB, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
	            dataA.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(keydata) {
	            		dataA2 = ResponseData.parse(masterTokenA, keydata);
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
        
        it("equals key ID", function() {
            var dataA = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, KeyId.SESSION, ENCRYPTION_KEY, HMAC_KEY);
            var dataA2;
            runs(function() {
	            dataA.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(keydata) {
	            		dataA2 = ResponseData.parse(PSK_MASTER_TOKEN, keydata);
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
            var dataA = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, encryptionKeyA, HMAC_KEY);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, encryptionKeyB, HMAC_KEY);
            var dataA2;
            runs(function() {
	            dataA.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(keydata) {
	            		dataA2 = ResponseData.parse(PSK_MASTER_TOKEN, keydata);
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
            var dataA = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, hmacKeyA);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, hmacKeyB);
            var dataA2;
            runs(function() {
	            dataA.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(keydata) {
	            		dataA2 = ResponseData.parse(PSK_MASTER_TOKEN, keydata);
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
            var data = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            expect(data.equals(null)).toBeFalsy();
            expect(data.equals(KEY_KEY_ID)).toBeFalsy();
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
                init.base.call(this, KeyExchangeScheme.SYMMETRIC_WRAPPED);
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
                init.base.call(this, PSK_MASTER_TOKEN, KeyExchangeScheme.SYMMETRIC_WRAPPED);
            },

            /** @inheritDoc */
            getKeydata: function getKeydata() {
                return null;
            },
        });
        
        /**
         * @param {MslContext} ctx MSL context.
         * @param {string} identity entity identity.
         * @param {SecretKey} encryptionKey master token encryption key.
         * @param {SecretKey hmacKey master token HMAC key.
         * @param callback
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslException if the master token is constructed incorrectly.
         * @throws JSONException if there is an error editing the JSON data.
         */
        function getUntrustedMasterToken(ctx, identity, encryptionKey, hmacKey, callback) {
        	AsyncExecutor(callback, function() {
	            var renewalWindow = new Date(Date.now() + 1000);
	            var expiration = new Date(Date.now() + 2000);
	            MasterToken.create(ctx, renewalWindow, expiration, 1, 1, null, identity, encryptionKey, hmacKey, {
		        	result: function(masterToken) {
		        		AsyncExecutor(callback, function() {
		        		    MslTestUtils.toMslObject(encoder, masterToken, {
		        		        result: function(mo) {
		        		            AsyncExecutor(callback, function() {
	                                    var signature = mo.getBytes("signature");
	                                    ++signature[1];
	                                    mo.put("signature", signature);
	                                    MasterToken.parse(ctx, mo, callback);
		        		            });
		        		        },
		        		        error: callback.error,
		        		    });
		        		});
		        	},
		        	error: callback.error,
	            });
        	});
        }

        /** Authentication utilities. */
        var authutils = new MockAuthenticationUtils();
        /** Key exchange factory. */
        var factory = new SymmetricWrappedExchange(authutils);
        /** Entity authentication data. */
        var entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        
        beforeEach(function() {
            authutils.reset();
            pskCtx.getMslStore().clearCryptoContexts();
            pskCtx.getMslStore().clearServiceTokens();
        });
        
        it("factory", function() {
            expect(factory.scheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
        });
        
        it("generate initial response for PSK key ID", function() {
            var keyRequestData = new RequestData(KeyId.PSK);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
            runs(function() {
	            expect(keyxData).not.toBeNull();
	            expect(keyxData.cryptoContext).not.toBeNull();
	            expect(keyxData.keyResponseData).not.toBeNull();
	            
	            var keyResponseData = keyxData.keyResponseData;
	            expect(keyResponseData.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
	            var masterToken = keyResponseData.masterToken;
	            expect(masterToken).not.toBeNull();
	            expect(masterToken.identity).toEqual(MockPresharedAuthenticationFactory.PSK_ESN);
            });
        });
        
        // Disabled because Web Crypto cannot wrap/unwrap with the session
        // encryption key.
        xit("generate initial response for SESSION key ID", function() {
            var keyRequestData = new RequestData(KeyId.SESSION);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
            runs(function() {
	            expect(keyxData).not.toBeNull();
	            expect(keyxData.cryptoContext).not.toBeNull();
	            expect(keyxData.keyResponseData).not.toBeNull();
	            
	            var keyResponseData = keyxData.keyResponseData;
	            expect(keyResponseData.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
	            var masterToken = keyResponseData.masterToken;
	            expect(masterToken).not.toBeNull();
	            expect(masterToken.identity).toEqual(PSK_MASTER_TOKEN.identity);
            });
        });
        
        it("generate initial response with invalid PSK identity", function() {
        	var exception;
            runs(function() {
	            var keyRequestData = new RequestData(KeyId.PSK);
	            var entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN + "x");
	            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslEntityAuthException(MslError.NONE));
            });
        });
        
        it("generate initial response for wrong request type", function() {
        	var exception;
            runs(function() {
	            var keyRequestData = new FakeKeyRequestData();
	            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        it("generate subsequent response for PSK key ID", function() {
            var keyRequestData = new RequestData(KeyId.PSK);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
            runs(function() {
	            expect(keyxData).not.toBeNull();
	            expect(keyxData.cryptoContext).not.toBeNull();
	            expect(keyxData.keyResponseData).not.toBeNull();
	            
	            var keyResponseData = keyxData.keyResponseData;
	            expect(keyResponseData.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
	            var masterToken = keyResponseData.masterToken;
	            expect(masterToken).not.toBeNull();
	            expect(masterToken.identity).toEqual(PSK_MASTER_TOKEN.identity);
	            expect(masterToken.serialNumber).toEqual(PSK_MASTER_TOKEN.serialNumber);
	            expect(masterToken.sequenceNumber).toEqual(PSK_MASTER_TOKEN.sequenceNumber + 1);
            });
        });

        // Disabled because Web Crypto cannot wrap/unwrap with the session
        // encryption key.
        xit("generate subsequent response for SESSION key ID", function() {
            var keyRequestData = new RequestData(KeyId.SESSION);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
            runs(function() {
	            expect(keyxData).not.toBeNull();
	            expect(keyxData.cryptoContext).not.toBeNull();
	            expect(keyxData.keyResponseData).not.toBeNull();
	            
	            var keyResponseData = keyxData.keyResponseData;
	            expect(keyResponseData.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
	            var masterToken = keyResponseData.masterToken;
	            expect(masterToken).not.toBeNull();
	            expect(masterToken.identity).toEqual(PSK_MASTER_TOKEN.identity);
	            expect(masterToken.serialNumber).toEqual(PSK_MASTER_TOKEN.serialNumber);
	            expect(masterToken.sequenceNumber).toEqual(PSK_MASTER_TOKEN.sequenceNumber + 1);
            });
        });
        
        it("generate subsequent response for PSK key ID with untrusted master token", function() {
        	var masterToken;
        	runs(function() {
        		var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        		var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        		var hmacKey = MockPresharedAuthenticationFactory.KPH;
        		getUntrustedMasterToken(pskCtx, identity, encryptionKey, hmacKey, {
	            	result: function(token) { masterToken = token; },
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	            });
        	});
        	waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);
            
        	var exception;
            runs(function() {
        		var keyRequestData = new RequestData(KeyId.PSK);
	            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, masterToken, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED));
            });
        });
        
        it("generate subsequent response with wrong request type", function() {
        	var exception;
            runs(function() {
	            var keyRequestData = new FakeKeyRequestData();
	            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        it("generate subsequent response with untrusted master token", function() {
        	var masterToken;
        	runs(function() {
        		var identity = MockPresharedAuthenticationFactory.PSK_ESN;
        		var encryptionKey = MockPresharedAuthenticationFactory.KPE;
        		var hmacKey = MockPresharedAuthenticationFactory.KPH;
        		getUntrustedMasterToken(pskCtx, identity, encryptionKey, hmacKey, {
        			result: function(token) { masterToken = token; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        		});
        	});
        	waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        	var exception;
            runs(function() {
	            var keyRequestData = new RequestData(KeyId.SESSION);
	            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, masterToken, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslMasterTokenException(MslError.NONE));
            });
        });
        
        it("get crypto context for PSK key ID", function() {
            var keyRequestData = new RequestData(KeyId.PSK);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
            
            var data = new Uint8Array(32);
            random.nextBytes(data);
            
            var requestCryptoContext, responseCryptoContext;
            runs(function() {
            	requestCryptoContext = keyxData.cryptoContext;
	            var keyResponseData = keyxData.keyResponseData;
	            factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, null, {
	            	result: function(cryptoContext) { responseCryptoContext = cryptoContext; },
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
            });
            waitsFor(function() { return requestCryptoContext && responseCryptoContext; }, "crypto contexts not received", MslTestConstants.TIMEOUT);
            
            // Ciphertext won't always be equal depending on how it was
            // enveloped. So we cannot check for equality or inequality.
            var requestCiphertext, responseCiphertext;
            runs(function() {
                expect(responseCryptoContext).not.toBeNull();requestCryptoContext.encrypt(data, encoder, ENCODER_FORMAT, {
                    result: function(data) { requestCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                responseCryptoContext.encrypt(data, encoder, ENCODER_FORMAT, {
                    result: function(data) { responseCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestCiphertext && responseCiphertext; }, "ciphertexts not received", MslTestConstants.TIMEOUT);
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
            waitsFor(function() { return requestSignature && responseSignature; }, "signatures not received", MslTestConstants.TIMEOUT);
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
            waitsFor(function() { return requestPlaintext && responsePlaintext; }, "plaintexts not received", MslTestConstants.TIMEOUT);
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
            waitsFor(function() { return requestVerified && responseVerified; }, "verifieds not received", 300);
            runs(function() {
	            expect(requestVerified).toBeTruthy();
	            expect(responseVerified).toBeTruthy();
            });
        });

        // Disabled because Web Crypto cannot wrap/unwrap with the session
        // encryption key.
        xit("get crypto context for SESSION key ID", function() {
            var keyRequestData = new RequestData(KeyId.SESSION);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
            
            var data = new Uint8Array(32);
            random.nextBytes(data);

            var requestCryptoContext, responseCryptoContext;
            runs(function() {
            	requestCryptoContext = keyxData.cryptoContext;
	            var keyResponseData = keyxData.keyResponseData;
	            factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, PSK_MASTER_TOKEN, {
	            	result: function(cryptoContext) { responseCryptoContext = cryptoContext; },
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
            });
            waitsFor(function() { return requestCryptoContext && responseCryptoContext; }, "crypto contexts not received", MslTestConstants.TIMEOUT);
            
            // Ciphertext won't always be equal depending on how it was
            // enveloped. So we cannot check for equality or inequality.
            var requestCiphertext, responseCiphertext;
            runs(function() {
                expect(responseCryptoContext).not.toBeNull();requestCryptoContext.encrypt(data, encoder, ENCODER_FORMAT, {
                    result: function(data) { requestCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                responseCryptoContext.encrypt(data, encoder, ENCODER_FORMAT, {
                    result: function(data) { responseCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestCiphertext && responseCiphertext; }, "ciphertexts not received", MslTestConstants.TIMEOUT);
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
            waitsFor(function() { return requestSignature && responseSignature; }, "signatures not received", MslTestConstants.TIMEOUT);
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
            waitsFor(function() { return requestPlaintext && responsePlaintext; }, "plaintexts not received", MslTestConstants.TIMEOUT);
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
            waitsFor(function() { return requestVerified && responseVerified; }, "verifieds not received", 300);
            runs(function() {
	            expect(requestVerified).toBeTruthy();
	            expect(responseVerified).toBeTruthy();
            });
        });

        // Disabled because Web Crypto cannot wrap/unwrap with the session
        // encryption key.
        xit("get crypto context with missing master token", function() {
        	var keyRequestData = new RequestData(KeyId.SESSION);
        	var keyxData;
        	runs(function() {
        		factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN, {
        			result: function(data) { keyxData = data; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);

        	var exception;
        	runs(function() {
        		var keyResponseData = keyxData.keyResponseData;
        		factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT);

            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_MASTER_TOKEN_MISSING));
            });
        });
        
        it("get crypto context with wrong request type", function() {
        	var keyRequestData = new RequestData(KeyId.PSK);
        	var keyxData;
        	runs(function() {
        		factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
        			result: function(data) { keyxData = data; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);

        	var exception;
        	runs(function() {
        		var keyResponseData = keyxData.keyResponseData;

        		var fakeKeyRequestData = new FakeKeyRequestData();
        		factory.getCryptoContext(pskCtx, fakeKeyRequestData, keyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT);

        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslInternalException(MslError.NONE));
        	});
        });
        
        it("get crypto context with wrong response type", function() {
        	var exception;
        	runs(function() {
	            var keyRequestData = new RequestData(KeyId.PSK);
	            var fakeKeyResponseData = new FakeKeyResponseData();
	            factory.getCryptoContext(pskCtx, keyRequestData, fakeKeyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT);
        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslInternalException(MslError.NONE));
        	});
        });
        
        it("get crypto context with mismatched key IDs", function() {
        	var keyRequestData = new RequestData(KeyId.PSK);
        	var keyxData;
        	runs(function() {
        		factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
        			result: function(data) { keyxData = data; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
        	
        	var exception;
        	runs(function() {
	            var keyResponseData = keyxData.keyResponseData;
	            var masterToken = keyResponseData.masterToken;
	            
	            var mismatchedKeyResponseData = new ResponseData(masterToken, KeyId.SESSION, ENCRYPTION_KEY, HMAC_KEY);
	            
	            factory.getCryptoContext(pskCtx, keyRequestData, mismatchedKeyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT);
        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH));
        	});
        });
        
        it("get crypto context with invalid wrapped encryption key", function() {
        	var keyRequestData = new RequestData(KeyId.PSK);
        	var keyxData;
        	runs(function() {
        		factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
        			result: function(data) { keyxData = data; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
        	
        	var keyResponseData, keydata;
        	runs(function() {
	            keyResponseData = keyxData.keyResponseData;
	            keyResponseData.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(x) { keydata = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
        	});
        	waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
        	
        	var exception;
        	runs(function() {
	            var wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);
	            ++wrappedEncryptionKey[wrappedEncryptionKey.length-1];
	            keydata.put(KEY_ENCRYPTION_KEY, wrappedEncryptionKey);
	            var wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);

	            var masterToken = keyResponseData.masterToken;
	            var invalidKeyResponseData = new ResponseData(masterToken, KeyId.PSK, wrappedEncryptionKey, wrappedHmacKey);
	            factory.getCryptoContext(pskCtx, keyRequestData, invalidKeyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT);
        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslCryptoException(MslError.NONE));
        	});
        });
        
        it("get crypto context with invalid wrapped HMAC key", function() {
            var keyRequestData = new RequestData(KeyId.PSK);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
        	
        	var keyResponseData, keydata;
        	runs(function() {
	            keyResponseData = keyxData.keyResponseData;
	            keyResponseData.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(x) { keydata = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
        	});
        	waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);

        	var exception;
        	runs(function() {
        		var wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);
        		++wrappedHmacKey[wrappedHmacKey.length-1];
        		keydata.put(KEY_HMAC_KEY, wrappedHmacKey);
        		var wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);

        		var masterToken = keyResponseData.masterToken;
        		var invalidKeyResponseData = new ResponseData(masterToken, KeyId.PSK, wrappedEncryptionKey, wrappedHmacKey);
        		factory.getCryptoContext(pskCtx, keyRequestData, invalidKeyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT);
        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslCryptoException(MslError.NONE));
        	});
        });
    });
});
