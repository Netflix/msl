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
 * Diffie-Hellman key exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
xdescribe("DiffieHellmanExchangeSuite", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var Random = require('msl-core/util/Random.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var DiffieHellmanExchange = require('msl-core/keyx/DiffieHellmanExchange.js');
    var DhParameterSpec = require('msl-core/keyx/DhParameterSpec.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslKeyExchangeException = require('msl-core/MslKeyExchangeException.js');
    var MslError = require('msl-core/MslError.js');
    var PresharedAuthenticationData = require('msl-core/entityauth/PresharedAuthenticationData.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var KeyRequestData = require('msl-core/keyx/KeyRequestData.js');
    var KeyResponseData = require('msl-core/keyx/KeyResponseData.js');
    var MslMasterTokenException = require('msl-core/MslMasterTokenException.js');
    var MasterToken = require('msl-core/tokens/MasterToken.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockDiffieHellmanParameters = require('msl-tests/keyx/MockDiffieHellmanParameters.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
    
	/** MSL encoder format. */
	var ENCODER_FORMAT = MslEncoderFormat.JSON;
	
    /** Key key exchange scheme. */
    var KEY_SCHEME = "scheme";
    /** Key key request data. */
    var KEY_KEYDATA = "keydata";
    
    /** Key Diffie-Hellman parameters ID. */
    var KEY_PARAMETERS_ID = "parametersid";
    /** Key Diffie-Hellman public key. */
    var KEY_PUBLIC_KEY = "publickey";
    
    /**
     * If the provided byte array begins with a null byte this function simply
     * returns the original array. Otherwise a new array is created that is a
     * copy of the original array with a null byte prepended, and this new array
     * is returned.
     * 
     * @param {Uint8Array} b the original array.
     * @return {Uint8Array} the resulting byte array.
     */
    function prependNullByte(b) {
        var result = b;
        if (result && result.length && result[0]) {
            result = new Uint8Array(b.length + 1);
            result[0] = 0x00;
            result.set(b, 1);
         }
         return result;
    }
    
    /** Diffie-Hellman parameters ID. */
    var PARAMETERS_ID = MockDiffieHellmanParameters.DEFAULT_ID;

    /** Random. */
    var random = new Random();
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    
    var REQUEST_PRIVATE_KEY, REQUEST_PUBLIC_KEY;
    var RESPONSE_PRIVATE_KEY, RESPONSE_PUBLIC_KEY;
    var MASTER_TOKEN;
    
    var initialized = false;
    beforeEach(function() {
    	if (!initialized) {
    	    runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                
                var params = MockDiffieHellmanParameters.getDefaultParameters();
                var paramSpec = params.getParameterSpec(PARAMETERS_ID);
                
                MslTestUtils.generateDiffieHellmanKeys(paramSpec, {
                    result: function(publicKey, privateKey) {
                        REQUEST_PUBLIC_KEY = publicKey;
                        REQUEST_PRIVATE_KEY = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MslTestUtils.generateDiffieHellmanKeys(paramSpec, {
                    result: function(publicKey, privateKey) {
                        RESPONSE_PUBLIC_KEY = publicKey;
                        RESPONSE_PRIVATE_KEY = privateKey;
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx && REQUEST_PUBLIC_KEY && REQUEST_PRIVATE_KEY && RESPONSE_PUBLIC_KEY && RESPONSE_PRIVATE_KEY; }, "ctx and DH keys", MslTestConstants.TIMEOUT_CTX);
            
		    runs(function() {
		    	encoder = ctx.getMslEncoderFactory();
		    	MslTestUtils.getMasterToken(ctx, 1, 1, {
		    		result: function(masterToken) {
		    			MASTER_TOKEN = masterToken;
		    		},
		    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    	});
		    });
		    waitsFor(function() { return MASTER_TOKEN; }, "static intialization", MslTestConstants.TIMEOUT);
		    
		    runs(function() { initialized = true; });
    	}
    });
    
    // Shortcuts.
    var RequestData = DiffieHellmanExchange.RequestData;
    var ResponseData = DiffieHellmanExchange.ResponseData;
    
    /** Request data unit tests. */
    describe("RequestData", function() {
        it("ctors", function() {
            var req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            expect(req.keyExchangeScheme).toEqual(KeyExchangeScheme.DIFFIE_HELLMAN);
            expect(req.parametersId).toEqual(PARAMETERS_ID);
            expect(req.privateKey.getEncoded()).toEqual(REQUEST_PRIVATE_KEY.getEncoded());
            expect(req.publicKey).toEqual(REQUEST_PUBLIC_KEY);
            
            var keydata;
            runs(function() {
            	req.getKeydata(encoder, ENCODER_FORMAT, {
            		result: function(x) { keydata = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
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
                expect(moReq.parametersId).toEqual(req.parametersId);
                expect(moReq.privateKey).toBeNull();
                expect(moReq.publicKey).toEqual(req.publicKey);
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
            var req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            var mo;
            runs(function() {
            	MslTestUtils.toMslObject(encoder, mo, {
            		result: function(x) { mo = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
            
            runs(function() {
            	expect(mo[KEY_SCHEME]).toEqual(KeyExchangeScheme.DIFFIE_HELLMAN.name);
            	var keydata = mo.getMslObject(KEY_KEYDATA, encoder);
	            expect(keydata.getString(KEY_PARAMETERS_ID)).toEqual(PARAMETERS_ID);
	            expect(prependNullByte(keydata.getBytes(KEY_PUBLIC_KEY))).toEqual(REQUEST_PUBLIC_KEY.getEncoded());
            });
        });
        
        it("create", function() {
            var data = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            
            var mo;
            runs(function() {
            	MslTestUtils.toMslObject(encoder, mo, {
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
                expect(moData.parametersId).toEqual(data.parametersId);
                expect(moData.privateKey).toBeNull();
                expect(moData.publicKey).toEqual(data.publicKey);
            });
        });
        
        it("missing parameters ID", function() {
        	var keydata;
        	runs(function() {
	            var req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
	            req.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(x) { keydata = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
        	});
        	waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
        	
	        runs(function() {
	        	keydata.remove(KEY_PARAMETERS_ID);
	        	var f = function() {
	        		RequestData.parse(keydata);
	        	};
	        	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
	        });
        });
        
        it("missing public key", function() {
        	var keydata;
        	runs(function() {
	            var req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
	            req.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(x) { keydata = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
        	});
        	waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
        	
	        runs(function() {
	        	keydata.remove(KEY_PUBLIC_KEY);
	        	var f = function() {
	        		RequestData.parse(keydata);
	        	};
	        	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
	        });
        });
        
        it("invalid public key", function() {
        	var keydata;
        	runs(function() {
	            var req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
	            req.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(x) { keydata = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
        	});
        	waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
        	
	        runs(function() {
	        	keydata.put(KEY_PUBLIC_KEY, "x");
	        	var f = function() {
	        		RequestData.parse(keydata);
	        	};
	        	expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY));
	        });
        });
        
        it("equals parameters ID", function() {
            var dataA = new RequestData(PARAMETERS_ID + "A", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            var dataB = new RequestData(PARAMETERS_ID + "B", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
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
            waitsFor(function() { return dataA2; }, "dataA2 not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(dataA.equals(dataA)).toBeTruthy();
                expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());
                
                expect(dataA.equals(dataB)).toBeFalsy();
                expect(dataB.equals(dataA)).toBeFalsy();
                expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());
                
                // The private keys don't transfer via the JSON constructor.
                expect(dataA.equals(dataA2)).toBeFalsy();
                expect(dataA2.equals(dataA)).toBeFalsy();
                expect(dataA2.uniqueKey()).not.toEqual(dataA.uniqueKey());
            });
        });
        
        it("equals public key", function() {
            var dataA = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            var dataB = new RequestData(PARAMETERS_ID, RESPONSE_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
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
            waitsFor(function() { return dataA2; }, "dataA2 not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(dataA.equals(dataA)).toBeTruthy();
                expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());
                
                expect(dataA.equals(dataB)).toBeFalsy();
                expect(dataB.equals(dataA)).toBeFalsy();
                expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());
                
                // The private keys don't transfer via the JSON constructor.
                expect(dataA.equals(dataA2)).toBeFalsy();
                expect(dataA2.equals(dataA)).toBeFalsy();
                expect(dataA2.uniqueKey()).not.toEqual(dataA.uniqueKey());
            });
        });
        
        it("equals private key", function() {
            var dataA = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            var dataB = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, RESPONSE_PRIVATE_KEY);
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
            waitsFor(function() { return dataA2; }, "dataA2 not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(dataA.equals(dataA)).toBeTruthy();
                expect(dataA.uniqueKey()).toEqual(dataA.uniqueKey());
                
                expect(dataA.equals(dataB)).toBeFalsy();
                expect(dataB.equals(dataA)).toBeFalsy();
                expect(dataB.uniqueKey()).not.toEqual(dataA.uniqueKey());
                
                // The private keys don't transfer via the JSON constructor.
                expect(dataA.equals(dataA2)).toBeFalsy();
                expect(dataA2.equals(dataA)).toBeFalsy();
                expect(dataA2.uniqueKey()).not.toEqual(dataA.uniqueKey());
            });
        });
        
        it("equals object", function() {
            var data = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            expect(data.equals(null)).toBeFalsy();
            expect(data.equals(PARAMETERS_ID)).toBeFalsy();
        });
    });
    
    /** Response data unit tests. */
    describe("ResponseData", function() {
        /** Key master token. */
        var KEY_MASTER_TOKEN = "mastertoken";
        
        it("ctors", function() {
            var resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.DIFFIE_HELLMAN);
            expect(resp.masterToken).toEqual(MASTER_TOKEN);
            expect(resp.parametersId).toEqual(PARAMETERS_ID);
            expect(resp.publicKey).toEqual(RESPONSE_PUBLIC_KEY);
            
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
	            
	            var moResp = ResponseData.parse(MASTER_TOKEN, keydata);
	            expect(moResp.keyExchangeScheme).toEqual(resp.keyExchangeScheme);
	            expect(moResp.masterToken).toEqual(resp.masterToken);
	            expect(moResp.parametersId).toEqual(resp.parametersId);
	            expect(moResp.publicKey).toEqual(resp.publicKey);
	            moResp.getKeydata(encoder, ENCODER_FORMAT, {
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
        		var resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
        		MslTestUtils.toMslObject(encoder, resp, {
        			result: function(x) { mo = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
        	
        	var masterToken;
        	runs(function() {
        		expect(mo.getString(KEY_SCHEME)).toEqual(KeyExchangeScheme.DIFFIE_HELLMAN.name);

        		MasterToken.parse(ctx, mo.getMslObject(KEY_MASTER_TOKEN, encoder), {
        			result: function(token) { masterToken = token; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);
        	
        	runs(function() {
        		expect(masterToken).toEqual(MASTER_TOKEN);
        		var keydata = mo.getMslObject(KEY_KEYDATA, encoder);
        		expect(keydata.getString(KEY_PARAMETERS_ID)).toEqual(PARAMETERS_ID);
        		expect(prependNullByte(keydata.getBytes(KEY_PUBLIC_KEY))).toEqual(RESPONSE_PUBLIC_KEY.getEncoded());
        	});
        });
        
        it("create", function() {
            var data = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            
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
            waitsFor(function() { return keyResponseData; }, "keyResponseData not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
	            expect(keyResponseData).not.toBeNull();
	            expect(keyResponseData instanceof ResponseData).toBeTruthy();
	            
	            var moData = keyResponseData;
	            expect(moData.keyExchangeScheme).toEqual(data.keyExchangeScheme);
	            expect(moData.masterToken).toEqual(data.masterToken);
	            expect(moData.parametersId).toEqual(data.parametersId);
	            expect(moData.publicKey).toEqual(data.publicKey);
            });
        });
        
        it("missing parameters ID", function() {
            var keydata;
            runs(function() {
	            var resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
	            resp.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(x) { keydata = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
	            
            runs(function() {
	            keydata.remove(KEY_PARAMETERS_ID);
	            var f = function() {
	            	ResponseData.parse(MASTER_TOKEN, keydata);
	            };
	            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });
        
        it("missing public key", function() {
            var keydata;
            runs(function() {
	            var resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
	            resp.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(x) { keydata = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
	            
            runs(function() {
	            keydata.remove(KEY_PUBLIC_KEY);
	            var f = function() {
	            	ResponseData.parse(MASTER_TOKEN, keydata);
	            };
	            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
            });
        });
        
        it("invalid public key", function() {
            var keydata;
            runs(function() {
	            var resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
	            resp.getKeydata(encoder, ENCODER_FORMAT, {
	            	result: function(x) { keydata = x; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
            });
            waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
	            
            runs(function() {
	            keydata.put(KEY_PUBLIC_KEY, "x");
	            var f = function() {
	            	ResponseData.parse(MASTER_TOKEN, keydata);
	            };
	            expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY));
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
            waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);
            
            var dataA, dataB, dataA2;
            runs(function() {
	            dataA = new ResponseData(masterTokenA, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
	            dataB = new ResponseData(masterTokenB, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
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
        
        it("equals parameter ID", function() {
            var dataA = new ResponseData(MASTER_TOKEN, PARAMETERS_ID + "A", RESPONSE_PUBLIC_KEY);
            var dataB = new ResponseData(MASTER_TOKEN, PARAMETERS_ID + "B", RESPONSE_PUBLIC_KEY);
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
        
        it("equals public key", function() {
            var dataA = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            var dataB = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, REQUEST_PUBLIC_KEY);
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
            var data = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            expect(data.equals(null)).toBeFalsy();
            expect(data.equals(PARAMETERS_ID)).toBeFalsy();
        });
    });
    
    /** Key exchange factory unit tests. */
    describe("KeyExchangeFactory", function() {
        /**
         * Fake key request data for the Diffie-Hellman key exchange scheme.
         */
        var FakeKeyRequestData = KeyRequestData.extend({
            /** Create a new fake key request data. */
            init: function init() {
                init.base.call(this, KeyExchangeScheme.DIFFIE_HELLMAN);
            },

            /** @inheritDoc */
            getKeydata: function getKeydata() {
                return null;
            },
        });
        
        /**
         * Fake key response data for the Diffie-Hellman key exchange scheme.
         */
        var FakeKeyResponseData = KeyResponseData.extend({
            /** Create a new fake key response data. */
            init: function init() {
                init.base.call(this, MASTER_TOKEN, KeyExchangeScheme.DIFFIE_HELLMAN);
            },

            /** @inheritDoc */
            getKeydata: function getKeydata() {
                return null;
            },
        });

        /** Diffie-Hellman parameter specifications. */
	    var paramSpecs = {};
	    var twentyThree = new Uint8Array([23]);
	    var five = new Uint8Array([5]);
	    paramSpecs['1'] = new DhParameterSpec(twentyThree, five);
        
        /** Key exchange factory. */
        var factory = new DiffieHellmanExchange(paramSpecs);
        
        /** Entity authentication data. */
        var entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        
        beforeEach(function() {
            ctx.getMslStore().clearCryptoContexts();
            ctx.getMslStore().clearServiceTokens();
        });
        
        it("factory", function() {
            expect(factory.scheme).toEqual(KeyExchangeScheme.DIFFIE_HELLMAN);
        });
        
        it("generate initial response", function() {
            var keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            var keyxData;
            runs(function() {
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
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
	            expect(keyResponseData.keyExchangeScheme).toEqual(KeyExchangeScheme.DIFFIE_HELLMAN);
	            var masterToken = keyResponseData.masterToken;
	            expect(masterToken).not.toBeNull();
	            expect(masterToken.identity).toEqual(MockPresharedAuthenticationFactory.PSK_ESN);
            });
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
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        it("generate initial response with invalid parameters ID", function() {
        	var exception;
            runs(function() {
	            var keyRequestData = new RequestData("x", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
	            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslKeyExchangeException(MslError.UNKNOWN_KEYX_PARAMETERS_ID));
            });
        });
        
        it("generate initial response with unknown parameters ID", function() {
        	var exception;
            runs(function() {
	            var keyRequestData = new RequestData('98765', REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
	            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslKeyExchangeException(MslError.UNKNOWN_KEYX_PARAMETERS_ID));
            });
        });
        
        it("generate subsequent response", function() {
            var keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            var keyxData;
            runs(function() {
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN, {
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
            	expect(keyResponseData.keyExchangeScheme).toEqual(KeyExchangeScheme.DIFFIE_HELLMAN);
            	var masterToken = keyResponseData.masterToken;
            	expect(masterToken).not.toBeNull();
            	expect(masterToken.identity).toEqual(MASTER_TOKEN.identity);
            	expect(masterToken.serialNumber).toEqual(MASTER_TOKEN.serialNumber);
            	expect(masterToken.sequenceNumber).toEqual(MASTER_TOKEN.sequenceNumber + 1);
            });
        });
        
        it("generate subsequent response with untrusted master token", function() {
            var keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);

        	var masterToken;
        	runs(function() {
	            MslTestUtils.getUntrustedMasterToken(ctx, {
	            	result: function(token) { masterToken = token; },
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	            });
        	});
        	waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);
        	
            var exception;
            runs(function() {
	            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, masterToken, {
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
	            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN, {
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
        
        it("generate subsequent response with invalid parameters ID", function() {
            var exception;
            runs(function() {
            	var keyRequestData = new RequestData("x", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            	factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN, {
            		result: function() {},
            		error: function(err) { exception = err; }
            	});
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslKeyExchangeException(MslError.UNKNOWN_KEYX_PARAMETERS_ID));
            });
        });
        
        it("generate subsequent response with unknown parameters ID", function() {
            var exception;
            runs(function() {
            	var keyRequestData = new RequestData('98765', REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            	factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN, {
            		result: function() {},
            		error: function(err) { exception = err; }
            	});
            });
            waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslKeyExchangeException(MslError.UNKNOWN_KEYX_PARAMETERS_ID));
            });
        });
        
        it("get crypto context", function() {
            var keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            var keyxData;
            runs(function() {
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
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
	            factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null, {
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
            waitsFor(function() { return requestVerified && responseVerified; }, "verifieds not received", MslTestConstants.TIMEOUT);
            runs(function() {
	            expect(requestVerified).toBeTruthy();
	            expect(responseVerified).toBeTruthy();
            });
        });
        
        it("get crypto context with wrong request type", function() {
        	var keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
        	var keyxData;
        	runs(function() {
        		factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
        			result: function(data) { keyxData = data; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
        	
        	var exception;
        	runs(function() {
	        	var keyResponseData = keyxData.keyResponseData;
	
	        	var fakeKeyRequestData = new FakeKeyRequestData();
	        	factory.getCryptoContext(ctx, fakeKeyRequestData, keyResponseData, null, {
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
	            var keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
	            var fakeKeyResponseData = new FakeKeyResponseData();
	            factory.getCryptoContext(ctx, keyRequestData, fakeKeyResponseData, null, {
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
        
        it("get crypto context with mismatched parameters ID", function() {
            var keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            var keyxData;
            runs(function() {
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);
            
        	var exception;
        	runs(function() {
	            var keyResponseData = keyxData.keyResponseData;
	            var masterToken = keyResponseData.masterToken;
	            
	            var mismatchedKeyResponseData = new ResponseData(masterToken, PARAMETERS_ID + "x", RESPONSE_PUBLIC_KEY);
	            
	            factory.getCryptoContext(ctx, keyRequestData, mismatchedKeyResponseData, null, {
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
        
        it("get crypto context with missing private key", function() {
            var keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, null);
            var keyxData;
            runs(function() {
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", MslTestConstants.TIMEOUT);

        	var exception;
        	runs(function() {
	            var keyResponseData = keyxData.keyResponseData;
	            
	            factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null, {
	        		result: function() {},
	        		error: function(err) { exception = err; }
	        	});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", MslTestConstants.TIMEOUT);
        	
        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_PRIVATE_KEY_MISSING));
        	});
        });
    });
});
