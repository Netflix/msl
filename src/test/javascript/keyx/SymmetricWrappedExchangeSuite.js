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
 * Symmetric wrapped key exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("SymmetricWrappedExchangeSuite", function() {
    /** JSON key key exchange scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key key request data. */
    var KEY_KEYDATA = "keydata";
    
    /** JSON key symmetric key ID. */
    var KEY_KEY_ID = "keyid";
    /** JSON key wrapped encryption key. */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /** JSON key wrapped HMAC key. */
    var KEY_HMAC_KEY = "hmackey";

    /** Random. */
    var random = new Random();
    /** Preshared keys entity context. */
    var pskCtx;
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
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { pskCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MockMslContext$create(EntityAuthenticationScheme.NONE, false, {
                    result: function(c) { unauthCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return pskCtx && unauthCtx; }, "MSL contexts", 100);
            
		    runs(function() {
		    	MslTestUtils.getMasterToken(pskCtx, 1, 1, {
		    		result: function(masterToken) {
		    			PSK_MASTER_TOKEN = masterToken;
		    		},
		    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    	});
		    });
		    waitsFor(function() { return PSK_MASTER_TOKEN; }, "static initialization", 100);
		    runs(function() { initialized = true; });
    	}
    });
    
    // Shortcuts
    var KeyId = SymmetricWrappedExchange$KeyId;
	var RequestData = SymmetricWrappedExchange$RequestData;
	var ResponseData = SymmetricWrappedExchange$ResponseData;
	var RequestData$parse = SymmetricWrappedExchange$RequestData$parse;
	var ResponseData$parse = SymmetricWrappedExchange$ResponseData$parse;
    
    /** Request data unit tests. */
    describe("RequestData", function() {
        it("ctor with PSK key ID", function() {
            var req = new RequestData(KeyId.PSK);
            expect(req.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
            expect(req.keyId).toEqual(KeyId.PSK);
            var keydata = req.getKeydata();
            expect(keydata).not.toBeNull();

            var joReq = RequestData$parse(keydata);
            expect(joReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
            expect(joReq.keyId).toEqual(req.keyId);
            var joKeydata = joReq.getKeydata();
            expect(joKeydata).not.toBeNull();
            expect(joKeydata).toEqual(keydata);
        });
        
        it("ctor with SESSION key ID", function() {
            var req = new RequestData(KeyId.SESSION);
            expect(req.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
            expect(req.keyId).toEqual(KeyId.SESSION);
            var keydata = req.getKeydata();
            expect(keydata).not.toBeNull();

            var joReq = RequestData$parse(keydata);
            expect(joReq.keyExchangeScheme).toEqual(req.keyExchangeScheme);
            expect(joReq.keyId).toEqual(req.keyId);
            var joKeydata = joReq.getKeydata();
            expect(joKeydata).not.toBeNull();
            expect(joKeydata).toEqual(keydata);
        });
        
        it("json is correct", function() {
            var req = new RequestData(KeyId.PSK);
            var jo = JSON.parse(JSON.stringify(req));
            expect(jo[KEY_SCHEME]).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED.name);
            var keydata = jo[KEY_KEYDATA];
            expect(keydata[KEY_KEY_ID]).toEqual(KeyId.PSK);
        });
        
        it("create", function() {
            var data = new RequestData(KeyId.PSK);
            var jsonString = JSON.stringify(data);
            var jo = JSON.parse(jsonString);
            var keyRequestData;
            runs(function() {
                KeyRequestData$parse(pskCtx, jo, {
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
                expect(joData.keyId).toEqual(data.keyId);
            });
        });

        it("missing key ID", function() {
            var f = function() {
	            var req = new RequestData(KeyId.PSK);
	            var keydata = req.getKeydata();
	
	            expect(keydata[KEY_KEY_ID]).not.toBeNull();
	            delete keydata[KEY_KEY_ID];
	
	            RequestData$parse(keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });

        it("invalid key ID", function() {
            var f = function() {
	            var req = new RequestData(KeyId.PSK);
	            var keydata = req.getKeydata();
	
	            keydata[KEY_KEY_ID] = "x";
	
	            RequestData$parse(keydata);
            };
            expect(f).toThrow(new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_KEY_ID));
        });
        
        it("equals key ID", function() {
        	var dataA = new RequestData(KeyId.PSK);
            var dataB = new RequestData(KeyId.SESSION);
            var dataA2 = RequestData$parse(dataA.getKeydata());
            
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
            var data = new RequestData(KeyId.PSK);
            expect(data.equals(null)).toBeFalsy();
            expect(data.equals(KEY_KEY_ID)).toBeFalsy();
        });
    });

    /** Response data unit tests. */
    describe("ResponseData", function() {
        /** JSON key master token. */
        var KEY_MASTER_TOKEN = "mastertoken";
        
        it("ctors", function() {
            var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            expect(resp.encryptionKey).toEqual(ENCRYPTION_KEY);
            expect(resp.hmacKey).toEqual(HMAC_KEY);
            expect(resp.keyExchangeScheme).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED);
            expect(resp.keyId).toEqual(KeyId.PSK);
            expect(resp.masterToken).toEqual(PSK_MASTER_TOKEN);
            var keydata = resp.getKeydata();
            expect(keydata).not.toBeNull();

            var joResp = ResponseData$parse(PSK_MASTER_TOKEN, keydata);
            expect(joResp.encryptionKey).toEqual(resp.encryptionKey);
            expect(joResp.hmacKey).toEqual(resp.hmacKey);
            expect(joResp.keyExchangeScheme).toEqual(resp.keyExchangeScheme);
            expect(joResp.keyId).toEqual(resp.keyId);
            expect(joResp.masterToken).toEqual(resp.masterToken);
            var joKeydata = resp.getKeydata();
            expect(joKeydata).not.toBeNull();
            expect(joKeydata).toEqual(keydata);
        });

        it("json is correct", function() {
        	var masterToken = undefined, jo;
        	runs(function() {
        		var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
        		jo = JSON.parse(JSON.stringify(resp));
        		expect(jo[KEY_SCHEME]).toEqual(KeyExchangeScheme.SYMMETRIC_WRAPPED.name);
        		MasterToken$parse(pskCtx, jo[KEY_MASTER_TOKEN], {
        			result: function(token) { masterToken = token; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return jo && masterToken; }, "json object and master token not received", 100);
        	runs(function() {
	            expect(PSK_MASTER_TOKEN.equals(masterToken)).toBeTruthy();
	            var keydata = jo[KEY_KEYDATA];
	            expect(keydata[KEY_KEY_ID]).toEqual(KeyId.PSK);
	            expect(base64$decode(keydata[KEY_ENCRYPTION_KEY])).toEqual(ENCRYPTION_KEY);
	            expect(base64$decode(keydata[KEY_HMAC_KEY])).toEqual(HMAC_KEY);
        	});
        });
        
        it("create", function() {
            var data = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);

            var keyResponseData;
            runs(function() {
            	var jsonString = JSON.stringify(data);
            	var jo = JSON.parse(jsonString);
            	KeyResponseData$parse(pskCtx, jo, {
            		result: function(data) { keyResponseData = data; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return keyResponseData; }, "keyResponseData not received", 100);
            runs(function() {
            	expect(keyResponseData).not.toBeNull();
            	expect(keyResponseData instanceof ResponseData).toBeTruthy();

            	var joData = keyResponseData;
            	expect(joData.encryptionKey).toEqual(data.encryptionKey);
            	expect(joData.hmacKey).toEqual(data.hmacKey);
            	expect(joData.keyExchangeScheme).toEqual(data.keyExchangeScheme);
            	expect(joData.keyId).toEqual(data.keyId);
            	expect(data.masterToken.equals(joData.masterToken)).toBeTruthy();
            });
        });

        it("missing key ID", function() {
            var f = function() {
	            var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
	            var keydata = resp.getKeydata();
	
	            expect(keydata[KEY_KEY_ID]).not.toBeNull();
	            delete keydata[KEY_KEY_ID];
	
	            ResponseData$parse(PSK_MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });

        it("missing encryption key", function() {
            var f = function() {
	            var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
	            var keydata = resp.getKeydata();
	
	            expect(keydata[KEY_ENCRYPTION_KEY]).not.toBeNull();
	            delete keydata[KEY_ENCRYPTION_KEY];
	
	            ResponseData$parse(PSK_MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });

        it("missing HMAC key", function() {
            var f = function() {
	            var resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
	            var keydata = resp.getKeydata();
	
	            expect(keydata[KEY_HMAC_KEY]).not.toBeNull();
	            delete keydata[KEY_HMAC_KEY];
	
	            ResponseData$parse(PSK_MASTER_TOKEN, keydata);
            };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
        
        it("equals master token", function() {
        	var masterTokenA = undefined, masterTokenB;
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
            waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 100);
            
            runs(function() {
	            var dataA = new ResponseData(masterTokenA, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
	            var dataB = new ResponseData(masterTokenB, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
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
        
        it("equals key ID", function() {
            var dataA = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, KeyId.SESSION, ENCRYPTION_KEY, HMAC_KEY);
            var dataA2 = ResponseData$parse(PSK_MASTER_TOKEN, dataA.getKeydata());
            
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
            var dataA = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, encryptionKeyA, HMAC_KEY);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, encryptionKeyB, HMAC_KEY);
            var dataA2 = ResponseData$parse(PSK_MASTER_TOKEN, dataA.getKeydata());
            
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
            var dataA = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, hmacKeyA);
            var dataB = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, hmacKeyB);
            var dataA2 = ResponseData$parse(PSK_MASTER_TOKEN, dataA.getKeydata());
            
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
         * @param {CipherKey} encryptionKey master token encryption key.
         * @param {CipherKey hmacKey master token HMAC key.
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
	            MasterToken$create(ctx, renewalWindow, expiration, 1, 1, null, identity, encryptionKey, hmacKey, {
	            	result: function(masterToken) {
	            		AsyncExecutor(callback, function() {
		    	            var json = JSON.stringify(masterToken);
		    	            var jo = JSON.parse(json);
		    	            var signature = base64$decode(jo["signature"]);
		    	            ++signature[1];
		    	            jo["signature"] = base64$encode(signature);
		    	            MasterToken$parse(ctx, jo, callback);
	            		});
	            	},
	            	error: function(err) { callback.error(err); }
	            });
        	});
        }
        
        /** Key exchange factory. */
        var factory = new SymmetricWrappedExchange();
        
        beforeEach(function() {
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
                factory.generateResponse(unauthCtx, keyRequestData, MockPresharedAuthenticationFactory.PSK_ESN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
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
                factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
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
	            factory.generateResponse(unauthCtx, keyRequestData, MockPresharedAuthenticationFactory.PSK_ESN + "x", {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", 100);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslEntityAuthException(MslError.NONE));
            });
        });
        
        it("generate initial response for wrong request type", function() {
        	var exception;
            runs(function() {
	            var keyRequestData = new FakeKeyRequestData();
	            factory.generateResponse(unauthCtx, keyRequestData, MockPresharedAuthenticationFactory.PSK_ESN, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", 100);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslInternalException(MslError.NONE));
            });
        });
        
        it("generate subsequent response for PSK key ID", function() {
            var keyRequestData = new RequestData(KeyId.PSK);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
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
                factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
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
        	waitsFor(function() { return masterToken; }, "master token not received", 100);
            
        	var exception;
            runs(function() {
        		var keyRequestData = new RequestData(KeyId.PSK);
	            factory.generateResponse(unauthCtx, keyRequestData, masterToken, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", 100);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED));
            });
        });
        
        it("generate subsequent response with wrong request type", function() {
        	var exception;
            runs(function() {
	            var keyRequestData = new FakeKeyRequestData();
	            factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", 100);
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
        	waitsFor(function() { return masterToken; }, "master token not received", 100);

        	var exception;
            runs(function() {
	            var keyRequestData = new RequestData(KeyId.SESSION);
	            factory.generateResponse(unauthCtx, keyRequestData, masterToken, {
                    result: function() {},
                    error: function(err) { exception = err; }
                });
            });
            waitsFor(function() { return exception; }, "exception not received", 100);
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslMasterTokenException(MslError.NONE));
            });
        });
        
        it("get crypto context for PSK key ID", function() {
            var keyRequestData = new RequestData(KeyId.PSK);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, keyRequestData, MockPresharedAuthenticationFactory.PSK_ESN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
            
            var data = new Uint8Array(32);
            random.nextBytes(data);
            
            var requestCryptoContext = undefined, responseCryptoContext;
            runs(function() {
            	requestCryptoContext = keyxData.cryptoContext;
	            var keyResponseData = keyxData.keyResponseData;
	            factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, null, {
	            	result: function(cryptoContext) { responseCryptoContext = cryptoContext; },
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
            });
            waitsFor(function() { return requestCryptoContext && responseCryptoContext; }, "crypto contexts not received", 100);
            
            // Ciphertext won't always be equal depending on how it was
            // enveloped. So we cannot check for equality or inequality.
            var requestCiphertext = undefined, responseCiphertext;
            runs(function() {
                expect(responseCryptoContext).not.toBeNull();requestCryptoContext.encrypt(data, {
                    result: function(data) { requestCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                responseCryptoContext.encrypt(data, {
                    result: function(data) { responseCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestCiphertext && responseCiphertext; }, "ciphertexts not received", 100);
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
            waitsFor(function() { return requestSignature && responseSignature; }, "signatures not received", 100);
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
            waitsFor(function() { return requestPlaintext && responsePlaintext; }, "plaintexts not received", 100);
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

        // Disabled because Web Crypto cannot wrap/unwrap with the session
        // encryption key.
        xit("get crypto context for SESSION key ID", function() {
            var keyRequestData = new RequestData(KeyId.SESSION);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);
            
            var data = new Uint8Array(32);
            random.nextBytes(data);

            var requestCryptoContext = undefined, responseCryptoContext;
            runs(function() {
            	requestCryptoContext = keyxData.cryptoContext;
	            var keyResponseData = keyxData.keyResponseData;
	            factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, PSK_MASTER_TOKEN, {
	            	result: function(cryptoContext) { responseCryptoContext = cryptoContext; },
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
            });
            waitsFor(function() { return requestCryptoContext && responseCryptoContext; }, "crypto contexts not received", 100);
            
         // Ciphertext won't always be equal depending on how it was
            // enveloped. So we cannot check for equality or inequality.
            var requestCiphertext = undefined, responseCiphertext;
            runs(function() {
                expect(responseCryptoContext).not.toBeNull();requestCryptoContext.encrypt(data, {
                    result: function(data) { requestCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                responseCryptoContext.encrypt(data, {
                    result: function(data) { responseCiphertext = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestCiphertext && responseCiphertext; }, "ciphertexts not received", 100);
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
            waitsFor(function() { return requestSignature && responseSignature; }, "signatures not received", 100);
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
            waitsFor(function() { return requestPlaintext && responsePlaintext; }, "plaintexts not received", 100);
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

        // Disabled because Web Crypto cannot wrap/unwrap with the session
        // encryption key.
        xit("get crypto context with missing master token", function() {
        	var keyRequestData = new RequestData(KeyId.SESSION);
        	var keyxData;
        	runs(function() {
        		factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN, {
        			result: function(data) { keyxData = data; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return keyxData; }, "keyxData not received", 100);

        	var exception;
        	runs(function() {
        		var keyResponseData = keyxData.keyResponseData;
        		factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", 100);

            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_MASTER_TOKEN_MISSING));
            });
        });
        
        it("get crypto context with wrong request type", function() {
        	var keyRequestData = new RequestData(KeyId.PSK);
        	var keyxData;
        	runs(function() {
        		factory.generateResponse(unauthCtx, keyRequestData, MockPresharedAuthenticationFactory.PSK_ESN, {
        			result: function(data) { keyxData = data; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return keyxData; }, "keyxData not received", 100);

        	var exception;
        	runs(function() {
        		var keyResponseData = keyxData.keyResponseData;

        		var fakeKeyRequestData = new FakeKeyRequestData();
        		factory.getCryptoContext(pskCtx, fakeKeyRequestData, keyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", 100);

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
        	waitsFor(function() { return exception; }, "exception not recevied", 100);
        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslInternalException(MslError.NONE));
        	});
        });
        
        it("get crypto context with mismatched key IDs", function() {
        	var keyRequestData = new RequestData(KeyId.PSK);
        	var keyxData;
        	runs(function() {
        		factory.generateResponse(unauthCtx, keyRequestData, MockPresharedAuthenticationFactory.PSK_ESN, {
        			result: function(data) { keyxData = data; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return keyxData; }, "keyxData not received", 100);
        	
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
        	waitsFor(function() { return exception; }, "exception not recevied", 100);
        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH));
        	});
        });
        
        it("get crypto context with invalid wrapped encryption key", function() {
        	var keyRequestData = new RequestData(KeyId.PSK);
        	var keyxData;
        	runs(function() {
        		factory.generateResponse(unauthCtx, keyRequestData, MockPresharedAuthenticationFactory.PSK_ESN, {
        			result: function(data) { keyxData = data; },
        			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        		});
        	});
        	waitsFor(function() { return keyxData; }, "keyxData not received", 100);
        	
        	var exception;
        	runs(function() {
	            var keyResponseData = keyxData.keyResponseData;
	            var masterToken = keyResponseData.masterToken;
	            
	            var keydata = keyResponseData.getKeydata();
	            var wrappedEncryptionKey = base64$decode(keydata[KEY_ENCRYPTION_KEY]);
	            ++wrappedEncryptionKey[wrappedEncryptionKey.length-1];
	            keydata[KEY_ENCRYPTION_KEY] = base64$encode(wrappedEncryptionKey);
	            var wrappedHmacKey = base64$decode(keydata[KEY_HMAC_KEY]);
	            
	            var invalidKeyResponseData = new ResponseData(masterToken, KeyId.PSK, wrappedEncryptionKey, wrappedHmacKey);
	            factory.getCryptoContext(pskCtx, keyRequestData, invalidKeyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", 100);
        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslCryptoException(MslError.NONE));
        	});
        });
        
        it("get crypto context with invalid wrapped HMAC key", function() {
            var keyRequestData = new RequestData(KeyId.PSK);
            var keyxData;
            runs(function() {
                factory.generateResponse(unauthCtx, keyRequestData, MockPresharedAuthenticationFactory.PSK_ESN, {
                    result: function(data) { keyxData = data; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "keyxData not received", 100);

        	var exception;
        	runs(function() {
        		var keyResponseData = keyxData.keyResponseData;
        		var masterToken = keyResponseData.masterToken;

        		var keydata = keyResponseData.getKeydata();
        		var wrappedHmacKey = base64$decode(keydata[KEY_HMAC_KEY]);
        		++wrappedHmacKey[wrappedHmacKey.length-1];
        		keydata[KEY_HMAC_KEY] = base64$encode(wrappedHmacKey);
        		var wrappedEncryptionKey = base64$decode(keydata[KEY_ENCRYPTION_KEY]);

        		var invalidKeyResponseData = new ResponseData(masterToken, KeyId.PSK, wrappedEncryptionKey, wrappedHmacKey);
        		factory.getCryptoContext(pskCtx, keyRequestData, invalidKeyResponseData, null, {
        			result: function() {},
        			error: function(err) { exception = err; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception not recevied", 100);
        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslCryptoException(MslError.NONE));
        	});
        });
    });
});
