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
 * Service token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
parameterize("ServiceToken", function data() {
    return [
        [ null ],
        [ MslConstants$CompressionAlgorithm.LZW ],
        [ MslConstants$CompressionAlgorithm.LZW ]
    ];
},
function(encoding, compressionAlgo) {
    /** JSON key token data. */
    var KEY_TOKENDATA = "tokendata";
    /** JSON key signature. */
    var KEY_SIGNATURE = "signature";
    
    // tokendata
    /** JSON key token name. */
    var KEY_NAME = "name";
    /** JSON key master token serial number. */
    var KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** JSON key user ID token serial number. */
    var KEY_USER_ID_TOKEN_SERIAL_NUMBER = "uitserialnumber";
    /** JSON key encrypted. */
    var KEY_ENCRYPTED = "encrypted";
    /** JSON key compression algorithm. */
    var KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** JSON key service data. */
    var KEY_SERVICEDATA = "servicedata";

    /** MSL context. */
    var ctx;
   /** Random. */
    var random = new Random();
    
    /**
     * @param {MslContext} ctx MSL context.
     * @param {result: function(ICryptoContext), error: function(Error)}
     *        callback the callback will receive the new crypto context
     *        or any thrown exceptions.
     * @throws CryptoException if there is an error creating the crypto
     *         context.
     */
    function getCryptoContext(ctx, callback) {
        AsyncExecutor(callback, function() {
            var keysetId = "keysetId";
            var encryptionBytes = new Uint8Array(16);
            random.nextBytes(encryptionBytes);
            var hmacBytes = new Uint8Array(32);
            random.nextBytes(hmacBytes);
            CipherKey$import(encryptionBytes, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                result: function(encryptionKey) {
                    CipherKey$import(hmacBytes, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                        result: function(hmacKey) {
                            AsyncExecutor(callback, function() {
                                var cryptoContext = new SymmetricCryptoContext(ctx, keysetId, encryptionKey, hmacKey, null);
                                return cryptoContext;
                            });
                        },
                        error: function(e) { callback.error(e); }
                    });
                },
                error: function(e) { callback.error(e); }
            });
        });
    }
    
    var NAME = "tokenName";
    var DATA = textEncoding$getBytes("We have to use some data that is compressible, otherwise service tokens will not always use the compression we request.", "utf-8");
    var MASTER_TOKEN;
    var USER_ID_TOKEN;
    var ENCRYPTED = true;
    var CRYPTO_CONTEXT;
    
    var initialized = false;
    beforeEach(function() {
    	if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
	    	runs(function() {
	    	    getCryptoContext(ctx, {
	    	        result: function(x) { CRYPTO_CONTEXT = x; },
	    	        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	    });
	    		MslTestUtils.getMasterToken(ctx, 1, 1, {
	    			result: function(token) { MASTER_TOKEN = token; },
	    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    		});
	    	});
	    	waitsFor(function() { return CRYPTO_CONTEXT && MASTER_TOKEN; }, "crypto context and master token not received", 100);
	    	runs(function() {
	    		MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
	    			result: function(token) { USER_ID_TOKEN = token; },
	    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    		});
	    	});
	    	waitsFor(function() { return USER_ID_TOKEN; }, "user ID token not received", 100);
	    	runs(function() { initialized = true; });
    	}
    });
    
    it("ctors", function() {
    	var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var jsonString;
        runs(function() {
	        expect(serviceToken.isDecrypted()).toBeTruthy();
	        expect(serviceToken.isDeleted()).toBeFalsy();
	        expect(serviceToken.isVerified()).toBeTruthy();
	        expect(serviceToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
	        expect(serviceToken.isBoundTo(USER_ID_TOKEN)).toBeTruthy();
	        expect(serviceToken.isMasterTokenBound()).toBeTruthy();
	        expect(serviceToken.isUserIdTokenBound()).toBeTruthy();
	        expect(serviceToken.isUnbound()).toBeFalsy();
	        expect(serviceToken.mtSerialNumber).toEqual(MASTER_TOKEN.serialNumber);
	        expect(serviceToken.uitSerialNumber).toEqual(USER_ID_TOKEN.serialNumber);
	        expect(serviceToken.name).toEqual(NAME);
	        expect(serviceToken.compressionAlgo).toEqual(compressionAlgo);
	        expect(new Uint8Array(serviceToken.data)).toEqual(DATA);
	        jsonString = JSON.stringify(serviceToken);
	        expect(jsonString).not.toBeNull();
        });
        waitsFor(function() { return jsonString; }, "json string not received", 100);

        var joServiceToken;
        runs(function() {
	        var jo = JSON.parse(jsonString);
            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joServiceToken; }, "joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isDecrypted()).toEqual(serviceToken.isDecrypted());
	        expect(joServiceToken.isDeleted()).toEqual(serviceToken.isDeleted());
	        expect(joServiceToken.isVerified()).toEqual(serviceToken.isVerified());
	        expect(joServiceToken.isBoundTo(MASTER_TOKEN)).toEqual(serviceToken.isBoundTo(MASTER_TOKEN));
	        expect(joServiceToken.isBoundTo(USER_ID_TOKEN)).toEqual(serviceToken.isBoundTo(USER_ID_TOKEN));
	        expect(joServiceToken.isMasterTokenBound()).toEqual(serviceToken.isMasterTokenBound());
	        expect(joServiceToken.isUserIdTokenBound()).toEqual(serviceToken.isUserIdTokenBound());
	        expect(joServiceToken.isUnbound()).toEqual(serviceToken.isUnbound());
	        expect(joServiceToken.mtSerialNumber).toEqual(serviceToken.mtSerialNumber);
	        expect(joServiceToken.uitSerialNumber).toEqual(serviceToken.uitSerialNumber);
	        expect(joServiceToken.name).toEqual(serviceToken.name);
	        expect(joServiceToken.compressionAlgo).toEqual(serviceToken.compressionAlgo);
	        expect(new Uint8Array(joServiceToken.data)).toEqual(new Uint8Array(serviceToken.data));
	        var joJsonString = JSON.stringify(joServiceToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("mismatched crypto contexts", function() {
        var serviceToken = undefined, joCryptoContext;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            getCryptoContext(ctx, {
                result: function(x) { joCryptoContext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken && joCryptoContext; }, "serviceToken and joCryptoContext not received", 100);

        var jsonString = undefined, joServiceToken;
        runs(function() {
            jsonString = JSON.stringify(serviceToken);
            var jo = JSON.parse(jsonString);
            
            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, joCryptoContext, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joServiceToken; }, "json string and joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isDecrypted()).toBeFalsy();
	        expect(serviceToken.isDeleted()).toBeFalsy();
	        expect(joServiceToken.isVerified()).toBeFalsy();
	        expect(joServiceToken.data).toBeNull();
	        expect(joServiceToken.isBoundTo(MASTER_TOKEN)).toEqual(serviceToken.isBoundTo(MASTER_TOKEN));
	        expect(joServiceToken.isBoundTo(USER_ID_TOKEN)).toEqual(serviceToken.isBoundTo(USER_ID_TOKEN));
	        expect(joServiceToken.isMasterTokenBound()).toEqual(serviceToken.isMasterTokenBound());
	        expect(joServiceToken.isUserIdTokenBound()).toEqual(serviceToken.isUserIdTokenBound());
	        expect(joServiceToken.isUnbound()).toEqual(serviceToken.isUnbound());
	        expect(joServiceToken.mtSerialNumber).toEqual(serviceToken.mtSerialNumber);
	        expect(joServiceToken.uitSerialNumber).toEqual(serviceToken.uitSerialNumber);
	        expect(joServiceToken.name).toEqual(serviceToken.name);
	        expect(joServiceToken.compressionAlgo).toEqual(serviceToken.compressionAlgo);
	        var joJsonString = JSON.stringify(joServiceToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("mapped crypto contexts", function() {
        var serviceToken = undefined, cryptoContexts = {};
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            
            cryptoContexts[NAME] = CRYPTO_CONTEXT;
            getCryptoContext(ctx, {
                result: function(x) { cryptoContexts[NAME + "1"] = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            getCryptoContext(ctx, {
                result: function(x) { cryptoContexts[NAME + "2"] = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken && Object.keys(cryptoContexts).length == 3; }, "serviceToken and cryptoContexts not received", 100);
       
        var jsonString = undefined, joServiceToken;
        runs(function() {
            jsonString = JSON.stringify(serviceToken);
            var jo = JSON.parse(jsonString);

            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, cryptoContexts, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joServiceToken; }, "json string and joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isDecrypted()).toEqual(serviceToken.isDecrypted());
	        expect(joServiceToken.isDeleted()).toEqual(serviceToken.isDeleted());
	        expect(joServiceToken.isVerified()).toEqual(serviceToken.isVerified());
	        expect(joServiceToken.isBoundTo(MASTER_TOKEN)).toEqual(serviceToken.isBoundTo(MASTER_TOKEN));
	        expect(joServiceToken.isBoundTo(USER_ID_TOKEN)).toEqual(serviceToken.isBoundTo(USER_ID_TOKEN));
	        expect(joServiceToken.isMasterTokenBound()).toEqual(serviceToken.isMasterTokenBound());
	        expect(joServiceToken.isUserIdTokenBound()).toEqual(serviceToken.isUserIdTokenBound());
	        expect(joServiceToken.isUnbound()).toEqual(serviceToken.isUnbound());
	        expect(joServiceToken.mtSerialNumber).toEqual(serviceToken.mtSerialNumber);
	        expect(joServiceToken.uitSerialNumber).toEqual(serviceToken.uitSerialNumber);
	        expect(joServiceToken.name).toEqual(serviceToken.name);
            expect(joServiceToken.compressionAlgo).toEqual(serviceToken.compressionAlgo);
	        expect(new Uint8Array(joServiceToken.data)).toEqual(new Uint8Array(serviceToken.data));
	        var joJsonString = JSON.stringify(joServiceToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
	    });
    });
    
    it("unmapped crypto context", function() {
        var serviceToken = undefined, cryptoContexts = {};
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            
            cryptoContexts[NAME + "0"] = CRYPTO_CONTEXT;
            getCryptoContext(ctx, {
                result: function(x) { cryptoContexts[NAME + "1"] = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            getCryptoContext(ctx, {
                result: function(x) { cryptoContexts[NAME + "2"] = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken && Object.keys(cryptoContexts).length == 3; }, "serviceToken and cryptoContexts not received", 100);
        
        var jsonString = undefined, joServiceToken;
        runs(function() {
        	jsonString = JSON.stringify(serviceToken);
        	var jo = JSON.parse(jsonString);

        	ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, cryptoContexts, {
        		result: function(token) { joServiceToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return jsonString && joServiceToken; }, "json string and joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isDecrypted()).toBeFalsy();
	        expect(joServiceToken.isDeleted()).toBeFalsy();
	        expect(joServiceToken.isVerified()).toBeFalsy();
	        expect(joServiceToken.data).toBeNull();
	        expect(joServiceToken.isBoundTo(MASTER_TOKEN)).toEqual(serviceToken.isBoundTo(MASTER_TOKEN));
	        expect(joServiceToken.isBoundTo(USER_ID_TOKEN)).toEqual(serviceToken.isBoundTo(USER_ID_TOKEN));
	        expect(joServiceToken.isMasterTokenBound()).toEqual(serviceToken.isMasterTokenBound());
	        expect(joServiceToken.isUserIdTokenBound()).toEqual(serviceToken.isUserIdTokenBound());
	        expect(joServiceToken.isUnbound()).toEqual(serviceToken.isUnbound());
	        expect(joServiceToken.mtSerialNumber).toEqual(serviceToken.mtSerialNumber);
	        expect(joServiceToken.uitSerialNumber).toEqual(serviceToken.uitSerialNumber);
	        expect(joServiceToken.name).toEqual(serviceToken.name);
            expect(joServiceToken.compressionAlgo).toEqual(serviceToken.compressionAlgo);
	        var joJsonString = JSON.stringify(joServiceToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("master token mismatched", function() {
        var masterToken = undefined, joMasterToken;
        runs(function() {
        	MslTestUtils.getMasterToken(ctx, 1, 1, {
        		result: function(token) { masterToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        	MslTestUtils.getMasterToken(ctx, 1, 2, {
        		result: function(token) { joMasterToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return masterToken && joMasterToken; }, "master tokens not received", 100);
        
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, masterToken, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        ServiceToken$parse(ctx, jo, joMasterToken, null, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH));
        });
    });
    
    it("master token missing", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        ServiceToken$parse(ctx, jo, null, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH));
        });
    });
    
    it("user ID token mismatched", function() {
    	var userIdToken = undefined, joUserIdToken;
    	runs(function() {
    		MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
    			result: function(token) { userIdToken = token; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    		MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
    			result: function(token) { joUserIdToken = token; },
    			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		});
    	});
    	waitsFor(function() { return userIdToken && joUserIdToken; }, "user ID tokens not received", 100);
    	
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, userIdToken, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, joUserIdToken, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH));
        });
    });
    
    it("user ID token missing", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, null, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH));
        });
    });
    
    it("tokens mismatched", function() {
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
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 100);
        
        var userIdToken;
        runs(function() {
        	MslTestUtils.getUserIdToken(ctx, masterTokenB, 1, MockEmailPasswordAuthenticationFactory.USER, {
        		result: function(token) { userIdToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", 100);

    	var exception;
    	runs(function() {
    		ServiceToken$create(ctx, NAME, DATA, masterTokenA, userIdToken, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
    			result: function() {},
    			error: function(err) { exception = err; }
    		});
    	});
    	waitsFor(function() { return exception; }, "exception not received", 100);
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslInternalException());
    	});
    });
    
    it("missing tokendata", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        expect([KEY_TOKENDATA]).not.toBeNull();
	        delete jo[KEY_TOKENDATA];
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid tokendata", function() {
    	var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        ++tokendata[0];
	        jo[KEY_TOKENDATA] = base64$encode(tokendata);
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("missing signature", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        expect(jo[KEY_SIGNATURE]).not.toBeNull();
	        delete jo[KEY_SIGNATURE];
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("missing name", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect([KEY_NAME]).not.toBeNull();
	        delete tokendataJo[KEY_NAME];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("missing master token serial number", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var joServiceToken;
        runs(function() {
        	var jsonString = JSON.stringify(serviceToken);
            var jo = JSON.parse(jsonString);
            
            var tokendata = base64$decode(jo[KEY_TOKENDATA]);
            var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            expect([KEY_MASTER_TOKEN_SERIAL_NUMBER]).not.toBeNull();
            delete tokendataJo[KEY_MASTER_TOKEN_SERIAL_NUMBER];
            jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
            
            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joServiceToken; }, "joServiceToken not received", 100);
        runs(function() {
	        expect(joServiceToken.mtSerialNumber).toEqual(-1);
	        expect(joServiceToken.isBoundTo(MASTER_TOKEN)).toBeFalsy();
        });
    });
    
    it("invalid master token serial number", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_MASTER_TOKEN_SERIAL_NUMBER] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("negative master token serial number", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_MASTER_TOKEN_SERIAL_NUMBER] = -1;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });
    
    it("too large master token serial number", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_MASTER_TOKEN_SERIAL_NUMBER] = MslConstants$MAX_LONG_VALUE + 2;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });
    
    it("missing user ID token serial number", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var joServiceToken;
        runs(function() {
        	var jsonString = JSON.stringify(serviceToken);
            var jo = JSON.parse(jsonString);
            
            var tokendata = base64$decode(jo[KEY_TOKENDATA]);
            var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            expect([KEY_USER_ID_TOKEN_SERIAL_NUMBER]).not.toBeNull();
            delete tokendataJo[KEY_USER_ID_TOKEN_SERIAL_NUMBER];
            jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
            
            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joServiceToken; }, "joServiceToken not received", 100);
        runs(function() {
	        expect(joServiceToken.uitSerialNumber).toEqual(-1);
	        expect(joServiceToken.isBoundTo(USER_ID_TOKEN)).toBeFalsy();
        });
    });
    
    it("invalid user ID token serial number", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_USER_ID_TOKEN_SERIAL_NUMBER] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("negative user ID token serial number", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_USER_ID_TOKEN_SERIAL_NUMBER] = -1;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);;
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });
    
    it("too large user ID token serial number", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_USER_ID_TOKEN_SERIAL_NUMBER] = MslConstants$MAX_LONG_VALUE + 2;
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);;
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE));
        });
    });
    
    it("missing encrypted", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect([KEY_ENCRYPTED]).not.toBeNull();
	        delete tokendataJo[KEY_ENCRYPTED];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid encrypted", function() {
    	var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        tokendataJo[KEY_ENCRYPTED] = "x";
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid compression algorithm", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
            var jsonString = JSON.stringify(serviceToken);
            var jo = JSON.parse(jsonString);
            
            var tokendata = base64$decode(jo[KEY_TOKENDATA]);
            var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            tokendataJo[KEY_COMPRESSION_ALGORITHM] = "x";
            jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
            
            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
                result: function() {},
                error: function(err) { exception = err; }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.UNIDENTIFIED_COMPRESSION));
        });
    });
    
    it("missing servicedata", function() {
    	var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        expect([KEY_SERVICEDATA]).not.toBeNull();
	        delete tokendataJo[KEY_SERVICEDATA];
	        jo[KEY_TOKENDATA] = base64$encode(textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET));
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid servicedata", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
        	var jsonString = JSON.stringify(serviceToken);
        	var jo = JSON.parse(jsonString);

        	var tokendata = base64$decode(jo[KEY_TOKENDATA]);
        	var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
        	tokendataJo[KEY_SERVICEDATA] = "x";

        	var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
        	CRYPTO_CONTEXT.sign(modifiedTokendata, {
        		result: function(signature) {
                	jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
                	jo[KEY_SIGNATURE] = base64$encode(signature);

                	ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
                		result: function() {},
                		error: function(err) { exception = err; }
                	});
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslException(MslError.SERVICETOKEN_SERVICEDATA_INVALID));
        });
    });
    
    it("empty servicedata", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, new Uint8Array(0), MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);

        var joServiceToken;
        runs(function() {
	        expect(serviceToken.isDeleted()).toBeTruthy();
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
        
            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joServiceToken; }, "joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isDeleted()).toBeTruthy();
	        expect(joServiceToken.data.length).toEqual(0);
        });
    });
    
    it("empty servicedata not verified", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, new Uint8Array(0), MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);

        var joServiceToken;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var signature = base64$decode(jo[KEY_SIGNATURE]);
	        ++signature[0];
	        jo[KEY_SIGNATURE] = base64$encode(signature);
	        
	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	        	result: function(token) { joServiceToken = token; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return joServiceToken; }, "joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isDeleted()).toBeTruthy();
	        expect(joServiceToken.data.length).toEqual(0);
        });
    });
    
    it("corrupt servicedata", function() {
    	var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var exception;
        runs(function() {
	        var jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        // This is testing service data that is verified but corrupt.
	        var tokendata = base64$decode(jo[KEY_TOKENDATA]);
	        var tokendataJo = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
	        var servicedata = base64$decode(tokendataJo[KEY_SERVICEDATA]);
	        ++servicedata[servicedata.length-1];
	        tokendataJo[KEY_SERVICEDATA] = base64$encode(servicedata);
	        
	        var modifiedTokendata = textEncoding$getBytes(JSON.stringify(tokendataJo), MslConstants$DEFAULT_CHARSET);
	        CRYPTO_CONTEXT.sign(modifiedTokendata, {
	        	result: function(signature) {
	    	        jo[KEY_TOKENDATA] = base64$encode(modifiedTokendata);
	    	        jo[KEY_SIGNATURE] = base64$encode(signature);
	    	        
	    	        ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
	    	        	result: function() {},
	    	        	error: function(err) { exception = err; }
	    	        });
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
    	});
        waitsFor(function() { return exception; }, "exception not received", 100);
        
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslCryptoException(MslError.NONE));
        });
    });
    
    it("not verified", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var jsonString = undefined, joServiceToken;
        runs(function() {
	        jsonString = JSON.stringify(serviceToken);
	        var jo = JSON.parse(jsonString);
	        
	        var signature = base64$decode(jo[KEY_SIGNATURE]);
	        ++signature[0];
	        jo[KEY_SIGNATURE] = base64$encode(signature);
        
            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joServiceToken; }, "json string and joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isDecrypted()).toBeFalsy();
	        expect(joServiceToken.isDeleted()).toBeFalsy();
	        expect(joServiceToken.isVerified()).toBeFalsy();
	        expect(joServiceToken.data).toBeNull();
	        expect(joServiceToken.isBoundTo(MASTER_TOKEN)).toEqual(serviceToken.isBoundTo(MASTER_TOKEN));
	        expect(joServiceToken.isBoundTo(USER_ID_TOKEN)).toEqual(serviceToken.isBoundTo(USER_ID_TOKEN));
	        expect(joServiceToken.isMasterTokenBound()).toEqual(serviceToken.isMasterTokenBound());
	        expect(joServiceToken.isUserIdTokenBound()).toEqual(serviceToken.isUserIdTokenBound());
	        expect(joServiceToken.isUnbound()).toEqual(serviceToken.isUnbound());
	        expect(joServiceToken.mtSerialNumber).toEqual(serviceToken.mtSerialNumber);
	        expect(joServiceToken.uitSerialNumber).toEqual(serviceToken.uitSerialNumber);
	        expect(joServiceToken.name).toEqual(serviceToken.name);
	        var joJsonString = JSON.stringify(joServiceToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).not.toEqual(jsonString);
        });
    });
    
    it("not encrypted", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, !ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var jsonString = undefined, joServiceToken;
        runs(function() {
        	expect(new Uint8Array(serviceToken.data)).toEqual(DATA);
        	jsonString = JSON.stringify(serviceToken);
        	var jo = JSON.parse(jsonString);

            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joServiceToken; }, "json string and joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isVerified()).toBeTruthy();
	        expect(joServiceToken.isDeleted()).toBeFalsy();
	        expect(joServiceToken.isDecrypted()).toBeTruthy();
	        expect(new Uint8Array(joServiceToken.data)).toEqual(new Uint8Array(serviceToken.data));
	        expect(joServiceToken.isBoundTo(MASTER_TOKEN)).toEqual(serviceToken.isBoundTo(MASTER_TOKEN));
	        expect(joServiceToken.isBoundTo(USER_ID_TOKEN)).toEqual(serviceToken.isBoundTo(USER_ID_TOKEN));
	        expect(joServiceToken.isMasterTokenBound()).toEqual(serviceToken.isMasterTokenBound());
	        expect(joServiceToken.isUserIdTokenBound()).toEqual(serviceToken.isUserIdTokenBound());
	        expect(joServiceToken.isUnbound()).toEqual(serviceToken.isUnbound());
	        expect(joServiceToken.mtSerialNumber).toEqual(serviceToken.mtSerialNumber);
	        expect(joServiceToken.uitSerialNumber).toEqual(serviceToken.uitSerialNumber);
	        expect(joServiceToken.name).toEqual(serviceToken.name);
	        var joJsonString = JSON.stringify(joServiceToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("null crypto context", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var jsonString = undefined, joServiceToken;
        runs(function() {
        	jsonString = JSON.stringify(serviceToken);
        	var jo = JSON.parse(jsonString);
        
            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joServiceToken; }, "joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isDecrypted()).toBeFalsy();
	        expect(joServiceToken.isDeleted()).toBeFalsy();
	        expect(joServiceToken.isVerified()).toBeFalsy();
	        expect(joServiceToken.data).toBeNull();
	        expect(joServiceToken.isBoundTo(MASTER_TOKEN)).toEqual(serviceToken.isBoundTo(MASTER_TOKEN));
	        expect(joServiceToken.isBoundTo(USER_ID_TOKEN)).toEqual(serviceToken.isBoundTo(USER_ID_TOKEN));
	        expect(joServiceToken.isMasterTokenBound()).toEqual(serviceToken.isMasterTokenBound());
	        expect(joServiceToken.isUserIdTokenBound()).toEqual(serviceToken.isUserIdTokenBound());
	        expect(joServiceToken.isUnbound()).toEqual(serviceToken.isUnbound());
	        expect(joServiceToken.mtSerialNumber).toEqual(serviceToken.mtSerialNumber);
	        expect(joServiceToken.uitSerialNumber).toEqual(serviceToken.uitSerialNumber);
	        expect(joServiceToken.name).toEqual(serviceToken.name);
	        var joJsonString = JSON.stringify(joServiceToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("not encrypted with null crypto context", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, !ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        
        var jsonString = undefined, joServiceToken;
        runs(function() {
        	jsonString = JSON.stringify(serviceToken);
        	var jo = JSON.parse(jsonString);

        	joServiceToken = undefined;
            ServiceToken$parse(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(token) { joServiceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return jsonString && joServiceToken; }, "json string and joServiceToken not received", 100);
        
        runs(function() {
	        expect(joServiceToken.isDecrypted()).toBeFalsy();
	        expect(joServiceToken.isDeleted()).toBeFalsy();
	        expect(joServiceToken.isVerified()).toBeFalsy();
	        expect(joServiceToken.data).toBeNull();
	        expect(joServiceToken.isBoundTo(MASTER_TOKEN)).toEqual(serviceToken.isBoundTo(MASTER_TOKEN));
	        expect(joServiceToken.isBoundTo(USER_ID_TOKEN)).toEqual(serviceToken.isBoundTo(USER_ID_TOKEN));
	        expect(joServiceToken.isMasterTokenBound()).toEqual(serviceToken.isMasterTokenBound());
	        expect(joServiceToken.isUserIdTokenBound()).toEqual(serviceToken.isUserIdTokenBound());
	        expect(joServiceToken.isUnbound()).toEqual(serviceToken.isUnbound());
	        expect(joServiceToken.mtSerialNumber).toEqual(serviceToken.mtSerialNumber);
	        expect(joServiceToken.uitSerialNumber).toEqual(serviceToken.uitSerialNumber);
	        expect(joServiceToken.name).toEqual(serviceToken.name);
	        var joJsonString = JSON.stringify(joServiceToken);
	        expect(joJsonString).not.toBeNull();
	        expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("isBoundTo(masterToken)", function() {
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
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 100);
        
        var serviceTokenA = undefined, serviceTokenB;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, masterTokenA, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken$create(ctx, NAME, DATA, masterTokenB, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceTokenA && serviceTokenB; }, "service tokens not received", 100);
        
        runs(function() {
	        expect(serviceTokenA.isBoundTo(masterTokenA)).toBeTruthy();
	        expect(serviceTokenA.isBoundTo(masterTokenB)).toBeFalsy();
	        expect(serviceTokenA.isBoundTo(null)).toBeFalsy();
	        expect(serviceTokenB.isBoundTo(masterTokenB)).toBeTruthy();
	        expect(serviceTokenB.isBoundTo(masterTokenA)).toBeFalsy();
	        expect(serviceTokenA.isBoundTo(null)).toBeFalsy();
        });
    });
    
    it("isBoundTo(userIdToken)", function() {
        var userIdTokenA = undefined, userIdTokenB;
        runs(function() {
        	MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
        		result: function(token) { userIdTokenA = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        	MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
        		result: function(token) { userIdTokenB = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", 100);
        
        var serviceTokenA = undefined, serviceTokenB;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenA, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenB, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceTokenA && serviceTokenB; }, "service tokens not received", 100);
        
        runs(function() {
	        expect(serviceTokenA.isBoundTo(userIdTokenA)).toBeTruthy();
	        expect(serviceTokenA.isBoundTo(userIdTokenB)).toBeFalsy();
	        expect(serviceTokenA.isBoundTo(null)).toBeFalsy();
	        expect(serviceTokenB.isBoundTo(userIdTokenB)).toBeTruthy();
	        expect(serviceTokenB.isBoundTo(userIdTokenA)).toBeFalsy();
	        expect(serviceTokenA.isBoundTo(null)).toBeFalsy();
        });
    });
    
    it("isUnbound", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, null, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        runs(function() {
	        expect(serviceToken.isUnbound()).toBeTruthy();
	        expect(serviceToken.isBoundTo(MASTER_TOKEN)).toBeFalsy();
	        expect(serviceToken.isBoundTo(USER_ID_TOKEN)).toBeFalsy();
	        expect(serviceToken.isBoundTo(null)).toBeFalsy();
        });
    });
    
    it("equals name", function() {
        var nameA = NAME + "A";
        var nameB = NAME + "B";
        var serviceTokenA = undefined, serviceTokenB;
        runs(function() {
            ServiceToken$create(ctx, nameA, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken$create(ctx, nameB, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceTokenA && serviceTokenB; }, "service tokens A and B not received", 100);
        
        var serviceTokenA2;
        runs(function() {
            ServiceToken$parse(ctx, JSON.parse(JSON.stringify(serviceTokenA)), MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenA2 = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceTokenA2; }, "service token A2 not received", 100);

        runs(function() {
	        expect(serviceTokenA.equals(serviceTokenA)).toBeTruthy();
	        expect(serviceTokenA.uniqueKey()).toEqual(serviceTokenA.uniqueKey());
	        
	        expect(serviceTokenA.equals(serviceTokenB)).toBeFalsy();
	        expect(serviceTokenB.equals(serviceTokenA)).toBeFalsy();
	        expect(serviceTokenB.uniqueKey()).not.toEqual(serviceTokenA.uniqueKey());
	        
	        expect(serviceTokenA.equals(serviceTokenA2)).toBeTruthy();
	        expect(serviceTokenA2.equals(serviceTokenA)).toBeTruthy();
	        expect(serviceTokenA2.uniqueKey()).toEqual(serviceTokenA.uniqueKey());
        });
    });
    
    it("equals master token serial number", function() {
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
        waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", 100);
        
        var serviceTokenA = undefined, serviceTokenB;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, masterTokenA, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken$create(ctx, NAME, DATA, masterTokenB, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceTokenA && serviceTokenB; }, "service tokens A and B not received", 100);
        
        var serviceTokenA2;
        runs(function() {
            ServiceToken$parse(ctx, JSON.parse(JSON.stringify(serviceTokenA)), masterTokenA, null, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenA2 = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceTokenA2; }, "service token A2 not received", 100);

        runs(function() {
	        expect(serviceTokenA.equals(serviceTokenA)).toBeTruthy();
	        expect(serviceTokenA.uniqueKey()).toEqual(serviceTokenA.uniqueKey());
	        
	        expect(serviceTokenA.equals(serviceTokenB)).toBeFalsy();
	        expect(serviceTokenB.equals(serviceTokenA)).toBeFalsy();
	        expect(serviceTokenB.uniqueKey()).not.toEqual(serviceTokenA.uniqueKey());
	        
	        expect(serviceTokenA.equals(serviceTokenA2)).toBeTruthy();
	        expect(serviceTokenA2.equals(serviceTokenA)).toBeTruthy();
	        expect(serviceTokenA2.uniqueKey()).toEqual(serviceTokenA.uniqueKey());
        });
    });
    
    it("equals user ID token serial number", function() {
        var userIdTokenA = undefined, userIdTokenB;
        runs(function() {
        	MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
        		result: function(token) { userIdTokenA = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        	MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
        		result: function(token) { userIdTokenB = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", 100);
        
        var serviceTokenA = undefined, serviceTokenB;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenA, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenB, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceTokenA && serviceTokenB; }, "service tokens A and B not received", 100);
        
        var serviceTokenA2;
        runs(function() {
            ServiceToken$parse(ctx, JSON.parse(JSON.stringify(serviceTokenA)), MASTER_TOKEN, userIdTokenA, CRYPTO_CONTEXT, {
                result: function(token) { serviceTokenA2 = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceTokenA2; }, "service token A2 not received", 100);

        runs(function() {
	        expect(serviceTokenA.equals(serviceTokenA)).toBeTruthy();
	        expect(serviceTokenA.uniqueKey()).toEqual(serviceTokenA.uniqueKey());
	        
	        expect(serviceTokenA.equals(serviceTokenB)).toBeFalsy();
	        expect(serviceTokenB.equals(serviceTokenA)).toBeFalsy();
	        expect(serviceTokenB.uniqueKey()).not.toEqual(serviceTokenA.uniqueKey());
	        
	        expect(serviceTokenA.equals(serviceTokenA2)).toBeTruthy();
	        expect(serviceTokenA2.equals(serviceTokenA)).toBeTruthy();
	        expect(serviceTokenA2.uniqueKey()).toEqual(serviceTokenA.uniqueKey());
        });
    });
    
    it("equals object", function() {
        var serviceToken;
        runs(function() {
            ServiceToken$create(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT, {
                result: function(token) { serviceToken = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", 100);
        runs(function() {
	        expect(serviceToken.equals(null)).toBeFalsy();
	        expect(serviceToken.equals(DATA)).toBeFalsy();
        });
    });
});
