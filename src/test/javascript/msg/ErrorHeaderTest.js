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
 * Error header unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("ErrorHeader", function() {
    /** JSON key entity authentication data. */
    var KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
    /** JSON key error data. */
    var KEY_ERRORDATA = "errordata";
    /** JSON key error data signature. */
    var KEY_SIGNATURE = "signature";
    
    // Message error data.
    /** JSON key recipient. */
    var KEY_RECIPIENT = "recipient";
    /** JSON key message ID. */
    var KEY_MESSAGE_ID = "messageid";
    /** JSON key error code. */
    var KEY_ERROR_CODE = "errorcode";
    /** JSON key internal code. */
    var KEY_INTERNAL_CODE = "internalcode";
    /** JSON key error message. */
    var KEY_ERROR_MESSAGE = "errormsg";
    /** JSON key user message. */
    var KEY_USER_MESSAGE = "usermsg";
    
    /** MSL context. */
    var ctx;
    
    var ENTITY_AUTH_DATA;
    var RECIPIENT = "recipient";
    var MESSAGE_ID = 17;
    var ERROR_CODE = MslConstants$ResponseCode.FAIL;
    var INTERNAL_CODE = 621;
    var ERROR_MSG = "Error message.";
    var USER_MSG = "User message.";
    var CRYPTO_CONTEXTS = {};
    
    /** Header crypto context. */
    var cryptoContext;
    
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
    			ctx.getEntityAuthenticationData(null, {
    				result: function(entityAuthData) { ENTITY_AUTH_DATA = entityAuthData; },
    				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    			});
    		});
    		waitsFor(function() { return ENTITY_AUTH_DATA; }, "entity authentication data", 100);
    		runs(function() {
    		    var scheme = ENTITY_AUTH_DATA.scheme;
    		    var factory = ctx.getEntityAuthenticationFactory(scheme);
    		    cryptoContext = factory.getCryptoContext(ctx, ENTITY_AUTH_DATA);
    		    initialized = true;
    		});
    	}
    });

    it("ctors", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);
        runs(function() {
	        expect(errorHeader.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
	        expect(errorHeader.errorCode).toEqual(ERROR_CODE);
	        expect(errorHeader.errorMessage).toEqual(ERROR_MSG);
	        expect(errorHeader.internalCode).toEqual(INTERNAL_CODE);
	        expect(errorHeader.messageId).toEqual(MESSAGE_ID);
	        expect(errorHeader.userMessage).toEqual(USER_MSG);
	        expect(errorHeader.recipient).toEqual(RECIPIENT);
        });
    });
    
    it("json is correct", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);
        
        var ciphertext = undefined, plaintext = undefined, signature;
        runs(function() {
	        var jsonString = JSON.stringify(errorHeader);
	        expect(jsonString).not.toBeNull();
	        
	        var jo = JSON.parse(jsonString);
	        var entityAuthDataJo = jo[KEY_ENTITY_AUTHENTICATION_DATA];
	        expect(entityAuthDataJo).toEqual(JSON.parse(JSON.stringify(ENTITY_AUTH_DATA)));
	        ciphertext = base64$decode(jo[KEY_ERRORDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(p) { plaintext = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	        signature = base64$decode(jo[KEY_SIGNATURE]);
        });
        waitsFor(function() { return ciphertext && plaintext && signature; }, "ciphertext, plaintext, and signature not received", 100);
        
        var verified;
        runs(function() {
	        cryptoContext.verify(ciphertext, signature, {
	        	result: function(v) { verified = v; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return verified; }, "verified not received", 100);
        
        runs(function() {
	        expect(verified).toBeTruthy();
	        
	        var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	        expect(errordata[KEY_RECIPIENT]).toEqual(RECIPIENT);
	        expect(parseInt(errordata[KEY_MESSAGE_ID])).toEqual(MESSAGE_ID);
	        expect(parseInt(errordata[KEY_ERROR_CODE])).toEqual(ERROR_CODE);
	        expect(parseInt(errordata[KEY_INTERNAL_CODE])).toEqual(INTERNAL_CODE);
	        expect(errordata[KEY_ERROR_MESSAGE]).toEqual(ERROR_MSG);
	        expect(errordata[KEY_USER_MESSAGE]).toEqual(USER_MSG);
        });
    });
    
    it("json is correct for negative internal code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, -17, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var ciphertext = undefined, plaintext = undefined, signature;
        runs(function() {
	        expect(errorHeader.internalCode).toEqual(-1);
	        var jsonString = JSON.stringify(errorHeader);
	        expect(jsonString).not.toBeNull();
	        
	        var jo = JSON.parse(jsonString);
	        var entityAuthDataJo = jo[KEY_ENTITY_AUTHENTICATION_DATA];
	        expect(entityAuthDataJo).toEqual(JSON.parse(JSON.stringify(ENTITY_AUTH_DATA)));
	        ciphertext = base64$decode(jo[KEY_ERRORDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(p) { plaintext = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	        signature = base64$decode(jo[KEY_SIGNATURE]);
        });
        waitsFor(function() { return ciphertext && plaintext && signature; }, "ciphertext, plaintext, and signature not received", 100);

        var verified;
        runs(function() {
	        cryptoContext.verify(ciphertext, signature, {
	        	result: function(v) { verified = v; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return verified; }, "verified not received", 100);
        
        runs(function() {
	        expect(verified).toBeTruthy();
	        
	        var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	
	        expect(errordata[KEY_RECIPIENT]).toEqual(RECIPIENT);
	        expect(parseInt(errordata[KEY_MESSAGE_ID])).toEqual(MESSAGE_ID);
	        expect(parseInt(errordata[KEY_ERROR_CODE])).toEqual(ERROR_CODE);
	        expect(errordata[KEY_INTERNAL_CODE]).toBeUndefined();
	        expect(errordata[KEY_ERROR_MESSAGE]).toEqual(ERROR_MSG);
            expect(errordata[KEY_USER_MESSAGE]).toEqual(USER_MSG);
        });
    });
    
    it("json is correct with null recipient", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, null, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var ciphertext = undefined, plaintext = undefined, signature;
        runs(function() {
            expect(errorHeader.recipient).toBeNull();
            var jsonString = JSON.stringify(errorHeader);
            expect(jsonString).not.toBeNull();
            
            var jo = JSON.parse(jsonString);
            var entityAuthDataJo = jo[KEY_ENTITY_AUTHENTICATION_DATA];
            expect(entityAuthDataJo).toEqual(JSON.parse(JSON.stringify(ENTITY_AUTH_DATA)));
            ciphertext = base64$decode(jo[KEY_ERRORDATA]);
            cryptoContext.decrypt(ciphertext, {
                result: function(p) { plaintext = p; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            signature = base64$decode(jo[KEY_SIGNATURE]);
        });
        waitsFor(function() { return ciphertext && plaintext && signature; }, "ciphertext, plaintext, and signature not received", 100);

        var verified;
        runs(function() {
            cryptoContext.verify(ciphertext, signature, {
                result: function(v) { verified = v; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return verified; }, "verified not received", 100);
        
        runs(function() {
            expect(verified).toBeTruthy();
            
            var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
    
            expect(errordata[KEY_RECIPIENT]).toBeUndefined();
            expect(parseInt(errordata[KEY_MESSAGE_ID])).toEqual(MESSAGE_ID);
            expect(parseInt(errordata[KEY_ERROR_CODE])).toEqual(ERROR_CODE);
            expect(errordata[KEY_INTERNAL_CODE]).toEqual(INTERNAL_CODE);
            expect(errordata[KEY_ERROR_MESSAGE]).toEqual(ERROR_MSG);
            expect(errordata[KEY_USER_MESSAGE]).toEqual(USER_MSG);
        });
    });
    
    it("json is correct with null error message", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, null, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var ciphertext = undefined, plaintext = undefined, signature;
        runs(function() {
	        expect(errorHeader.errorMessage).toBeNull();
	        var jsonString = JSON.stringify(errorHeader);
	        expect(jsonString).not.toBeNull();
	        
	        var jo = JSON.parse(jsonString);
	        var entityAuthDataJo = jo[KEY_ENTITY_AUTHENTICATION_DATA];
	        expect(entityAuthDataJo).toEqual(JSON.parse(JSON.stringify(ENTITY_AUTH_DATA)));
	        ciphertext = base64$decode(jo[KEY_ERRORDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(p) { plaintext = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	        signature = base64$decode(jo[KEY_SIGNATURE]);
        });
        waitsFor(function() { return ciphertext && plaintext && signature; }, "ciphertext, plaintext, and signature not received", 100);

        var verified;
        runs(function() {
	        cryptoContext.verify(ciphertext, signature, {
	        	result: function(v) { verified = v; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return verified; }, "verified not received", 100);
        
        runs(function() {
	        expect(verified).toBeTruthy();
	        
	        var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	
	        expect(errordata[KEY_RECIPIENT]).toEqual(RECIPIENT);
	        expect(parseInt(errordata[KEY_MESSAGE_ID])).toEqual(MESSAGE_ID);
	        expect(parseInt(errordata[KEY_ERROR_CODE])).toEqual(ERROR_CODE);
	        expect(parseInt(errordata[KEY_INTERNAL_CODE])).toEqual(INTERNAL_CODE);
	        expect(errordata[KEY_ERROR_MESSAGE]).toBeUndefined();
	        expect(errordata[KEY_USER_MESSAGE]).toEqual(USER_MSG);
        });
    });
    
    it("json is correct with null user message", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, null, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var ciphertext = undefined, plaintext = undefined, signature;
        runs(function() {
            expect(errorHeader.userMessage).toBeNull();
            var jsonString = JSON.stringify(errorHeader);
            expect(jsonString).not.toBeNull();
            
            var jo = JSON.parse(jsonString);
            var entityAuthDataJo = jo[KEY_ENTITY_AUTHENTICATION_DATA];
            expect(entityAuthDataJo).toEqual(JSON.parse(JSON.stringify(ENTITY_AUTH_DATA)));
            ciphertext = base64$decode(jo[KEY_ERRORDATA]);
            cryptoContext.decrypt(ciphertext, {
                result: function(p) { plaintext = p; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            signature = base64$decode(jo[KEY_SIGNATURE]);
        });
        waitsFor(function() { return ciphertext && plaintext && signature; }, "ciphertext, plaintext, and signature not received", 100);

        var verified;
        runs(function() {
            cryptoContext.verify(ciphertext, signature, {
                result: function(v) { verified = v; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return verified; }, "verified not received", 100);
        
        runs(function() {
            expect(verified).toBeTruthy();
            
            var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
    
            expect(errordata[KEY_RECIPIENT]).toEqual(RECIPIENT);
            expect(parseInt(errordata[KEY_MESSAGE_ID])).toEqual(MESSAGE_ID);
            expect(parseInt(errordata[KEY_ERROR_CODE])).toEqual(ERROR_CODE);
            expect(parseInt(errordata[KEY_INTERNAL_CODE])).toEqual(INTERNAL_CODE);
            expect(errordata[KEY_ERROR_MESSAGE]).toEqual(ERROR_MSG);
            expect(errordata[KEY_USER_MESSAGE]).toBeUndefined();
        });
    });
    
    it("parseHeader", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);
        
        var header;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	        	result: function(hdr) { header = hdr; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return header; }, "header not received", 100);
        
        runs(function() {
	        expect(header).not.toBeNull();
	        expect(header instanceof ErrorHeader).toBeTruthy();
	        var joErrorHeader = header;
	        
	        expect(joErrorHeader.entityAuthenticationData).toEqual(errorHeader.entityAuthenticationData);
	        expect(joErrorHeader.errorCode).toEqual(errorHeader.errorCode);
	        expect(joErrorHeader.errorMessage).toEqual(errorHeader.errorMessage);
	        expect(joErrorHeader.internalCode).toEqual(errorHeader.internalCode);
	        expect(joErrorHeader.messageId).toEqual(errorHeader.messageId);
	        expect(joErrorHeader.recipient).toEqual(errorHeader.recipient);
	        expect(joErrorHeader.userMessage).toEqual(errorHeader.userMessage);
        });
    });

    it("ctor with missing entity authentication data", function() {
    	var exception;
        runs(function() {
            ErrorHeader$create(ctx, null, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { },
                error: function(err) { exception = err; }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND));
        });
    });
    
    it("parseHeader with missing entity authentication data", function() {
    	var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);
        
        var exception;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	        
	        expect(errorHeaderJo[KEY_ENTITY_AUTHENTICATION_DATA]).not.toBeNull();
	        delete errorHeaderJo[KEY_ENTITY_AUTHENTICATION_DATA];
	        
	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND));
        });
    });
    
    it("invalid entity authentication data", function() {
    	var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	        
	        errorHeaderJo[KEY_ENTITY_AUTHENTICATION_DATA] = "x";
	
	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("missing signature", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	        
	        expect(errorHeaderJo[KEY_SIGNATURE]).not.toBeNull();
	        delete errorHeaderJo[KEY_SIGNATURE];
	
	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid signature", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
            var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
            
            errorHeaderJo[KEY_SIGNATURE] = "x";
    
            Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.HEADER_SIGNATURE_INVALID));
        });
    });
    
    it("incorrect signature", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	        
	        errorHeaderJo[KEY_SIGNATURE] = "AAA=";
	
	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslCryptoException(MslError.MESSAGE_VERIFICATION_FAILED));
        });
    });
    
    it("missing errordata", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	        
	        expect(errorHeaderJo[KEY_ERRORDATA]).not.toBeNull();
	        delete errorHeaderJo[KEY_ERRORDATA];
	        
	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid errordata", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	        
	        // This tests invalid but trusted error data so we must sign it.
	        //
	        // This differs from the Java unit tests because we cannot sign
	        // empty ciphertext.
	        errorHeaderJo[KEY_ERRORDATA] = base64$encode("x");
	        var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
	        cryptoContext.sign(ciphertext, {
	        	result: function(signature) {
	        		errorHeaderJo[KEY_SIGNATURE] = base64$encode(signature);
	    	        
	    	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	    	        	result: function() {},
	    	        	error: function(e) { exception = e; },
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
    
    // Not applicable because we cannot sign empty ciphertext with
    // Web Crypto.
    xit("empty errordata", function() {
        var errorHeader;
        runs(function() {
        	ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);
    	
        var exception;
        runs(function() {
        	var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));

        	// This tests empty but trusted error data so we must sign it.
        	var ciphertext = new Uint8Array(0);
        	errorHeaderJo[KEY_ERRORDATA] = base64$encode(ciphertext);
        	cryptoContext.sign(ciphertext, {
        		result: function(signature) {
        			errorHeaderJo[KEY_SIGNATURE] = base64$encode(signature);

                	Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
        	        	result: function() {},
        	        	error: function(err) { exception = err; },
        	        });
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.HEADER_DATA_MISSING));
        });
    });
    
    it("missing message ID", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	        
	        // Before modifying the error data we need to decrypt it.
	        var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	        		var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	    	        
	    	        // After modifying the error data we need to encrypt it.
	    	        expect(errordata[KEY_MESSAGE_ID]).not.toBeNull();
	    	        delete errordata[KEY_MESSAGE_ID];
	    	        var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
	    	        cryptoContext.encrypt(modifiedPlaintext, {
	    	        	result: function(modifiedCiphertext) {
	    	        		errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);
	    	    	        
	    	    	        // The error data must be signed otherwise the error data will not be
	    	    	        // processed.
	    	    	        cryptoContext.sign(modifiedCiphertext, {
	    	    	        	result: function(modifiedSignature) {
	    	    	        		errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);
	    	    	    	        
	    	    	    	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	    	    	    	        	result: function() {},
	    	    	    	        	error: function(err) { exception = err; },
	    	    	    	        });
	    	    	        	},
	    	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	    	        });
	    	        	},
	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	        });
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid message ID", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	
	        // Before modifying the error data we need to decrypt it.
	        var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	    	        var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	    	    	
	    	        // After modifying the error data we need to encrypt it.
	    	        errordata[KEY_MESSAGE_ID] = "x";
	    	        var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
	    	        cryptoContext.encrypt(modifiedPlaintext, {
	    	        	result: function(modifiedCiphertext) {
	    	    	        errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);
	    	    	    	
	    	    	        // The error data must be signed otherwise the error data will not be
	    	    	        // processed.
	    	    	        cryptoContext.sign(modifiedCiphertext, {
	    	    	        	result: function(modifiedSignature) {
	    	    	    	        errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);
	    	    	    	        
	    	    	    	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	    	    	    	        	result: function() {},
	    	    	    	        	error: function(err) { exception = err; },
	    	    	    	        });
	    	    	        	},
	    	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	    	        });
	    	        	},
	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	        });
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
	        });
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("ctor with negative message ID", function() {
        var exception;
        runs(function() {
        	ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, -1, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
        		result: function() {},
        		error: function(e) { exception = e; }
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });
    
    it("ctor with too large message ID", function() {
        var exception;
        runs(function() {
        	ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MslConstants$MAX_LONG_VALUE + 2, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
        		result: function() {},
        		error: function(e) { exception = e; }
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });
    
    it("parseHeader with negative message ID", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
        	var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));

        	// Before modifying the error data we need to decrypt it.
        	var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
        	cryptoContext.decrypt(ciphertext, {
        		result: function(plaintext) {
        			var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));

        			// After modifying the error data we need to encrypt it.
        			errordata[KEY_MESSAGE_ID] = -1;
        			var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
        			cryptoContext.encrypt(modifiedPlaintext, {
        				result: function(modifiedCiphertext) {
        					errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);

        					// The error data must be signed otherwise the error data will not be
        					// processed.
        					cryptoContext.sign(modifiedCiphertext, {
        						result: function(modifiedSignature) {
        							errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);

        							Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
        								result: function() {},
        								error: function(err) { exception = err; },
        							});
        						},
        						error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        					});
        				},
        				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        			});
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE));
        });
    });
        
    it("parseHeader with too large message ID", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
        	var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));

        	// Before modifying the error data we need to decrypt it.
        	var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
        	cryptoContext.decrypt(ciphertext, {
        		result: function(plaintext) {
        			var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));

        			// After modifying the error data we need to encrypt it.
        			errordata[KEY_MESSAGE_ID] = MslConstants$MAX_LONG_VALUE + 2;
        			var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
        			cryptoContext.encrypt(modifiedPlaintext, {
        				result: function(modifiedCiphertext) {
        					errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);

        					// The error data must be signed otherwise the error data will not be
        					// processed.
        					cryptoContext.sign(modifiedCiphertext, {
        						result: function(modifiedSignature) {
        							errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);

        							Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
        								result: function() {},
        								error: function(err) { exception = err; },
        							});
        						},
        						error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        					});
        				},
        				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        			});
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE));
        });
    });
    
    it("missing error code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
        	var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));

        	// Before modifying the error data we need to decrypt it.
        	var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
        	cryptoContext.decrypt(ciphertext, {
        		result: function(plaintext) {
        			var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));

        			// After modifying the error data we need to encrypt it.
        			expect(errordata[KEY_ERROR_CODE]).not.toBeNull();
        			delete errordata[KEY_ERROR_CODE];
        			var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
        			cryptoContext.encrypt(modifiedPlaintext, {
        				result: function(modifiedCiphertext) {
        					errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);

        					// The error data must be signed otherwise the error data will not be
        					// processed.
        					cryptoContext.sign(modifiedCiphertext, {
        						result: function(modifiedSignature) {
        							errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);

        							Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
        								result: function() {},
        								error: function(err) { exception = err; },
        							});
        						},
        						error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        					});
        				},
        				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        			});
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR, messageid = MESSAGE_ID));
        });
    });

    it("invalid error code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
        	var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));

        	// Before modifying the error data we need to decrypt it.
        	var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
        	cryptoContext.decrypt(ciphertext, {
        		result: function(plaintext) {
        			var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));

        			// After modifying the error data we need to encrypt it.
        			expect(errordata[KEY_ERROR_CODE]).not.toBeNull();
        			errordata[KEY_ERROR_CODE] = "AAA=";
        			var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
        			cryptoContext.encrypt(modifiedPlaintext, {
        				result: function(modifiedCiphertext) {
        					errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);

        					// The error data must be signed otherwise the error data will not be
        					// processed.
        					cryptoContext.sign(modifiedCiphertext, {
        						result: function(modifiedSignature) {
        							errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);

        							Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
        								result: function() {},
        								error: function(err) { exception = err; },
        							});
        						},
        						error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        					});
        				},
        				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        			});
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR, messageid = MESSAGE_ID));
        });
    });
    
    it("missing internal code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);
        
        var joErrorHeader;
        runs(function() {
	        var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));
	        
	        // Before modifying the error data we need to decrypt it.
	        var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
	        cryptoContext.decrypt(ciphertext, {
	        	result: function(plaintext) {
	    	        var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));
	    	        
	    	        // After modifying the error data we need to encrypt it.
	    	        expect(errordata[KEY_INTERNAL_CODE]).not.toBeNull();
	    	        delete errordata[KEY_INTERNAL_CODE];
	    	        var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
	    	        cryptoContext.encrypt(modifiedPlaintext, {
	    	        	result: function(modifiedCiphertext) {
	    	        		errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);
	    	    	        
	    	    	        // The error data must be signed otherwise the error data will not be
	    	    	        // processed.
	    	    	        cryptoContext.sign(modifiedCiphertext, {
	    	    	        	result: function(modifiedSignature) {
	    	    	    	        errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);
	    	    	    	        
	    	    	    	        Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
	    	    	    	        	result: function(hdr) { joErrorHeader = hdr; },
	    	    	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	    	    	        });
	    	    	        	},
	    	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	    	        });
	    	        	},
	    	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	    	        });
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return joErrorHeader; }, "joErrorHeader not received", 100);
        runs(function() {
	        expect(joErrorHeader.internalCode).toEqual(-1);
        });
    });
    
    it("invalid internal code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
        	var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));

        	// Before modifying the error data we need to decrypt it.
        	var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
        	cryptoContext.decrypt(ciphertext, {
        		result: function(plaintext) {
        			var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));

        			// After modifying the error data we need to encrypt it.
        			expect(errordata[KEY_INTERNAL_CODE]).not.toBeNull();
        			errordata[KEY_INTERNAL_CODE] = "x";
        			var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
        			cryptoContext.encrypt(modifiedPlaintext, {
        				result: function(modifiedCiphertext) {
        					errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);

        					// The error data must be signed otherwise the error data will not be
        					// processed.
        					cryptoContext.sign(modifiedCiphertext, {
        						result: function(modifiedSignature) {
        							errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);

        							Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
        								result: function() {},
        								error: function(err) { exception = err; },
        							});
        						},
        						error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        					});
        				},
        				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        			});
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR, messageid = MESSAGE_ID));
        });
    });
    
    it("negative internal code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);

        var exception;
        runs(function() {
        	var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));

        	// Before modifying the error data we need to decrypt it.
        	var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
        	cryptoContext.decrypt(ciphertext, {
        		result: function(plaintext) {
        			var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));

        			// After modifying the error data we need to encrypt it.
        			expect(errordata[KEY_INTERNAL_CODE]).not.toBeNull();
        			errordata[KEY_INTERNAL_CODE] = -1;
        			var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
        			cryptoContext.encrypt(modifiedPlaintext, {
        				result: function(modifiedCiphertext) {
        					errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);

        					// The error data must be signed otherwise the error data will not be
        					// processed.
        					cryptoContext.sign(modifiedCiphertext, {
        						result: function(modifiedSignature) {
        							errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);

        							Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
        								result: function() {},
        								error: function(err) { exception = err; },
        							});
        						},
        						error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        					});
        				},
        				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        			});
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return exception; }, "exception not received", 100);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.INTERNAL_CODE_NEGATIVE, messageid = MESSAGE_ID));
        });
    });
    
    it("missing error message", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);
        
        var joErrorHeader;
        runs(function() {
        	var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));

        	// Before modifying the error data we need to decrypt it.
        	var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
        	cryptoContext.decrypt(ciphertext, {
        		result: function(plaintext) {
        			var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));

        			// After modifying the error data we need to encrypt it.
        			expect(errordata[KEY_ERROR_MESSAGE]).not.toBeNull();
        			delete errordata[KEY_ERROR_MESSAGE];
        			var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
        			cryptoContext.encrypt(modifiedPlaintext, {
        				result: function(modifiedCiphertext) {
        					errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);

        					// The error data must be signed otherwise the error data will not be
        					// processed.
        					cryptoContext.sign(modifiedCiphertext, {
        						result: function(modifiedSignature) {
        							errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);

        							Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
        								result: function(hdr) { joErrorHeader = hdr; },
        								error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        							});
        						},
        						error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        					});
        				},
        				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        			});
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); },
        	});
        });
        waitsFor(function() { return joErrorHeader; }, "joErrorHeader not received", 100);
        runs(function() {
        	expect(joErrorHeader.errorMessage).toBeUndefined();
        });
    });
    
    it("missing user message", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);
        
        var joErrorHeader;
        runs(function() {
            var errorHeaderJo = JSON.parse(JSON.stringify(errorHeader));

            // Before modifying the error data we need to decrypt it.
            var ciphertext = base64$decode(errorHeaderJo[KEY_ERRORDATA]);
            cryptoContext.decrypt(ciphertext, {
                result: function(plaintext) {
                    var errordata = JSON.parse(textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET));

                    // After modifying the error data we need to encrypt it.
                    expect(errordata[KEY_USER_MESSAGE]).not.toBeNull();
                    delete errordata[KEY_USER_MESSAGE];
                    var modifiedPlaintext = textEncoding$getBytes(JSON.stringify(errordata), MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(modifiedPlaintext, {
                        result: function(modifiedCiphertext) {
                            errorHeaderJo[KEY_ERRORDATA] = base64$encode(modifiedCiphertext);

                            // The error data must be signed otherwise the error data will not be
                            // processed.
                            cryptoContext.sign(modifiedCiphertext, {
                                result: function(modifiedSignature) {
                                    errorHeaderJo[KEY_SIGNATURE] = base64$encode(modifiedSignature);

                                    Header$parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS, {
                                        result: function(hdr) { joErrorHeader = hdr; },
                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                                    });
                                },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                            });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return joErrorHeader; }, "joErrorHeader not received", 100);
        runs(function() {
            expect(joErrorHeader.userMessage).toBeUndefined();
        });
    });
    
    xit("equals recipient", function() {
        var recipientA = "A";
        var recipientB = "B";
        var errorHeaderA, errorHeaderB;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, recipientA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, recipientB, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB; }, "error headers not received", 100);
        var errorHeaderA2;
        runs(function() {
            Header$parseHeader(ctx, JSON.parse(JSON.stringify(errorHeaderA)), CRYPTO_CONTEXTS, {
                result: function(hdr) { errorHeaderA2 = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2 not received", 100);

        runs(function() {
            expect(errorHeaderA.equals(errorHeaderA)).toBeTruthy();
            expect(errorHeaderA.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
            
            expect(errorHeaderA.equals(errorHeaderB)).toBeFalsy();
            expect(errorHeaderB.equals(errorHeaderA)).toBeFalsy();
            expect(errorHeaderB.uniqueKey()).not.toEqual(errorHeaderA.uniqueKey());
            
            expect(errorHeaderA.equals(errorHeaderA2)).toBeTruthy();
            expect(errorHeaderA2.equals(errorHeaderA)).toBeTruthy();
            expect(errorHeaderA2.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
        });
    });

    xit("equals message ID", function() {
    	var messageIdA = 1;
    	var messageIdB = 2;
    	var errorHeaderA, errorHeaderB;
    	runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, messageIdA, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, messageIdB, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB; }, "error headers not received", 100);
        var errorHeaderA2;
        runs(function() {
        	Header$parseHeader(ctx, JSON.parse(JSON.stringify(errorHeaderA)), CRYPTO_CONTEXTS, {
        		result: function(hdr) { errorHeaderA2 = hdr; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2 not received", 100);

        runs(function() {
	        expect(errorHeaderA.equals(errorHeaderA)).toBeTruthy();
	        expect(errorHeaderA.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
	        
	        expect(errorHeaderA.equals(errorHeaderB)).toBeFalsy();
	        expect(errorHeaderB.equals(errorHeaderA)).toBeFalsy();
	        expect(errorHeaderB.uniqueKey()).not.toEqual(errorHeaderA.uniqueKey());
	        
	        expect(errorHeaderA.equals(errorHeaderA2)).toBeTruthy();
	        expect(errorHeaderA2.equals(errorHeaderA)).toBeTruthy();
	        expect(errorHeaderA2.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
        });
    });
    
    xit("equals error code", function() {
        var errorCodeA = ResponseCode.FAIL;
        var errorCodeB = ResponseCode.TRANSIENT_FAILURE;
        var errorHeaderA, errorHeaderB;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, errorCodeA, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, errorCodeB, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB; }, "error headers not received", 100);
        var errorHeaderA2;
        runs(function() {
        	Header$parseHeader(ctx, JSON.parse(JSON.stringify(errorHeaderA)), CRYPTO_CONTEXTS, {
        		result: function(hdr) { errorHeaderA2 = hdr; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2 not received", 100);

        runs(function() {
	        expect(errorHeaderA.equals(errorHeaderA)).toBeTruthy();
	        expect(errorHeaderA.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
	        
	        expect(errorHeaderA.equals(errorHeaderB)).toBeFalsy();
	        expect(errorHeaderB.equals(errorHeaderA)).toBeFalsy();
	        expect(errorHeaderB.uniqueKey()).not.toEqual(errorHeaderA.uniqueKey());
	        
	        expect(errorHeaderA.equals(errorHeaderA2)).toBeTruthy();
	        expect(errorHeaderA2.equals(errorHeaderA)).toBeTruthy();
	        expect(errorHeaderA2.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
        });
    });
    
    xit("equals internal code", function() {
        var internalCodeA = 1;
        var internalCodeB = 2;
        var errorHeaderA, errorHeaderB;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, internalCodeA, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, internalCodeB, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB; }, "error headers not received", 100);
        var errorHeaderA2;
        runs(function() {
        	Header$parseHeader(ctx, JSON.parse(JSON.stringify(errorHeaderA)), CRYPTO_CONTEXTS, {
        		result: function(hdr) { errorHeaderA2 = hdr; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2 not received", 100);

        runs(function() {
	        expect(errorHeaderA.equals(errorHeaderA)).toBeTruthy();
	        expect(errorHeaderA.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
	        
	        expect(errorHeaderA.equals(errorHeaderB)).toBeFalsy();
	        expect(errorHeaderB.equals(errorHeaderA)).toBeFalsy();
	        expect(errorHeaderB.uniqueKey()).not.toEqual(errorHeaderA.uniqueKey());
	        
	        expect(errorHeaderA.equals(errorHeaderA2)).toBeTruthy();
	        expect(errorHeaderA2.equals(errorHeaderA)).toBeTruthy();
	        expect(errorHeaderA2.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
        });
    });
    
    xit("equals error message", function() {
        var errorMsgA = "A";
        var errorMsgB = "B";
        var errorHeaderA, errorHeaderB, errorHeaderC;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgA, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgB, USER_MSG, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, null, USER_MSG, {
                result: function(token) { errorHeaderC = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB && errorHeaderC; }, "error headers not received", 100);
        var errorHeaderA2;
        runs(function() {
        	Header$parseHeader(ctx, JSON.parse(JSON.stringify(errorHeaderA)), CRYPTO_CONTEXTS, {
        		result: function(hdr) { errorHeaderA2 = hdr; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2 not received", 100);

        runs(function() {
	        expect(errorHeaderA.equals(errorHeaderA)).toBeTruthy();
	        expect(errorHeaderA.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
	        
	        expect(errorHeaderA.equals(errorHeaderB)).toBeFalsy();
	        expect(errorHeaderB.equals(errorHeaderA)).toBeFalsy();
	        expect(errorHeaderB.uniqueKey()).not.toEqual(errorHeaderA.uniqueKey());
	        
	        expect(errorHeaderA.equals(errorHeaderA2)).toBeTruthy();
	        expect(errorHeaderA2.equals(errorHeaderA)).toBeTruthy();
	        expect(errorHeaderA2.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
        });
    });
    
    xit("equals user message", function() {
        var userMsgA = "A";
        var userMsgB = "B";
        var errorHeaderA, errorHeaderB, errorHeaderC;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgA, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgB, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, null, {
                result: function(token) { errorHeaderC = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB && errorHeaderC; }, "error headers not received", 100);
        var errorHeaderA2;
        runs(function() {
            Header$parseHeader(ctx, JSON.parse(JSON.stringify(errorHeaderA)), CRYPTO_CONTEXTS, {
                result: function(hdr) { errorHeaderA2 = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2 not received", 100);

        runs(function() {
            expect(errorHeaderA.equals(errorHeaderA)).toBeTruthy();
            expect(errorHeaderA.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
            
            expect(errorHeaderA.equals(errorHeaderB)).toBeFalsy();
            expect(errorHeaderB.equals(errorHeaderA)).toBeFalsy();
            expect(errorHeaderB.uniqueKey()).not.toEqual(errorHeaderA.uniqueKey());
            
            expect(errorHeaderA.equals(errorHeaderA2)).toBeTruthy();
            expect(errorHeaderA2.equals(errorHeaderA)).toBeTruthy();
            expect(errorHeaderA2.uniqueKey()).toEqual(errorHeaderA.uniqueKey());
        });
    });
    
    xit("equals object", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader$create(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader not received", 100);
        runs(function() {
	        expect(errorHeader.equals(null)).toBeFalsy();
	        expect(errorHeader.equals(ERROR_MSG)).toBeFalsy();
        });
    });
});
