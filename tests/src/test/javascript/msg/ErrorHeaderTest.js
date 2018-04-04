/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var ErrorHeader = require('msl-core/msg/ErrorHeader.js');
    var Header = require('msl-core/msg/Header.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslError = require('msl-core/MslError.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslMessageException = require('msl-core/MslMessageException.js');
    var Base64 = require('msl-core/util/Base64.js');
    var MslConstants = require('msl-core/MslConstants.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Milliseconds per second. */
    var MILLISECONDS_PER_SECOND = 1000;
    
    /** Key entity authentication data. */
    var KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
    /** Key error data. */
    var KEY_ERRORDATA = "errordata";
    /** Key error data signature. */
    var KEY_SIGNATURE = "signature";
    
    // Message error data.
    /** Key timestamp. */
    var KEY_TIMESTAMP = "timestamp";
    /** Key message ID. */
    var KEY_MESSAGE_ID = "messageid";
    /** Key error code. */
    var KEY_ERROR_CODE = "errorcode";
    /** Key internal code. */
    var KEY_INTERNAL_CODE = "internalcode";
    /** Key error message. */
    var KEY_ERROR_MESSAGE = "errormsg";
    /** Key user message. */
    var KEY_USER_MESSAGE = "usermsg";
    
    /**
     * Checks if the given timestamp is close to "now".
     * 
     * @param {Date} timestamp the timestamp to compare.
     * @return {boolean} true if the timestamp is about now.
     */
    function isAboutNow(timestamp) {
        var now = Date.now();
        var time = timestamp.getTime();
        return (now - 1000 <= time && time <= now + 1000);
    }

    /**
     * Checks if the given timestamp is close to "now".
     * 
     * @param {number} seconds the timestamp to compare in seconds since the epoch.
     * @return {boolean} true if the timestamp is about now.
     */
    function isAboutNowSeconds(seconds) {
        var now = Date.now();
        var time = seconds * MILLISECONDS_PER_SECOND;
        return (now - 2000 <= time && time <= now + 2000);
    }
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Header crypto context. */
    var cryptoContext;
    
    var ENTITY_AUTH_DATA;
    var ENTITY_AUTH_DATA_MO;
    var MESSAGE_ID = 17;
    var ERROR_CODE = MslConstants.ResponseCode.FAIL;
    var INTERNAL_CODE = 621;
    var ERROR_MSG = "Error message.";
    var USER_MSG = "User message.";
    var CRYPTO_CONTEXTS = {};
    
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
                encoder = ctx.getMslEncoderFactory();
                ctx.getEntityAuthenticationData(null, {
                    result: function(entityAuthData) { ENTITY_AUTH_DATA = entityAuthData; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ENTITY_AUTH_DATA; }, "entity authentication data", MslTestConstants.TIMEOUT);
            runs(function() {
                MslTestUtils.toMslObject(encoder, ENTITY_AUTH_DATA, {
                    result: function(x) { ENTITY_AUTH_DATA_MO = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ENTITY_AUTH_DATA_MO; }, "ENTITY_AUTH_DATA_MO", MslTestConstants.TIMEOUT);
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
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(errorHeader.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
	        expect(errorHeader.errorCode).toEqual(ERROR_CODE);
	        expect(errorHeader.errorMessage).toEqual(ERROR_MSG);
	        expect(errorHeader.internalCode).toEqual(INTERNAL_CODE);
	        expect(errorHeader.messageId).toEqual(MESSAGE_ID);
	        expect(errorHeader.userMessage).toEqual(USER_MSG);
	        expect(isAboutNow(errorHeader.timestamp)).toBeTruthy();
        });
    });
    
    it("mslobject is correct", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
        
        var ciphertext, plaintext, signature;
        runs(function() {
	        var entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA);
	        expect(entityAuthDataMo).toEqual(ENTITY_AUTH_DATA_MO);
	        ciphertext = mo.getBytes(KEY_ERRORDATA);
	        cryptoContext.decrypt(ciphertext, encoder, {
	        	result: function(p) { plaintext = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	        signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return ciphertext && plaintext && signature; }, "ciphertext, plaintext, and signature", MslTestConstants.TIMEOUT);
        
        var verified;
        runs(function() {
	        cryptoContext.verify(ciphertext, signature, encoder, {
	        	result: function(v) { verified = v; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return verified; }, "verified", MslTestConstants.TIMEOUT);
        
        runs(function() {
	        expect(verified).toBeTruthy();
	        
	        var errordata = encoder.parseObject(plaintext);
	        expect(errordata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
	        expect(errordata.getInt(KEY_ERROR_CODE)).toEqual(ERROR_CODE);
	        expect(errordata.getInt(KEY_INTERNAL_CODE)).toEqual(INTERNAL_CODE);
	        expect(errordata.getString(KEY_ERROR_MESSAGE)).toEqual(ERROR_MSG);
	        expect(errordata.getString(KEY_USER_MESSAGE)).toEqual(USER_MSG);
            expect(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP))).toBeTruthy();
        });
    });
    
    it("mslobject is correct for negative internal code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, -17, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var mo;
        runs(function() {
            expect(errorHeader.internalCode).toEqual(-1);
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var ciphertext, plaintext, signature;
        runs(function() {
	        var entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA);
	        expect(entityAuthDataMo).toEqual(ENTITY_AUTH_DATA_MO);
	        ciphertext = mo.getBytes(KEY_ERRORDATA);
	        cryptoContext.decrypt(ciphertext, encoder, {
	        	result: function(p) { plaintext = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	        signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return ciphertext && plaintext && signature; }, "ciphertext, plaintext, and signature", MslTestConstants.TIMEOUT);

        var verified;
        runs(function() {
	        cryptoContext.verify(ciphertext, signature, encoder, {
	        	result: function(v) { verified = v; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return verified; }, "verified", MslTestConstants.TIMEOUT);
        
        runs(function() {
	        expect(verified).toBeTruthy();
	        
	        var errordata = encoder.parseObject(plaintext);

            expect(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP))).toBeTruthy();
	        expect(errordata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
	        expect(errordata.getInt(KEY_ERROR_CODE)).toEqual(ERROR_CODE);
	        expect(errordata.has(KEY_INTERNAL_CODE)).toBeFalsy();
	        expect(errordata.getString(KEY_ERROR_MESSAGE)).toEqual(ERROR_MSG);
            expect(errordata.getString(KEY_USER_MESSAGE)).toEqual(USER_MSG);
        });
    });
    
    it("mslobject is correct with null error message", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, null, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var mo;
        runs(function() {
            expect(errorHeader.errorMessage).toBeNull();
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var ciphertext, plaintext, signature;
        runs(function() {
	        var entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA);
	        expect(entityAuthDataMo).toEqual(ENTITY_AUTH_DATA_MO);
	        ciphertext = mo.getBytes(KEY_ERRORDATA);
	        cryptoContext.decrypt(ciphertext, encoder, {
	        	result: function(p) { plaintext = p; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	        signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return ciphertext && plaintext && signature; }, "ciphertext, plaintext, and signature", MslTestConstants.TIMEOUT);

        var verified;
        runs(function() {
	        cryptoContext.verify(ciphertext, signature, encoder, {
	        	result: function(v) { verified = v; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return verified; }, "verified", MslTestConstants.TIMEOUT);
        
        runs(function() {
	        expect(verified).toBeTruthy();
	        
	        var errordata = encoder.parseObject(plaintext);
            expect(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP))).toBeTruthy();
	        expect(errordata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
	        expect(errordata.getInt(KEY_ERROR_CODE)).toEqual(ERROR_CODE);
	        expect(errordata.getInt(KEY_INTERNAL_CODE)).toEqual(INTERNAL_CODE);
	        expect(errordata.has(KEY_ERROR_MESSAGE)).toBeFalsy();
	        expect(errordata.getString(KEY_USER_MESSAGE)).toEqual(USER_MSG);
        });
    });
    
    it("mslobject is correct with null user message", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, null, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var mo;
        runs(function() {
            expect(errorHeader.userMessage).toBeNull();
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var ciphertext, plaintext, signature;
        runs(function() {
            var entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA);
            expect(entityAuthDataMo).toEqual(ENTITY_AUTH_DATA_MO);
            ciphertext = mo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(p) { plaintext = p; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return ciphertext && plaintext && signature; }, "ciphertext, plaintext, and signature", MslTestConstants.TIMEOUT);

        var verified;
        runs(function() {
            cryptoContext.verify(ciphertext, signature, encoder, {
                result: function(v) { verified = v; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return verified; }, "verified", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(verified).toBeTruthy();
            
            var errordata = encoder.parseObject(plaintext);
            expect(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP))).toBeTruthy();
            expect(errordata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
            expect(errordata.getInt(KEY_ERROR_CODE)).toEqual(ERROR_CODE);
            expect(errordata.getInt(KEY_INTERNAL_CODE)).toEqual(INTERNAL_CODE);
            expect(errordata.getString(KEY_ERROR_MESSAGE)).toEqual(ERROR_MSG);
            expect(errordata.has(KEY_USER_MESSAGE)).toBeFalsy();
        });
    });
    
    it("parse header", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);
        
        var header;
        runs(function() {
	        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
	        	result: function(hdr) { header = hdr; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return header; }, "header", MslTestConstants.TIMEOUT);
        
        runs(function() {
	        expect(header).not.toBeNull();
	        expect(header instanceof ErrorHeader).toBeTruthy();
	        var moErrorHeader = header;
	        
	        expect(moErrorHeader.entityAuthenticationData).toEqual(errorHeader.entityAuthenticationData);
	        expect(moErrorHeader.timestamp).toEqual(errorHeader.timestamp);
	        expect(moErrorHeader.errorCode).toEqual(errorHeader.errorCode);
	        expect(moErrorHeader.errorMessage).toEqual(errorHeader.errorMessage);
	        expect(moErrorHeader.internalCode).toEqual(errorHeader.internalCode);
	        expect(moErrorHeader.messageId).toEqual(errorHeader.messageId);
	        expect(moErrorHeader.userMessage).toEqual(errorHeader.userMessage);
        });
    });

    it("ctor with missing entity authentication data", function() {
    	var exception;
        runs(function() {
            ErrorHeader.create(ctx, null, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { },
                error: function(err) { exception = err; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND));
        });
    });
    
    it("parseHeader with missing entity authentication data", function() {
    	var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            errorHeaderMo.remove(KEY_ENTITY_AUTHENTICATION_DATA);
	        
	        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; }
	        });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND));
        });
    });
    
    it("invalid entity authentication data", function() {
    	var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
	        errorHeaderMo.put(KEY_ENTITY_AUTHENTICATION_DATA, "x");
	
	        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("missing signature", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            errorHeaderMo.remove(KEY_SIGNATURE);
	
	        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("invalid signature", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, "x");
    
            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("incorrect signature", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
	        errorHeaderMo.put(KEY_SIGNATURE, Base64.decode("AAA="));
	
	        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslCryptoException(MslError.MESSAGE_VERIFICATION_FAILED));
        });
    });
    
    it("missing errordata", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            errorHeaderMo.remove(KEY_ERRORDATA);
	        
	        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
	        	result: function() {},
	        	error: function(err) { exception = err; },
	        });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("invalid errordata", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
	        // This tests invalid but trusted error data so we must sign it.
            var errordata = new Uint8Array(1);
            errordata[0] = 'x';
	        errorHeaderMo.put(KEY_ERRORDATA, errordata);
	        cryptoContext.sign(errordata, encoder, ENCODER_FORMAT, {
	        	result: function(signature) {
	        		errorHeaderMo.put(KEY_SIGNATURE, signature);
	    	        
	    	        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
	    	        	result: function() {},
	    	        	error: function(e) { exception = e; },
	    	        });	
	        	},
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslCryptoException(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR));
        });
    });
    
    it("empty errordata", function() {
        var errorHeader;
        runs(function() {
        	ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);
    	
        var exception;
        runs(function() {
        	// This tests empty but trusted error data so we must sign it.
        	var ciphertext = new Uint8Array(0);
        	errorHeaderMo.put(KEY_ERRORDATA, ciphertext);
        	cryptoContext.sign(ciphertext, encoder, ENCODER_FORMAT, {
        		result: function(signature) {
        			errorHeaderMo.put(KEY_SIGNATURE, signature);

                	Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
        	        	result: function() {},
        	        	error: function(err) { exception = err; },
        	        });
        		},
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.HEADER_DATA_MISSING));
        });
    });
    
    it("missing timestamp", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.remove(KEY_TIMESTAMP);
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var header;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function(x) { header = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return header; }, "header", MslTestConstants.TIMEOUT);
    });
    
    it("invalid timestamp", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.put(KEY_TIMESTAMP, "x");
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("missing message ID", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.remove(KEY_MESSAGE_ID);
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("invalid message ID", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.put(KEY_MESSAGE_ID, "x");
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("ctor with negative message ID", function() {
        var exception;
        runs(function() {
        	ErrorHeader.create(ctx, ENTITY_AUTH_DATA, -1, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
        		result: function() {},
        		error: function(e) { exception = e; }
        	});
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });
    
    it("ctor with too large message ID", function() {
        var exception;
        runs(function() {
        	ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MslConstants.MAX_LONG_VALUE + 2, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
        		result: function() {},
        		error: function(e) { exception = e; }
        	});
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });
    
    it("parseHeader with negative message ID", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.put(KEY_MESSAGE_ID, -1);
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE));
        });
    });
        
    it("parseHeader with too large message ID", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);

        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);

            // After modifying the error data we need to encrypt it.
            errordata.put(KEY_MESSAGE_ID, MslConstants.MAX_LONG_VALUE + 2);
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);

        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);

            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE));
        });
    });
    
    it("missing error code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.remove(KEY_ERROR_CODE);
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR, MESSAGE_ID));
        });
    });

    it("invalid error code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.put(KEY_ERROR_CODE, "x");
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR, MESSAGE_ID));
        });
    });
    
    it("missing internal code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.remove(KEY_INTERNAL_CODE);
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var moErrorHeader;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function(x) { moErrorHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moErrorHeader; }, "moErrorHeader", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(moErrorHeader.internalCode).toEqual(-1);
        });
    });
    
    it("invalid internal code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.put(KEY_INTERNAL_CODE, "x");
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR, MESSAGE_ID));
        });
    });
    
    it("negative internal code", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.put(KEY_INTERNAL_CODE, -1);
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        runs(function() {
        	var f = function() { throw exception; };
        	expect(f).toThrow(new MslMessageException(MslError.INTERNAL_CODE_NEGATIVE, MESSAGE_ID));
        });
    });
    
    it("missing error message", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.remove(KEY_ERROR_MESSAGE);
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var moErrorHeader;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function(x) { moErrorHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moErrorHeader; }, "moErrorHeader", MslTestConstants.TIMEOUT);
        runs(function() {
        	expect(moErrorHeader.errorMessage).toBeNull();
        });
    });
    
    it("missing user message", function() {
        var errorHeader;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        
        var errorHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeader, {
                result: function(x) { errorHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderMo; }, "errorHeaderMo", MslTestConstants.TIMEOUT);

        var plaintext;
        runs(function() {
            // Before modifying the error data we need to decrypt it.
            var ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(x) { plaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return plaintext; }, "plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedPlaintext;
        runs(function() {
            var errordata = encoder.parseObject(plaintext);
                    
            // After modifying the error data we need to encrypt it.
            errordata.remove(KEY_USER_MESSAGE);
            encoder.encodeObject(errordata, ENCODER_FORMAT, {
            	result: function(x) { modifiedPlaintext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedPlaintext; }, "modified plaintext", MslTestConstants.TIMEOUT);
        
        var modifiedCiphertext;
        runs(function() {
            cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedCiphertext = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedCiphertext; }, "modified ciphertext", MslTestConstants.TIMEOUT);
        
        var modifiedSignature;
        runs(function() {
            errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
                            
            // The error data must be signed otherwise the error data will not be
            // processed.
            cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT, {
                result: function(x) { modifiedSignature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return modifiedSignature; }, MslTestConstants.TIMEOUT);
        
        var moErrorHeader;
        runs(function() {
            errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

            Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS, {
                result: function(x) { moErrorHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moErrorHeader; }, "moErrorHeader", MslTestConstants.TIMEOUT);
        runs(function() {
            expect(moErrorHeader.userMessage).toBeNull();
        });
    });
    
    xit("equals timestamp", function() {
        var errorHeaderA, errorHeaderB;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            setTimeout(MILLISECONDS_PER_SECOND, function() {
                ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                    result: function(hdr) { errorHeaderB = hdr; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB; }, "error headers", 2000);
        var errorHeaderA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeaderA, {
                result: function(mo) {
                    Header.parseHeader(ctx, mo, CRYPTO_CONTEXTS, {
                        result: function(hdr) { errorHeaderA2 = hdr; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2", MslTestConstants.TIMEOUT);

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
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, messageIdA, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, messageIdB, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB; }, "error headers", MslTestConstants.TIMEOUT);
        var errorHeaderA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeaderA, {
                result: function(mo) {
                    Header.parseHeader(ctx, mo, CRYPTO_CONTEXTS, {
                        result: function(hdr) { errorHeaderA2 = hdr; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2", MslTestConstants.TIMEOUT);

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
        var errorCodeA = MslConstants.ResponseCode.FAIL;
        var errorCodeB = MslConstants.ResponseCode.TRANSIENT_FAILURE;
        var errorHeaderA, errorHeaderB;
        runs(function() {
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, errorCodeA, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, errorCodeB, INTERNAL_CODE, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB; }, "error headers", MslTestConstants.TIMEOUT);
        var errorHeaderA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeaderA, {
                result: function(mo) {
                    Header.parseHeader(ctx, mo, CRYPTO_CONTEXTS, {
                        result: function(hdr) { errorHeaderA2 = hdr; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2", MslTestConstants.TIMEOUT);

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
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, internalCodeA, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, internalCodeB, ERROR_MSG, USER_MSG, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB; }, "error headers", MslTestConstants.TIMEOUT);
        var errorHeaderA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeaderA, {
                result: function(mo) {
                    Header.parseHeader(ctx, mo, CRYPTO_CONTEXTS, {
                        result: function(hdr) { errorHeaderA2 = hdr; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2", MslTestConstants.TIMEOUT);

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
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgA, USER_MSG, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgB, USER_MSG, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, null, USER_MSG, {
                result: function(token) { errorHeaderC = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB && errorHeaderC; }, "error headers", MslTestConstants.TIMEOUT);
        var errorHeaderA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeaderA, {
                result: function(mo) {
                    Header.parseHeader(ctx, mo, CRYPTO_CONTEXTS, {
                        result: function(hdr) { errorHeaderA2 = hdr; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2", MslTestConstants.TIMEOUT);

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
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgA, {
                result: function(hdr) { errorHeaderA = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgB, {
                result: function(hdr) { errorHeaderB = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, null, {
                result: function(token) { errorHeaderC = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA && errorHeaderB && errorHeaderC; }, "error headers", MslTestConstants.TIMEOUT);
        var errorHeaderA2;
        runs(function() {
            MslTestUtils.toMslObject(encoder, errorHeaderA, {
                result: function(mo) {
                    Header.parseHeader(ctx, mo, CRYPTO_CONTEXTS, {
                        result: function(hdr) { errorHeaderA2 = hdr; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeaderA2; }, "errorHeaderA2", MslTestConstants.TIMEOUT);

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
            ErrorHeader.create(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, {
                result: function(hdr) { errorHeader = hdr; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);
        runs(function() {
	        expect(errorHeader.equals(null)).toBeFalsy();
	        expect(errorHeader.equals(ERROR_MSG)).toBeFalsy();
        });
    });
});
