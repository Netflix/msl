/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
 * User ID token user authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UserIdTokenAuthenticationData", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var UserIdTokenAuthenticationData = require('msl-core/userauth/UserIdTokenAuthenticationData.js');
    var UserAuthenticationData = require('msl-core/userauth/UserAuthenticationData.js');
    var UserAuthenticationScheme = require('msl-core/userauth/UserAuthenticationScheme.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslError = require('msl-core/MslError.js');
    var MslUserAuthException = require('msl-core/MslUserAuthException.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockMslUser = require('msl-tests/tokens/MockMslUser.js');
    
	/** MSL encoder format. */
	var ENCODER_FORMAT = MslEncoderFormat.JSON;
	
    /** Key user authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** Key user authentication data. */
    var KEY_AUTHDATA = "authdata";
    /** Key master token. */
    var KEY_MASTER_TOKEN = "mastertoken";
    /** Key user ID token. */
    var KEY_USER_ID_TOKEN = "useridtoken";
    
    /** Master token. */
    var MASTER_TOKEN, MASTER_TOKEN_MO;
    /** User ID token. */
    var USER_ID_TOKEN, USER_ID_TOKEN_MO;
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.X509, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
            runs(function() {
            	encoder = ctx.getMslEncoderFactory();
                MslTestUtils.getMasterToken(ctx, 1, 1, {
                    result: function(x) { MASTER_TOKEN = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return MASTER_TOKEN; }, "master token", MslTestConstants.TIMEOUT);
            runs(function() {
                var user = new MockMslUser("user1");
                MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, user, {
                    result: function(x) { USER_ID_TOKEN = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return USER_ID_TOKEN; }, "user ID token", MslTestConstants.TIMEOUT);
            runs(function() {
            	MslTestUtils.toMslObject(encoder, MASTER_TOKEN, {
            		result: function(x) { MASTER_TOKEN_MO = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            	MslTestUtils.toMslObject(encoder, USER_ID_TOKEN, {
            		result: function(x) { USER_ID_TOKEN_MO = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return MASTER_TOKEN_MO && USER_ID_TOKEN_MO; }, "msl objects", MslTestConstants.TIMEOUT);
            runs(function() { initialized = true; });
        }
    });
    
    it("ctors", function() {
        var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        
        var authdata;
        runs(function () {
            expect(data.scheme).toEqual(UserAuthenticationScheme.USER_ID_TOKEN);
            expect(data.masterToken).toEqual(MASTER_TOKEN);
            expect(data.userIdToken).toEqual(USER_ID_TOKEN);
        
            data.getAuthData(encoder, ENCODER_FORMAT, {
            	result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var encode;
        runs(function() {
            expect(authdata).not.toBeNull();
            data.toMslEncoding(encoder, ENCODER_FORMAT, {
            	result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var moData;
        runs(function() {
            UserIdTokenAuthenticationData.parse(ctx, authdata, {
                result: function(x) { moData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moData; }, "moData", MslTestConstants.TIMEOUT);
        
        var moAuthdata;
        runs(function() {
            expect(moData.scheme).toEqual(data.scheme);
            expect(moData.masterToken).toEqual(data.masterToken);
            expect(moData.userIdToken).toEqual(data.userIdToken);
            moData.getAuthData(encoder, ENCODER_FORMAT, {
            	result: function(x) { moAuthdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moAuthdata; }, "moAuthdata", MslTestConstants.TIMEOUT);
        
        var moEncode;
        runs(function() {
            expect(moAuthdata).not.toBeNull();
            moData.toMslEncoding(encoder, ENCODER_FORMAT, {
            	result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(moEncode).not.toBeNull();
            expect(moEncode).toEqual(encode);
        });
    });
    
    it("mslobject is correct", function() {
        var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        
        var mo;
        runs(function() {
        	MslTestUtils.toMslObject(encoder, data, {
        		result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
        
        runs(function() {
        	expect(mo.getString(KEY_SCHEME)).toEqual(UserAuthenticationScheme.USER_ID_TOKEN.name);
        	var authdata = mo.getMslObject(KEY_AUTHDATA, encoder);
        	var masterTokenMo = authdata.getMslObject(KEY_MASTER_TOKEN);
	        expect(masterTokenMo).toEqual(MASTER_TOKEN_MO);
	        var userIdTokenJo = authdata.getMslObject(KEY_USER_ID_TOKEN);
	        expect(userIdTokenJo).toEqual(USER_ID_TOKEN_MO);
        });
    });
    
    it("create", function() {
        var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        
        var encode;
        runs(function() {
            data.toMslEncoding(encoder, ENCODER_FORMAT, {
            	result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var userdata;
        runs(function() {
        	var mo = encoder.parseObject(encode);
            UserAuthenticationData.parse(ctx, null, mo, {
                result: function(x) { userdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userdata; }, "userdata", MslTestConstants.TIMEOUT);
        
        var moData, moAuthdata;
        runs(function() {
            expect(userdata).not.toBeNull();
            expect(userdata instanceof UserIdTokenAuthenticationData).toBeTruthy();
            
            moData = userdata;
            expect(moData.scheme).toEqual(data.scheme);
            expect(moData.masterToken).toEqual(data.masterToken);
            expect(moData.userIdToken).toEqual(data.userIdToken);
            moData.getAuthData(encoder, ENCODER_FORMAT, {
            	result: function(x) { moAuthdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moAuthdata; }, "moAuthdata", MslTestConstants.TIMEOUT);
        
        var moEncode;
        runs(function() {
            expect(moAuthdata).not.toBeNull();
            moData.toMslEncoding(encoder, ENCODER_FORMAT, {
            	result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(moEncode).not.toBeNull();
            expect(moEncode).toEqual(encode);
        });
    });
    
    it("missing master token", function() {
        var authdata;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            data.getAuthData(encoder, ENCODER_FORMAT, {
            	result: function(x) { authdata = x; },
            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            authdata.remove(KEY_MASTER_TOKEN);
            UserIdTokenAuthenticationData.parse(ctx, authdata, {
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
    
    it("invalid master token", function() {
        var authdata;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            data.getAuthData(encoder, ENCODER_FORMAT, {
            	result: function(x) { authdata = x; },
            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            authdata.put(KEY_MASTER_TOKEN, encoder.createObject());
            UserIdTokenAuthenticationData.parse(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_INVALID));
        });
    });
    
    it("missing user ID token", function() {
        var authdata;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            data.getAuthData(encoder, ENCODER_FORMAT, {
            	result: function(x) { authdata = x; },
            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            authdata.remove(KEY_USER_ID_TOKEN);
            UserIdTokenAuthenticationData.parse(ctx, authdata, {
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
    
    it("invalid user ID token", function() {
        var authdata;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            data.getAuthData(encoder, ENCODER_FORMAT, {
            	result: function(x) { authdata = x; },
            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            authdata.put(KEY_USER_ID_TOKEN, encoder.createObject());
            UserIdTokenAuthenticationData.parse(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_INVALID));
        });
    });
    
    it("equals master token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, MASTER_TOKEN.sequenceNumber + 1, MASTER_TOKEN.serialNumber, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT);
        
        var dataA, dataB, authdata;
        runs(function() {
            dataA = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            dataB = new UserIdTokenAuthenticationData(masterToken, USER_ID_TOKEN);
            dataA.getAuthData(encoder, ENCODER_FORMAT, {
            	result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var dataA2;
        runs(function() {
        	UserIdTokenAuthenticationData.parse(ctx, authdata, {
        		result: function(x) { dataA2 = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return dataA2; }, "data", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(dataA.equals(dataA)).toBeTruthy();
            
            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            
            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
        });
    });
    
    it("equals user ID token", function() {
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, USER_ID_TOKEN.serialNumber + 1, USER_ID_TOKEN.user, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken", MslTestConstants.TIMEOUT);

        var dataA, dataB, authdata;
        runs(function() {
            dataA = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            dataB = new UserIdTokenAuthenticationData(MASTER_TOKEN, userIdToken);
            dataA.getAuthData(encoder, ENCODER_FORMAT, {
            	result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
            
        var dataA2;
        runs(function() {
        	UserIdTokenAuthenticationData.parse(ctx, authdata, {
        		result: function(x) { dataA2 = x; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return dataA2; }, "data", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(dataA.equals(dataA)).toBeTruthy();
            
            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            
            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
        });
    });
    
    it("equals object", function() {
        var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        expect(data.equals(null)).toBeFalsy();
        expect(data.equals(KEY_MASTER_TOKEN)).toBeFalsy();
    });
});