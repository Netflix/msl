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
 * Email/password user authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("EmailPasswordAuthenticationFactory", function() {
    const MslEncoderFormat = require('../../../../../core/src/main/javascript/io/MslEncoderFormat.js');
    const EntityAuthenticationScheme = require('../../../../../core/src/main/javascript/entityauth/EntityAuthenticationScheme.js');
    const EmailPasswordAuthenticationFactory = require('../../../../../core/src/main/javascript/userauth/EmailPasswordAuthenticationFactory.js');
    const EmailPasswordAuthenticationData = require('../../../../../core/src/main/javascript/userauth/EmailPasswordAuthenticationData.js');
    const MslEncodingException = require('../../../../../core/src/main/javascript/MslEncodingException.js');
    const MslError = require('../../../../../core/src/main/javascript/MslError.js');
    const MslUserAuthException = require('../../../../../core/src/main/javascript/MslUserAuthException.js');

    const MockMslContext = require('../../../main/javascript/util/MockMslContext.js');
    const MockEmailPasswordStore = require('../../../main/javascript/userauth/MockEmailPasswordStore.js');
    const MockEmailPasswordAuthenticationFactory = require('../../../main/javascript/userauth/MockEmailPasswordAuthenticationFactory.js');
    const MockAuthenticationUtils = require('../../../main/javascript/util/MockAuthenticationUtils.js');
    const MslTestUtils = require('../../../main/javascript/util/MslTestUtils.js');
    
	/** MSL encoder format. */
	var ENCODER_FORMAT = MslEncoderFormat.JSON;
	
    /** Key email. */
    var KEY_EMAIL = "email";
    
    /** Empty string. */
    var EMPTY_STRING = "";
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Authentication utilities. */
    var authutils;
    /** User authentication factory. */
    var factory;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 900);
            runs(function() {
            	encoder = ctx.getMslEncoderFactory();
                var store = new MockEmailPasswordStore();
                store.addUser(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD, MockEmailPasswordAuthenticationFactory.USER);
                authutils = new MockAuthenticationUtils();
                factory = new EmailPasswordAuthenticationFactory(store, authutils);
                
                initialized = true;
            });
        } else {
        	authutils.reset();
        }
    });

    it("create data", function() {
        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        
        var userAuthMo;
        runs(function() {
        	data.getAuthData(encoder, ENCODER_FORMAT, {
        		result: function(x) { userAuthMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return userAuthMo; }, "userAuthMo", 100);
        
        var authdata;
        runs(function() {
            factory.createData(ctx, null, userAuthMo, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", 100);
        
        var dataMo, authdataMo;
        runs(function() {
            expect(authdata).not.toBeNull();
            expect(authdata instanceof EmailPasswordAuthenticationData).toBeTruthy();
            
            MslTestUtils.toMslObject(encoder, data, {
            	result: function(x) { dataMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.toMslObject(encoder, authdata, {
            	result: function(x) { authdataMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataMo && authdataMo; }, "msl objects", 100);
        
        runs(function() {
            expect(authdataMo).toEqual(dataMo);
        });
    });
    
    it("encode exception", function() {
    	var userAuthMo;
    	runs(function() {
	        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        	data.getAuthData(encoder, ENCODER_FORMAT, {
        		result: function(x) { userAuthMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return userAuthMo; }, "userAuthMo", 100);
        
        var exception;
        runs(function() {
	        userAuthMo.remove(KEY_EMAIL);
	        factory.createData(ctx, null, userAuthMo, {
	            result: function() {},
	            error: function(e) { exception = e; },
	        });
    	});
    	waitsFor(function() { return exception; }, "exception", 100);
    	
    	runs(function() {
    	    var f = function() { throw exception; };
    	    expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
    	});
    });
    
    it("authenticate", function() {
        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        var user = factory.authenticate(ctx, null, data, null);
        expect(user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
    });
    
    it("authenticate with user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", 100);
        
        var userIdToken;
        runs(function() {
            var user = MockEmailPasswordAuthenticationFactory.USER;
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, user, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token", 100);
        
        runs(function() {
            var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
            var user = factory.authenticate(ctx, null, data, null);
            expect(user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
        });
    });
    
    it("authenticate with mismatched user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", 100);
        
        var userIdToken;
        runs(function() {
            var user = MockEmailPasswordAuthenticationFactory.USER_2;
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, user, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token", 100);
        
        runs(function() {
            var f = function() {
                var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
                factory.authenticate(ctx, null, data, userIdToken);
            };
            expect(f).toThrow(new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH));
        });
    });
    
    it("email is blank", function() {
    	var f = function() {
	        var data = new EmailPasswordAuthenticationData(EMPTY_STRING, MockEmailPasswordAuthenticationFactory.PASSWORD);
	        factory.authenticate(ctx, null, data, null);
    	};
        expect(f).toThrow(new MslUserAuthException(MslError.EMAILPASSWORD_BLANK));
    });
    
    it("password is blank", function() {
    	var f = function() {
    		var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, EMPTY_STRING);
    		factory.authenticate(ctx, null, data, null);
    	};
    	expect(f).toThrow(new MslUserAuthException(MslError.EMAILPASSWORD_BLANK));
    });
    
    it("bad login", function() {
    	var f = function() {
	        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD + "x");
	        factory.authenticate(ctx, null, data, null);
    	};
    	expect(f).toThrow(new MslUserAuthException(MslError.EMAILPASSWORD_INCORRECT));
    });
});
