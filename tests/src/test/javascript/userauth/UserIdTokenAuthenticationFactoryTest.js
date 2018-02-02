/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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
 * User ID token user authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UserIdTokenAuthenticationFactory", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var UserAuthenticationScheme = require('msl-core/userauth/UserAuthenticationScheme.js');
    var UserIdTokenAuthenticationFactory = require('msl-core/userauth/UserIdTokenAuthenticationFactory.js');
    var UserIdTokenAuthenticationData = require('msl-core/userauth/UserIdTokenAuthenticationData.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslError = require('msl-core/MslError.js');
    var MslUserAuthException = require('msl-core/MslUserAuthException.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MockAuthenticationUtils = require('msl-tests/util/MockAuthenticationUtils.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockMslUser = require('msl-tests/tokens/MockMslUser.js');
    var MockTokenFactory = require('msl-tests/tokens/MockTokenFactory.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key master token. */
    var KEY_MASTER_TOKEN = "mastertoken";
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Authentication utilities. */
    var authutils;
    /** User authentication factory. */
    var factory;
    /** Token factory. */
    var tokenFactory;
    
    /** Master token. */
    var MASTER_TOKEN;
    /** User ID token. */
    var USER_ID_TOKEN;

    beforeEach(function() {
        if (!ctx) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(x) { ctx = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                authutils = new MockAuthenticationUtils();
                factory = new UserIdTokenAuthenticationFactory(authutils);
                ctx.addUserAuthenticationFactory(factory);
                tokenFactory = new MockTokenFactory();
                ctx.setTokenFactory(tokenFactory);
            
                MslTestUtils.getMasterToken(ctx, 1, 1, {
                    result: function(x) { MASTER_TOKEN = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return MASTER_TOKEN; }, "master token", MslTestConstants.TIMEOUT);
            runs(function() {
                var user = new MockMslUser("user1");
                MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, user, {
                    result: function(x) { USER_ID_TOKEN = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return USER_ID_TOKEN; }, "user ID token", MslTestConstants.TIMEOUT);
        }
    });
    
    afterEach(function() {
        authutils.reset();
        tokenFactory.reset();
    });
    
    it("create data", function() {
        var data, userAuthMo;
        runs(function() {
            data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { userAuthMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return userAuthMo; }, "userAuthMo", MslTestConstants.TIMEOUT);

        var authdata;
        runs(function() {
            factory.createData(ctx, null, userAuthMo, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(authdata).not.toBeNull();
            expect(authdata instanceof UserIdTokenAuthenticationData).toBeTruthy();
            expect(authdata).toEqual(data);
        });
    });
    
    it("encode exception", function() {
        var userAuthMo;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { userAuthMo = x; },
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return userAuthMo; }, "userAuthMo", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            userAuthMo.remove(KEY_MASTER_TOKEN);
            factory.createData(ctx, null, userAuthMo, {
                result: function(x) {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("authenticate", function() {
        var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        
        var user;
        runs(function() {
            factory.authenticate(ctx, MASTER_TOKEN.identity, data, null, {
                result: function(x) { user = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return user; }, "user", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(user).not.toBeNull();
            expect(user).toEqual(USER_ID_TOKEN.user);
        });
    });
    
    it("authenticate user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, MASTER_TOKEN.sequenceNumber + 1, MASTER_TOKEN.serialNumber + 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT);
        
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, USER_ID_TOKEN.serialNumber + 1, USER_ID_TOKEN.user, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token", MslTestConstants.TIMEOUT);
        
        var user;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            factory.authenticate(ctx, MASTER_TOKEN.identity, data, userIdToken, {
                result: function(x) { user = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return user; }, "user", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(user).toEqual(USER_ID_TOKEN.user);
        });
    });
    
    it("authenticate mismatched user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT);
        
        var userIdToken;
        runs(function() {
            var user = new MockMslUser("user2");
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, user, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            factory.authenticate(ctx, MASTER_TOKEN.identity, data, userIdToken, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH));
        });
    });
    
    it("untrusted master token", function() {
        var untrustedMasterToken;
        runs(function() {
            MslTestUtils.getUntrustedMasterToken(ctx, {
                result: function(x) { untrustedMasterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return untrustedMasterToken; }, "untrusted master token", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(untrustedMasterToken, USER_ID_TOKEN);
            factory.authenticate(ctx, MASTER_TOKEN.identity, data, null, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_NOT_DECRYPTED));
        });
    });

    it("mismatched master token identity", function() {
        var mismatchedCtx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.X509, false, {
                result: function(x) { mismatchedCtx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return mismatchedCtx; }, "mismatched ctx", MslTestConstants.TIMEOUT);
        
        var mismatchedMasterToken;
        runs(function() {
            MslTestUtils.getMasterToken(mismatchedCtx, 1, 1, {
                result: function(x) { mismatchedMasterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return mismatchedMasterToken; }, "mismatched master token", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(mismatchedMasterToken, USER_ID_TOKEN);
            factory.authenticate(ctx, MASTER_TOKEN.identity, data, null, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_ENTITY_MISMATCH));
        });
    });
    
    it("untrusted user ID token", function() {
        var untrustedUserIdToken;
        runs(function() {
            MslTestUtils.getUntrustedUserIdToken(ctx, MASTER_TOKEN, USER_ID_TOKEN.serialNumber, USER_ID_TOKEN.user, {
                result: function(x) { untrustedUserIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return untrustedUserIdToken; }, "untrusted user ID token", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, untrustedUserIdToken);
            factory.authenticate(ctx, MASTER_TOKEN.identity, data, null, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_NOT_DECRYPTED));
        });
    });
    
    it("user not permitted", function() {
        var exception;
        runs(function() {
            authutils.disallowScheme(MASTER_TOKEN.identity, USER_ID_TOKEN.user, UserAuthenticationScheme.USER_ID_TOKEN);

            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            factory.authenticate(ctx, MASTER_TOKEN.identity, data, null, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_ENTITYUSER_INCORRECT_DATA));
        });
    });
    
    it("token revoked", function() {
        var exception;
        runs(function() {
            tokenFactory.setRevokedUserIdToken(USER_ID_TOKEN);

            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            factory.authenticate(ctx, MASTER_TOKEN.identity, data, null, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERIDTOKEN_REVOKED));
        });
    });
});
