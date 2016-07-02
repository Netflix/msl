/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
    /** Key master token. */
    var KEY_MASTER_TOKEN = "mastertoken";
    
    /** MSL context. */
    var ctx;
    /** Authentication utilities. */
    var authutils;
    /** User authentication factory. */
    var factory;
    
    /** Master token. */
    var MASTER_TOKEN;
    /** User ID token. */
    var USER_ID_TOKEN;

    beforeEach(function() {
        if (!ctx) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(x) { ctx = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
            runs(function() {
                authutils = new MockAuthenticationUtils();
                factory = new UserIdTokenAuthenticationFactory(authutils);
                ctx.addUserAuthenticationFactory(factory);
            
                MslTestUtils.getMasterToken(ctx, 1, 1, {
                    result: function(x) { MASTER_TOKEN = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return MASTER_TOKEN; }, "master token", 100);
            runs(function() {
                var user = new MockMslUser("user1");
                MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, user, {
                    result: function(x) { USER_ID_TOKEN = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return USER_ID_TOKEN; }, "user ID token", 100);
        }
    });
    
    afterEach(function() {
        authutils.reset();
    });
    
    it("create data", function() {
        var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        var userAuthJO = data.getAuthData();
        
        var authdata;
        runs(function() {
            factory.createData(ctx, null, userAuthJO, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", 100);
        
        runs(function() {
            expect(authdata).not.toBeNull();
            expect(authdata instanceof UserIdTokenAuthenticationData).toBeTruthy();
            
            var dataJo = JSON.parse(JSON.stringify(data));
            var authdataJo = JSON.parse(JSON.stringify(authdata));
            expect(authdataJo).toEqual(dataJo);
        });
    });
    
    it("encode exception", function() {
        var exception;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            var userAuthJO = data.getAuthData();
            delete userAuthJO[KEY_MASTER_TOKEN];
            factory.createData(ctx, null, userAuthJO, {
                result: function(x) {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        })
    });
    
    it("authenticate", function() {
        var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        var user = factory.authenticate(ctx, MASTER_TOKEN.identity, data, null);
        expect(user).not.toBeNull();
        expect(user).toEqual(USER_ID_TOKEN.user);
    });
    
    it("authenticate user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, MASTER_TOKEN.sequenceNumber + 1, MASTER_TOKEN.serialNumber + 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return masterToken; }, "master token", 100);
        
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, USER_ID_TOKEN.serialNumber + 1, USER_ID_TOKEN.user, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token", 100);
        
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            var u = factory.authenticate(ctx, MASTER_TOKEN.identity, data, userIdToken);
            expect(u).toEqual(USER_ID_TOKEN.user);
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
        waitsFor(function() { return masterToken; }, "master token", 100);
        
        var userIdToken;
        runs(function() {
            var user = new MockMslUser("user2");
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, user, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return userIdToken; }, "user ID token", 100);
        
        runs(function() {
            var f = function() {
                var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
                factory.authenticate(ctx, MASTER_TOKEN.identity, data, userIdToken);
            };
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
        waitsFor(function() { return untrustedMasterToken; }, "untrusted master token", 100);
        
        runs(function() {
            var f = function() {
                var data = new UserIdTokenAuthenticationData(untrustedMasterToken, USER_ID_TOKEN);
                factory.authenticate(ctx, MASTER_TOKEN.identity, data, null);
            };
            expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_NOT_DECRYPTED));
        });
    });
    
    it("mismatched master token identity", function() {
        var mismatchedCtx;
        runs(function() {
            MockMslContext$create(EntityAuthenticationScheme.X509, false, {
                result: function(x) { mismatchedCtx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return mismatchedCtx; }, "mismatched ctx", 100);
        
        var mismatchedMasterToken;
        runs(function() {
            MslTestUtils.getMasterToken(mismatchedCtx, 1, 1, {
                result: function(x) { mismatchedMasterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return mismatchedMasterToken; }, "mismatched master token", 100);
        
        runs(function() {
            var f = function() {
                var data = new UserIdTokenAuthenticationData(mismatchedMasterToken, USER_ID_TOKEN);
                factory.authenticate(ctx, MASTER_TOKEN.identity, data, null);
            };
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
        waitsFor(function() { return untrustedUserIdToken; }, "untrusted user ID token", 100);
        
        runs(function() {
            var f = function() {
                var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, untrustedUserIdToken);
                factory.authenticate(ctx, MASTER_TOKEN.identity, data, null);
            };
            expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_NOT_DECRYPTED));
        });
    });
    
    it("user not permitted", function() {
        var f = function() {
            authutils.disallowScheme(MASTER_TOKEN.identity, USER_ID_TOKEN.user, UserAuthenticationScheme.USER_ID_TOKEN);

            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            factory.authenticate(ctx, MASTER_TOKEN.identity, data, null);
        };
        expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_ENTITYUSER_INCORRECT_DATA));
    });
});
