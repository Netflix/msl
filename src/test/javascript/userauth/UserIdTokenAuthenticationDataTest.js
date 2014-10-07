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
 * User ID token user authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UserIdTokenAuthenticationData", function() {
    /** JSON key user authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key user authentication data. */
    var KEY_AUTHDATA = "authdata";
    /** JSON master token key. */
    var KEY_MASTER_TOKEN = "mastertoken";
    /** JSON user ID token key. */
    var KEY_USER_ID_TOKEN = "useridtoken";
    
    /** Master token. */
    var MASTER_TOKEN;
    /** User ID token. */
    var USER_ID_TOKEN;
    
    /** MSL context. */
    var ctx;
    beforeEach(function() {
        if (!ctx) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.X509, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
            runs(function() {
                MslTestUtils.getMasterToken(ctx, 1, 1, {
                    result: function(x) { MASTER_TOKEN = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return MASTER_TOKEN; }, "master token", 100);
            runs(function() {
                var user = new MockMslUser("user1");
                MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, user, {
                    result: function(x) { USER_ID_TOKEN = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return USER_ID_TOKEN; }, "user ID token", 100);
        }
    });
    
    it("ctors", function() {
        var data, authdata, jsonString, joData;
        runs(function () {
            data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            expect(data.scheme).toEqual(UserAuthenticationScheme.USER_ID_TOKEN);
            expect(data.masterToken).toEqual(MASTER_TOKEN);
            expect(data.userIdToken).toEqual(USER_ID_TOKEN);
            authdata = data.getAuthData();
            expect(authdata).not.toBeNull();
            jsonString = JSON.stringify(data);
            
            UserIdTokenAuthenticationData$parse(ctx, authdata, {
                result: function(x) { joData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joData; }, "joData", 100);
        
        runs(function() {
            expect(joData.scheme).toEqual(data.scheme);
            expect(joData.masterToken).toEqual(data.masterToken);
            expect(joData.userIdToken).toEqual(data.userIdToken);
            var joAuthdata = joData.getAuthData();
            expect(joAuthdata).not.toBeNull();
            expect(joAuthdata).toEqual(authdata);
            var joJsonString = JSON.stringify(joData);
            expect(joJsonString).not.toBeNull();
            expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("json is correct", function() {
        var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        var jo = JSON.parse(JSON.stringify(data));
        expect(jo[KEY_SCHEME]).toEqual(UserAuthenticationScheme.USER_ID_TOKEN.name);
        var authdata = jo[KEY_AUTHDATA];
        var masterTokenJo = authdata[KEY_MASTER_TOKEN];
        expect(masterTokenJo).toEqual(JSON.parse(JSON.stringify(MASTER_TOKEN)));
        var userIdTokenJo = authdata[KEY_USER_ID_TOKEN];
        expect(userIdTokenJo).toEqual(JSON.parse(JSON.stringify(USER_ID_TOKEN)));
    });
    
    it("create", function() {
        var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        var jsonString = JSON.stringify(data);
        var jo = JSON.parse(jsonString);
        var userdata;
        runs(function() {
            UserAuthenticationData$parse(ctx, null, jo, {
                result: function(x) { userdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userdata; }, "userdata", 100);
        
        runs(function() {
            expect(userdata).not.toBeNull();
            expect(userdata instanceof UserIdTokenAuthenticationData).toBeTruthy();
            
            var joData = userdata;
            expect(joData.scheme).toEqual(data.scheme);
            expect(joData.masterToken).toEqual(data.masterToken);
            expect(joData.userIdToken).toEqual(data.userIdToken);
            var joAuthdata = joData.getAuthData();
            expect(joAuthdata).not.toBeNull();
            expect(joAuthdata).toEqual(data.getAuthData());
            var joJsonString = JSON.stringify(joData);
            expect(joJsonString).not.toBeNull();
            expect(joJsonString).toEqual(jsonString);
        });        
    });
    
    it("missing master token", function() {
        var exception;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            var authdata = data.getAuthData();
            delete authdata[KEY_MASTER_TOKEN];
            UserIdTokenAuthenticationData$parse(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid master token", function() {
        var exception;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            var authdata = data.getAuthData();
            authdata[KEY_MASTER_TOKEN] = {};
            UserIdTokenAuthenticationData$parse(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_INVALID));
        });
    });
    
    it("missing user ID token", function() {
        var exception;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            var authdata = data.getAuthData();
            delete authdata[KEY_USER_ID_TOKEN];
            UserIdTokenAuthenticationData$parse(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
        });
    });
    
    it("invalid user ID token", function() {
        var exception;
        runs(function() {
            var data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            var authdata = data.getAuthData();
            authdata[KEY_USER_ID_TOKEN] = {};
            UserIdTokenAuthenticationData$parse(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);

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
        waitsFor(function() { return masterToken; }, "masterToken", 100);
        
        var dataA, dataB, dataA2;
        runs(function() {
            dataA = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            dataB = new UserIdTokenAuthenticationData(masterToken, USER_ID_TOKEN);
            UserIdTokenAuthenticationData$parse(ctx, dataA.getAuthData(), {
                result: function(x) { dataA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataA && dataB && dataA2; }, "data", 100);
        
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
        waitsFor(function() { return userIdToken; }, "userIdToken", 100);
        
        var dataA, dataB, dataA2;
        runs(function() {
            dataA = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
            dataB = new UserIdTokenAuthenticationData(MASTER_TOKEN, userIdToken);
            UserIdTokenAuthenticationData$parse(ctx, dataA.getAuthData(), {
                result: function(x) { dataA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataA && dataB && dataA2; }, "data", 100);
        
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