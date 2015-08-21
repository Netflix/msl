/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
 * Master token protected entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MasterTokenProtectedAuthenticationData", function() {
    /**
     * JSON key entity authentication scheme.
     * @const
     * @type {string}
     */
    var KEY_SCHEME = "scheme";
    /**
     * JSON key entity authentication data.
     * @const
     * @type {string}
     */
    var KEY_AUTHDATA = "authdata";
    
    /**
     * JSON key master token.
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN = "mastertoken";
    /**
     * JSON key authentication data.
     * @const
     * @type {string}
     */
    var KEY_AUTHENTICATION_DATA = "authdata";
    /**
     * JSON key signature.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";
    
    var IDENTITY = "identity";

    /** MSL context. */
    var ctx;
    /** Master token. */
    var masterToken;
    /** Encapsulated entity authentication data. */
    var eAuthdata;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.X509, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 900);
            runs(function() {
                MslTestUtils.getMasterToken(ctx, 1, 1, {
                    result: function(x) { masterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                });
                eAuthdata = new UnauthenticatedAuthenticationData(IDENTITY);
            });
            waitsFor(function() { return masterToken; }, "master token", 100);
            runs(function() {
                initialized = true;
            });
        }
    });
    
    it("ctors", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);

        var authdata, jsonString, joData;
        runs(function() {
            expect(data.getIdentity()).toEqual(eAuthdata.getIdentity());
            expect(data.scheme).toEqual(EntityAuthenticationScheme.MT_PROTECTED);
            expect(data.encapsulatedAuthdata.equals(eAuthdata)).toBeTruthy();
            authdata = data.getAuthData();
            expect(authdata).not.toBeNull();
            jsonString = JSON.stringify(data);
            expect(jsonString).not.toBeNull();
       
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
                result: function(x) { joData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return joData; }, "joData", 100);
        
        runs(function() {
            expect(joData.getIdentity()).toEqual(data.getIdentity());
            expect(joData.scheme).toEqual(data.scheme);
            expect(joData.encapsulatedAuthdata).toEqual(data.encapsulatedAuthdata);
            var joAuthdata = joData.getAuthData();
            expect(joAuthdata).not.toBeNull();
            expect(joAuthdata).toEqual(authdata);
            var joJsonString = JSON.stringify(joData);
            expect(joJsonString).not.toBeNull();
            expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("json is correct", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        runs(function() {
            var jo = JSON.parse(JSON.stringify(data));
            expect(jo[KEY_SCHEME]).toEqual(EntityAuthenticationScheme.MT_PROTECTED.name);
            var authdata = jo[KEY_AUTHDATA];
    
            var masterTokenStr = JSON.stringify(masterToken);
            expect(authdata[KEY_MASTER_TOKEN]).toEqual(JSON.parse(masterTokenStr));
            // Signature and ciphertext may not be predictable depending on the
            // master token encryption and signature algorithms.
        });
    });
    
    it("create", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        var jsonString, entitydata;
        runs(function() {
            jsonString = JSON.stringify(data);
            var jo = JSON.parse(jsonString);
            EntityAuthenticationData$parse(ctx, jo, {
                result: function(x) { entitydata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entitydata; }, "entitydata", 100);
        
        runs(function() {
            expect(entitydata).not.toBeNull();
            expect(entitydata instanceof MasterTokenProtectedAuthenticationData).toBeTruthy();
            
            var joData = entitydata;
            expect(joData.getIdentity()).toEqual(data.getIdentity());
            expect(joData.scheme).toEqual(data.scheme);
            expect(joData.encapsulatedAuthdata).toEqual(data.encapsulatedAuthdata);
            var joAuthdata = joData.getAuthData();
            expect(joAuthdata).not.toBeNull();
            expect(joAuthdata).toEqual(data.getAuthData());
            var joJsonString = JSON.stringify(joData);
            expect(joJsonString).not.toBeNull();
            expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("missing master token", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        var exception;
        runs(function() {
            var authdata = data.getAuthData();
            delete authdata[KEY_MASTER_TOKEN];
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
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
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);

        var exception;
        runs(function() {
            var authdata = data.getAuthData();
            authdata[KEY_MASTER_TOKEN] = "x";
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
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
    
    it("corrupt master token", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        var exception;
        runs(function() {
            var authdata = data.getAuthData();
            authdata[KEY_MASTER_TOKEN] = {};
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_MASTERTOKEN_INVALID));
        });
    });
    
    it("missing authdata", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);

        var exception;
        runs(function() {
            var authdata = data.getAuthData();
            delete authdata[KEY_AUTHENTICATION_DATA];
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
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
    
    it("invalid authdata", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);

        var exception;
        runs(function() {
            var authdata = data.getAuthData();
            authdata[KEY_AUTHENTICATION_DATA] = true;
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
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
    
    xit("corrupt authdata", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);

        var exception;
        runs(function() {
            var authdata = data.getAuthData();
            authdata[KEY_AUTHENTICATION_DATA] = "x";
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_CIPHERTEXT_INVALID));
        });
    });
    
    it("missing signature", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);

        var exception;
        runs(function() {
            var authdata = data.getAuthData();
            delete authdata[KEY_SIGNATURE];
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
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
    
    it("invalid signature", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);

        var exception;
        runs(function() {
            var authdata = data.getAuthData();
            authdata[KEY_SIGNATURE] = true;
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
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
    
    xit("corrupt signature", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);

        var exception;
        runs(function() {
            var authdata = data.getAuthData();
            authdata[KEY_SIGNATURE] = "x";
            MasterTokenProtectedAuthenticationData$parse(ctx, authdata, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", 100);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_SIGNATURE_INVALID));
        });
    });
    
    it("equals master token", function() {
        var masterTokenB;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 2, 2, {
                result: function(x) { masterTokenB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterTokenB; }, "master token", 100);
        
        var dataA, dataB;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { dataA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterTokenProtectedAuthenticationData$create(ctx, masterTokenB, eAuthdata, {
                result: function(x) { dataB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataA && dataB; }, "dataA && dataB", 100);
        var dataA2;
        runs(function() {
            EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)), {
                result: function(x) { dataA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataA2; }, "dataA2", 100);
        
        runs(function() {
            expect(dataA.equals(dataA)).toBeTruthy();
            
            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            
            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
        });
    });
    
    it("equals authdata", function() {
        var eAuthdataB = new UnauthenticatedAuthenticationData(IDENTITY + "B");
        var dataA, dataB;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { dataA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdataB, {
                result: function(x) { dataB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataA && dataB; }, "dataA && dataB", 100);
        var dataA2;
        runs(function() {
            EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)), {
                result: function(x) { dataA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataA2; }, "dataA2", 100);

        runs(function() {
            expect(dataA.equals(dataA)).toBeTruthy();
            
            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            
            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
        });
    });
    
    it("equals object", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        runs(function() {
            expect(data.equals(null)).toBeFalsy();
            expect(data.equals(IDENTITY)).toBeFalsy();
        });
    });
});