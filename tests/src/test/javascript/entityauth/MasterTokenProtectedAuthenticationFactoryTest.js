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
 * Master token protected authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MasterTokenProtectedAuthenticationFactory", function() {
    /**
     * JSON key master token.
     * 
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN = "mastertoken";
    
    var IDENTITY = "identity";
    
    /** MSL context. */
    var ctx;
    /** Authentication utilities. */
    var authutils;
    /** Entity authentication factory. */
    var factory;

    /** Master token. */
    var masterToken;
    /** Encapsulated entity authentication data. */
    var eAuthdata;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.NONE, false, {
                    result: function(x) { ctx = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
            
            runs(function() {
                authutils = new MockAuthenticationUtils();
                factory = new MasterTokenProtectedAuthenticationFactory(authutils);
                ctx.addEntityAuthenticationFactory(factory);
                
                MslTestUtils.getMasterToken(ctx, 1, 1, {
                    result: function(x) { masterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                eAuthdata = new UnauthenticatedAuthenticationData(IDENTITY);
            });
            waitsFor(function() { return masterToken; }, "master token", 100);
        }
    });
    
    afterEach(function() {
        authutils.reset();
    });
    
    it("create data", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        var authdata;
        runs(function() {
            var entityAuthJO = data.getAuthData();
            
            factory.createData(ctx, entityAuthJO, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", 100);
        
        runs(function() {
            expect(authdata).not.toBeNull();
            expect(authdata instanceof MasterTokenProtectedAuthenticationData).toBeTruthy();
            
            var dataJo = JSON.parse(JSON.stringify(data));
            var authdataJo = JSON.parse(JSON.stringify(authdata));
            expect(authdataJo).toEqual(dataJo);
        });
    });
    
    it("encode exception", function() {
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
            var entityAuthJO = data.getAuthData();
            delete entityAuthJO[KEY_MASTER_TOKEN];
            factory.createData(ctx, entityAuthJO, {
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
    
    it("crypto context", function() {
        var data;
        runs(function() {
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        runs(function() {
            var cryptoContext = factory.getCryptoContext(ctx, data);
            expect(cryptoContext).not.toBeNull();
        });
    });
    
    it("unsupported encapsulated scheme", function() {
        var ctx;
        runs(function() {
            MockMslContext$create(EntityAuthenticationScheme.NONE, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", 100);
        
        var data;
        runs(function() {
            ctx.removeEntityAuthenticationFactory(EntityAuthenticationScheme.NONE);

            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        runs(function() {
            var f = function() {
                factory.getCryptoContext(ctx, data);
            };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND));
        });
    });
    
    it("revoked", function() {
        var data;
        runs(function() {
            authutils.revokeEntity(IDENTITY);
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        runs(function() {
            var f = function() {
                factory.getCryptoContext(ctx, data);
            };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITY_REVOKED));
        });
    });
    
    it("scheme not permitted", function() {
        var data;
        runs(function() {
            authutils.disallowScheme(IDENTITY, EntityAuthenticationScheme.MT_PROTECTED);
            MasterTokenProtectedAuthenticationData$create(ctx, masterToken, eAuthdata, {
                result: function(x) { data = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return data; }, "data", 100);
        
        runs(function() {
            var f = function() {
                factory.getCryptoContext(ctx, data);
            };
            expect(f).toThrow(new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA));
        });
    });
});