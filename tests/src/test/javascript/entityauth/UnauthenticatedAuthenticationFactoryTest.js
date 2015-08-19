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
 * Unauthenticated authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UnauthenticatedAuthenticationFactory", function() {
    /** JSON key entity identity. */
    var KEY_IDENTITY = "identity";
    
    var UNAUTHENTICATED_ESN = "MOCKUNAUTH-ESN";
    
    /** MSL context. */
    var ctx;
    /** Entity authentication factory. */
    var factory = new UnauthenticatedAuthenticationFactory();
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.NONE, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
            runs(function() {
                ctx.addEntityAuthenticationFactory(factory);
                initialized = true;
            });
        }
    });
    
    it("createData", function() {
        var data = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        var entityAuthJO = data.getAuthData();

        var authdata;
        runs(function() {
            factory.createData(ctx, entityAuthJO, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", 100);

        runs(function() {
            expect(authdata).not.toBeNull();
            expect(authdata instanceof UnauthenticatedAuthenticationData).toBeTruthy();
            
            var dataJo = JSON.parse(JSON.stringify(data));
            var authdataJo = JSON.parse(JSON.stringify(authdata));
            expect(authdataJo).toEqual(dataJo);
        });
    });
    
    it("encode exception", function() {
        var exception;
        runs(function() {
        	var data = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        	var entityAuthJO = data.getAuthData();
        	delete entityAuthJO[KEY_IDENTITY];
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
        var data = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        var cryptoContext = factory.getCryptoContext(ctx, data);
        expect(cryptoContext).not.toBeNull();
    });
});