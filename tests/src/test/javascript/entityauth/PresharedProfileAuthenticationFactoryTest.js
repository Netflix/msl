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
 * Pre-shared keys profile entity authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("PresharedProfileAuthenticationFactory", function() {
    /** JSON key entity preshared keys identity. */
    var KEY_PSKID = "pskid";

    /** Authentication utilities. */
    var authutils = new MockAuthenticationUtils();
    /** Entity authentication factory. */
    var factory;
    /** MSL context. */
    var ctx;
    
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
                var store = new MockPresharedKeyStore();
                store.addKeys(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.KPE, MockPresharedProfileAuthenticationFactory.KPH, MockPresharedProfileAuthenticationFactory.KPW);
                factory = new PresharedProfileAuthenticationFactory(store, authutils);
                ctx.addEntityAuthenticationFactory(factory);
                initialized = true;
            });
        }
    });
    
    afterEach(function() {
        authutils.reset();
    });
    
    it("createData", function () {
        var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        var entityAuthJO = data.getAuthData();
        
        var authdata = factory.createData(ctx, entityAuthJO);
        expect(authdata).not.toBeNull();
        expect(authdata instanceof PresharedProfileAuthenticationData).toBeTruthy();
        
        var dataJo = JSON.parse(JSON.stringify(data));
        var authdataJo = JSON.parse(JSON.stringify(authdata));
        expect(authdataJo).toEqual(dataJo);
    });
    
    it("encode exception", function() {
        var f = function() {
            var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
            var entityAuthJO = data.getAuthData();
            delete entityAuthJO[KEY_PSKID];
            factory.createData(ctx, entityAuthJO);
        };
        expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });
    
    it("crypto context", function() {
        var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        var cryptoContext = factory.getCryptoContext(ctx, data);
        expect(cryptoContext).not.toBeNull();
    });
    
    it("unknown ESN", function() {
        var f = function() {
            var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN2, MockPresharedProfileAuthenticationFactory.PROFILE);
            factory.getCryptoContext(ctx, data);
        };
        expect(f).toThrow(new MslEntityAuthException(MslError.ENTITY_NOT_FOUND));
    });
    
    it("revoked", function() {
        var f = function() {
            authutils.revokeEntity(MockPresharedProfileAuthenticationFactory.PSK_ESN);
            var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
            factory.getCryptoContext(ctx, data);
        };
        expect(f).toThrow(new MslEntityAuthException(MslError.ENTITY_REVOKED));
    });
});
