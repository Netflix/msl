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
 * Pre-shared keys entity authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("PresharedAuthenticationFactory", function() {
    /** JSON key entity identity. */
    var KEY_IDENTITY = "identity";

    /** Entity authentication factory. */
    var factory = new PresharedAuthenticationFactory(MockPresharedAuthenticationFactory.PSK_ESN);
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
                ctx.addEntityAuthenticationFactory(factory);
                initialized = true;
            });
        }
    });
    
    it("createData", function () {
        var data = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        var entityAuthJO = data.getAuthData();
        
        var authdata = factory.createData(ctx, entityAuthJO);
        expect(authdata).not.toBeNull();
        expect(authdata instanceof PresharedAuthenticationData).toBeTruthy();
        
        var dataJo = JSON.parse(JSON.stringify(data));
        var authdataJo = JSON.parse(JSON.stringify(authdata));
        expect(authdataJo).toEqual(dataJo);
    });
    
    it("encode exception", function() {
    	var f = function() {
	        var data = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
	        var entityAuthJO = data.getAuthData();
	        delete entityAuthJO[KEY_IDENTITY];
	        factory.createData(ctx, entityAuthJO);
    	};
    	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });
    
    it("crypto context", function() {
        var data = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        var cryptoContext = factory.getCryptoContext(ctx, data);
        expect(cryptoContext).not.toBeNull();
    });
    
    it("incorrect ESN", function() {
    	var f = function() {
	        var data = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN + "x");
	        factory.getCryptoContext(ctx, data);
    	};
    	expect(f).toThrow(new MslEntityAuthException(MslError.ENTITY_NOT_FOUND));
    });
});
