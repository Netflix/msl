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
 * Null MSL store unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("NullMslStore", function() {
    const NullMslStore = require('../../../../../core/src/main/javascript/util/NullMslStore.js');
    const EntityAuthenticationScheme = require('../../../../../core/src/main/javascript/entityauth/EntityAuthenticationScheme.js');
    const NullCryptoContext = require('../../../../../core/src/main/javascript/crypto/NullCryptoContext.js');
    const ServiceToken = require('../../../../../core/src/main/javascript/tokens/ServiceToken.js');
    const MslException = require('../../../../../core/src/main/javascript/MslException.js');
    const MslError = require('../../../../../core/src/main/javascript/MslError.js');
    
    const MockMslContext = require('../../../main/javascript/util/MockMslContext.js');
    const MslTestUtils = require('../../../main/javascript/util/MslTestUtils.js');
    const MockEmailPasswordAuthenticationFactory = require('../../../main/javascript/userauth/MockEmailPasswordAuthenticationFactory.js');

    var TOKEN_NAME = "name";
    
    /** MSL context. */
    var ctx;
    /** MSL store. */
    var store = new NullMslStore();

    beforeEach(function() {
        if (!ctx) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.NONE, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
        }
    });
    
    afterEach(function() {
        store = new NullMslStore();
    });
    
    it("crypto contexts", function() {
        var masterToken;
        runs(function() {
        	MslTestUtils.getMasterToken(ctx, 1, 1, {
        		result: function(token) { masterToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return masterToken; }, "master token not received", 100);
        
        runs(function() {
            expect(store.getCryptoContext(masterToken)).toBeNull();
            
            var cryptoContext = new NullCryptoContext();
            store.setCryptoContext(masterToken, cryptoContext);
            expect(store.getCryptoContext(masterToken)).toBeNull();
            store.clearCryptoContexts();
        });
    });
    
    it("service tokens", function() {
    	var serviceToken;
    	runs(function() {
	        expect(store.getServiceTokens(null, null).length).toEqual(0);
	        
	        var cryptoContext = new NullCryptoContext();
	        var data = new Uint8Array(8);
	        ctx.getRandom().nextBytes(data);
	        ServiceToken.create(ctx, TOKEN_NAME, data, null, null, false, null, cryptoContext, {
	        	result: function(t) { serviceToken = t; },
	        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
    	});
    	waitsFor(function() { return serviceToken; }, "service token not received", 100);
        
        runs(function() {
        	var tokens = [ serviceToken ];
        	store.addServiceTokens(tokens);
        	expect(store.getServiceTokens(null, null).length).toEqual(0);

        	store.removeServiceTokens(TOKEN_NAME, null, null);
        	store.clearServiceTokens();
        });
    });
    
    it("get service tokens with mismatched tokens", function() {
        var masterToken, mismatchedMasterToken;
        runs(function() {
        	MslTestUtils.getMasterToken(ctx, 1, 1, {
        		result: function(token) { masterToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	MslTestUtils.getMasterToken(ctx, 2, 2, {
        		result: function(token) { mismatchedMasterToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return masterToken && mismatchedMasterToken; }, "master tokens not received", 100);
        
        var userIdToken;
        runs(function() {
        	MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
        		result: function(token) { userIdToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", 100);

        runs(function() {
	        var f = function() {
	        	store.getServiceTokens(mismatchedMasterToken, userIdToken);
	        };
	        expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH));
        });
    });
    
    it("get user-bound service tokens without a master token", function() {
        var masterToken;
        runs(function() {
        	MslTestUtils.getMasterToken(ctx, 1, 1, {
        		result: function(token) { masterToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return masterToken; }, "master token not received", 100);
        
        var userIdToken;
        runs(function() {
        	MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
        		result: function(token) { userIdToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", 100);
        
        runs(function() {
	        var f = function() {
	        	store.getServiceTokens(null, userIdToken);
	        };
	        expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_NULL));
        });
    });
    
    it("remove service tokens with mismatched tokens", function() {
        var masterToken, mismatchedMasterToken;
        runs(function() {
        	MslTestUtils.getMasterToken(ctx, 1, 1, {
        		result: function(token) { masterToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        	MslTestUtils.getMasterToken(ctx, 2, 2, {
        		result: function(token) { mismatchedMasterToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return masterToken && mismatchedMasterToken; }, "master tokens not received", 100);
        
        var userIdToken;
        runs(function() {
        	MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
        		result: function(token) { userIdToken = token; },
        		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	});
        });
        waitsFor(function() { return userIdToken; }, "user ID token not received", 100);
        
        runs(function() {
	        var f = function() {
	        	store.removeServiceTokens(null, mismatchedMasterToken, userIdToken);
	        };
	        expect(f).toThrow(new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH));
        });
    });
});
