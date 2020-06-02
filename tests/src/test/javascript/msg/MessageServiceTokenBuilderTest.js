/**
 * Copyright (c) 2012-2020 Netflix, Inc.  All rights reserved.
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
 * Message service token builder unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MessageServiceTokenBuilder", function() {
    var Random = require('msl-core/util/Random.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var UserAuthenticationScheme = require('msl-core/userauth/UserAuthenticationScheme.js');
    var SymmetricWrappedExchange = require('msl-core/keyx/SymmetricWrappedExchange.js');
    var MessageFactory = require('msl-core/msg/MessageFactory.js');
    var MessageServiceTokenBuilder = require('msl-core/msg/MessageServiceTokenBuilder.js');
    var ServiceToken = require('msl-core/tokens/ServiceToken.js');
    var NullCryptoContext = require('msl-core/crypto/NullCryptoContext.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslError = require('msl-core/MslError.js');

    /** Message factory. */
    var messageFactory = new MessageFactory();

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MockMessageContext = require('msl-tests/msg/MockMessageContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockEmailPasswordAuthenticationFactory = require('msl-tests/userauth/MockEmailPasswordAuthenticationFactory.js');
    
	var random = new Random();
	var trustedNetCtx;
	var trustedNetMsgCtx;
	var p2pCtx;
	var p2pMsgCtx;

	var KEYPAIR_ID = "keyPairId";
	var USER_ID = "userid";
	var TOKEN_NAME = "tokenName";
	var EMPTY_TOKEN_NAME = "";
	var DATA = new Uint8Array(128);
	random.nextBytes(DATA);
	var ENCRYPT = true;
	var COMPRESSION_ALGO = null;

	var MASTER_TOKEN;
	var PEER_MASTER_TOKEN;
	var USER_ID_TOKEN;
	var PEER_USER_ID_TOKEN;
	var SERVICE_TOKENS;
	var PEER_SERVICE_TOKENS;
	var KEY_REQUEST_DATA;
	
	var initialized = false;
	beforeEach(function() {
		if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { trustedNetCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MockMslContext.create(EntityAuthenticationScheme.PSK, true, {
                    result: function(c) { p2pCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return trustedNetCtx && p2pCtx; }, "trustedNetCtx and p2pCtx", MslTestConstants.TIMEOUT_CTX);
            runs(function() {
                MockMessageContext.create(trustedNetCtx, USER_ID, UserAuthenticationScheme.EMAIL_PASSWORD, {
                    result: function(c) { trustedNetMsgCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
			    MockMessageContext.create(p2pCtx, USER_ID, UserAuthenticationScheme.EMAIL_PASSWORD, {
			        result: function(c) { p2pMsgCtx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
				MslTestUtils.getMasterToken(p2pCtx, 1, 1, {
					result: function(token) { MASTER_TOKEN = token; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.getMasterToken(p2pCtx, 1, 2, {
					result: function(token) { PEER_MASTER_TOKEN = token; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return trustedNetMsgCtx && p2pMsgCtx && MASTER_TOKEN && PEER_MASTER_TOKEN; }, "message contexts and master tokens not received", MslTestConstants.TIMEOUT);
			runs(function() {
				MslTestUtils.getUserIdToken(p2pCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
					result: function(token) { USER_ID_TOKEN = token; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
					result: function(token) { PEER_USER_ID_TOKEN = token; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				KEY_REQUEST_DATA = new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK);
            });
			waitsFor(function() { return USER_ID_TOKEN && PEER_USER_ID_TOKEN && KEY_REQUEST_DATA; }, "user ID tokens and key request data not received", MslTestConstants.TIMEOUT);
			runs(function() {
				MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, {
					result: function(tokens) { SERVICE_TOKENS = tokens; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
					result: function(tokens) { PEER_SERVICE_TOKENS = tokens; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return SERVICE_TOKENS && PEER_SERVICE_TOKENS; }, "service tokens not received", MslTestConstants.TIMEOUT);
			runs(function() { initialized = true; });
		}
	});

	afterEach(function() {
	    p2pMsgCtx = undefined;
		runs(function() {
	        p2pCtx.getMslStore().clearCryptoContexts();
	        p2pCtx.getMslStore().clearServiceTokens();
	        p2pCtx.getMslStore().clearUserIdTokens();
	        MockMessageContext.create(p2pCtx, USER_ID, UserAuthenticationScheme.EMAIL_PASSWORD, {
	            result: function(c) { p2pMsgCtx = c; },
	            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
		});
		waitsFor(function() { return p2pMsgCtx; }, "p2pMsgCtx reset", MslTestConstants.TIMEOUT);
	});

	it("primary master token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.isPrimaryMasterTokenAvailable()).toBeTruthy();
			expect(tokenBuilder.isPrimaryUserIdTokenAvailable()).toBeFalsy();
			expect(tokenBuilder.isPeerMasterTokenAvailable()).toBeFalsy();
			expect(tokenBuilder.isPeerUserIdTokenAvailable()).toBeFalsy();
		});
	});
	
	it("primary master token with key exchange data", function() {
        var requestBuilder;
        runs(function() {
            messageFactory.createRequest(trustedNetCtx, null, null, null, {
                result: function(x) { requestBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
        
        var request;
        runs(function() {
            requestBuilder.setRenewable(true);
            requestBuilder.addKeyRequestData(KEY_REQUEST_DATA);
            requestBuilder.getHeader({
                result: function(x) { request = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return request; }, "request", MslTestConstants.TIMEOUT);
        
        var responseBuilder;
        runs(function() {
            messageFactory.createResponse(trustedNetCtx, request, {
                result: function(x) { responseBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
        
        runs(function() {
            var tokenBuilder = new MessageServiceTokenBuilder(trustedNetCtx, trustedNetMsgCtx, responseBuilder);
            expect(responseBuilder.getMasterToken()).toBeNull();
            expect(responseBuilder.getKeyExchangeData()).not.toBeNull();
    
            expect(tokenBuilder.isPrimaryMasterTokenAvailable()).toBeTruthy();
            expect(tokenBuilder.isPrimaryUserIdTokenAvailable()).toBeFalsy();
            expect(tokenBuilder.isPeerMasterTokenAvailable()).toBeFalsy();
            expect(tokenBuilder.isPeerUserIdTokenAvailable()).toBeFalsy();
        });
	});

	it("primary user ID token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.isPrimaryMasterTokenAvailable()).toBeTruthy();
			expect(tokenBuilder.isPrimaryUserIdTokenAvailable()).toBeTruthy();
			expect(tokenBuilder.isPeerMasterTokenAvailable()).toBeFalsy();
			expect(tokenBuilder.isPeerUserIdTokenAvailable()).toBeFalsy();
		});
	});

	it("peer master token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.isPrimaryMasterTokenAvailable()).toBeFalsy();
			expect(tokenBuilder.isPrimaryUserIdTokenAvailable()).toBeFalsy();
			expect(tokenBuilder.isPeerMasterTokenAvailable()).toBeTruthy();
			expect(tokenBuilder.isPeerUserIdTokenAvailable()).toBeFalsy();
		});
	});
	
	it("peer master token with key exchange data", function() {
	    var requestBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, null, null, null, {
                result: function(x) { requestBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
        
        var request;
        runs(function() {
            requestBuilder.setRenewable(true);
            requestBuilder.addKeyRequestData(KEY_REQUEST_DATA);
            requestBuilder.getHeader({
                result: function(x) { request = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return request; }, "request", MslTestConstants.TIMEOUT);
        
        var responseBuilder;
        runs(function() {
            messageFactory.createResponse(p2pCtx, request, {
                result: function(x) { responseBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
        
        runs(function() {
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, responseBuilder);
            expect(responseBuilder.getMasterToken()).toBeNull();
            expect(responseBuilder.getKeyExchangeData()).not.toBeNull();
            
            expect(tokenBuilder.isPrimaryMasterTokenAvailable()).toBeFalsy();
            expect(tokenBuilder.isPrimaryUserIdTokenAvailable()).toBeFalsy();
            expect(tokenBuilder.isPeerMasterTokenAvailable()).toBeFalsy();
            expect(tokenBuilder.isPeerUserIdTokenAvailable()).toBeFalsy();
        });
	});

	it("peer user ID token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.isPrimaryMasterTokenAvailable()).toBeFalsy();
			expect(tokenBuilder.isPrimaryUserIdTokenAvailable()).toBeFalsy();
			expect(tokenBuilder.isPeerMasterTokenAvailable()).toBeTruthy();
			expect(tokenBuilder.isPeerUserIdTokenAvailable()).toBeTruthy();
		});
	});

	it("get primary service tokens", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
		SERVICE_TOKENS.forEach(function(serviceToken) {
				msgBuilder.addServiceToken(serviceToken);
			}, this);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.getPrimaryServiceTokens()).toEqual(SERVICE_TOKENS);
			expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
		});
	});

	it("get peer service tokens", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			PEER_SERVICE_TOKENS.forEach(function(peerServiceToken) {
				msgBuilder.addPeerServiceToken(peerServiceToken);
			}, this);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.getPeerServiceTokens()).toEqual(PEER_SERVICE_TOKENS);
			expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
		});
	});

	it("get both service tokens", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			SERVICE_TOKENS.forEach(function(serviceToken) {
				msgBuilder.addServiceToken(serviceToken);
			}, this);
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			PEER_SERVICE_TOKENS.forEach(function(peerServiceToken) {
				msgBuilder.addPeerServiceToken(peerServiceToken);
			}, this);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.getPrimaryServiceTokens()).toEqual(SERVICE_TOKENS);
			expect(tokenBuilder.getPeerServiceTokens()).toEqual(PEER_SERVICE_TOKENS);
		});
	});
	
	it("add primary service token", function() {
	    var msgBuilder, serviceToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && serviceToken; }, "msgBuilder and serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeTruthy();
            var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
            expect(serviceTokens.length).toEqual(1);
            var builderServiceToken = serviceTokens[0];
            expect(serviceToken.equals(builderServiceToken)).toBeTruthy();
        });
	});
	
	it("add named primary service tokens", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var tokenBuilder, unboundServiceTokenA;
        runs(function() {
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, null, null, false, null, new NullCryptoContext(), {
                result: function(x) { unboundServiceTokenA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return unboundServiceTokenA; }, "unboundServiceTokenA not received", MslTestConstants.TIMEOUT);
        
        var unboundServiceTokenB;
        runs(function() {
            expect(tokenBuilder.addPrimaryServiceToken(unboundServiceTokenA)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, null, null, false, null, new NullCryptoContext(), {
                result: function(x) { unboundServiceTokenB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return unboundServiceTokenB; }, "unboundServiceTokenB not received", MslTestConstants.TIMEOUT);
        
        var masterBoundServiceTokenA;
        runs(function() {
            expect(tokenBuilder.addPrimaryServiceToken(unboundServiceTokenB)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                result: function(x) { masterBoundServiceTokenA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundServiceTokenA; }, "masterBoundServiceTokenA not received", MslTestConstants.TIMEOUT);
        
        var masterBoundServiceTokenB;
        runs(function() {
            expect(tokenBuilder.addPrimaryServiceToken(masterBoundServiceTokenA)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(2);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                result: function(x) { masterBoundServiceTokenB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundServiceTokenB; }, "masterBoundServiceTokenB not received", MslTestConstants.TIMEOUT);
        
        var userBoundServiceTokenA;
        runs(function() {
            expect(tokenBuilder.addPrimaryServiceToken(masterBoundServiceTokenB)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(2);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                result: function(x) { userBoundServiceTokenA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userBoundServiceTokenA; }, "userBoundServiceTokenA not received", MslTestConstants.TIMEOUT);
        
        var userBoundServiceTokenB;
        runs(function() {
            expect(tokenBuilder.addPrimaryServiceToken(userBoundServiceTokenA)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(3);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                result: function(x) { userBoundServiceTokenB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userBoundServiceTokenB; }, "userBoundServiceTokenB not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(tokenBuilder.addPrimaryServiceToken(userBoundServiceTokenB)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(3);
        });
	});
	
	it("add primary service token with mismatched master token", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && serviceToken; }, "msgBuilder and serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
        });
	});
	
	it("add primary service token with mismatched user ID token", function() {
	    var msgBuilder, userIdToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(p2pCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && userIdToken; }, "msgBuilder and userIdToken not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, userIdToken, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
        });
	});
	
	it("add primary service token with no master token", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, null, null, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && serviceToken; }, "msgBuilder and serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
        });
	});
	
	it("add primary service token with no user ID token", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && serviceToken; }, "msgBuilder and serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
        });
	});
	
	it("add peer service token", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && serviceToken; }, "msgBuilder and serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeTruthy();
            var serviceTokens = tokenBuilder.getPeerServiceTokens();
            expect(serviceTokens.length).toEqual(1);
            var builderServiceToken = serviceTokens[0];
            expect(serviceToken.equals(builderServiceToken)).toBeTruthy();
        });
	});
	
    it("add named peer service tokens", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var tokenBuilder, unboundServiceTokenA;
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, null, null, false, null, new NullCryptoContext(), {
                result: function(x) { unboundServiceTokenA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return unboundServiceTokenA; }, "unboundServiceTokenA not received", MslTestConstants.TIMEOUT);
        
        var unboundServiceTokenB;
        runs(function() {
            expect(tokenBuilder.addPeerServiceToken(unboundServiceTokenA)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, null, null, false, null, new NullCryptoContext(), {
                result: function(x) { unboundServiceTokenB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return unboundServiceTokenB; }, "unboundServiceTokenB not received", MslTestConstants.TIMEOUT);
        
        var masterBoundServiceTokenA;
        runs(function() {
            expect(tokenBuilder.addPeerServiceToken(unboundServiceTokenB)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                result: function(x) { masterBoundServiceTokenA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundServiceTokenA; }, "masterBoundServiceTokenA not received", MslTestConstants.TIMEOUT);
        
        var masterBoundServiceTokenB;
        runs(function() {
            expect(tokenBuilder.addPeerServiceToken(masterBoundServiceTokenA)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(2);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                result: function(x) { masterBoundServiceTokenB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterBoundServiceTokenB; }, "masterBoundServiceTokenB not received", MslTestConstants.TIMEOUT);
        
        var userBoundServiceTokenA;
        runs(function() {
            expect(tokenBuilder.addPeerServiceToken(masterBoundServiceTokenB)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(2);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                result: function(x) { userBoundServiceTokenA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userBoundServiceTokenA; }, "userBoundServiceTokenA not received", MslTestConstants.TIMEOUT);
        
        var userBoundServiceTokenB;
        runs(function() {
            expect(tokenBuilder.addPeerServiceToken(userBoundServiceTokenA)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(3);

            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                result: function(x) { userBoundServiceTokenB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userBoundServiceTokenB; }, "userBoundServiceTokenB not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(tokenBuilder.addPeerServiceToken(userBoundServiceTokenB)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(3);
        });
    });
	
	it("add peer service token with mismatched master token", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && serviceToken; }, "msgBuilder and serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
        });
    });
    
    it("add peer service token with mismatched user ID token", function() {
        var msgBuilder, userIdToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(x) { userIdToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && userIdToken; }, "msgBuilder and userIdToken not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, userIdToken, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
        });
    });
    
    it("add peer service token with no master token", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && serviceToken; }, "msgBuilder and serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
        });
    });
    
    it("add peer service token with no user ID token", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && serviceToken; }, "msgBuilder and serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
        });
    });
    
    it("add peer service token to trusted network message", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ServiceToken.create(trustedNetCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder && serviceToken; }, "msgBuilder and serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var tokenBuilder = new MessageServiceTokenBuilder(trustedNetCtx, trustedNetMsgCtx, msgBuilder);
            var f = function() {
                tokenBuilder.addPeerServiceToken(serviceToken);
            };
            expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });

	it("add unbound primary service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
			expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
		    tokenBuilder.addUnboundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeTruthy(); });
		
		runs(function() {
			var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(serviceTokens.length).toEqual(1);
			var serviceToken = serviceTokens[0];
			expect(serviceToken.name).toEqual(TOKEN_NAME);
			expect(serviceToken.data).toEqual(DATA);
			expect(serviceToken.isEncrypted()).toEqual(ENCRYPT);
			expect(serviceToken.isUnbound()).toBeTruthy();
	
			expect(msgBuilder.getServiceTokens()).toEqual(serviceTokens);
		});
	});

	it("add unbound primary service token with no crypto context", function() {
		p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
		p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);

		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addUnboundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });
		
		runs(function() {
			var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("add master bound primary service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
			expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
			tokenBuilder.addMasterBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeTruthy(); });
		
		runs(function() {
			var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(serviceTokens.length).toEqual(1);
			var serviceToken = serviceTokens[0];
			expect(serviceToken.name).toEqual(TOKEN_NAME);
			expect(serviceToken.data).toEqual(DATA);
			expect(serviceToken.isEncrypted()).toEqual(ENCRYPT);
			expect(serviceToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
	
			expect(msgBuilder.getServiceTokens()).toEqual(serviceTokens);
		});
	});

	it("add master bound primary service token with no master token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addMasterBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("add master bound primary service token with no crypto context", function() {
		p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
		p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);

		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addMasterBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("add user bound primary service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
			expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
		    tokenBuilder.addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeTruthy(); });
		
		runs(function() {
			var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(serviceTokens.length).toEqual(1);
			var serviceToken = serviceTokens[0];
			expect(serviceToken.name).toEqual(TOKEN_NAME);
			expect(serviceToken.data).toEqual(DATA);
			expect(serviceToken.isEncrypted()).toEqual(ENCRYPT);
			expect(serviceToken.isBoundTo(USER_ID_TOKEN)).toBeTruthy();

			expect(msgBuilder.getServiceTokens()).toEqual(serviceTokens);
		});
	});

	it("add user bound primary service token with no master token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("add user bound primary service token with no user ID token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("add user bound primary service token with no crypto context", function() {
		p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
		p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);

		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("exclude unbound primary service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
		var serviceToken;
		runs(function() {
		    ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, null, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
		        result: function(x) { serviceToken = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
		
		var tokenBuilder;
		runs(function() {
			msgBuilder.addServiceToken(serviceToken);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		});
		waitsFor(function() { return tokenBuilder; }, "token builder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
			expect(msgBuilder.getServiceTokens().length).toEqual(1);
			
			expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, false)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, true)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, false, false)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(msgBuilder.getServiceTokens().length).toEqual(0);
            
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

    it("exclude master bound primary service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
        
        var tokenBuilder;
        runs(function() {
            msgBuilder.addServiceToken(serviceToken);
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        });
        waitsFor(function() { return tokenBuilder; }, "token builder not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, false, false)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, true)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, false)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(msgBuilder.getServiceTokens().length).toEqual(0);
            
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(msgBuilder.getServiceTokens().length).toEqual(0);
        });
    });

    it("exclude user bound primary service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
        
        var tokenBuilder;
        runs(function() {
            msgBuilder.addServiceToken(serviceToken);
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        });
        waitsFor(function() { return tokenBuilder; }, "token builder not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, false, false)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, false)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, true)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(msgBuilder.getServiceTokens().length).toEqual(0);
            
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            expect(msgBuilder.getServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePrimaryServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(msgBuilder.getServiceTokens().length).toEqual(0);
        });
    });

	it("exclude unknown user bound primary service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);

            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, false, false)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(msgBuilder.getServiceTokens().length).toEqual(0);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, false)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(msgBuilder.getServiceTokens().length).toEqual(0);
            
            expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, true)).toBeFalsy();
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
            expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("delete unbound primary service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
		var serviceToken;
		runs(function() {
		    ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, null, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
		        result: function(x) { serviceToken = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
		
		var tokenBuilder;
		runs(function() {
			msgBuilder.addServiceToken(serviceToken);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		});
		waitsFor(function() { return tokenBuilder; }, "token builder not received", MslTestConstants.TIMEOUT);
		
		var delA;
		runs(function() {
			expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
			tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false, {
		        result: function(b) { delA = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return delA !== undefined; }, "delA not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(delA).toBeFalsy(); });
        
        var delB;
        runs(function() {
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true, {
                result: function(b) { delB = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delB !== undefined; }, "delB not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delB).toBeFalsy(); });
        
        var delC;
        runs(function() {
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false, {
                result: function(b) { delC = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delC !== undefined; }, "delC not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delC).toBeTruthy(); });
		
        var delD;
		runs(function() {
			var builderServiceTokens = tokenBuilder.getPrimaryServiceTokens();
			expect(builderServiceTokens.length).toEqual(1);
			var builderServiceToken = builderServiceTokens[0];
			expect(builderServiceToken.name).toEqual(TOKEN_NAME);
			expect(builderServiceToken.data.length).toEqual(0);
			expect(builderServiceToken.isEncrypted()).toBeFalsy();
			expect(builderServiceToken.isBoundTo(MASTER_TOKEN)).toBeFalsy();
			expect(builderServiceToken.isBoundTo(USER_ID_TOKEN)).toBeFalsy();
	
			var msgServiceTokens = msgBuilder.getServiceTokens();
			expect(msgServiceTokens.length).toEqual(1);
			var msgServiceToken = msgServiceTokens[0];
			expect(msgServiceToken.name).toEqual(TOKEN_NAME);
			expect(msgServiceToken.data.length).toEqual(0);
			expect(msgServiceToken.isEncrypted()).toBeFalsy();
			expect(msgServiceToken.isBoundTo(MASTER_TOKEN)).toBeFalsy();
			expect(msgServiceToken.isBoundTo(USER_ID_TOKEN)).toBeFalsy();
			
			expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeTruthy();
			tokenBuilder.deletePrimaryServiceToken(serviceToken, {
			    result: function(b) { delD = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delD !== undefined; }, "delD not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(delD).toBeTruthy();
            var builderServiceTokens = tokenBuilder.getPrimaryServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var msgServiceTokens = msgBuilder.getServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
        });
	});

    it("delete master bound primary service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
        
        var tokenBuilder;
        runs(function() {
            msgBuilder.addServiceToken(serviceToken);
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        });
        waitsFor(function() { return tokenBuilder; }, "token builder not received", MslTestConstants.TIMEOUT);
        
        var delA;
        runs(function() {
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false, {
                result: function(b) { delA = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delA !== undefined; }, "delA not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delA).toBeFalsy(); });
        
        var delB;
        runs(function() {
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true, {
                result: function(b) { delB = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delB !== undefined; }, "delB not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delB).toBeFalsy(); });
        
        var delC;
        runs(function() {
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false, {
                result: function(b) { delC = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delC !== undefined; }, "delC not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delC).toBeTruthy(); });
        
        var delD;
        runs(function() {
            var builderServiceTokens = tokenBuilder.getPrimaryServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var builderServiceToken = builderServiceTokens[0];
            expect(builderServiceToken.name).toEqual(TOKEN_NAME);
            expect(builderServiceToken.data.length).toEqual(0);
            expect(builderServiceToken.isEncrypted()).toBeFalsy();
            expect(builderServiceToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
            expect(builderServiceToken.isBoundTo(USER_ID_TOKEN)).toBeFalsy();
    
            var msgServiceTokens = msgBuilder.getServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
            var msgServiceToken = msgServiceTokens[0];
            expect(msgServiceToken.name).toEqual(TOKEN_NAME);
            expect(msgServiceToken.data.length).toEqual(0);
            expect(msgServiceToken.isEncrypted()).toBeFalsy();
            expect(msgServiceToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
            expect(msgServiceToken.isBoundTo(USER_ID_TOKEN)).toBeFalsy();
            
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeTruthy();
            tokenBuilder.deletePrimaryServiceToken(serviceToken, {
                result: function(b) { delD = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delD !== undefined; }, "delD not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(delD).toBeTruthy();
            var builderServiceTokens = tokenBuilder.getPrimaryServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var msgServiceTokens = msgBuilder.getServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
        });
    });

    it("delete user bound primary service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
        
        var tokenBuilder;
        runs(function() {
            msgBuilder.addServiceToken(serviceToken);
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        });
        waitsFor(function() { return tokenBuilder; }, "token builder not received", MslTestConstants.TIMEOUT);
        
        var delA;
        runs(function() {
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false, {
                result: function(b) { delA = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delA !== undefined; }, "delA not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delA).toBeFalsy(); });
        
        var delB;
        runs(function() {
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false, {
                result: function(b) { delB = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delB !== undefined; }, "delB not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delB).toBeFalsy(); });
        
        var delC;
        runs(function() {
            expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true, {
                result: function(b) { delC = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delC !== undefined; }, "delC not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delC).toBeTruthy(); });
        
        var delD;
        runs(function() {
            var builderServiceTokens = tokenBuilder.getPrimaryServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var builderServiceToken = builderServiceTokens[0];
            expect(builderServiceToken.name).toEqual(TOKEN_NAME);
            expect(builderServiceToken.data.length).toEqual(0);
            expect(builderServiceToken.isEncrypted()).toBeFalsy();
            expect(builderServiceToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
            expect(builderServiceToken.isBoundTo(USER_ID_TOKEN)).toBeTruthy();
    
            var msgServiceTokens = msgBuilder.getServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
            var msgServiceToken = msgServiceTokens[0];
            expect(msgServiceToken.name).toEqual(TOKEN_NAME);
            expect(msgServiceToken.data.length).toEqual(0);
            expect(msgServiceToken.isEncrypted()).toBeFalsy();
            expect(msgServiceToken.isBoundTo(MASTER_TOKEN)).toBeTruthy();
            expect(msgServiceToken.isBoundTo(USER_ID_TOKEN)).toBeTruthy();
            
            expect(tokenBuilder.addPrimaryServiceToken(serviceToken)).toBeTruthy();
            tokenBuilder.deletePrimaryServiceToken(serviceToken, {
                result: function(b) { delD = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delD !== undefined; }, "delD not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(delD).toBeTruthy();
            var builderServiceTokens = tokenBuilder.getPrimaryServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var msgServiceTokens = msgBuilder.getServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
        });
    });

	it("delete unknown primary service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, delA;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false, {
		        result: function(b) { delA = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && delA !== undefined; }, "tokenBuilder and delA not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(delA).toBeFalsy(); });

        var delB;
        runs(function() {
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false, {
                result: function(b) { delB = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delB !== undefined; }, "delB not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delB).toBeFalsy(); });

        var delC;
        runs(function() {
            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true, {
                result: function(b) { delC = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delC !== undefined; }, "delC not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delC).toBeFalsy(); });
	});

	it("p2p add unbound peer service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
			expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
		    tokenBuilder.addUnboundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeTruthy(); });
		
		runs(function() {
			var serviceTokens = tokenBuilder.getPeerServiceTokens();
			expect(serviceTokens.length).toEqual(1);
			var serviceToken = serviceTokens[0];
			expect(serviceToken.name).toEqual(TOKEN_NAME);
			expect(serviceToken.data).toEqual(DATA);
			expect(serviceToken.isEncrypted()).toEqual(ENCRYPT);
			expect(serviceToken.isUnbound()).toBeTruthy();
	
			expect(msgBuilder.getPeerServiceTokens()).toEqual(serviceTokens);
		});
	});

	it("trusted network add unbound peer service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(trustedNetCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		var exception;
		runs(function() {
			var tokenBuilder = new MessageServiceTokenBuilder(trustedNetCtx, trustedNetMsgCtx, msgBuilder);

			tokenBuilder.addUnboundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
				result: function() {},
				error: function(e) { exception = e; }
			});
		});
		waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException(MslError.NONE));
		});
	});

	it("add unbound peer service token with no crypto context", function() {
		p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
		p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);

		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addUnboundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPeerServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("add master bound peer service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		var tokenBuilder, add;
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
			expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
		    tokenBuilder.addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeTruthy(); });
		
		runs(function() {
			var serviceTokens = tokenBuilder.getPeerServiceTokens();
			expect(serviceTokens.length).toEqual(1);
			var serviceToken = serviceTokens[0];
			expect(serviceToken.name).toEqual(TOKEN_NAME);
			expect(serviceToken.data).toEqual(DATA);
			expect(serviceToken.isEncrypted()).toEqual(ENCRYPT);
			expect(serviceToken.isBoundTo(PEER_MASTER_TOKEN)).toBeTruthy();
	
			expect(msgBuilder.getPeerServiceTokens()).toEqual(serviceTokens);
		});
	});

	it("add master bound peer service token with no master token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPeerServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("add master bound peer service token with no crypto context", function() {
		var msgBuilder;
		runs(function() {
			p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
			p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPeerServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("trusted network add master bound peer service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(trustedNetCtx, trustedNetMsgCtx, msgBuilder);
		    tokenBuilder.addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });
	});

	it("add user bound peer service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
			expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
		    tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeTruthy(); });
		
		runs(function() {
			var serviceTokens = tokenBuilder.getPeerServiceTokens();
			expect(serviceTokens.length).toEqual(1);
			var serviceToken = serviceTokens[0];
			expect(serviceToken.name).toEqual(TOKEN_NAME);
			expect(serviceToken.data).toEqual(DATA);
			expect(serviceToken.isEncrypted()).toEqual(ENCRYPT);
			expect(serviceToken.isBoundTo(USER_ID_TOKEN)).toBeTruthy();
	
			expect(msgBuilder.getPeerServiceTokens()).toEqual(serviceTokens);
		});
	});

	it("add user bound peer service token with no master token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, null, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder && add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPeerServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("add user bound peer service token with no user ID token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPeerServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("add user bound peer service token with no crypto context", function() {
		p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
		p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);

		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });

		runs(function() {
			var serviceTokens = tokenBuilder.getPeerServiceTokens();
			expect(serviceTokens.length).toEqual(0);
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("trusted network add user bound peer service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, add;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(trustedNetCtx, trustedNetMsgCtx, msgBuilder);
		    tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO, {
		        result: function(b) { add = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && add !== undefined; }, "tokenBuilder and add not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(add).toBeFalsy(); });
	});

	it("exclude unbound peer service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
		var serviceToken;
		runs(function() {
		    msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
		    ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, null, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
		        result: function(x) { serviceToken = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			msgBuilder.addPeerServiceToken(serviceToken);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
			expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
			expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, false)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, true)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, false, false)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(0);
            
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(0);
		});
	});

    it("exclude master bound peer service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            msgBuilder.addPeerServiceToken(serviceToken);
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, false, false)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, true)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, false)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(0);
            
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(0);
        });
    });

    it("exclude user bound peer service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            msgBuilder.addPeerServiceToken(serviceToken);
            var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, false, false)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, false)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, true)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(0);
            
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(1);
            
            expect(tokenBuilder.excludePeerServiceToken(serviceToken)).toBeTruthy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(0);
        });
    });

	it("exclude unknown peer service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, false, false)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(0);
    
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, false)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(0);
    
            expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, true)).toBeFalsy();
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
            expect(msgBuilder.getPeerServiceTokens().length).toEqual(0);
		});
	});

	it("delete unbound peer service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
		var serviceToken;
		runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
		    ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, null, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
		        result: function(x) { serviceToken = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, delA;
		runs(function() {
			msgBuilder.addPeerServiceToken(serviceToken);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
			expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
		    tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, false, {
		        result: function(b) { delA = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && delA !== undefined; }, "tokenBuilder and delA not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(delA).toBeFalsy(); });

        var delB;
        runs(function() {
            tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, false, {
                result: function(b) { delB = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delB !== undefined; }, "delB not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delB).toBeFalsy(); });

        var delC;
        runs(function() {
            tokenBuilder.deletePeerServiceToken(TOKEN_NAME, false, false, {
                result: function(b) { delC = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delC !== undefined; }, "delC not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delC).toBeTruthy(); });
		
        var delD;
		runs(function() {
			var builderServiceTokens = tokenBuilder.getPeerServiceTokens();
			expect(builderServiceTokens.length).toEqual(1);
			var builderServiceToken = builderServiceTokens[0];
			expect(builderServiceToken.name).toEqual(TOKEN_NAME);
			expect(builderServiceToken.data.length).toEqual(0);
			expect(builderServiceToken.isEncrypted()).toBeFalsy();
			expect(builderServiceToken.isBoundTo(PEER_MASTER_TOKEN)).toBeFalsy();
			expect(builderServiceToken.isBoundTo(PEER_USER_ID_TOKEN)).toBeFalsy();
	
			var msgServiceTokens = msgBuilder.getPeerServiceTokens();
			expect(msgServiceTokens.length).toEqual(1);
			var msgServiceToken = msgServiceTokens[0];
			expect(msgServiceToken.name).toEqual(TOKEN_NAME);
			expect(msgServiceToken.data.length).toEqual(0);
			expect(msgServiceToken.isEncrypted()).toBeFalsy();
			expect(msgServiceToken.isBoundTo(PEER_MASTER_TOKEN)).toBeFalsy();
			expect(msgServiceToken.isBoundTo(PEER_USER_ID_TOKEN)).toBeFalsy();
            
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeTruthy();
            tokenBuilder.deletePeerServiceToken(serviceToken, {
                result: function(b) { delD = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delD !== undefined; }, "delD not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(delD).toBeTruthy();
            var builderServiceTokens = tokenBuilder.getPeerServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var msgServiceTokens = msgBuilder.getPeerServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
        });
	});

    it("delete master bound peer service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

        var tokenBuilder, delA;
        runs(function() {
            msgBuilder.addPeerServiceToken(serviceToken);
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            tokenBuilder.deletePeerServiceToken(TOKEN_NAME, false, false, {
                result: function(b) { delA = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenBuilder && delA !== undefined; }, "tokenBuilder and delA not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delA).toBeFalsy(); });

        var delB;
        runs(function() {
            tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, true, {
                result: function(b) { delB = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delB !== undefined; }, "delB not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delB).toBeFalsy(); });

        var delC;
        runs(function() {
            tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, false, {
                result: function(b) { delC = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delC !== undefined; }, "delC not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delC).toBeTruthy(); });
        
        var delD;
        runs(function() {
            var builderServiceTokens = tokenBuilder.getPeerServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var builderServiceToken = builderServiceTokens[0];
            expect(builderServiceToken.name).toEqual(TOKEN_NAME);
            expect(builderServiceToken.data.length).toEqual(0);
            expect(builderServiceToken.isEncrypted()).toBeFalsy();
            expect(builderServiceToken.isBoundTo(PEER_MASTER_TOKEN)).toBeTruthy();
            expect(builderServiceToken.isBoundTo(PEER_USER_ID_TOKEN)).toBeFalsy();
    
            var msgServiceTokens = msgBuilder.getPeerServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
            var msgServiceToken = msgServiceTokens[0];
            expect(msgServiceToken.name).toEqual(TOKEN_NAME);
            expect(msgServiceToken.data.length).toEqual(0);
            expect(msgServiceToken.isEncrypted()).toBeFalsy();
            expect(msgServiceToken.isBoundTo(PEER_MASTER_TOKEN)).toBeTruthy();
            expect(msgServiceToken.isBoundTo(PEER_USER_ID_TOKEN)).toBeFalsy();
            
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeTruthy();
            tokenBuilder.deletePeerServiceToken(serviceToken, {
                result: function(b) { delD = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delD !== undefined; }, "delD not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(delD).toBeTruthy();
            var builderServiceTokens = tokenBuilder.getPeerServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var msgServiceTokens = msgBuilder.getPeerServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
        });
    });

    it("delete user bound peer service token", function() {
        var msgBuilder;
        runs(function() {
            messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                result: function(x) { msgBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
        
        var serviceToken;
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
                result: function(x) { serviceToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

        var tokenBuilder, delA;
        runs(function() {
            msgBuilder.addPeerServiceToken(serviceToken);
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
            expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
            tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, false, {
                result: function(b) { delA = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenBuilder && delA !== undefined; }, "tokenBuilder and delA not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delA).toBeFalsy(); });

        var delB;
        runs(function() {
            tokenBuilder.deletePeerServiceToken(TOKEN_NAME, false, false, {
                result: function(b) { delB = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delB !== undefined; }, "delB not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delB).toBeFalsy(); });

        var delC;
        runs(function() {
            tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, true, {
                result: function(b) { delC = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delC !== undefined; }, "delC not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delC).toBeTruthy(); });
        
        var delD;
        runs(function() {
            var builderServiceTokens = tokenBuilder.getPeerServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var builderServiceToken = builderServiceTokens[0];
            expect(builderServiceToken.name).toEqual(TOKEN_NAME);
            expect(builderServiceToken.data.length).toEqual(0);
            expect(builderServiceToken.isEncrypted()).toBeFalsy();
            expect(builderServiceToken.isBoundTo(PEER_MASTER_TOKEN)).toBeTruthy();
            expect(builderServiceToken.isBoundTo(PEER_USER_ID_TOKEN)).toBeTruthy();
    
            var msgServiceTokens = msgBuilder.getPeerServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
            var msgServiceToken = msgServiceTokens[0];
            expect(msgServiceToken.name).toEqual(TOKEN_NAME);
            expect(msgServiceToken.data.length).toEqual(0);
            expect(msgServiceToken.isEncrypted()).toBeFalsy();
            expect(msgServiceToken.isBoundTo(PEER_MASTER_TOKEN)).toBeTruthy();
            expect(msgServiceToken.isBoundTo(PEER_USER_ID_TOKEN)).toBeTruthy();
            
            expect(tokenBuilder.addPeerServiceToken(serviceToken)).toBeTruthy();
            tokenBuilder.deletePeerServiceToken(serviceToken, {
                result: function(b) { delD = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delD !== undefined; }, "delD not received", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(delD).toBeTruthy();
            var builderServiceTokens = tokenBuilder.getPeerServiceTokens();
            expect(builderServiceTokens.length).toEqual(1);
            var msgServiceTokens = msgBuilder.getPeerServiceTokens();
            expect(msgServiceTokens.length).toEqual(1);
        });
    });

	it("delete unknown peer service token", function() {
		var msgBuilder;
		runs(function() {
		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		var tokenBuilder, delA;
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);

			tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false, {
		        result: function(b) { delA = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return delA !== undefined; }, "delA not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(delA).toBeFalsy(); });
        
        var delB;
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);

            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false, {
                result: function(b) { delB = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delB !== undefined; }, "delB not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delB).toBeFalsy(); });
        
        var delC;
        runs(function() {
            msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);

            tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true, {
                result: function(b) { delC = b; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return delC !== undefined; }, "delC not received", MslTestConstants.TIMEOUT);
        runs(function() { expect(delC).toBeFalsy(); });
	});
});
