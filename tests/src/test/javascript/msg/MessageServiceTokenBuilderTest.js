/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
    var Random = require('../../../../../core/src/main/javascript/util/Random.js');
    var EntityAuthenticationScheme = require('../../../../../core/src/main/javascript/entityauth/EntityAuthenticationScheme.js');
    var UserAuthenticationScheme = require('../../../../../core/src/main/javascript/userauth/UserAuthenticationScheme.js');
    var SymmetricWrappedExchange = require('../../../../../core/src/main/javascript/keyx/SymmetricWrappedExchange.js');
    var MessageBuilder = require('../../../../../core/src/main/javascript/msg/MessageBuilder.js');
    var MessageServiceTokenBuilder = require('../../../../../core/src/main/javascript/msg/MessageServiceTokenBuilder.js');
    var ServiceToken = require('../../../../../core/src/main/javascript/tokens/ServiceToken.js');
    var NullCryptoContext = require('../../../../../core/src/main/javascript/crypto/NullCryptoContext.js');
    var MslInternalException = require('../../../../../core/src/main/javascript/MslInternalException.js');
    var MslError = require('../../../../../core/src/main/javascript/MslError.js');

    var MslTestConstants = require('../../../main/javascript/MslTestConstants.js');
    var MockMslContext = require('../../../main/javascript/util/MockMslContext.js');
    var MockMessageContext = require('../../../main/javascript/msg/MockMessageContext.js');
    var MslTestUtils = require('../../../main/javascript/util/MslTestUtils.js');
    var MockEmailPasswordAuthenticationFactory = require('../../../main/javascript/userauth/MockEmailPasswordAuthenticationFactory.js');
    
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, null, null, null, {
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
            MessageBuilder.createRequest(trustedNetCtx, null, null, null, null, {
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
            MessageBuilder.createResponse(trustedNetCtx, request, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
            MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
            MessageBuilder.createResponse(p2pCtx, request, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
            MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
	
	it("add primary service token with mismatched master token", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
            MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
            MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
            MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, null, null, null, {
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
            MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
	
	it("add peer service token with mismatched master token", function() {
        var msgBuilder, serviceToken;
        runs(function() {
            MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
            MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
            MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
            MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
            MessageBuilder.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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

	it("exclude primary service token", function() {
		var serviceToken;
		runs(function() {
		    ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
		        result: function(x) { serviceToken = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
		
		var msgBuilder;
		runs(function() {
			MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
				result: function(x) { msgBuilder = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		var tokenBuilder;
		runs(function() {
			msgBuilder.addServiceToken(serviceToken);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		});
		waitsFor(function() { return tokenBuilder; }, "token builder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
			expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME)).toBeTruthy();
			expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(0);
			
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("exclude unknown primary service token", function() {
		var msgBuilder;
		runs(function() {
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME)).toBeFalsy();
		});
	});

	it("delete primary service token", function() {
		var serviceToken;
		runs(function() {
		    ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
		        result: function(x) { serviceToken = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

		var msgBuilder;
		runs(function() {
			MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
				result: function(x) { msgBuilder = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		var tokenBuilder;
		runs(function() {
			msgBuilder.addServiceToken(serviceToken);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		});
		waitsFor(function() { return tokenBuilder; }, "token builder not received", MslTestConstants.TIMEOUT);
		
		var del;
		runs(function() {
			expect(tokenBuilder.getPrimaryServiceTokens().length).toEqual(1);
			tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, {
		        result: function(b) { del = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return del !== undefined; }, "del not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(del).toBeTruthy(); });
		
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
		});
	});

	it("delete unknown primary service token", function() {
		var msgBuilder;
		runs(function() {
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, del;
		runs(function() {
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
		    tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, {
		        result: function(b) { del = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && del !== undefined; }, "tokenBuilder and del not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(del).toBeFalsy(); });
	});

	it("p2p add unbound peer service token", function() {
		var msgBuilder;
		runs(function() {
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(trustedNetCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, null, null, null, {
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
		    MessageBuilder.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, null, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, null, null, null, {
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
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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
		    MessageBuilder.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
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

	it("exclude peer service token", function() {
		var serviceToken;
		runs(function() {
		    ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
		        result: function(x) { serviceToken = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

		var msgBuilder;
		runs(function() {
			MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
				result: function(x) { msgBuilder = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			msgBuilder.addPeerServiceToken(serviceToken);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);

			expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
			expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME)).toBeTruthy();
			expect(tokenBuilder.getPeerServiceTokens().length).toEqual(0);
			
			expect(msgBuilder.getServiceTokens().length).toEqual(0);
		});
	});

	it("exclude unknown peer service token", function() {
		var msgBuilder;
		runs(function() {
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
	
			expect(tokenBuilder.excludePeerServiceToken(TOKEN_NAME)).toBeFalsy();
		});
	});

	it("delete peer service token", function() {
		var serviceToken;
		runs(function() {
		    ServiceToken.create(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext(), {
		        result: function(x) { serviceToken = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

		var msgBuilder;
		runs(function() {
			MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
				result: function(x) { msgBuilder = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);

		var tokenBuilder, del;
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			msgBuilder.addPeerServiceToken(serviceToken);
			tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
			expect(tokenBuilder.getPeerServiceTokens().length).toEqual(1);
		    tokenBuilder.deletePeerServiceToken(TOKEN_NAME, {
		        result: function(b) { del = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return tokenBuilder && del !== undefined; }, "tokenBuilder and del not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(del).toBeTruthy(); });
		
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
		});
	});

	it("delete unknown peer service token", function() {
		var msgBuilder;
		runs(function() {
		    MessageBuilder.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, null, {
		        result: function(x) { msgBuilder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return msgBuilder; }, "msgBuilder not received", MslTestConstants.TIMEOUT);
		
		var del;
		runs(function() {
			msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			var tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);

			tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, {
		        result: function(b) { del = b; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return del !== undefined; }, "del not received", MslTestConstants.TIMEOUT);
		runs(function() { expect(del).toBeFalsy(); });
	});
});
