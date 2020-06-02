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
 * Message builder unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MessageBuilder", function() {
    var Random = require('msl-core/util/Random.js');
    var NullCryptoContext = require('msl-core/crypto/NullCryptoContext.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var SecretKey = require('msl-core/crypto/SecretKey.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var SymmetricCryptoContext = require('msl-core/crypto/SymmetricCryptoContext.js');
    var UserAuthenticationScheme = require('msl-core/userauth/UserAuthenticationScheme.js');
    var EmailPasswordAuthenticationData = require('msl-core/userauth/EmailPasswordAuthenticationData.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    var SymmetricWrappedExchange = require('msl-core/keyx/SymmetricWrappedExchange.js');
    var Header = require('msl-core/msg/Header.js');
    var MessageHeader = require('msl-core/msg/MessageHeader.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MessageFactory = require('msl-core/msg/MessageFactory.js');
    var MessageBuilder = require('msl-core/msg/MessageBuilder.js');
    var ResopnseMessageBuilder = require('msl-core/msg/ResponseMessageBuilder.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var Arrays = require('msl-core/util/Arrays.js');
    var ServiceToken = require('msl-core/tokens/ServiceToken.js');
    var MslMessageException = require('msl-core/MslMessageException.js');
    var MslError = require('msl-core/MslError.js');
    var MslException = require('msl-core/MslException.js');
    var MasterToken = require('msl-core/tokens/MasterToken.js');
    var SessionCryptoContext = require('msl-core/crypto/SessionCryptoContext.js');
    var MslMasterTokenException = require('msl-core/MslMasterTokenException.js');
    var MslUserAuthException = require('msl-core/MslUserAuthException.js');
    var MslKeyExchangeException = require('msl-core/MslKeyExchangeException.js');
    var AsymmetricWrappedExchange = require('msl-core/keyx/AsymmetricWrappedExchange.js');
    var UserIdToken = require('msl-core/tokens/UserIdToken.js');
    var MessageCapabilities = require('msl-core/msg/MessageCapabilities.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MockEmailPasswordAuthenticationFactory = require('msl-tests/userauth/MockEmailPasswordAuthenticationFactory.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockAuthenticationUtils = require('msl-tests/util/MockAuthenticationUtils.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
    
	var SERVICE_TOKEN_NAME = "serviceTokenName";
	var USER_ID = "userid";
	var PEER_USER_ID = "peeruserid";
	var PARAMETERS_ID = "1";

    /** Message factory. */
    var messageFactory = new MessageFactory();

	/** Random. */
	var random = new Random();
    /** MSL trusted network context. */
    var trustedNetCtx;
	/** MSL peer-to-peer context. */
	var p2pCtx;
    /** MSL encoder factory. */
    var encoder;
	
	var CRYPTO_CONTEXT = new NullCryptoContext();
	
	var ALT_MSL_CRYPTO_CONTEXT;
	var USER_AUTH_DATA;

	var KEY_REQUEST_DATA;
	var PEER_KEY_REQUEST_DATA;
	
	var MASTER_TOKEN;
	var PEER_MASTER_TOKEN;
	var USER_ID_TOKEN;
	var PEER_USER_ID_TOKEN;
	var ENTITY_AUTH_DATA;
	var PEER_ENTITY_AUTH_DATA;
	
	var initialized = false;
	beforeEach(function() {
	    if (!initialized) {
	        // This may take a while to finish.
            var encryptionKey, hmacKey, wrappingKey;
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { trustedNetCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MockMslContext.create(EntityAuthenticationScheme.PSK, true, {
                    result: function(c) { p2pCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                
                var mke = new Uint8Array(16);
                var mkh = new Uint8Array(32);
                var mkw = new Uint8Array(16);
                random.nextBytes(mke);
                random.nextBytes(mkh);
                random.nextBytes(mkw);
                SecretKey.import(mke, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function (key) { encryptionKey = key; },
                    error: function (e) { expect(function() { throw e; }).not.toThrow(); }
                });
                SecretKey.import(mkh, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function (key) { hmacKey = key; },
                    error: function (e) { expect(function() { throw e; }).not.toThrow(); }
                });
                SecretKey.import(mkw, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                    result: function(key) { wrappingKey = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return trustedNetCtx && p2pCtx && encryptionKey && hmacKey && wrappingKey; }, "MSL contexts and keys", MslTestConstants.TIMEOUT_CTX);

			runs(function() {
			    encoder = trustedNetCtx.getMslEncoderFactory();
			    ALT_MSL_CRYPTO_CONTEXT = new SymmetricCryptoContext(trustedNetCtx, "clientMslCryptoContext", encryptionKey, hmacKey, wrappingKey);
			    USER_AUTH_DATA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
			    
			    KEY_REQUEST_DATA = [];
			    {
			        /* FIXME Web Crypto needs Diffie-Hellman
			        var params = trustedNetCtx.getDhParameterSpecs()[PARAMETERS_ID];
			        var xNum = random.nextInt(0x7FFFFFFF);
			        var x = new BigInteger(xNum.toString(), 10);
			        var privateKey = new PrivateKey(x);
			        var y = params.g.modPowInt(x, params.p);
			        var publicKey = new PublicKey(y);

			        KEY_REQUEST_DATA.push(new DiffieHellmanExchange.RequestData(PARAMETERS_ID, publicKey, privateKey));
			        */
			        KEY_REQUEST_DATA.push(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.SESSION));
			        KEY_REQUEST_DATA.push(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK));
			    }

			    PEER_KEY_REQUEST_DATA = [];
			    {
			        PEER_KEY_REQUEST_DATA.push(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.SESSION));
			        PEER_KEY_REQUEST_DATA.push(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.MGK));
			    }
			    
			    MslTestUtils.getMasterToken(trustedNetCtx, 1, 1, {
			        result: function(t) { MASTER_TOKEN = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getMasterToken(p2pCtx, 1, 2, {
			        result: function(t) { PEER_MASTER_TOKEN = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    
                trustedNetCtx.getEntityAuthenticationData(null, {
                    result: function(x) { ENTITY_AUTH_DATA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                p2pCtx.getEntityAuthenticationData(null, {
                    result: function(x) { PEER_ENTITY_AUTH_DATA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
			});
			waitsFor(function() { return MASTER_TOKEN && PEER_MASTER_TOKEN && ENTITY_AUTH_DATA && PEER_ENTITY_AUTH_DATA; }, "master tokens and entity authentication data", MslTestConstants.TIMEOUT);
			
			runs(function() {
			    MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
			        result: function(t) { USER_ID_TOKEN = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
			        result: function(t) { PEER_USER_ID_TOKEN = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return USER_ID_TOKEN && PEER_USER_ID_TOKEN; }, "user ID tokens", MslTestConstants.TIMEOUT);
			runs(function() { initialized = true; });
		}
	});
	
	// Shortcuts.
	var HeaderData = MessageHeader.HeaderData;
	var HeaderPeerData = MessageHeader.HeaderPeerData;
	var CompressionAlgorithm = MslConstants.CompressionAlgorithm;

	it("increment message ID", function() {
		var one = MessageBuilder.incrementMessageId(0);
		expect(one).toEqual(1);

		var zero = MessageBuilder.incrementMessageId(MslConstants.MAX_LONG_VALUE);
		expect(zero).toEqual(0);

		for (var i = 0; i < 1000; ++i) {
			var initial = -1;
			do {
				initial = random.nextLong();
			} while (initial < 0 || initial > MslConstants.MAX_LONG_VALUE);
			var next = MessageBuilder.incrementMessageId(initial);
			expect(next).toEqual((initial != MslConstants.MAX_LONG_VALUE) ? initial + 1 : 0);
		}
	});

	it("increment negative message ID", function() {
		var f = function() {
			MessageBuilder.incrementMessageId(-1);
		};
		expect(f).toThrow(new MslInternalException());
	});

	it("increment too large message ID", function() {
		var f = function() {
			MessageBuilder.incrementMessageId(MslConstants.MAX_LONG_VALUE + 2);
		};
		expect(f).toThrow(new MslInternalException());
	});

	it("decrement message ID", function() {
		var max = MessageBuilder.decrementMessageId(0);
		expect(max).toEqual(MslConstants.MAX_LONG_VALUE);

		var max_m1 = MessageBuilder.decrementMessageId(MslConstants.MAX_LONG_VALUE);
		expect(max_m1).toEqual(MslConstants.MAX_LONG_VALUE - 1);

		for (var i = 0; i < 1000; ++i) {
			var initial = -1;
			do {
				initial = random.nextLong();
			} while (initial < 0 || initial > MslConstants.MAX_LONG_VALUE);
			var next = MessageBuilder.decrementMessageId(initial);
			expect(next).toEqual((initial != 0) ? initial - 1 : MslConstants.MAX_LONG_VALUE);
		}
	});

	it("decrement negative message ID", function() {
		var f = function() {
			MessageBuilder.decrementMessageId(-1);
		};
		expect(f).toThrow(new MslInternalException());
	});

	it("decrement too large message ID", function() {
		var f = function() {
			MessageBuilder.decrementMessageId(MslConstants.MAX_LONG_VALUE + 2);
		};
		expect(f).toThrow(new MslInternalException());
	});

	/** Create request unit tests. */
	describe("createRequest", function() {
		beforeEach(function() {
			trustedNetCtx.getMslStore().clearCryptoContexts();
			trustedNetCtx.getMslStore().clearServiceTokens();
			p2pCtx.getMslStore().clearCryptoContexts();
			p2pCtx.getMslStore().clearServiceTokens();
		});

		it("create null request", function() {
			var builder;
			runs(function() {
				messageFactory.createRequest(trustedNetCtx, null, null, null, {
					result: function(b) { builder = b; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var header;
			runs(function() {
				expect(builder.willEncryptHeader()).toBeTruthy();
				expect(builder.willEncryptPayloads()).toBeTruthy();
				expect(builder.willIntegrityProtectHeader()).toBeTruthy();
				expect(builder.willIntegrityProtectPayloads()).toBeTruthy();
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(header).not.toBeNull();
	
				expect(header.nonReplayableId).toBeFalsy();
				expect(header.isRenewable()).toBeFalsy();
				expect(header.isHandshake()).toBeFalsy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
				expect(header.keyRequestData.length).toEqual(0);
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toBeNull();
				expect(header.messageId).toBeGreaterThan(0);
				expect(header.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
				expect(header.peerMasterToken).toBeNull();
				expect(header.peerServiceTokens.length).toEqual(0);
				expect(header.peerUserIdToken).toBeNull();
				expect(header.serviceTokens.length).toEqual(0);
				expect(header.userAuthenticationData).toBeNull();
				expect(header.userIdToken).toBeNull();
			});
		});

		it("p2p create null request", function() {
			var builder;
			runs(function() {
				messageFactory.createRequest(p2pCtx, null, null, null, {
					result: function(b) { builder = b; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(builder.willEncryptHeader()).toBeTruthy();
				expect(builder.willEncryptPayloads()).toBeTruthy();
                expect(builder.willIntegrityProtectHeader()).toBeTruthy();
                expect(builder.willIntegrityProtectPayloads()).toBeTruthy();
			});

			var header;
			runs(function() {
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);
			runs(function() {
				expect(header).not.toBeNull();

				expect(header.nonReplayableId).toBeFalsy();
				expect(header.isRenewable()).toBeFalsy();
				expect(header.isHandshake()).toBeFalsy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toEqual(PEER_ENTITY_AUTH_DATA);
				expect(header.keyRequestData.length).toEqual(0);
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toBeNull();
				expect(header.messageId).toBeGreaterThan(0);
				expect(header.messageCapabilities).toEqual(p2pCtx.getMessageCapabilities());
				expect(header.peerMasterToken).toBeNull();
				expect(header.peerServiceTokens.length).toEqual(0);
				expect(header.peerUserIdToken).toBeNull();
				expect(header.serviceTokens.length).toEqual(0);
				expect(header.userAuthenticationData).toBeNull();
				expect(header.userIdToken).toBeNull();
			});
		});

		it("create request", function() {
			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
			
			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);

			var header;
			runs(function() {
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					builder.addKeyRequestData(keyRequestData);
				}, this);
				serviceTokens.forEach(function(serviceToken) {
					builder.addServiceToken(serviceToken);
				}, this);
				builder.setNonReplayable(true);
				builder.setRenewable(true);
				expect(builder.willEncryptHeader()).toBeTruthy();
				expect(builder.willEncryptPayloads()).toBeTruthy();
                expect(builder.willIntegrityProtectHeader()).toBeTruthy();
                expect(builder.willIntegrityProtectPayloads()).toBeTruthy();
				expect(Arrays.containEachOther(builder.getServiceTokens(), serviceTokens)).toBeTruthy();
				expect(builder.getPeerServiceTokens().length).toEqual(0);

			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);
			runs(function() {
				expect(header).not.toBeNull();
	
				expect(header.nonReplayableId).toBeTruthy();
				expect(header.isRenewable()).toBeTruthy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toBeNull();
				expect(Arrays.containEachOther(header.keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toEqual(MASTER_TOKEN);
				expect(header.messageId).toBeGreaterThan(0);
				expect(header.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
                expect(header.nonReplayableId).not.toBeNull();
				expect(header.peerMasterToken).toBeNull();
				expect(header.peerServiceTokens.length).toEqual(0);
				expect(header.peerUserIdToken).toBeNull();
				expect(Arrays.containEachOther(header.serviceTokens, serviceTokens)).toBeTruthy();
				expect(header.userAuthenticationData).toBeNull();
				expect(header.userIdToken).toEqual(USER_ID_TOKEN);
			});
		});

		it("create request with message ID", function() {
			var messageId = 17;
			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, messageId, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

			var header;
			runs(function() {
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					builder.addKeyRequestData(keyRequestData);
				}, this);
				serviceTokens.forEach(function(serviceToken) {
					builder.addServiceToken(serviceToken);
				}, this);
				builder.setNonReplayable(true);
				builder.setRenewable(true);
				expect(builder.willEncryptHeader()).toBeTruthy();
				expect(builder.willEncryptPayloads()).toBeTruthy();
                expect(builder.willIntegrityProtectHeader()).toBeTruthy();
                expect(builder.willIntegrityProtectPayloads()).toBeTruthy(); 
				expect(Arrays.containEachOther(builder.getServiceTokens(), serviceTokens)).toBeTruthy();
				expect(builder.getPeerServiceTokens().length).toEqual(0);
				
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);
			runs(function() {
				expect(header).not.toBeNull();
	
				expect(header.isRenewable()).toBeTruthy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toBeNull();
				expect(Arrays.containEachOther(header.keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toEqual(MASTER_TOKEN);
				expect(header.messageId).toEqual(messageId);
				expect(header.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
                expect(header.nonReplayableId).not.toBeNull();
				expect(header.peerMasterToken).toBeNull();
				expect(header.peerServiceTokens.length).toEqual(0);
				expect(header.peerUserIdToken).toBeNull();
				expect(Arrays.containEachOther(header.serviceTokens, serviceTokens)).toBeTruthy();
				expect(header.userAuthenticationData).toBeNull();
				expect(header.userIdToken).toEqual(USER_ID_TOKEN);
			});
		});

		it("p2p create request", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			    	result: function(t) { peerServiceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
			
			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);

			var header;
			runs(function() {
				builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					builder.addKeyRequestData(keyRequestData);
				}, this);
				serviceTokens.forEach(function(serviceToken) {
					builder.addServiceToken(serviceToken);
				}, this);
				builder.setNonReplayable(true);
				builder.setRenewable(true);
				peerServiceTokens.forEach(function(peerServiceToken) {
					builder.addPeerServiceToken(peerServiceToken);
				}, this);
				expect(builder.willEncryptHeader()).toBeTruthy();
				expect(builder.willEncryptPayloads()).toBeTruthy();
                expect(builder.willIntegrityProtectHeader()).toBeTruthy();
                expect(builder.willIntegrityProtectPayloads()).toBeTruthy();
				expect(Arrays.containEachOther(builder.getServiceTokens(), serviceTokens)).toBeTruthy();
				expect(Arrays.containEachOther(builder.getPeerServiceTokens(), peerServiceTokens)).toBeTruthy();
				
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(header).not.toBeNull();
	
				expect(header.isRenewable()).toBeTruthy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toBeNull();
				expect(Arrays.containEachOther(header.keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toEqual(MASTER_TOKEN);
				expect(header.messageId).toBeGreaterThan(0);
				expect(header.messageCapabilities).toEqual(p2pCtx.getMessageCapabilities());
                expect(header.nonReplayableId).not.toBeNull();
				expect(header.peerMasterToken).toEqual(PEER_MASTER_TOKEN);
				expect(Arrays.containEachOther(header.peerServiceTokens, peerServiceTokens)).toBeTruthy();
				expect(header.peerUserIdToken).toEqual(PEER_USER_ID_TOKEN);
				expect(Arrays.containEachOther(header.serviceTokens, serviceTokens)).toBeTruthy();
				expect(header.userAuthenticationData).toBeNull();
				expect(header.userIdToken).toEqual(USER_ID_TOKEN);
			});
		});
		
		it("create handshake request", function() {
		    var builder;
            runs(function() {
                messageFactory.createRequest(trustedNetCtx, null, null, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
            var header;
            runs(function() {
                builder.setNonReplayable(true);
                builder.setRenewable(false);
                builder.setHandshake(true);
                expect(builder.nonReplayableId).toBeFalsy();
                expect(builder.isRenewable()).toBeTruthy();
                expect(builder.isHandshake()).toBeTruthy();
                builder.getHeader({
                    result: function(x) { header = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);

            runs(function() {
    		    expect(header).not.toBeNull();
    
    		    expect(header.isRenewable()).toBeTruthy();
    		    expect(header.isHandshake()).toBeTruthy();
    		    expect(header.cryptoContext).not.toBeNull();
                expect(header.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
                expect(header.keyRequestData.length).toEqual(0);
                expect(header.keyResponseData).toBeNull();
                expect(header.masterToken).toBeNull();
                expect(header.messageId).toBeGreaterThan(0);
                expect(header.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
                expect(header.nonReplayableId).toBeFalsy();
                expect(header.peerMasterToken).toBeNull();
                expect(header.peerServiceTokens.length).toEqual(0);
                expect(header.peerUserIdToken).toBeNull();
                expect(header.serviceTokens.length).toEqual(0);
                expect(header.userAuthenticationData).toBeNull();
                expect(header.userIdToken).toBeNull();
            });
		});
		
		it("p2p create handshake request", function() {
		    var builder;
            runs(function() {
                messageFactory.createRequest(p2pCtx, null, null, null, {
                    result: function(b) { builder = b; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);

            var header;
            runs(function() {
                builder.setNonReplayable(true);
                builder.setRenewable(false);
                builder.setHandshake(true);
                expect(builder.nonReplayableId).toBeFalsy();
                expect(builder.isRenewable()).toBeTruthy();
                expect(builder.isHandshake()).toBeTruthy();
                
                builder.getHeader({
                    result: function(x) { header = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(header).not.toBeNull();

                expect(header.isRenewable()).toBeTruthy();
                expect(header.isHandshake()).toBeTruthy();
                expect(header.cryptoContext).not.toBeNull();
                expect(header.entityAuthenticationData).toEqual(PEER_ENTITY_AUTH_DATA);
                expect(header.keyRequestData.length).toEqual(0);
                expect(header.keyResponseData).toBeNull();
                expect(header.masterToken).toBeNull();
                expect(header.messageId).toBeGreaterThan(0);
                expect(header.messageCapabilities).toEqual(p2pCtx.getMessageCapabilities());
                expect(header.nonReplayableId).toBeFalsy();
                expect(header.peerMasterToken).toBeNull();
                expect(header.peerServiceTokens.length).toEqual(0);
                expect(header.peerUserIdToken).toBeNull();
                expect(header.serviceTokens.length).toEqual(0);
                expect(header.userAuthenticationData).toBeNull();
                expect(header.userIdToken).toBeNull();
            });
		});

		it("will encrypt with RSA entity authentication data", function() {
			var rsaCtx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.RSA, false, {
			        result: function(c) { rsaCtx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return rsaCtx; }, "rsaCtx", MslTestConstants.TIMEOUT);
			
			var builder;
			runs(function() {
			    messageFactory.createRequest(rsaCtx, null, null, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(builder.willEncryptHeader()).toBeFalsy();
				expect(builder.willEncryptPayloads()).toBeFalsy();
                expect(builder.willIntegrityProtectHeader()).toBeTruthy();
                expect(builder.willIntegrityProtectPayloads()).toBeTruthy();
			});
		});
		
		it("will integrity protect with NONE entity authentication data", function() {
            var noneCtx;
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.NONE, false, {
                    result: function(c) { noneCtx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return noneCtx; }, "noneCtx", MslTestConstants.TIMEOUT);
            
            var builder;
            runs(function() {
                messageFactory.createRequest(noneCtx, null, null, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(builder.willEncryptHeader()).toBeFalsy();
                expect(builder.willEncryptPayloads()).toBeFalsy();
                expect(builder.willIntegrityProtectHeader()).toBeFalsy();
                expect(builder.willIntegrityProtectPayloads()).toBeFalsy();
            });
		});

		it("stored service tokens", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);
			
			var updatedServiceTokens;
			runs(function() {
				var store = trustedNetCtx.getMslStore();
				store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(USER_ID, USER_ID_TOKEN);
				store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

			    store.addServiceTokens(serviceTokens);
			    store.addServiceTokens(peerServiceTokens);
			    
				// The message will include all unbound service tokens.
				updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
					function(peerServiceToken) { return peerServiceToken.isUnbound(); });
			});
			waitsFor(function() { return updatedServiceTokens; }, "updated service tokens not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
				messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
					result: function(x) { builder = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var header;
			runs(function() {
				expect(Arrays.containEachOther(builder.getServiceTokens(), updatedServiceTokens)).toBeTruthy();
				expect(builder.getPeerServiceTokens().length).toEqual(0);
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);
			runs(function() {
				expect(Arrays.containEachOther(header.serviceTokens, updatedServiceTokens)).toBeTruthy();
				expect(header.peerServiceTokens.length).toEqual(0);
			});
		});

		it("p2p stored service tokens", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

			var updatedServiceTokens, updatedPeerServiceTokens;
			runs(function() {
				var store = p2pCtx.getMslStore();
				store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(USER_ID, USER_ID_TOKEN);
				store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
			    store.addServiceTokens(serviceTokens);
			    store.addServiceTokens(peerServiceTokens);

			    // The non-peer service tokens will include all unbound service
			    // tokens.
			    updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
			    		function(peerServiceToken) { return peerServiceToken.isUnbound(); });

			    // The peer service tokens will include all unbound service tokens.
			    updatedPeerServiceTokens = Arrays.combineTokens(peerServiceTokens, serviceTokens,
			    		function(serviceToken) { return serviceToken.isUnbound(); });
			});
			waitsFor(function() { return updatedServiceTokens && updatedPeerServiceTokens; }, "updated service tokens not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
				messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
					result: function(x) { builder = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);

			var header;
			runs(function() {
			    builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
			    expect(Arrays.containEachOther(builder.getServiceTokens(), updatedServiceTokens)).toBeTruthy();
			    expect(Arrays.containEachOther(builder.getPeerServiceTokens(), updatedPeerServiceTokens)).toBeTruthy();

			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(Arrays.containEachOther(header.serviceTokens, updatedServiceTokens)).toBeTruthy();
				expect(Arrays.containEachOther(header.peerServiceTokens, updatedPeerServiceTokens)).toBeTruthy();
			});
		});

		it("set user authentication data", function() {
			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var header;
			runs(function() {
				// Setting the user authentication data will replace the user ID token
				// and remove any user ID token bound service tokens.
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					builder.addKeyRequestData(keyRequestData);
				}, this);
				serviceTokens.forEach(function(serviceToken) {
					builder.addServiceToken(serviceToken);
				}, this);
				builder.setNonReplayable(true);
				builder.setRenewable(true);
				builder.setUserAuthenticationData(USER_AUTH_DATA);
				expect(Arrays.containEachOther(builder.getServiceTokens(), serviceTokens)).toBeTruthy();
				expect(builder.getPeerServiceTokens().length).toEqual(0);
			
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);

			runs(function() {
				expect(header.nonReplayableId).not.toBeNull();
				expect(header.isRenewable()).toBeTruthy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toBeNull();
				expect(Arrays.containEachOther(header.keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toEqual(MASTER_TOKEN);
				expect(header.messageId).toBeGreaterThan(0);
				expect(header.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
				expect(header.peerMasterToken).toBeNull();
				expect(header.peerServiceTokens.length).toEqual(0);
				expect(header.peerUserIdToken).toBeNull();
				expect(Arrays.containEachOther(header.serviceTokens, serviceTokens)).toBeTruthy();
				expect(header.userAuthenticationData).toEqual(USER_AUTH_DATA);
				expect(header.userIdToken).toEqual(USER_ID_TOKEN);
			});
		});

		it("set user authentication data to null", function() {
			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var header;
			runs(function() {
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					builder.addKeyRequestData(keyRequestData);
				}, this);
				serviceTokens.forEach(function(serviceToken) {
					builder.addServiceToken(serviceToken);
				}, this);
				builder.setNonReplayable(true);
				builder.setRenewable(true);
				builder.setUserAuthenticationData(null);
				expect(Arrays.containEachOther(builder.getServiceTokens(), serviceTokens)).toBeTruthy();
				expect(builder.getPeerServiceTokens().length).toEqual(0);
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);

			runs(function() {
				expect(header.nonReplayableId).not.toBeNull();
				expect(header.isRenewable()).toBeTruthy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toBeNull();
				expect(Arrays.containEachOther(header.keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toEqual(MASTER_TOKEN);
				expect(header.messageId).toBeGreaterThan(0);
				expect(header.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
				expect(header.peerMasterToken).toBeNull();
				expect(header.peerServiceTokens.length).toEqual(0);
				expect(header.peerUserIdToken).toBeNull();
				expect(Arrays.containEachOther(header.serviceTokens, serviceTokens)).toBeTruthy();
				expect(header.userAuthenticationData).toBeNull();
				expect(header.userIdToken).toEqual(USER_ID_TOKEN);
			});
		});

		it("unset user authentication data", function() {
			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
			
			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var header;
			runs(function() {
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					builder.addKeyRequestData(keyRequestData);
				}, this);
				serviceTokens.forEach(function(serviceToken) {
					builder.addServiceToken(serviceToken);
				}, this);
				builder.setNonReplayable(true);
				builder.setRenewable(true);
				builder.setUserAuthenticationData(USER_AUTH_DATA);
				builder.setUserAuthenticationData(null);
				expect(Arrays.containEachOther(builder.getServiceTokens(), serviceTokens)).toBeTruthy();
				expect(builder.getPeerServiceTokens().length).toEqual(0);
				builder.getHeader({
					result: function(x) { header = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);

			runs(function() {
				expect(header.nonReplayableId).not.toBeNull();
				expect(header.isRenewable()).toBeTruthy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toBeNull();
				expect(Arrays.containEachOther(header.keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toEqual(MASTER_TOKEN);
				expect(header.messageId).toBeGreaterThan(0);
				expect(header.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
				expect(header.peerMasterToken).toBeNull();
				expect(header.peerServiceTokens.length).toEqual(0);
				expect(header.peerUserIdToken).toBeNull();
				expect(Arrays.containEachOther(header.serviceTokens, serviceTokens)).toBeTruthy();
				expect(header.userAuthenticationData).toBeNull();
				expect(header.userIdToken).toEqual(USER_ID_TOKEN);
			});
		});

		it("overwrite key request data", function() {
			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, null, null, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var header;
			runs(function() {
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					builder.addKeyRequestData(keyRequestData);
				}, this);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					builder.addKeyRequestData(keyRequestData);
				}, this);
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);

			runs(function() {
				expect(header.nonReplayableId).toBeFalsy();
				expect(header.isRenewable()).toBeFalsy();
				expect(header.isHandshake()).toBeFalsy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
				expect(Arrays.containEachOther(header.keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toBeNull();
				expect(header.messageId).toBeGreaterThan(0);
				expect(header.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
				expect(header.peerMasterToken).toBeNull();
				expect(header.peerServiceTokens.length).toEqual(0);
				expect(header.peerUserIdToken).toBeNull();
				expect(header.serviceTokens.length).toEqual(0);
				expect(header.userAuthenticationData).toBeNull();
				expect(header.userIdToken).toBeNull();
			});
		});

		it("remove key request data", function() {
			var updatedKeyRequestData = Arrays.copyOf(KEY_REQUEST_DATA, 1, KEY_REQUEST_DATA.length - 1);

			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, null, null, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var header;
			runs(function() {
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					builder.addKeyRequestData(keyRequestData);
				}, this);
				var keyRequestData = KEY_REQUEST_DATA[0];
				builder.removeKeyRequestData(keyRequestData);
				builder.removeKeyRequestData(keyRequestData);
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);

			runs(function() {
				expect(header.nonReplayableId).toBeFalsy();
				expect(header.isRenewable()).toBeFalsy();
				expect(header.isHandshake()).toBeFalsy();
				expect(header.cryptoContext).not.toBeNull();
				expect(header.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
				expect(Arrays.containEachOther(header.keyRequestData, updatedKeyRequestData)).toBeTruthy();
				expect(header.keyResponseData).toBeNull();
				expect(header.masterToken).toBeNull();
				expect(header.messageId).toBeGreaterThan(0);
				expect(header.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
				expect(header.peerMasterToken).toBeNull();
				expect(header.peerServiceTokens.length).toEqual(0);
				expect(header.peerUserIdToken).toBeNull();
				expect(header.serviceTokens.length).toEqual(0);
				expect(header.userAuthenticationData).toBeNull();
				expect(header.userIdToken).toBeNull();
			});
		});
		
		it("non-replayable with null master token", function() {
		    var builder;
            runs(function() {
                messageFactory.createRequest(trustedNetCtx, null, null, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
                builder.setNonReplayable(true);
                builder.getHeader({
                    result: function(x) {},
                    error: function(e) { exception = e; },
                });
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() { throw exception; };
                expect(f).toThrow(new MslMessageException(MslError.NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN));
            });
		});

		it("add service token with mismatched master token", function() {
			var serviceToken;
			runs(function() {
				var data = new Uint8Array(1);
				random.nextBytes(data);
				ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
					result: function(token) { serviceToken = token; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return serviceToken; }, "service token not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.addServiceToken(serviceToken);
				};
				expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH));
			});
		});

		it("add service token with null master token", function() {
			var serviceToken;
			runs(function() {
				var data = new Uint8Array(1);
				random.nextBytes(data);
				ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
					result: function(x) { serviceToken = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, null, null, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.addServiceToken(serviceToken);
				};
				expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH));
			});
		});

		it("add service token with mismatched user ID token", function() {
			var userIdTokenA, userIdTokenB;
			runs(function() {
				MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
					result: function(t) { userIdTokenA = t; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
					result: function(t) { userIdTokenB = t; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return userIdTokenB; }, "userIdTokenB not received", MslTestConstants.TIMEOUT);
			
			var serviceToken;
			runs(function() {
				var data = new Uint8Array(1);
				random.nextBytes(data);
				ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, userIdTokenB, false, null, new NullCryptoContext(), {
					result: function(x) { serviceToken = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, userIdTokenA, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.addServiceToken(serviceToken);
				};
				expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH));
			});
		});

		it("add service token with null user ID token", function() {
			var serviceToken;
			runs(function() {
				var data = new Uint8Array(1);
				random.nextBytes(data);
			    ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
				    result: function(x) { serviceToken = x; },
				    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
			
            var builder;
            runs(function() {
                messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var f = function() {
                    builder.addServiceToken(serviceToken);
                };
                expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH));
            });
		});

		it("add named service tokens", function() {
		    var builder;
            runs(function() {
                messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
		    var data = new Uint8Array(1);
		    random.nextBytes(data);
		    
		    var unboundServiceTokenA;
            runs(function() {
                ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, null, null, false, null, new NullCryptoContext(), {
                    result: function(x) { unboundServiceTokenA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unboundServiceTokenA; }, "unboundServiceTokenA not received", MslTestConstants.TIMEOUT);

            var unboundServiceTokenB;
            runs(function() {
                builder.addServiceToken(unboundServiceTokenA);
                expect(builder.getServiceTokens().length).toEqual(1);
                
                ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, null, null, false, null, new NullCryptoContext(), {
                    result: function(x) { unboundServiceTokenB = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unboundServiceTokenB; }, "unboundServiceTokenB not received", MslTestConstants.TIMEOUT);

            var masterBoundServiceTokenA;
            runs(function() {
                builder.addServiceToken(unboundServiceTokenB);
                expect(builder.getServiceTokens().length).toEqual(1);
                
                ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                    result: function(x) { masterBoundServiceTokenA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterBoundServiceTokenA; }, "masterBoundServiceTokenA not received", MslTestConstants.TIMEOUT);

            var masterBoundServiceTokenB;
            runs(function() {
                builder.addServiceToken(masterBoundServiceTokenA);
                expect(builder.getServiceTokens().length).toEqual(2);
                
                ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                    result: function(x) { masterBoundServiceTokenB = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterBoundServiceTokenB; }, "masterBoundServiceTokenB not received", MslTestConstants.TIMEOUT);

            var userBoundServiceTokenA;
            runs(function() {
                builder.addServiceToken(masterBoundServiceTokenB);
                expect(builder.getServiceTokens().length).toEqual(2);
                
                ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                    result: function(x) { userBoundServiceTokenA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return userBoundServiceTokenA; }, "userBoundServiceTokenA not received", MslTestConstants.TIMEOUT);

            var userBoundServiceTokenB;
            runs(function() {
                builder.addServiceToken(userBoundServiceTokenA);
                expect(builder.getServiceTokens().length).toEqual(3);
                
                ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                    result: function(x) { userBoundServiceTokenB = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return userBoundServiceTokenB; }, "userBoundServiceTokenB not received", MslTestConstants.TIMEOUT);

            runs(function() {
                builder.addServiceToken(userBoundServiceTokenB);
                expect(builder.getServiceTokens().length).toEqual(3);
            });
		});

		it("exclude service token", function() {
			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			// This may take a while to finish.
			var count = 0, expected = -1;
			runs(function() {
				serviceTokens.forEach(function(serviceToken) {
					builder.addServiceToken(serviceToken);
				}, this);
	
				expected = serviceTokens.length;
				function next() {
				    if (serviceTokens.length == 0)
				        return;
				    var token = serviceTokens[0];
				    builder.excludeServiceToken(token.name, token.isMasterTokenBound(), token.isUserIdTokenBound());
				    serviceTokens.splice(0, 1);
                    builder.getHeader({
                        result: function(messageHeader) {
                            expect(Arrays.containEachOther(messageHeader.serviceTokens, serviceTokens)).toBeTruthy();
                            ++count;
                            next();
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
				}
				next();
			});
			waitsFor(function() { return count == expected; }, "service tokens to be processed", 1000);
		});

        it("exclude service token using alternate parameters", function() {
            var serviceTokens;
            runs(function() {
                MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
                    result: function(t) { serviceTokens = t; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

            var builder;
            runs(function() {
                messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
            // This may take a while to finish.
            var count = 0, expected = -1;
            runs(function() {
                serviceTokens.forEach(function(serviceToken) {
                    builder.addServiceToken(serviceToken);
                }, this);
    
                expected = serviceTokens.length;
                function next() {
                    if (serviceTokens.length == 0)
                        return;
                    var token = serviceTokens[0];
                    builder.excludeServiceToken(token);
                    serviceTokens.splice(0, 1);
                    builder.getHeader({
                        result: function(messageHeader) {
                            expect(Arrays.containEachOther(messageHeader.serviceTokens, serviceTokens)).toBeTruthy();
                            ++count;
                            next();
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                }
                next();
            });
            waitsFor(function() { return count == expected; }, "service tokens to be processed", 1000);
        });

		it("delete service token", function() {
			// The service token must exist before it can be deleted.
			var serviceToken;
			runs(function() {
				var data = new Uint8Array(1);
				random.nextBytes(data);
			    ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
			        result: function(x) { serviceToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var deleted = false;
			runs(function() {
				builder.addServiceToken(serviceToken);
	
				// Delete the service token.
				builder.deleteServiceToken(SERVICE_TOKEN_NAME, true, true, {
					result: function(x) { deleted = (x === builder); },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return deleted; }, "service token to be deleted", MslTestConstants.TIMEOUT);

			var messageHeader;
			runs(function() {
			    builder.getHeader({
			        result: function(x) { messageHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var tokens = messageHeader.serviceTokens;
				for (var i = 0; i < tokens.length; ++i) {
					var token = tokens[i];
					if (token.name == SERVICE_TOKEN_NAME) {
						expect(token.data.length).toEqual(0);
						return;
					}
				}
				throw new Error("Deleted service token not found.");
			});
		});

        it("delete service token using alternate parameters", function() {
            // The service token must exist before it can be deleted.
            var serviceToken;
            runs(function() {
                var data = new Uint8Array(1);
                random.nextBytes(data);
                ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                    result: function(x) { serviceToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);

            var builder;
            runs(function() {
                messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
            var deleted = false;
            runs(function() {
                builder.addServiceToken(serviceToken);
    
                // Delete the service token.
                builder.deleteServiceToken(serviceToken, {
                    result: function(x) { deleted = (x === builder); },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return deleted; }, "service token to be deleted", MslTestConstants.TIMEOUT);

            var messageHeader;
            runs(function() {
                builder.getHeader({
                    result: function(x) { messageHeader = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var tokens = messageHeader.serviceTokens;
                for (var i = 0; i < tokens.length; ++i) {
                    var token = tokens[i];
                    if (token.name == SERVICE_TOKEN_NAME) {
                        expect(token.data.length).toEqual(0);
                        return;
                    }
                }
                throw new Error("Deleted service token not found.");
            });
        });

		it("delete unknown service token", function() {
			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var deleted = false;
			runs(function() {
				builder.deleteServiceToken(SERVICE_TOKEN_NAME, true, true, {
					result: function(x) { deleted = (x === builder); },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return deleted; }, "service token to be deleted", MslTestConstants.TIMEOUT);
			
			var messageHeader;
			runs(function() {
			    builder.getHeader({
			        result: function(x) { messageHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var tokens = messageHeader.serviceTokens;
				for (var i = 0; i < tokens.length; ++i) {
				    var token = tokens[i];
					if (token.name == SERVICE_TOKEN_NAME) {
					    expect(token.data.length).toEqual(0);
					    return;
					}
				}
                throw new Error("Deleted unknown service token.");
			});
		});

		it("trusted network create peer request", function() {
			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
				};
				expect(f).toThrow(new MslInternalException(MslError.NONE));
			});
		});

		it("p2p create peer request with missing peer master token", function() {
			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.setPeerAuthTokens(null, PEER_USER_ID_TOKEN);
				};
				expect(f).toThrow(new MslInternalException(MslError.NONE));
			});
		});

		it("p2p create peer request with mismatched peer master token", function() {
			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.setPeerAuthTokens(MASTER_TOKEN, PEER_USER_ID_TOKEN);
				};
				expect(f).toThrow(new MslException(MslError.NONE));
			});
		});

		it("trusted network add peer service token", function() {
			var peerServiceToken;
			runs(function() {
				ServiceToken.create(trustedNetCtx, SERVICE_TOKEN_NAME, new Uint8Array(0), null, null, false, null, new NullCryptoContext(), {
					result: function(x) { peerServiceToken = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return peerServiceToken; }, "peerServiceToken not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.addPeerServiceToken(peerServiceToken);
				};
				expect(f).toThrow(new MslInternalException(MslError.NONE));
			});
		});

		it("p2p add peer service token with missing peer master token", function() {
			var peerServiceToken;
			runs(function() {
				ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, new Uint8Array(0), PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
					result: function(x) { peerServiceToken = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return peerServiceToken; }, "peerServiceToken not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.addPeerServiceToken(peerServiceToken);
				};
				expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH));
			});
		});

		it("add peer service token with mismatched peer master token", function() {
			var peerServiceToken;
			runs(function() {
			    ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, new Uint8Array(0), MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
			        result: function(x) { peerServiceToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return peerServiceToken; }, "peerServiceToken not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
					builder.addPeerServiceToken(peerServiceToken);
				};
				expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH));
			});
		});

		it("add peer service token with missing peer user ID token", function() {
			var peerServiceToken;
			runs(function() {
			    ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, new Uint8Array(0), PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext(), {
			        result: function(x) { peerServiceToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return peerServiceToken; }, "peerServiceToken not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
					builder.addPeerServiceToken(peerServiceToken);
				};
				expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH));
			});
		});

		it("add peer service token with mismatched peer user ID token", function() {
			var userIdTokenA, userIdTokenB;
			runs(function() {
			    MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
			        result: function(t) { userIdTokenA = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
			        result: function(t) { userIdTokenB = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);
			
			var peerServiceToken;
			runs(function() {
			    ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, new Uint8Array(0), PEER_MASTER_TOKEN, userIdTokenB, false, null, new NullCryptoContext(), {
			        result: function(x) { peerServiceToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return peerServiceToken; }, "peerServiceToken not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.setPeerAuthTokens(PEER_MASTER_TOKEN, userIdTokenA);
					builder.addPeerServiceToken(peerServiceToken);
				};
				expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH));
			});
		});
		
		it("add named peer service tokens", function() {
            var builder;
            runs(function() {
                messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
            var data, unboundServiceTokenA;
            runs(function() {
                builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
                data = new Uint8Array(1);
                random.nextBytes(data);
                
                ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, data, null, null, false, null, new NullCryptoContext(), {
                    result: function(x) { unboundServiceTokenA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unboundServiceTokenA; }, "unboundServiceTokenA not received", MslTestConstants.TIMEOUT);

            var unboundServiceTokenB;
            runs(function() {
                builder.addPeerServiceToken(unboundServiceTokenA);
                expect(builder.getPeerServiceTokens().length).toEqual(1);
                
                ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, data, null, null, false, null, new NullCryptoContext(), {
                    result: function(x) { unboundServiceTokenB = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return unboundServiceTokenB; }, "unboundServiceTokenB not received", MslTestConstants.TIMEOUT);

            var masterBoundServiceTokenA;
            runs(function() {
                builder.addPeerServiceToken(unboundServiceTokenB);
                expect(builder.getPeerServiceTokens().length).toEqual(1);
                
                ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                    result: function(x) { masterBoundServiceTokenA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterBoundServiceTokenA; }, "masterBoundServiceTokenA not received", MslTestConstants.TIMEOUT);

            var masterBoundServiceTokenB;
            runs(function() {
                builder.addPeerServiceToken(masterBoundServiceTokenA);
                expect(builder.getPeerServiceTokens().length).toEqual(2);
                
                ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext(), {
                    result: function(x) { masterBoundServiceTokenB = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return masterBoundServiceTokenB; }, "masterBoundServiceTokenB not received", MslTestConstants.TIMEOUT);

            var userBoundServiceTokenA;
            runs(function() {
                builder.addPeerServiceToken(masterBoundServiceTokenB);
                expect(builder.getPeerServiceTokens().length).toEqual(2);
                
                ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                    result: function(x) { userBoundServiceTokenA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return userBoundServiceTokenA; }, "userBoundServiceTokenA not received", MslTestConstants.TIMEOUT);

            var userBoundServiceTokenB;
            runs(function() {
                builder.addPeerServiceToken(userBoundServiceTokenA);
                expect(builder.getPeerServiceTokens().length).toEqual(3);
                
                ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext(), {
                    result: function(x) { userBoundServiceTokenB = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return userBoundServiceTokenB; }, "userBoundServiceTokenB not received", MslTestConstants.TIMEOUT);

            runs(function() {
                builder.addPeerServiceToken(userBoundServiceTokenB);
                expect(builder.getPeerServiceTokens().length).toEqual(3);
            });
        });

		it("exclude peer service token", function() {
			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
			
			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			// This may take a while to finish.
			var count = 0, expected = -1;
			runs(function() {
				builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
				serviceTokens.forEach(function(serviceToken) {
					builder.addPeerServiceToken(serviceToken);
				}, this);
				
                expected = serviceTokens.length;
                function next() {
                    if (serviceTokens.length == 0)
                        return;
                    var token = serviceTokens[0];
                    builder.excludePeerServiceToken(token.name, token.isMasterTokenBound(), token.isUserIdTokenBound());
                    serviceTokens.splice(0, 1);
                    expect(Arrays.containEachOther(builder.getPeerServiceTokens(), serviceTokens)).toBeTruthy();
                    builder.getHeader({
                        result: function(messageHeader) {
                            expect(Arrays.containEachOther(messageHeader.peerServiceTokens, serviceTokens)).toBeTruthy();
                            ++count;
                            next();
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                }
                next();
			});
			waitsFor(function() { return count == expected; }, "service tokens to be processed", 1000);
		});

		it("delete peer service token", function() {
			// The service token must exist before it can be deleted.
			var serviceToken;
			runs(function() {
				var data = new Uint8Array(1);
				random.nextBytes(data);
			    ServiceToken.create(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext(), {
			        result: function(x) { serviceToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceToken; }, "serviceToken not received", MslTestConstants.TIMEOUT);
			
			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var deleted = false;
			runs(function() {
				builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
				builder.addPeerServiceToken(serviceToken);
	
				// Delete the service token.
				builder.deletePeerServiceToken(SERVICE_TOKEN_NAME, true, true, {
					result: function(x) { deleted = (x === builder); },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return deleted; }, "deleted service token", MslTestConstants.TIMEOUT);
			
			var messageHeader;
			runs(function() {
			    builder.getHeader({
			        result: function(x) { messageHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var tokens = messageHeader.peerServiceTokens;
				for (var i = 0; i < tokens.length; ++i) {
					var token = tokens[i];
					if (token.name == SERVICE_TOKEN_NAME) {
						expect(token.data.length).toEqual(0);
						return;
					}
				}
				throw new Error("Deleted peer service token not found.");
			});
		});

		it("delete unknown peer service token", function() {
			var builder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);

			var deleted = false;
			runs(function() {
				builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	
				// Delete the service token.
				builder.deletePeerServiceToken(SERVICE_TOKEN_NAME, true, true, {
					result: function(x) { deleted = (x === builder); },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return deleted; }, "deleted service token", MslTestConstants.TIMEOUT);
			
			var messageHeader;
			runs(function() {
			    builder.getHeader({
			        result: function(x) { messageHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var tokens = messageHeader.peerServiceTokens;
				for (var i = 0; i < tokens.length; ++i) {
				    var token = tokens[i];
					if (token.name == SERVICE_TOKEN_NAME) {
					    expect(token.data.length).toEqual(0);
					    return;
					}
				}
                throw new Error("Deleted unknown service token.");
			});
		});

		it("set master token", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
				var store = trustedNetCtx.getMslStore();
				store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
				store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
				store.addServiceTokens(serviceTokens);
				store.addServiceTokens(peerServiceTokens);

				messageFactory.createRequest(trustedNetCtx, null, null, null, {
					result: function(x) { builder = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			var messageHeader, updatedServiceTokens;
			runs(function() {
				builder.setAuthTokens(MASTER_TOKEN, null);

				// The message service tokens will include all unbound service
				// tokens.
				updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
					function(peerServiceToken) { return peerServiceToken.isUnbound(); });

				expect(Arrays.containEachOther(builder.getServiceTokens(), updatedServiceTokens)).toBeTruthy();
				expect(builder.getPeerServiceTokens().length).toEqual(0);
			
				builder.getHeader({
			        result: function(x) { messageHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return messageHeader && updatedServiceTokens; }, "message header and updated service tokens not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(Arrays.containEachOther(messageHeader.serviceTokens, updatedServiceTokens)).toBeTruthy();
				expect(messageHeader.peerServiceTokens.length).toEqual(0);
			});
		});

		it("set master token with existing master token", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

		    var builder;
		    runs(function() {
		    	var store = trustedNetCtx.getMslStore();
		    	store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
		    	store.addUserIdToken(USER_ID, USER_ID_TOKEN);
		    	store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
		    	store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
		    	store.addServiceTokens(serviceTokens);
		    	store.addServiceTokens(peerServiceTokens);

		    	messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, {
		    		result: function(x) { builder = x; },
		    		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    	});
		    });
		    waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
		    
		    var messageHeader, updatedServiceTokens;
		    runs(function() {
			    builder.setAuthTokens(MASTER_TOKEN, null);

			    // The message service tokens will include all unbound service
			    // tokens.
			    updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
			    	function(peerServiceToken) { return peerServiceToken.isUnbound(); });

			    expect(Arrays.containEachOther(builder.getServiceTokens(), updatedServiceTokens)).toBeTruthy();
			    expect(builder.getPeerServiceTokens().length).toEqual(0);
			    
			    builder.getHeader({
			        result: function(x) { messageHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return messageHeader && updatedServiceTokens; }, "message header and updated service tokens not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(Arrays.containEachOther(messageHeader.serviceTokens, updatedServiceTokens)).toBeTruthy();
				expect(messageHeader.peerServiceTokens.length).toEqual(0);
			});
		});

		it("set authentication tokens", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

			var builder;
			runs(function() {
				var store = trustedNetCtx.getMslStore();
				store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(USER_ID, USER_ID_TOKEN);
				store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
			    store.addServiceTokens(serviceTokens);
			    store.addServiceTokens(peerServiceTokens);

			    messageFactory.createRequest(trustedNetCtx, null, null, null, {
			    	result: function(x) { builder = x; },
			    	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var messageHeader, updatedServiceTokens;
			runs(function() {
				builder.setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);

				// The message service tokens will include all unbound service
				// tokens.
				updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
					function(peerServiceToken) { return peerServiceToken.isUnbound(); });

				expect(Arrays.containEachOther(builder.getServiceTokens(), updatedServiceTokens)).toBeTruthy();
				expect(builder.getPeerServiceTokens().length).toEqual(0);
			
			    builder.getHeader({
			        result: function(x) { messageHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return messageHeader && updatedServiceTokens; }, "message header and updated service tokens not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(Arrays.containEachOther(messageHeader.serviceTokens, updatedServiceTokens)).toBeTruthy();
				expect(messageHeader.peerServiceTokens.length).toEqual(0);
			});
		});
		
        it("set existing authentication tokens", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);
			
			var builder;
			runs(function() {
				var store = trustedNetCtx.getMslStore();
				store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(USER_ID, USER_ID_TOKEN);
				store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
				store.addServiceTokens(serviceTokens);
				store.addServiceTokens(peerServiceTokens);

				messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, {
					result: function(x) { builder = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);

			var messageHeader, updatedServiceTokens;
			runs(function() {
				builder.setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);

				// The message service tokens will include all unbound service
				// tokens.
				updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
					function(peerServiceToken) { return peerServiceToken.isUnbound(); });
				expect(Arrays.containEachOther(builder.getServiceTokens(), updatedServiceTokens)).toBeTruthy();
				expect(builder.getPeerServiceTokens().length).toEqual(0);
			
			    builder.getHeader({
			        result: function(x) { messageHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return messageHeader && updatedServiceTokens; }, "message header and updated service tokens not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(Arrays.containEachOther(messageHeader.serviceTokens, updatedServiceTokens)).toBeTruthy();
				expect(messageHeader.peerServiceTokens.length).toEqual(0);
			});
        });

		it("set null master token", function() {
			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, null, null, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			var header;
			runs(function() {
				builder.setAuthTokens(null, null);
				
			    builder.getHeader({
			        result: function(x) { header = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return header; }, "header not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(header).not.toBeNull();
	
				expect(header.masterToken).toBeNull();
				expect(header.userIdToken).toBeNull();
			});
		});

		it("set mismatched authentication tokens", function() {
			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, null, null, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() {
					builder.setAuthTokens(MASTER_TOKEN, PEER_USER_ID_TOKEN);
				};
				expect(f).toThrow(new MslInternalException());
			});
		});
		
		it("set user", function() {
			var builder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, {
			        result: function(x) { builder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
			var complete = false;
			runs(function() {
				builder.setUser(USER_ID_TOKEN.user, {
					result: function(success) { complete = success; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return complete; }, "set user", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var userIdToken = builder.getUserIdToken();
				expect(userIdToken).not.toBeNull();
				expect(userIdToken.user).toEqual(USER_ID_TOKEN.user);
			});
        });
        
        it("set user with no master token", function() {
            var builder;
            runs(function() {
                messageFactory.createRequest(trustedNetCtx, null, null, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
            
        	var exception;
        	runs(function() {
	            builder.setUser(USER_ID_TOKEN.user, {
	            	result: function() {},
	            	error: function(e) { exception = e; }
	            });
        	});
        	waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        	
	        runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslInternalException());
            });
        });
        
        it("set user with existing user ID token", function() {
    		var builder;
    		runs(function() {
    		    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
    		        result: function(x) { builder = x; },
    		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		    });
    		});
    		waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
    		
        	var exception;
        	runs(function() {
        		builder.setUser(USER_ID_TOKEN.user, {
        			result: function() {},
        			error: function(e) { exception = e; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslInternalException());
        	});
        });
        
        it("p2p set user", function() {
            var builder;
            runs(function() {
                messageFactory.createRequest(p2pCtx, null, null, null, {
                    result: function(x) { builder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);

			var complete = false;
			runs(function() {
				builder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
				builder.setUser(PEER_USER_ID_TOKEN.user, {
					result: function(success) { complete = success; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return complete; }, "set user", MslTestConstants.TIMEOUT);

			runs(function() {
				var userIdToken = builder.getPeerUserIdToken();
				expect(userIdToken).not.toBeNull();
				expect(userIdToken.user).toEqual(PEER_USER_ID_TOKEN.user);
			});
        });
        
        it("p2p set user with no peer master token", function() {
    		var builder;
    		runs(function() {
    		    messageFactory.createRequest(p2pCtx, null, null, null, {
    		        result: function(x) { builder = x; },
    		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		    });
    		});
    		waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
    		
        	var exception;
        	runs(function() {
        		builder.setUser(PEER_USER_ID_TOKEN.user, {
        			result: function() {},
        			error: function(e) { exception = e; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        	
            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslInternalException());
            });
        });
        
        it("p2p set user with existing peer user ID token", function() {
    		var builder;
    		runs(function() {
    		    messageFactory.createRequest(p2pCtx, null, null, null, {
    		        result: function(x) { builder = x; },
    		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		    });
    		});
    		waitsFor(function() { return builder; }, "builder not received", MslTestConstants.TIMEOUT);
    		
        	var exception;
        	runs(function() {
        		builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        		builder.setUser(USER_ID_TOKEN.user, {
        			result: function() {},
        			error: function(e) { exception = e; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslInternalException());
        	});
        });

		it("negative message ID", function() {
			var exception;
			runs(function() {
				messageFactory.createRequest(trustedNetCtx, null, null, -1, {
					result: function() {},
					error: function(e) { exception = e; }
				});
			});
			waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() { throw exception; };
				expect(f).toThrow(new MslInternalException());
			});
		});

		it("too large message ID", function() {
			var exception;
			runs(function() {
				messageFactory.createRequest(trustedNetCtx, null, null, MslConstants.MAX_LONG_VALUE + 2, {
					result: function() {},
					error: function(e) { exception = e; }
				});
			});
			waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() { throw exception; };
				expect(f).toThrow(new MslInternalException());
			});
		});
	});

	/** Create error unit tests. */
	describe("createError", function() {
		var REQUEST_MESSAGE_ID = 17;
		var MSL_ERROR = MslError.MSL_PARSE_ERROR;
		var USER_MESSAGE = "user message";

		it("ctor", function() {
			var errorHeader;
			runs(function() {
			    messageFactory.createErrorResponse(trustedNetCtx, REQUEST_MESSAGE_ID, MSL_ERROR, USER_MESSAGE, {
			        result: function(x) { errorHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return errorHeader; }, "errorHeader not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(errorHeader).not.toBeNull();
				expect(errorHeader.errorCode).toEqual(MSL_ERROR.responseCode);
				expect(errorHeader.errorMessage).toEqual(MSL_ERROR.message);
				expect(errorHeader.userMessage).toEqual(USER_MESSAGE);
				expect(errorHeader.messageId).toEqual(REQUEST_MESSAGE_ID + 1);
			});
		});

		it("max message ID", function() {
			var messageId = MslConstants.MAX_LONG_VALUE;
			var errorHeader;
			runs(function() {
			    messageFactory.createErrorResponse(trustedNetCtx, messageId, MSL_ERROR, USER_MESSAGE, {
			        result: function(x) { errorHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return errorHeader; }, "errorHeader not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(errorHeader).not.toBeNull();
				expect(errorHeader.errorCode).toEqual(MSL_ERROR.responseCode);
				expect(errorHeader.errorMessage).toEqual(MSL_ERROR.message);
				expect(errorHeader.userMessage).toEqual(USER_MESSAGE);
				expect(errorHeader.messageId).toEqual(0);
			});
		});

		it("null message ID", function() {
			var errorHeader;
			runs(function() {
			    messageFactory.createErrorResponse(trustedNetCtx, null, MSL_ERROR, USER_MESSAGE, {
			        result: function(x) { errorHeader = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return errorHeader; }, "errorHeader not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(errorHeader).not.toBeNull();
				expect(errorHeader.errorCode).toEqual(MSL_ERROR.responseCode);
				expect(errorHeader.errorMessage).toEqual(MSL_ERROR.message);
				expect(errorHeader.userMessage).toEqual(USER_MESSAGE);
				expect(errorHeader.messageId > 0).toBeTruthy();
			});
		});

		it("negative message ID", function() {
			var exception;
			runs(function() {
				var messageId = -12;
				messageFactory.createErrorResponse(trustedNetCtx, messageId, MSL_ERROR, USER_MESSAGE, {
					result: function() {},
					error: function(err) { exception = err; }
				});
			});
			waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);

			runs(function() {
				var f = function() { throw exception; };
				expect(f).toThrow(new MslInternalException(MslError.NONE));
			});
		});
		
		it("null user message", function() {
            var errorHeader;
            runs(function() {
                messageFactory.createErrorResponse(trustedNetCtx, REQUEST_MESSAGE_ID, MSL_ERROR, null, {
                    result: function(x) { errorHeader = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return errorHeader; }, "errorHeader not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(errorHeader).not.toBeNull();
                expect(errorHeader.errorCode).toEqual(MSL_ERROR.responseCode);
                expect(errorHeader.errorMessage).toEqual(MSL_ERROR.message);
                expect(errorHeader.userMessage).toBeNull();
                expect(errorHeader.messageId).toEqual(REQUEST_MESSAGE_ID + 1);
            });
		});
	});

	/** Create response unit tests. */
	describe("createResponse", function() {
		var REQUEST_MESSAGE_ID = 17;

		var KEY_PAIR_ID = "rsaKeyPairId";
		var RSA_PUBLIC_KEY;
		var RSA_PRIVATE_KEY;
		var CRYPTO_CONTEXTS = {};

		var ISSUER_DATA;
		var USER = MockEmailPasswordAuthenticationFactory.USER;
        
        /**
         * @param {number} value the value to increment.
         * @return {number} the value + 1, wrapped back to zero on overflow.
         */
        function incrementLong(value) {
            if (value == MslConstants.MAX_LONG_VALUE) return 0;
            return value + 1;
        }

        var initialized = false;
        beforeEach(function() {
            trustedNetCtx.getMslStore().clearCryptoContexts();
            trustedNetCtx.getMslStore().clearServiceTokens();
            p2pCtx.getMslStore().clearCryptoContexts();
            p2pCtx.getMslStore().clearServiceTokens();
            
		    if (!initialized) {
		        runs(function() {
		        	ISSUER_DATA = encoder.parseObject(TextEncoding.getBytes("{ \"issuerid\" : 17 }"));
		        	
		            MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSA_OAEP, WebCryptoUsage.WRAP_UNWRAP, 2048, {
		                result: function(publicKey, privateKey) {
		                    RSA_PUBLIC_KEY = publicKey;
		                    RSA_PRIVATE_KEY = privateKey;
		                },
		                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		            });
		        });
		        waitsFor(function() { return RSA_PUBLIC_KEY && RSA_PRIVATE_KEY; }, "RSA keys", 1200);
		        runs(function() { initialized = true; });
		    }
		});

		it("create null response", function() {
			// This will not exercise any of the complex logic, so no key
			// request data, entity auth data, or user auth data. Just tokens.
			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				serviceTokens.forEach(function(serviceToken) {
					requestBuilder.addServiceToken(serviceToken);
				}, this);
				
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			runs(function() {
				expect(responseBuilder.willEncryptHeader()).toBeTruthy();
				expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
				expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), serviceTokens)).toBeTruthy();
				expect(responseBuilder.getPeerServiceTokens().length).toEqual(0);
			});

			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response).not.toBeNull();
                expect(response.nonReplayableId).toBeFalsy();
				expect(response.isRenewable()).toBeFalsy();
				expect(response.isHandshake()).toBeFalsy();
				expect(response.cryptoContext).not.toBeNull();
				expect(response.entityAuthenticationData).toBeNull();
				expect(response.keyRequestData.length).toEqual(0);
				expect(response.keyResponseData).toBeNull();
				expect(response.masterToken).toEqual(MASTER_TOKEN);
				expect(response.messageId).toEqual(incrementLong(request.messageId));
				expect(response.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
				expect(response.peerMasterToken).toBeNull();
				expect(response.peerServiceTokens.length).toEqual(0);
				expect(response.peerUserIdToken).toBeNull();
				expect(Arrays.containEachOther(response.serviceTokens, serviceTokens)).toBeTruthy();
				expect(response.userAuthenticationData).toBeNull();
				expect(response.userIdToken).toEqual(USER_ID_TOKEN);
			});
		});

		it("p2p create null request", function() {
			// This will not exercise any of the complex logic, so no key
			// request data, entity auth data, or user auth data. Just tokens.
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(t) { peerServiceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
				serviceTokens.forEach(function(serviceToken) {
					requestBuilder.addServiceToken(serviceToken);
				}, this);
				peerServiceTokens.forEach(function(peerServiceToken) {
					requestBuilder.addPeerServiceToken(peerServiceToken);
				}, this);
				requestBuilder.getHeader({
					result: function(x) { request = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			// The tokens should be swapped.
			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			runs(function() {
				expect(responseBuilder.willEncryptHeader()).toBeTruthy();
				expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
				expect(Arrays.containEachOther(responseBuilder.getPeerServiceTokens(), serviceTokens)).toBeTruthy();
				expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), peerServiceTokens)).toBeTruthy();
			});
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			runs(function() {
				expect(response).not.toBeNull();
                expect(response.nonReplayableId).toBeFalsy();
				expect(response.isRenewable()).toBeFalsy();
                expect(response.isHandshake()).toBeFalsy();
				expect(response.cryptoContext).not.toBeNull();
				expect(response.entityAuthenticationData).toBeNull();
				expect(response.keyRequestData.length).toEqual(0);
				expect(response.keyResponseData).toBeNull();
				expect(response.masterToken).toEqual(PEER_MASTER_TOKEN);
				expect(response.messageId).toEqual(incrementLong(request.messageId));
				expect(response.messageCapabilities).toEqual(p2pCtx.getMessageCapabilities());
				expect(response.peerMasterToken).toEqual(MASTER_TOKEN);
				expect(response.peerUserIdToken).toEqual(USER_ID_TOKEN);
				expect(response.userAuthenticationData).toBeNull();
				expect(response.userIdToken).toEqual(PEER_USER_ID_TOKEN);
				expect(Arrays.containEachOther(response.peerServiceTokens, serviceTokens)).toBeTruthy();
				expect(Arrays.containEachOther(response.serviceTokens, peerServiceTokens)).toBeTruthy();
			});
		});
		
		it("create response with entity authentication data", function() {
            var serviceTokens;
            runs(function() {
                MslTestUtils.getServiceTokens(trustedNetCtx, null, null, {
                    result: function(t) { serviceTokens = t; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

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
                serviceTokens.forEach(function(serviceToken) {
                    requestBuilder.addServiceToken(serviceToken);
                }, this);
                
                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(trustedNetCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            runs(function() {
                expect(responseBuilder.willEncryptHeader()).toBeTruthy();
                expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
                expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), serviceTokens)).toBeTruthy();
                expect(responseBuilder.getPeerServiceTokens().length).toEqual(0);
            });

            var response, entityAuthData;
            runs(function() {
                responseBuilder.getHeader({
                    result: function(x) { response = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                trustedNetCtx.getEntityAuthenticationData(null, {
                    result: function(x) { entityAuthData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return response && entityAuthData; }, "response and entity authentication data not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(response).not.toBeNull();
                expect(response.nonReplayableId).toBeFalsy();
                expect(response.isRenewable()).toBeFalsy();
                expect(response.isHandshake()).toBeFalsy();
                expect(response.cryptoContext).not.toBeNull();
                expect(response.entityAuthenticationData).toEqual(entityAuthData);
                expect(response.keyRequestData.length).toEqual(0);
                expect(response.keyResponseData).toBeNull();
                expect(response.masterToken).toBeNull();
                expect(response.messageId).toEqual(incrementLong(request.messageId));
                expect(response.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
                expect(response.peerMasterToken).toBeNull();
                expect(response.peerServiceTokens.length).toEqual(0);
                expect(response.peerUserIdToken).toBeNull();
                expect(Arrays.containEachOther(response.serviceTokens, serviceTokens)).toBeTruthy();
                expect(response.userAuthenticationData).toBeNull();
                expect(response.userIdToken).toBeNull();
            });
		});
		
		it("create peer response with entity authentication data", function() {
		    var serviceTokens, peerServiceTokens;
            runs(function() {
                MslTestUtils.getServiceTokens(p2pCtx, null, null, {
                    result: function(t) { serviceTokens = t; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
                    result: function(t) { peerServiceTokens = t; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

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
                requestBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
                serviceTokens.forEach(function(serviceToken) {
                    requestBuilder.addServiceToken(serviceToken);
                }, this);
                peerServiceTokens.forEach(function(peerServiceToken) {
                    requestBuilder.addPeerServiceToken(peerServiceToken);
                }, this);
                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

            // The tokens should be swapped.
            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(p2pCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            runs(function() {
                expect(responseBuilder.willEncryptHeader()).toBeTruthy();
                expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
                expect(Arrays.containEachOther(responseBuilder.getPeerServiceTokens(), serviceTokens)).toBeTruthy();
                expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), peerServiceTokens)).toBeTruthy();
            });
            
            var response, entityAuthData;
            runs(function() {
                responseBuilder.getHeader({
                    result: function(x) { response = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                p2pCtx.getEntityAuthenticationData(null, {
                    result: function(x) { entityAuthData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return response; }, "response and entity authentication data not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(response).not.toBeNull();
                expect(response.nonReplayableId).toBeFalsy();
                expect(response.isRenewable()).toBeFalsy();
                expect(response.isHandshake()).toBeFalsy();
                expect(response.cryptoContext).not.toBeNull();
                expect(response.entityAuthenticationData).toBeNull();
                expect(response.keyRequestData.length).toEqual(0);
                expect(response.keyResponseData).toBeNull();
                expect(response.masterToken).toEqual(PEER_MASTER_TOKEN);
                expect(response.messageId).toEqual(incrementLong(request.messageId));
                expect(response.messageCapabilities).toEqual(p2pCtx.getMessageCapabilities());
                expect(response.peerMasterToken).toBeNull();
                expect(response.peerUserIdToken).toBeNull();
                expect(response.userAuthenticationData).toBeNull();
                expect(response.userIdToken).toEqual(PEER_USER_ID_TOKEN);
                expect(Arrays.containEachOther(response.peerServiceTokens, serviceTokens)).toBeTruthy();
                expect(Arrays.containEachOther(response.serviceTokens, peerServiceTokens)).toBeTruthy();
            });
		});

		it("create response", function() {
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);

			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, null, null, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

			var response;
			runs(function() {
				responseBuilder.setNonReplayable(true);
				responseBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					responseBuilder.addKeyRequestData(keyRequestData);
				}, this);
				
				serviceTokens.forEach(function(serviceToken) {
					responseBuilder.addServiceToken(serviceToken);
				}, this);
				responseBuilder.setUserAuthenticationData(USER_AUTH_DATA);
				expect(responseBuilder.willEncryptHeader()).toBeTruthy();
				expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
				expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), serviceTokens)).toBeTruthy();
				expect(responseBuilder.getPeerServiceTokens().length).toEqual(0);
				
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response).not.toBeNull();
				expect(response.nonReplayableId).not.toBeNull();
				expect(response.isRenewable()).toBeTruthy();
                expect(response.isHandshake()).toBeFalsy();
				expect(response.cryptoContext).not.toBeNull();
				expect(response.entityAuthenticationData).toBeNull();
				expect(Arrays.containEachOther(response.keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
				expect(response.keyResponseData).toBeNull();
				expect(response.masterToken).toEqual(MASTER_TOKEN);
				expect(response.messageId).toEqual(incrementLong(request.messageId));
				expect(response.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
				expect(response.peerMasterToken).toBeNull();
				expect(response.peerServiceTokens.length).toEqual(0);
				expect(response.peerUserIdToken).toBeNull();
				expect(Arrays.containEachOther(response.serviceTokens, serviceTokens)).toBeTruthy();
				expect(response.userAuthenticationData).toEqual(USER_AUTH_DATA);
				expect(response.userIdToken).toEqual(USER_ID_TOKEN);
			});
		});

		it("create idempotent response", function() {
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createIdempotentResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);

			var serviceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, null, null, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

			var response;
			runs(function() {
				responseBuilder.setNonReplayable(true);
				responseBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					responseBuilder.addKeyRequestData(keyRequestData);
				}, this);
				
				serviceTokens.forEach(function(serviceToken) {
					responseBuilder.addServiceToken(serviceToken);
				}, this);
				responseBuilder.setUserAuthenticationData(USER_AUTH_DATA);
				expect(responseBuilder.willEncryptHeader()).toBeTruthy();
				expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
				expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), serviceTokens)).toBeTruthy();
				expect(responseBuilder.getPeerServiceTokens().length).toEqual(0);
				
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response).not.toBeNull();
				expect(response.nonReplayableId).not.toBeNull();
				expect(response.isRenewable()).toBeTruthy();
                expect(response.isHandshake()).toBeFalsy();
				expect(response.cryptoContext).not.toBeNull();
				expect(response.entityAuthenticationData).toBeNull();
				expect(Arrays.containEachOther(response.keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
				expect(response.keyResponseData).toBeNull();
				expect(response.masterToken).toEqual(MASTER_TOKEN);
				expect(response.messageId).toEqual(incrementLong(request.messageId));
				expect(response.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
				expect(response.peerMasterToken).toBeNull();
				expect(response.peerServiceTokens.length).toEqual(0);
				expect(response.peerUserIdToken).toBeNull();
				expect(Arrays.containEachOther(response.serviceTokens, serviceTokens)).toBeTruthy();
				expect(response.userAuthenticationData).toEqual(USER_AUTH_DATA);
				expect(response.userIdToken).toEqual(USER_ID_TOKEN);
			});
		});

		it("p2p create response", function() {
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var serviceTokens, peerServiceTokens;
			runs(function() {
				
				MslTestUtils.getServiceTokens(p2pCtx, null, null, {
			        result: function(t) { serviceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(t) { peerServiceTokens = t; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

			var response;
			runs(function() {
				serviceTokens.forEach(function(serviceToken) {
					responseBuilder.addServiceToken(serviceToken);
				}, this);
				responseBuilder.setUserAuthenticationData(USER_AUTH_DATA);
				peerServiceTokens.forEach(function(peerServiceToken) {
					responseBuilder.addPeerServiceToken(peerServiceToken);
				}, this);
				expect(responseBuilder.willEncryptHeader()).toBeTruthy();
				expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
				expect(Arrays.containEachOther(responseBuilder.getPeerServiceTokens(), peerServiceTokens)).toBeTruthy();
				expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), serviceTokens)).toBeTruthy();
				
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response).not.toBeNull();
				expect(response.nonReplayableId).toBeFalsy();
				expect(response.isRenewable()).toBeFalsy();
                expect(response.isHandshake()).toBeFalsy();
				expect(response.cryptoContext).not.toBeNull();
				expect(response.keyRequestData.length).toEqual(0);
				expect(response.keyResponseData).toBeNull();
				expect(response.masterToken).toBeNull();
				expect(response.messageId).toEqual(incrementLong(request.messageId));
				expect(response.messageCapabilities).toEqual(p2pCtx.getMessageCapabilities());
				expect(response.peerMasterToken).toEqual(PEER_MASTER_TOKEN);
				expect(response.peerUserIdToken).toEqual(PEER_USER_ID_TOKEN);
				expect(response.userAuthenticationData).toEqual(USER_AUTH_DATA);
				expect(Arrays.containEachOther(response.peerServiceTokens, peerServiceTokens)).toBeTruthy();
				expect(Arrays.containEachOther(response.serviceTokens, serviceTokens)).toBeTruthy();
				expect(response.userIdToken).toBeNull();
			});
		});
		
		it("create handshake response", function() {
		    // This will not exercise any of the complex logic, so no key
            // request data, entity auth data, or user auth data. Just tokens.
            var serviceTokens;
            runs(function() {
                MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
                    result: function(t) { serviceTokens = t; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);

            var requestBuilder;
            runs(function() {
                messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                    result: function(x) { requestBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
            
            var request;
            runs(function() {
                serviceTokens.forEach(function(serviceToken) {
                    requestBuilder.addServiceToken(serviceToken);
                }, this);
                
                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(trustedNetCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            runs(function() {
                responseBuilder.setNonReplayable(true);
                responseBuilder.setRenewable(false);
                responseBuilder.setHandshake(true);
                expect(responseBuilder.willEncryptHeader()).toBeTruthy();
                expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
                expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), serviceTokens)).toBeTruthy();
                expect(responseBuilder.getPeerServiceTokens().length).toEqual(0);
            });

            var response;
            runs(function() {
                responseBuilder.getHeader({
                    result: function(x) { response = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(response).not.toBeNull();
                expect(response.nonReplayableId).toBeFalsy();
                expect(response.isRenewable()).toBeTruthy();
                expect(response.isHandshake()).toBeTruthy();
                expect(response.cryptoContext).not.toBeNull();
                expect(response.entityAuthenticationData).toBeNull();
                expect(response.keyRequestData.length).toEqual(0);
                expect(response.keyResponseData).toBeNull();
                expect(response.masterToken).toEqual(MASTER_TOKEN);
                expect(response.messageId).toEqual(incrementLong(request.messageId));
                expect(response.messageCapabilities).toEqual(trustedNetCtx.getMessageCapabilities());
                expect(response.peerMasterToken).toBeNull();
                expect(response.peerServiceTokens.length).toEqual(0);
                expect(response.peerUserIdToken).toBeNull();
                expect(Arrays.containEachOther(response.serviceTokens, serviceTokens)).toBeTruthy();
                expect(response.userAuthenticationData).toBeNull();
                expect(response.userIdToken).toEqual(USER_ID_TOKEN);
            });
		});
		
		it("create peer handshake response", function() {
		    // This will not exercise any of the complex logic, so no key
            // request data, entity auth data, or user auth data. Just tokens.
            var serviceTokens, peerServiceTokens;
            runs(function() {
                MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, {
                    result: function(t) { serviceTokens = t; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
                    result: function(t) { peerServiceTokens = t; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

            var requestBuilder;
            runs(function() {
                messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
                    result: function(x) { requestBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
            
            var request;
            runs(function() {
                requestBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
                serviceTokens.forEach(function(serviceToken) {
                    requestBuilder.addServiceToken(serviceToken);
                }, this);
                peerServiceTokens.forEach(function(peerServiceToken) {
                    requestBuilder.addPeerServiceToken(peerServiceToken);
                }, this);
                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

            // The tokens should be swapped.
            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(p2pCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            runs(function() {
                responseBuilder.setNonReplayable(true);
                responseBuilder.setRenewable(false);
                responseBuilder.setHandshake(true);
                expect(responseBuilder.willEncryptHeader()).toBeTruthy();
                expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
                expect(Arrays.containEachOther(responseBuilder.getPeerServiceTokens(), serviceTokens)).toBeTruthy();
                expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), peerServiceTokens)).toBeTruthy();
            });
            
            var response;
            runs(function() {
                responseBuilder.getHeader({
                    result: function(x) { response = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
            runs(function() {
                expect(response).not.toBeNull();
                expect(response.nonReplayableId).toBeFalsy();
                expect(response.isRenewable()).toBeTruthy();
                expect(response.isHandshake()).toBeTruthy();
                expect(response.cryptoContext).not.toBeNull();
                expect(response.entityAuthenticationData).toBeNull();
                expect(response.keyRequestData.length).toEqual(0);
                expect(response.keyResponseData).toBeNull();
                expect(response.masterToken).toEqual(PEER_MASTER_TOKEN);
                expect(response.messageId).toEqual(incrementLong(request.messageId));
                expect(response.messageCapabilities).toEqual(p2pCtx.getMessageCapabilities());
                expect(response.peerMasterToken).toEqual(MASTER_TOKEN);
                expect(response.peerUserIdToken).toEqual(USER_ID_TOKEN);
                expect(response.userAuthenticationData).toBeNull();
                expect(response.userIdToken).toEqual(PEER_USER_ID_TOKEN);
                expect(Arrays.containEachOther(response.peerServiceTokens, serviceTokens)).toBeTruthy();
                expect(Arrays.containEachOther(response.serviceTokens, peerServiceTokens)).toBeTruthy();
            });
		});

		it("will encrypt with RSA entity authentication data", function() {
			var rsaCtx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.RSA, false, {
			        result: function(c) { rsaCtx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return rsaCtx; }, "rsaCtx", MslTestConstants.TIMEOUT);
			
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(rsaCtx, null, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(rsaCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			runs(function() {
				expect(responseBuilder.willEncryptHeader()).toBeFalsy();
				expect(responseBuilder.willEncryptPayloads()).toBeFalsy();
			});
		});

		// FIXME: This will fail until Web Crypto supports Diffie-Hellman
		xit("will encrypt with RSA entity authentication data and key exchange data", function() {
			var rsaCtx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.RSA, false, {
			        result: function(c) { rsaCtx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return rsaCtx; }, "rsaCtx", MslTestConstants.TIMEOUT);
			
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(rsaCtx, null, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(rsaCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			runs(function() {
				expect(responseBuilder.willEncryptHeader()).toBeFalsy();
				expect(responseBuilder.willEncryptPayloads()).toBeTruthy();
			});
		});

		it("stored service tokens", function() {
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
				expect(request.serviceTokens.length).toEqual(0);

				var store = trustedNetCtx.getMslStore();
				store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(USER_ID, USER_ID_TOKEN);
				store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
			    store.addServiceTokens(serviceTokens);
			    store.addServiceTokens(peerServiceTokens);

			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);

			var response, updatedServiceTokens;
			runs(function() {
				// The message will include all unbound service tokens.
				updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
					function(peerServiceToken) { return peerServiceToken.isUnbound(); });
	
				expect(Arrays.containEachOther(responseBuilder.getServiceTokens(), updatedServiceTokens)).toBeTruthy();
				expect(responseBuilder.getPeerServiceTokens().length).toEqual(0);

				responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response && updatedServiceTokens; }, "response and updated service tokens not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(Arrays.containEachOther(response.serviceTokens, updatedServiceTokens)).toBeTruthy();
				expect(response.peerServiceTokens.length).toEqual(0);
			});
		});

		it("stored peer service tokens", function() {
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);
			
			var responseBuilder;
			runs(function() {
				expect(request.serviceTokens.length).toEqual(0);
				expect(request.peerServiceTokens.length).toEqual(0);

				var store = p2pCtx.getMslStore();
				store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(USER_ID, USER_ID_TOKEN);
				store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
				store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
				store.addServiceTokens(serviceTokens);
				store.addServiceTokens(peerServiceTokens);

			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);

			var response, updatedServiceTokens;
			runs(function() {
				// Update the set of expected peer service tokens with any unbound
				// service tokens.
				updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
					function(peerServiceToken) { return peerServiceToken.isUnbound(); });

				// The service tokens will all be unbound.
				responseBuilder.getServiceTokens().forEach(function(serviceToken) {
					expect(serviceToken.isUnbound()).toBeTruthy();
					expect(Arrays.contains(serviceTokens, serviceToken) || Arrays.contains(peerServiceTokens, serviceToken)).toBeTruthy();
				}, this);
				expect(Arrays.containEachOther(responseBuilder.getPeerServiceTokens(), updatedServiceTokens)).toBeTruthy();
				
				responseBuilder.getHeader({
					result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response && updatedServiceTokens; }, "response and updated service tokens not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				// The service tokens will all be unbound.
				response.serviceTokens.forEach(function(serviceToken) {
					expect(serviceToken.isUnbound()).toBeTruthy();
					expect(Arrays.contains(serviceTokens, serviceToken) || Arrays.contains(peerServiceTokens, serviceToken)).toBeTruthy();
				}, this);
				expect(Arrays.containEachOther(response.peerServiceTokens, updatedServiceTokens)).toBeTruthy();
			});
		});

		it("add service token with key response data", function() {
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
                KEY_REQUEST_DATA.forEach(function(keyRequestData) {
                    requestBuilder.addKeyRequestData(keyRequestData);
                }, this);
                requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);

                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
            
            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(trustedNetCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            var serviceTokens;
            runs(function() {
                expect(responseBuilder.getMasterToken()).toBeNull();
                var userIdToken = responseBuilder.getUserIdToken();
                expect(userIdToken).not.toBeNull();
                expect(responseBuilder.getKeyExchangeData()).not.toBeNull();
                var keyxMasterToken = responseBuilder.getKeyExchangeData().keyResponseData.masterToken;
                MslTestUtils.getServiceTokens(trustedNetCtx, keyxMasterToken, userIdToken, {
                    result: function(tokens) { serviceTokens = tokens; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceTokens; }, "serviceTokens", MslTestConstants.TIMEOUT);
            
            var response;
            runs(function() {
                serviceTokens.forEach(function(serviceToken) {
                    responseBuilder.addServiceToken(serviceToken);
                }, this);
                responseBuilder.getHeader({
                    result: function(x) { response = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);

            runs(function() {
                expect(Arrays.containEachOther(serviceTokens, response.serviceTokens)).toBeTruthy();
            });
        });
        
        it("add service token with no key exchange data", function() {
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
                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(trustedNetCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            var serviceTokens;
            runs(function() {
                expect(responseBuilder.getMasterToken()).toBeNull();
                expect(responseBuilder.getKeyExchangeData()).toBeNull();
                MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null, {
                    result: function(tokens) { serviceTokens = tokens; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceTokens; }, "serviceTokens", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var f = function() {
                    for (var i = 0; i < serviceTokens.length; ++i) {
                        var serviceToken = serviceTokens[i];
                        responseBuilder.addServiceToken(serviceToken);
                    }
                };
                expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH));
            });
        });
        
        it("add service token with mismatched key exchange data master token", function() {
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
                KEY_REQUEST_DATA.forEach(function(keyRequestData) {
                    requestBuilder.addKeyRequestData(keyRequestData);
                }, this);

                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(trustedNetCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            var serviceTokens;
            runs(function() {
                expect(responseBuilder.getMasterToken()).toBeNull();
                expect(responseBuilder.getKeyExchangeData()).not.toBeNull();
                MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null, {
                    result: function(tokens) { serviceTokens = tokens; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceTokens; }, "serviceTokens", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var f = function() {
                    for (var i = 0; i < serviceTokens.length; ++i) {
                        var serviceToken = serviceTokens[i];
                        responseBuilder.addServiceToken(serviceToken);
                    }
                };
                expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH));
            });
        });
        
        it("p2p add service token with mismatched key exchange data master token", function() {
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
                KEY_REQUEST_DATA.forEach(function(keyRequestData) {
                    requestBuilder.addKeyRequestData(keyRequestData);
                }, this);
                requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);

                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(p2pCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            var serviceTokens;
            runs(function() {
                expect(responseBuilder.getMasterToken()).toBeNull();
                expect(responseBuilder.getUserIdToken()).toBeNull();
                expect(responseBuilder.getKeyExchangeData()).not.toBeNull();
                var keyxMasterToken = responseBuilder.getKeyExchangeData().keyResponseData.masterToken;
                MslTestUtils.getServiceTokens(p2pCtx, keyxMasterToken, null, {
                    result: function(tokens) { serviceTokens = tokens; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return serviceTokens; }, "serviceTokens", MslTestConstants.TIMEOUT);

            runs(function() {
                var f = function() {
                    for (var i = 0; i < serviceTokens.length; ++i) {
                        var serviceToken = serviceTokens[i];
                        responseBuilder.addServiceToken(serviceToken);
                    }
                };
                expect(f).toThrow(new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH));
            });
        });
        
		it("max request message ID", function() {
			var request;
			runs(function() {
				var headerData = new HeaderData(MslConstants.MAX_LONG_VALUE, null, false, false, null, null, null, null, null, null);
				var peerData = new HeaderPeerData(null, null, null);
			    MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.messageId).toEqual(0);
			});
		});

		it("renew master token", function() {
			var requestMasterToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 10000);
				var expiration = new Date(Date.now() + 10000);
			    MasterToken.create(trustedNetCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, requestMasterToken, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(requestMasterToken);
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(requestMasterToken.identity);
				expect(keyxMasterToken.sequenceNumber).toEqual(incrementLong(requestMasterToken.sequenceNumber));
				expect(keyxMasterToken.serialNumber).toEqual(requestMasterToken.serialNumber);
			});
		});

		it("p2p renew master token", function() {
			var requestMasterToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 10000);
				var expirationWindow = new Date(Date.now() + 10000);
			    MasterToken.create(p2pCtx, renewalWindow, expirationWindow, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, requestMasterToken, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toBeNull();
				expect(response.peerMasterToken).toEqual(requestMasterToken);
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(requestMasterToken.identity);
				expect(keyxMasterToken.sequenceNumber).toEqual(incrementLong(requestMasterToken.sequenceNumber));
				expect(keyxMasterToken.serialNumber).toEqual(requestMasterToken.serialNumber);
			});
		});

		it("renew master token with max sequence number", function() {
			var requestMasterToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 10000);
				var expirationWindow = new Date(Date.now() + 10000);
			    MasterToken.create(trustedNetCtx, renewalWindow, expirationWindow, MslConstants.MAX_LONG_VALUE, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, requestMasterToken, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var responseMasterToken = response.masterToken;
				expect(responseMasterToken.identity).toEqual(requestMasterToken.identity);
				expect(responseMasterToken.sequenceNumber).toEqual(requestMasterToken.sequenceNumber);
				expect(responseMasterToken.serialNumber).toEqual(requestMasterToken.serialNumber);
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(requestMasterToken.identity);
				expect(keyxMasterToken.sequenceNumber).toEqual(incrementLong(requestMasterToken.sequenceNumber));
				expect(keyxMasterToken.serialNumber).toEqual(requestMasterToken.serialNumber);
			});
		});
		
		it("renew master token with future renewal window", function() {
            var requestMasterToken;
            runs(function() {
                var renewalWindow = new Date(Date.now() + 10000);
                var expirationWindow = new Date(Date.now() + 20000);
                MasterToken.create(trustedNetCtx, renewalWindow, expirationWindow, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
                    result: function(x) { requestMasterToken = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);

            var requestBuilder;
            runs(function() {
                messageFactory.createRequest(trustedNetCtx, requestMasterToken, null, null, {
                    result: function(x) { requestBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
            
            var request;
            runs(function() {
                requestBuilder.setRenewable(true);
                KEY_REQUEST_DATA.forEach(function(keyRequestData) {
                    requestBuilder.addKeyRequestData(keyRequestData);
                }, this);
                
                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(trustedNetCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            var response;
            runs(function() {
                responseBuilder.getHeader({
                    result: function(x) { response = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
            
            runs(function() {
                var responseMasterToken = response.masterToken;
                expect(responseMasterToken.identity).toEqual(requestMasterToken.identity);
                expect(responseMasterToken.sequenceNumber).toEqual(requestMasterToken.sequenceNumber);
                expect(responseMasterToken.serialNumber).toEqual(requestMasterToken.serialNumber);
                var keyResponseData = response.keyResponseData;
                expect(keyResponseData).toBeNull();
            });
        });

		it("expired master token", function() {
			var requestMasterToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 20000);
				var expirationWindow = new Date(Date.now() - 10000);
			    MasterToken.create(trustedNetCtx, renewalWindow, expirationWindow, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, requestMasterToken, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(requestMasterToken);
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(requestMasterToken.identity);
				expect(keyxMasterToken.sequenceNumber).toEqual(incrementLong(requestMasterToken.sequenceNumber));
				expect(keyxMasterToken.serialNumber).toEqual(requestMasterToken.serialNumber);
			});
		});

		it("non-replayable request", function() {
			var requestMasterToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() + 10000);
				var expirationWindow = new Date(Date.now() + 20000);
				MasterToken.create(trustedNetCtx, renewalWindow, expirationWindow, MslConstants.MAX_LONG_VALUE, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, requestMasterToken, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setNonReplayable(true);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(requestMasterToken);
				expect(response.keyResponseData).toBeNull();
			});
		});

		it("renew master token with unsupported key exchange scheme", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

			var requestMasterToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 10000);
				var expirationWindow = new Date(Date.now() + 10000);
				MasterToken.create(ctx, renewalWindow, expirationWindow, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
					result: function(x) { requestMasterToken = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);

			var request;
			runs(function() {
				var headerData = new HeaderData(REQUEST_MESSAGE_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
				var peerData = new HeaderPeerData(null, null, null);
				MessageHeader.create(trustedNetCtx, null, requestMasterToken, headerData, peerData, {
					result: function(x) { request = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var exception;
			runs(function() {
			    for (var prop in KeyExchangeScheme) {
			        var scheme = KeyExchangeScheme.getScheme(prop);
			        if (scheme)
			            ctx.removeKeyExchangeFactories(scheme);
			    }
				messageFactory.createResponse(ctx, request, {
					result: function() {},
					error: function(err) { exception = err; }
				});
			});
			waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() { throw exception; };
				expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND), REQUEST_MESSAGE_ID);
			});
		});

		it("renew master token with one supported key exchange scheme", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

			var requestMasterToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 10000);
				var expirationWindow = new Date(Date.now() + 10000);
			    MasterToken.create(ctx, renewalWindow, expirationWindow, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(ctx, requestMasterToken, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				// This should place the supported key exchange scheme in the
				// middle, guaranteeing that we will have to skip one unsupported
				// scheme.
				requestBuilder.addKeyRequestData(new AsymmetricWrappedExchange.RequestData(KEY_PAIR_ID, AsymmetricWrappedExchange.Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
				requestBuilder.addKeyRequestData(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK));
				requestBuilder.addKeyRequestData(new AsymmetricWrappedExchange.RequestData(KEY_PAIR_ID, AsymmetricWrappedExchange.Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
				
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
                for (var prop in KeyExchangeScheme) {
                    var scheme = KeyExchangeScheme.getScheme(prop);
                    if (scheme)
                        ctx.removeKeyExchangeFactories(scheme);
                }
				ctx.addKeyExchangeFactory(new SymmetricWrappedExchange(new MockAuthenticationUtils()));
				
			    messageFactory.createResponse(ctx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(requestMasterToken);
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(requestMasterToken.identity);
				expect(keyxMasterToken.sequenceNumber).toEqual(incrementLong(requestMasterToken.sequenceNumber));
				expect(keyxMasterToken.serialNumber).toEqual(requestMasterToken.serialNumber);
			});
		});

		it("renew master token with untrusted master token", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
			
			var requestMasterToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 10000);
				var expirationWindow = new Date(Date.now() + 10000);
			    MasterToken.create(ctx, renewalWindow, expirationWindow, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);

			var request;
			runs(function() {
				var headerData = new HeaderData(REQUEST_MESSAGE_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
				var peerData = new HeaderPeerData(null, null, null);
				MessageHeader.create(ctx, null, requestMasterToken, headerData, peerData, {
					result: function(x) { request = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function () { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var encryptionKey2, hmacKey2, wrappingKey2;
			runs(function () {
	            var mke = new Uint8Array(16);
	            var mkh = new Uint8Array(32);
	            var mkw = new Uint8Array(16);
	            random.nextBytes(mke);
	            random.nextBytes(mkh);
	            random.nextBytes(mkw);
			    SecretKey.import(mke, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
			        result: function(key) { encryptionKey2 = key; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
                SecretKey.import(mkh, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function (key) { hmacKey2 = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                SecretKey.import(mkw, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                    result: function(key) { wrappingKey2 = key; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
			});
			waitsFor(function() { return encryptionKey2 && hmacKey2 && wrappingKey2; }, "secondary keys", MslTestConstants.TIMEOUT);
			
			var mo;
			runs(function() {
			    MslTestUtils.toMslObject(encoder, request, {
			        result: function(x) { mo = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

			var untrustedRequest;
			runs(function() {
				// The master token's crypto context must be cached, so we can
	            // rebuild the message.
	            var cryptoContext = new SessionCryptoContext(ctx, requestMasterToken);
	            ctx.getMslStore().setCryptoContext(requestMasterToken, cryptoContext);
				
		        // Change the MSL crypto context so the master token can no longer be
		        // verified or decrypted.
		        ctx.setMslCryptoContext(new SymmetricCryptoContext(ctx, "clientMslCryptoContext", encryptionKey2, hmacKey2, wrappingKey2));
		        
		        // Reconstruct the request with an untrusted master token.
		        Header.parseHeader(ctx, mo, CRYPTO_CONTEXTS, {
		        	result: function(x) { untrustedRequest = x; },
		        	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		        });
			});
			waitsFor(function() { return untrustedRequest; }, "untrusted request not received", 3000);

			var exception;
			runs(function() {
				messageFactory.createResponse(ctx, untrustedRequest, {
					result: function(x) {},
					error: function(err) { exception = err; }
				});
			});
			waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() { throw exception; };
				expect(f).toThrow(new MslMasterTokenException(MslError.NONE));
			});
		});
        
		it("create response to request with key response data", function() {
			var localRequestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, null, null, null, {
			        result: function(x) { localRequestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return localRequestBuilder; }, "localRequestBuilder not received", MslTestConstants.TIMEOUT);
			
			var localRequest;
			runs(function() {
				localRequestBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					localRequestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				localRequestBuilder.getHeader({
					result: function(x) { localRequest = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return localRequest; }, "localRequest not receeived", MslTestConstants.TIMEOUT);
            
			var remoteResponse;
			runs(function() {
				messageFactory.createResponse(trustedNetCtx, localRequest, {
					result: function(remoteResponseBuilder) {
						remoteResponseBuilder.getHeader({
							result: function(x) { remoteResponse = x; },
							error: function(e) { expect(function() { throw e; }).not.toThrow(); }
						});
					},
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return remoteResponse; }, "remoteResponse not received", 200);
			
			var keyResponseData, localResponse;
			runs(function() {
	            keyResponseData = remoteResponse.keyResponseData;
	            expect(keyResponseData).not.toBeNull();
	            
	            messageFactory.createResponse(trustedNetCtx, remoteResponse, {
	            	result: function(localResponseBuilder) {
	            		localResponseBuilder.getHeader({
	            			result: function(x) { localResponse = x; },
	            			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            		});
	            	},
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
			});
			waitsFor(function() { return keyResponseData && localResponse; }, "keyResponseData and localResponse not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
	            var localMasterToken = localResponse.masterToken;
	            expect(localMasterToken).not.toBeNull();
	            expect(localMasterToken.equals(keyResponseData.masterToken)).toBeTruthy();
			});
        });
		
		it("p2p create response to request with key response data", function() {
			var localRequestBuilder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, null, null, null, {
			        result: function(x) { localRequestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return localRequestBuilder; }, "localRequestBuilder not received", MslTestConstants.TIMEOUT);
			
			var localRequest;
			runs(function() {
				localRequestBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					localRequestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				localRequestBuilder.getHeader({
					result: function(x) { localRequest = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return localRequest; }, "localRequest not receeived", MslTestConstants.TIMEOUT);
            
			var remoteResponse;
			runs(function() {
				messageFactory.createResponse(p2pCtx, localRequest, {
					result: function(remoteResponseBuilder) {
						remoteResponseBuilder.getHeader({
							result: function(x) { remoteResponse = x; },
							error: function(e) { expect(function() { throw e; }).not.toThrow(); }
						});
					},
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return remoteResponse; }, "remoteResponse not received", 200);
			
			var keyResponseData, localResponse;
			runs(function() {
	            expect(remoteResponse.masterToken).toBeNull();
	            expect(remoteResponse.peerMasterToken).toBeNull();
	            keyResponseData = remoteResponse.keyResponseData;
	            expect(keyResponseData).not.toBeNull();
	            
	            messageFactory.createResponse(p2pCtx, remoteResponse, {
	            	result: function(localResponseBuilder) {
	            		localResponseBuilder.getHeader({
	            			result: function(x) { localResponse = x; },
	            			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            		});
	            	},
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
			});
			waitsFor(function() { return keyResponseData && localResponse; }, "keyResponseData and localResponse not received", MslTestConstants.TIMEOUT);
			
			var localMasterToken, remoteSecondResponse;
			runs(function() {
	            localMasterToken = localResponse.masterToken;
	            expect(localMasterToken).not.toBeNull();
	            expect(localMasterToken.equals(keyResponseData.masterToken)).toBeTruthy();
	            expect(localResponse.peerMasterToken).toBeNull();
	            
	            messageFactory.createResponse(p2pCtx, localResponse, {
	            	result: function(remoteSecondResponseBuilder) {
	            		remoteSecondResponseBuilder.getHeader({
	            			result: function(x) { remoteSecondResponse = x; },
	            			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            		});
	            	},
	            	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	            });
			});
			waitsFor(function() { return localMasterToken && remoteSecondResponse; }, "localMasterToken and remoteSecondResponse not received", MslTestConstants.TIMEOUT);

			runs(function() {
				expect(remoteResponse.masterToken).toBeNull();
				var remotePeerMasterToken = remoteSecondResponse.peerMasterToken;
				expect(remotePeerMasterToken).not.toBeNull();
				expect(remotePeerMasterToken.equals(localMasterToken)).toBeTruthy();
			});
        });

		it("not renewable request with entity authentication data", function() {
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
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toBeNull();
				expect(response.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
				expect(response.messageId).toEqual(incrementLong(request.messageId));
			});
		});

		it("renewable request with entity authentication data", function() {
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
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toBeNull();
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(ENTITY_AUTH_DATA.identity);
			});
		});

		it("p2p renewable request with entity authentication data", function() {
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
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toBeNull();
				expect(response.peerMasterToken).toBeNull();
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken).not.toBeNull();
				expect(keyxMasterToken.identity).toEqual(PEER_ENTITY_AUTH_DATA.getIdentity());
			});
		});

		it("request with entity authentication data and unsupported key exchange scheme", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
			
			var entityAuthData;
			runs(function() {
				ctx.getEntityAuthenticationData(null, {
					result: function(x) { entityAuthData = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return entityAuthData; }, "entity authentication data not received", MslTestConstants.TIMEOUT);

			var request;
			runs(function() {
				var headerData = new HeaderData(REQUEST_MESSAGE_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
				var peerData = new HeaderPeerData(null, null, null);
				MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
					result: function(x) { request = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var exception;
			runs(function() {
                for (var prop in KeyExchangeScheme) {
                    var scheme = KeyExchangeScheme.getScheme(prop);
                    if (scheme)
                        ctx.removeKeyExchangeFactories(scheme);
                }
				messageFactory.createResponse(ctx, request, {
					result: function() {},
					error: function(err) { exception = err; }
				});
			});
			waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var f = function() { throw exception; };
				expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND), REQUEST_MESSAGE_ID);
			});
		});

		it("request with entity authentication data and one supported key exchange scheme", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
			
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(ctx, null, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				// This should place the supported key exchange scheme in the
				// middle, guaranteeing that we will have to skip one unsupported
				// scheme.
				requestBuilder.addKeyRequestData(new AsymmetricWrappedExchange.RequestData(KEY_PAIR_ID, AsymmetricWrappedExchange.Mechanism.JWEJS_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
				requestBuilder.addKeyRequestData(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK));
				requestBuilder.addKeyRequestData(new AsymmetricWrappedExchange.RequestData(KEY_PAIR_ID, AsymmetricWrappedExchange.Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
                for (var prop in KeyExchangeScheme) {
                    var scheme = KeyExchangeScheme.getScheme(prop);
                    if (scheme)
                        ctx.removeKeyExchangeFactories(scheme);
                }
				ctx.addKeyExchangeFactory(new SymmetricWrappedExchange(new MockAuthenticationUtils()));

			    messageFactory.createResponse(ctx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.keyResponseData).not.toBeNull();
			});
		});

		it("renew user ID token", function() {
			var requestUserIdToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 10000);
				var expiration = new Date(Date.now() + 10000);
			    UserIdToken.create(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1, ISSUER_DATA, USER, {
			        result: function(x) { requestUserIdToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestUserIdToken; }, "requestUserIdToken not received", MslTestConstants.TIMEOUT);
			
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(MASTER_TOKEN);
				var responseUserIdToken = response.userIdToken;
				expect(responseUserIdToken).not.toBeNull();
				expect(responseUserIdToken.user).toEqual(requestUserIdToken.user);
				expect(responseUserIdToken.mtSerialNumber).toEqual(requestUserIdToken.mtSerialNumber);
				expect(responseUserIdToken.serialNumber).toEqual(requestUserIdToken.serialNumber);
				expect(responseUserIdToken.isRenewable(null)).toBeFalsy();
			});
		});

		it("renew user ID token message not renewable", function() {
			var requestUserIdToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 10000);
				var expiration = new Date(Date.now() + 10000);
			    UserIdToken.create(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1, ISSUER_DATA, USER, {
			        result: function(x) { requestUserIdToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestUserIdToken; }, "requestUserIdToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(MASTER_TOKEN);
				var responseUserIdToken = response.userIdToken;
				expect(responseUserIdToken).not.toBeNull();
				expect(responseUserIdToken.user).toEqual(requestUserIdToken.user);
				expect(responseUserIdToken.mtSerialNumber).toEqual(requestUserIdToken.mtSerialNumber);
				expect(responseUserIdToken.serialNumber).toEqual(requestUserIdToken.serialNumber);
				expect(responseUserIdToken.renewalWindow).toEqual(requestUserIdToken.renewalWindow);
				expect(responseUserIdToken.expiration).toEqual(requestUserIdToken.expiration);
			});
		});
		
		it("p2p renew user ID token", function() {
			var requestUserIdToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 10000);
				var expiration = new Date(Date.now() + 10000);
				UserIdToken.create(p2pCtx, renewalWindow, expiration, MASTER_TOKEN, 1, ISSUER_DATA, USER, {
			        result: function(x) { requestUserIdToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestUserIdToken; }, "requestUserIdToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, requestUserIdToken, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.peerMasterToken).toEqual(MASTER_TOKEN);
				expect(response.userIdToken).toBeNull();
				var responseUserIdToken = response.peerUserIdToken;
				expect(responseUserIdToken).not.toBeNull();
				expect(responseUserIdToken.user).toEqual(requestUserIdToken.user);
				expect(responseUserIdToken.mtSerialNumber).toEqual(requestUserIdToken.mtSerialNumber);
				expect(responseUserIdToken.serialNumber).toEqual(requestUserIdToken.serialNumber);
				expect(responseUserIdToken.isRenewable(null)).toBeFalsy();
			});
		});

		it("expired user ID token", function() {
			var requestUserIdToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 20000);
				var expiration = new Date(Date.now() - 10000);
				UserIdToken.create(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1, ISSUER_DATA, USER, {
			        result: function(x) { requestUserIdToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestUserIdToken; }, "requestUserIdToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(MASTER_TOKEN);
				var responseUserIdToken = response.userIdToken;
				expect(responseUserIdToken).not.toBeNull();
				expect(responseUserIdToken.user).toEqual(requestUserIdToken.user);
				expect(responseUserIdToken.mtSerialNumber).toEqual(requestUserIdToken.mtSerialNumber);
				expect(responseUserIdToken.serialNumber).toEqual(requestUserIdToken.serialNumber);
				expect(responseUserIdToken.isExpired(null)).toBeFalsy();
			});
		});
		
		it("expired user ID token message not renewable", function() {
			var requestUserIdToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 20000);
				var expiration = new Date(Date.now() - 10000);
				UserIdToken.create(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1, ISSUER_DATA, USER, {
			        result: function(x) { requestUserIdToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestUserIdToken; }, "requestUserIdToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(MASTER_TOKEN);
				var responseUserIdToken = response.userIdToken;
				expect(responseUserIdToken).not.toBeNull();
				expect(responseUserIdToken.user).toEqual(requestUserIdToken.user);
				expect(responseUserIdToken.mtSerialNumber).toEqual(requestUserIdToken.mtSerialNumber);
				expect(responseUserIdToken.serialNumber).toEqual(requestUserIdToken.serialNumber);
				expect(responseUserIdToken.isExpired(null)).toBeFalsy();
			});
		});
		
		it("expired user ID token server message", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
			
			var requestUserIdToken;
			runs(function() {
				var renewalWindow = new Date(Date.now() - 20000);
				var expiration = new Date(Date.now() - 10000);
				UserIdToken.create(ctx, renewalWindow, expiration, MASTER_TOKEN, 1, ISSUER_DATA, USER, {
			        result: function(x) { requestUserIdToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestUserIdToken; }, "requestUserIdToken not received", MslTestConstants.TIMEOUT);
			
			var userIdTokenMo;
			runs(function() {
                // Change the MSL crypto context so the master token and user ID
                // token are not issued by the local entity.
                ctx.setMslCryptoContext(ALT_MSL_CRYPTO_CONTEXT);

                // Now rebuild the user ID token and the build the request.
			    MslTestUtils.toMslObject(encoder, requestUserIdToken, {
			        result: function(x) { userIdTokenMo = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return userIdTokenMo; }, "userIdTokenMo", MslTestConstants.TIMEOUT);
			
            var unverifiedUserIdToken;
            runs(function() {
            	UserIdToken.parse(ctx, userIdTokenMo, MASTER_TOKEN, {
            		result: function(x) { unverifiedUserIdToken = x; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return unverifiedUserIdToken; }, "unverifiedUserIdToken", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(ctx, MASTER_TOKEN, unverifiedUserIdToken, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(ctx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(MASTER_TOKEN);
				var responseUserIdToken = response.userIdToken;
				expect(responseUserIdToken).not.toBeNull();
				// Can't compare users because the unverified user ID token
				// won't have it.
				expect(responseUserIdToken.mtSerialNumber).toEqual(unverifiedUserIdToken.mtSerialNumber);
				expect(responseUserIdToken.serialNumber).toEqual(unverifiedUserIdToken.serialNumber);
				expect(responseUserIdToken.isExpired(null)).toBeFalsy();
			});
		});

		it("renew master token and user ID token", function() {
			var renewalWindow = new Date(Date.now() - 10000);
			var expiration = new Date(Date.now() + 10000);
			
			var requestMasterToken;
			runs(function() {
				MasterToken.create(trustedNetCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);
			
			var requestUserIdToken;
			runs(function() {
			    UserIdToken.create(trustedNetCtx, renewalWindow, expiration, requestMasterToken, 1, ISSUER_DATA, USER, {
			        result: function(x) { requestUserIdToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestUserIdToken; }, "requestUserIdToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, requestMasterToken, requestUserIdToken, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toEqual(requestMasterToken);
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(requestMasterToken.identity);
				expect(keyxMasterToken.sequenceNumber).toEqual(incrementLong(requestMasterToken.sequenceNumber));
				expect(keyxMasterToken.serialNumber).toEqual(requestMasterToken.serialNumber);
				var responseUserIdToken = response.userIdToken;
				expect(responseUserIdToken).not.toBeNull();
				expect(responseUserIdToken.user).toEqual(requestUserIdToken.user);
				expect(responseUserIdToken.mtSerialNumber).toEqual(requestUserIdToken.mtSerialNumber);
				expect(responseUserIdToken.serialNumber).toEqual(requestUserIdToken.serialNumber);
			});
		});

		it("renew tokens without key request data", function() {
			var renewalWindow = new Date(Date.now() - 10000);
			var expiration = new Date(Date.now() + 10000);
			
			var requestMasterToken;
			runs(function() {
			    MasterToken.create(trustedNetCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);
			
			var requestUserIdToken;
			runs(function() {
			    UserIdToken.create(trustedNetCtx, renewalWindow, expiration, requestMasterToken, 1, ISSUER_DATA, USER, {
			        result: function(x) { requestUserIdToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestUserIdToken; }, "requestUserIdToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, requestMasterToken, requestUserIdToken, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken.equals(requestMasterToken)).toBeTruthy();
				expect(response.masterToken.renewalWindow).toEqual(requestMasterToken.renewalWindow);
				expect(response.masterToken.expiration).toEqual(requestMasterToken.expiration);
				expect(response.userIdToken.equals(requestUserIdToken)).toBeTruthy();
				expect(response.userIdToken.renewalWindow).not.toEqual(requestUserIdToken.renewalWindow);
				expect(response.userIdToken.expiration).not.toEqual(requestUserIdToken.expiration);
				expect(response.keyResponseData).toBeNull();
			});
		});

		it("p2p renew master token and user ID token", function() {
			var renewalWindow = new Date(Date.now() - 10000);
			var expiration = new Date(Date.now() + 10000);
			
			var requestMasterToken;
			runs(function() {
			    MasterToken.create(p2pCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
			        result: function(x) { requestMasterToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMasterToken; }, "requestMasterToken not received", MslTestConstants.TIMEOUT);
			
			var requestUserIdToken;
			runs(function() {
			    UserIdToken.create(p2pCtx, renewalWindow, expiration, requestMasterToken, 1, ISSUER_DATA, USER, {
			        result: function(x) { requestUserIdToken = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestUserIdToken; }, "requestUserIdToken not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, requestMasterToken, requestUserIdToken, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toBeNull();
				expect(response.peerMasterToken).toEqual(requestMasterToken);
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(requestMasterToken.identity);
				expect(keyxMasterToken.sequenceNumber).toEqual(incrementLong(requestMasterToken.sequenceNumber));
				expect(keyxMasterToken.serialNumber).toEqual(requestMasterToken.serialNumber);
				expect(response.userIdToken).toBeNull();
				var responseUserIdToken = response.peerUserIdToken;
				expect(responseUserIdToken).not.toBeNull();
				expect(responseUserIdToken.user).toEqual(requestUserIdToken.user);
				expect(responseUserIdToken.mtSerialNumber).toEqual(requestUserIdToken.mtSerialNumber);
				expect(responseUserIdToken.serialNumber).toEqual(requestUserIdToken.serialNumber);
			});
		});

		it("master token with user authentication data", function() {
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var userIdToken = response.userIdToken;
				expect(userIdToken).not.toBeNull();
				expect(userIdToken.user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
			});
		});

		it("master token and user is authenticated", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(ctx, MASTER_TOKEN, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
			
			var requestMo;
			runs(function() {
			    MslTestUtils.toMslObject(encoder, request, {
			        result: function(x) { requestMo = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestMo; }, "requestMo", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
				Header.parseHeader(ctx, requestMo, CRYPTO_CONTEXTS, {
					result: function(moRequest) {
						expect(moRequest.user).not.toBeNull();

						// Remove support for user authentication to prove the response
						// does not perform it.
						ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.scheme);

					    messageFactory.createResponse(ctx, moRequest, {
					        result: function(x) { responseBuilder = x; },
					        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
					    });
					},
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var userIdToken = response.userIdToken;
				expect(userIdToken).not.toBeNull();
				expect(userIdToken.user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
			});
		});

		it("p2p master token with user authentication data", function() {
			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.userIdToken).toBeNull();
				var userIdToken = response.peerUserIdToken;
				expect(userIdToken).not.toBeNull();
				expect(userIdToken.user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
			});
		});

		it("p2p master token and user is authenticated", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, true, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(ctx, MASTER_TOKEN, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
            
            var requestMo;
            runs(function() {
                MslTestUtils.toMslObject(encoder, request, {
                    result: function(x) { requestMo = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestMo; }, "requestMo", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
				Header.parseHeader(ctx, requestMo, CRYPTO_CONTEXTS, {
					result: function(moRequest) {
						expect(moRequest.user).not.toBeNull();

						// Remove support for user authentication to prove the response
						// does not perform it.
						ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.scheme);

						messageFactory.createResponse(ctx, moRequest, {
							result: function(x) { responseBuilder = x; },
							error: function(e) { expect(function() { throw e; }).not.toThrow(); }
						});
					},
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				var userIdToken = response.peerUserIdToken;
				expect(userIdToken).not.toBeNull();
				expect(userIdToken.user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
			});
		});

		it("entity authentication data and user authentication data", function() {
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
				requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toBeNull();
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(ENTITY_AUTH_DATA.getIdentity());
				var userIdToken = response.userIdToken;
				expect(userIdToken).not.toBeNull();
				expect(userIdToken.user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
				expect(userIdToken.isBoundTo(keyxMasterToken)).toBeTruthy();
			});
		});

		it("entity authentication data and user is authenticated", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(ctx, null, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.setRenewable(true);
				requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
				KEY_REQUEST_DATA.forEach(function(keyRequestData) {
					requestBuilder.addKeyRequestData(keyRequestData);
				}, this);
				
			    requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
            
            var requestMo;
            runs(function() {
                MslTestUtils.toMslObject(encoder, request, {
                    result: function(x) { requestMo = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestMo; }, "requestMo", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
				Header.parseHeader(ctx, requestMo, CRYPTO_CONTEXTS, {
					result: function(moRequest) {
						expect(moRequest.user).not.toBeNull();

						// Remove support for user authentication to prove the response
						// does not perform it.
						ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.scheme);

						messageFactory.createResponse(ctx, moRequest, {
							result: function(x) { responseBuilder = x; },
							error: function(e) { expect(function() { throw e; }).not.toThrow(); }
						});
					},
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toBeNull();
				var keyResponseData = response.keyResponseData;
				expect(keyResponseData).not.toBeNull();
				var keyxMasterToken = keyResponseData.masterToken;
				expect(keyxMasterToken.identity).toEqual(ENTITY_AUTH_DATA.getIdentity());
				var userIdToken = response.userIdToken;
				expect(userIdToken).not.toBeNull();
				expect(userIdToken.user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
				expect(userIdToken.isBoundTo(keyxMasterToken)).toBeTruthy();
			});
		});

		it("entity authentication data and user authentication data with no key request data", function() {
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
				requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
				requestBuilder.getHeader({
			        result: function(x) { request = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(x) { response = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				expect(response.masterToken).toBeNull();
				expect(response.userIdToken).toBeNull();
				expect(response.keyResponseData).toBeNull();
				expect(response.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
			});
		});

		it("p2p entity authentication data and user authentication data", function() {
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
                requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
                KEY_REQUEST_DATA.forEach(function(keyRequestData) {
                    requestBuilder.addKeyRequestData(keyRequestData);
                }, this);
                requestBuilder.getHeader({
                    result: function(h) { request = h; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
			    responseBuilder.getHeader({
			        result: function(h) { response = h; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
                expect(response.masterToken).toBeNull();
                var keyResponseData = response.keyResponseData;
                expect(keyResponseData).not.toBeNull();
                var keyxMasterToken = keyResponseData.masterToken;
                expect(keyxMasterToken.identity).toEqual(PEER_ENTITY_AUTH_DATA.getIdentity());
                expect(response.userIdToken).toBeNull();
                var userIdToken = response.peerUserIdToken;
                expect(userIdToken).not.toBeNull();
                expect(userIdToken.user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
            });
		});

		it("p2p entity authentication data and user is authenticated", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, true, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

            var requestBuilder;
            runs(function() {
                messageFactory.createRequest(ctx, null, null, null, {
                    result: function(x) { requestBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
            
            var request;
            runs(function() {
                requestBuilder.setRenewable(true);
                requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
                KEY_REQUEST_DATA.forEach(function(keyRequestData) {
                    requestBuilder.addKeyRequestData(keyRequestData);
                }, this);
                requestBuilder.getHeader({
                    result: function(h) { request = h; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
            
            var requestMo;
            runs(function() {
                MslTestUtils.toMslObject(encoder, request, {
                    result: function(x) { requestMo = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return requestMo; }, "requestMo", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
                Header.parseHeader(ctx, requestMo, CRYPTO_CONTEXTS, {
                	result: function(moRequest) {
                		expect(moRequest.user).not.toBeNull();

                		// Remove support for user authentication to prove the response
                		// does not perform it.
                		ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.scheme);

                		messageFactory.createResponse(ctx, moRequest, {
                			result: function(x) { responseBuilder = x; },
                			error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                		});
                	},
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
			var response;
            runs(function() {
                responseBuilder.getHeader({
                    result: function(x) { response = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
                expect(response.masterToken).toBeNull();
                var keyResponseData = response.keyResponseData;
                expect(keyResponseData).not.toBeNull();
                var keyxMasterToken = keyResponseData.masterToken;
                expect(keyxMasterToken.identity).toEqual(PEER_ENTITY_AUTH_DATA.getIdentity());
                expect(response.userIdToken).toBeNull();
                var userIdToken = response.peerUserIdToken;
                expect(userIdToken).not.toBeNull();
                expect(userIdToken.user).toEqual(MockEmailPasswordAuthenticationFactory.USER);
            });
		});

		it("unsupported user authentication scheme", function() {
			var ctx;
			runs(function() {
			    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
			        result: function(c) { ctx = c; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

			var request;
			runs(function() {
				var headerData = new HeaderData(REQUEST_MESSAGE_ID, null, true, false, null, null, null, USER_AUTH_DATA, null, null);
				var peerData = new HeaderPeerData(null, null, null);
				MessageHeader.create(ctx, null, MASTER_TOKEN, headerData, peerData, {
					result: function(x) { request = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var exception;
			runs(function() {
                for (var prop in UserAuthenticationScheme) {
                    var scheme = UserAuthenticationScheme.getScheme(prop);
                    if (scheme)
                        ctx.removeUserAuthenticationFactory(scheme);
                }

				messageFactory.createResponse(ctx, request, {
				    result: function() {},
				    error: function(e) { exception = e; }
				});
			});
			waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
			runs(function() {
			    var f = function() { throw exception; };
			    expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND), REQUEST_MESSAGE_ID);
			});
		});

		it("set master token", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

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
	            requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
			
			var responseBuilder;
			runs(function() {
                var store = trustedNetCtx.getMslStore();
                store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
                store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
                store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
			    store.addServiceTokens(serviceTokens);
			    store.addServiceTokens(peerServiceTokens);
			    
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);

            var messageHeader, updatedServiceTokens;
            runs(function() {
                // The message service tokens will include all unbound service
                // tokens.
                updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
                    function(peerServiceToken) { return peerServiceToken.isUnbound(); });
                
                responseBuilder.setAuthTokens(MASTER_TOKEN, null);
                responseBuilder.getHeader({
                	result: function(x) { messageHeader = x; },
                	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return messageHeader && updatedServiceTokens; }, "message and updated service tokens not received", MslTestConstants.TIMEOUT);
    
            runs(function() {
                expect(Arrays.containEachOther(messageHeader.serviceTokens, updatedServiceTokens)).toBeTruthy();
            });
		});

		it("set master token with existing master token", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

			var requestBuilder;
			runs(function() {
			    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, {
			        result: function(x) { requestBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
			
			var request;
			runs(function() {
				requestBuilder.getHeader({
					result: function(x) { request = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
                var store = trustedNetCtx.getMslStore();
                store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
                store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
                store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
			    store.addServiceTokens(serviceTokens);
			    store.addServiceTokens(peerServiceTokens);
			    
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);

            var messageHeader, updatedServiceTokens;
            runs(function() {
                // The message service tokens will include all unbound service
                // tokens.
                updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
                    function(peerServiceToken) { return peerServiceToken.isUnbound(); });

            	responseBuilder.setAuthTokens(MASTER_TOKEN, null);
            	responseBuilder.getHeader({
            		result: function(x) { messageHeader = x; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return messageHeader && updatedServiceTokens; }, "message header and updated service tokens not received", MslTestConstants.TIMEOUT);
    
            runs(function() {
                expect(Arrays.containEachOther(messageHeader.serviceTokens, updatedServiceTokens)).toBeTruthy();
            });
		});

		it("set authentication tokens", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

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
            	requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
                var store = trustedNetCtx.getMslStore();
                store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
                store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
                store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
			    store.addServiceTokens(serviceTokens);
			    store.addServiceTokens(peerServiceTokens);
                
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);

            var messageHeader, updatedServiceTokens;
            runs(function() {
                // The message service tokens will include all unbound service
                // tokens.
                updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
                    function(peerServiceToken) { return peerServiceToken.isUnbound(); });

                responseBuilder.setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);
                responseBuilder.getHeader({
                    result: function(x) { messageHeader = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return messageHeader && updatedServiceTokens; }, "message header and updated service tokens not received", MslTestConstants.TIMEOUT);

			runs(function() {
				expect(Arrays.containEachOther(messageHeader.serviceTokens, updatedServiceTokens)).toBeTruthy();
            });
		});

		it("set existing authentication tokens", function() {
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);

        	var requestBuilder;
        	runs(function() {
        	    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
        	        result: function(x) { requestBuilder = x; },
        	        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	    });
        	});
        	waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
        	
			var request;
            runs(function() {
            	requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);

			var responseBuilder;
			runs(function() {
                var store = trustedNetCtx.getMslStore();
                store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
                store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
                store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
			    store.addServiceTokens(serviceTokens);
			    store.addServiceTokens(peerServiceTokens);
                
			    messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);

            var messageHeader, updatedServiceTokens;
            runs(function() {
                // The message service tokens will include all unbound service
                // tokens.
                updatedServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
                    function(peerServiceToken) { return peerServiceToken.isUnbound(); });

                responseBuilder.setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);
                responseBuilder.getHeader({
                    result: function(x) { messageHeader = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return messageHeader && updatedServiceTokens; }, "message header and updated service tokens not received", MslTestConstants.TIMEOUT);

			runs(function() {
				expect(Arrays.containEachOther(messageHeader.serviceTokens, updatedServiceTokens)).toBeTruthy();
            });
		});

		it("set null master token", function() {
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
            	requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
		    
			var responseBuilder;
			runs(function() {
                messageFactory.createResponse(trustedNetCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
				responseBuilder.setAuthTokens(null, null);
				responseBuilder.getHeader({
					result: function(x) { response = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);

			runs(function() {
				expect(response.masterToken).toBeNull();
                expect(response.userIdToken).toBeNull();
            });
		});

		it("set mismatched authentication tokens", function() {
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
            	requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
            
            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(trustedNetCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
            
            runs(function() {
                var f = function() {
                    responseBuilder.setAuthTokens(MASTER_TOKEN, PEER_USER_ID_TOKEN);
                };
                expect(f).toThrow(new MslInternalException());
            });
		});

		it("set master token when key exchange data exists", function() {
		    var masterToken;
		    runs(function() {
                // The master token must be renewable to force a key exchange to
				// happen.
				var renewalWindow = new Date(Date.now() - 1000);
				var expiration = new Date(Date.now() + 2000);
				var identity = MockPresharedAuthenticationFactory.PSK_ESN;
				var encryptionKey = MockPresharedAuthenticationFactory.KPE;
				var hmacKey = MockPresharedAuthenticationFactory.KPH;
				MasterToken.create(trustedNetCtx, renewalWindow, expiration, 1, 1, null, identity, encryptionKey, hmacKey, {
				    result: function(token) { masterToken = token; },
				    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
		    });
		    waitsFor(function() { return masterToken; }, "master token not received", MslTestConstants.TIMEOUT);

        	var requestBuilder;
        	runs(function() {
        	    messageFactory.createRequest(trustedNetCtx, masterToken, null, null, {
        	        result: function(x) { requestBuilder = x; },
        	        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
        	    });
        	});
        	waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
        	
            var request;
            runs(function() {
                requestBuilder.setRenewable(true);
                KEY_REQUEST_DATA.forEach(function(keyRequestData) {
                    requestBuilder.addKeyRequestData(keyRequestData);
                }, this);
                requestBuilder.getHeader({
                    result: function(x) { request = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
		
            var responseBuilder;
            runs(function() {
                messageFactory.createResponse(trustedNetCtx, request, {
                    result: function(x) { responseBuilder = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
				
			runs(function() {
                var f = function() {
                    responseBuilder.setAuthTokens(MASTER_TOKEN, null);
                };
                expect(f).toThrow(new MslInternalException());
            });
		});

		it("p2p set master token when key exchange data exists", function() {
		    var requestBuilder;
		    runs(function() {
		        messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
		            result: function(x) { requestBuilder = x; },
		            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		        });
		    });
		    waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
		    
			var request;
			runs(function() {
			    KEY_REQUEST_DATA.forEach(function(keyRequestData) {
				    requestBuilder.addKeyRequestData(keyRequestData);
			    }, this);
			    requestBuilder.getHeader({
			    	result: function(x) { request = x; },
			    	error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return request; }, "request not received", MslTestConstants.TIMEOUT);
			
			var serviceTokens, peerServiceTokens;
			runs(function() {
			    MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, {
			        result: function(tokens) { serviceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			    MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
			        result: function(tokens) { peerServiceTokens = tokens; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return serviceTokens && peerServiceTokens; }, "service tokens not received", MslTestConstants.TIMEOUT);
			
			var responseBuilder;
			runs(function() {
			    var store = p2pCtx.getMslStore();
			    store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
			    store.addUserIdToken(USER_ID, USER_ID_TOKEN);
			    store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
			    store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
			    store.addServiceTokens(serviceTokens);
			    store.addServiceTokens(peerServiceTokens);

			    messageFactory.createResponse(p2pCtx, request, {
			        result: function(x) { responseBuilder = x; },
			        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			    });
			});
			waitsFor(function() { return responseBuilder; }, "responseBuilder not received", 200);
			
			var response;
			runs(function() {
				responseBuilder.setAuthTokens(PEER_MASTER_TOKEN, null);
				responseBuilder.getHeader({
					result: function(x) { response = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return response; }, "response not received", MslTestConstants.TIMEOUT);

			runs(function() {
				// Build the set of expected service tokens.
				var expectedServiceTokens = Arrays.combineTokens([], serviceTokens,
					function(serviceToken) { return serviceToken.isUnbound(); });
				expectedServiceTokens = Arrays.combineTokens(expectedServiceTokens, peerServiceTokens,
					function(peerServiceToken) { return !peerServiceToken.isUserIdTokenBound(); });
				expect(Arrays.containEachOther(response.serviceTokens, expectedServiceTokens)).toBeTruthy();

				// Build the set of expected peer service tokens.
				var expectedPeerServiceTokens = Arrays.combineTokens(serviceTokens, peerServiceTokens,
					function(peerServiceToken) { return peerServiceToken.isUnbound(); });
				expect(Arrays.containEachOther(response.peerServiceTokens, expectedPeerServiceTokens)).toBeTruthy();
			});
		});
		
        it("set user", function() {
    		var requestBuilder;
    		runs(function() {
    		    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null, null, {
    		        result: function(x) { requestBuilder = x; },
    		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		    });
    		});
    		waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
    		
        	var request;
        	runs(function() {
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
			waitsFor(function() { return responseBuilder; }, "responseBuilder", MslTestConstants.TIMEOUT);
        	
            var complete = false;
            runs(function() {
            	responseBuilder.setUser(USER_ID_TOKEN.user, {
					result: function(success) { complete = success; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return complete; }, "set user", MslTestConstants.TIMEOUT);

			runs(function() {
	            var userIdToken = responseBuilder.getUserIdToken();
	            expect(userIdToken).not.toBeNull();
	            expect(userIdToken.user).toEqual(USER_ID_TOKEN.user);
			});
        });
        
        it("set user with no master token", function() {
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
			waitsFor(function() { return responseBuilder; }, "responseBuilder", MslTestConstants.TIMEOUT);
            
            var exception;
            runs(function() {
            	responseBuilder.setUser(USER_ID_TOKEN.user, {
            		result: function() {},
            		error: function(e) { exception = e; }
            	});
            });
            waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

            runs(function() {
            	var f = function() { throw exception; };
            	expect(f).toThrow(new MslInternalException());
            });
        });
        
        it("set user with existing user ID token", function() {
    		var requestBuilder;
    		runs(function() {
    		    messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
    		        result: function(x) { requestBuilder = x; },
    		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		    });
    		});
    		waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
    		
        	var request;
        	runs(function() {
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
			waitsFor(function() { return responseBuilder; }, "responseBuilder", MslTestConstants.TIMEOUT);
        	
        	var exception;
        	runs(function() {
        		responseBuilder.setUser(USER_ID_TOKEN.user, {
        			result: function() {},
        			error: function(e) { exception = e; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslInternalException());
        	});
        });
        
        it("p2p set user", function() {
    		var requestBuilder;
    		runs(function() {
    		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null, null, {
    		        result: function(x) { requestBuilder = x; },
    		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		    });
    		});
    		waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
    		
        	var request;
        	runs(function() {
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
			waitsFor(function() { return responseBuilder; }, "responseBuilder", MslTestConstants.TIMEOUT);
            
            var complete = false;
            runs(function() {
            	responseBuilder.setUser(USER_ID_TOKEN.user, {
            		result: function(success) { complete = success; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return complete; }, "set user", MslTestConstants.TIMEOUT);

            runs(function() {
            	var userIdToken = responseBuilder.getPeerUserIdToken();
            	expect(userIdToken).not.toBeNull();
            	expect(userIdToken.user).toEqual(USER_ID_TOKEN.user);
            });
        });
        
        it("p2p set user with no peer master token", function() {
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
			waitsFor(function() { return responseBuilder; }, "responseBuilder", MslTestConstants.TIMEOUT);
    		
        	var exception;
        	runs(function() {
        		responseBuilder.setUser(USER_ID_TOKEN.user, {
        			result: function() {},
        			error: function(e) { exception = e; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslInternalException());
        	});
        });

        it("p2p set user with existing peer user ID token", function() {
    		var requestBuilder;
    		runs(function() {
    		    messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, null, {
    		        result: function(x) { requestBuilder = x; },
    		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
    		    });
    		});
    		waitsFor(function() { return requestBuilder; }, "requestBuilder not received", MslTestConstants.TIMEOUT);
    		
        	var request;
        	runs(function() {
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
			waitsFor(function() { return responseBuilder; }, "responseBuilder", MslTestConstants.TIMEOUT);
    		
        	var exception;
        	runs(function() {
        		responseBuilder.setUser(USER_ID_TOKEN.user, {
        			result: function() {},
        			error: function(e) { exception = e; }
        		});
        	});
        	waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        	runs(function() {
        		var f = function() { throw exception; };
        		expect(f).toThrow(new MslInternalException());
        	});
        });
        
        it("one compression algorithm in request", function() {
            var algos = [ CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW ];
            var lzwOnly = [ CompressionAlgorithm.LZW ];
            var caps = new MessageCapabilities(lzwOnly, null, null);
            
            var ctx;
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
            
            var request;
            runs(function() {
                ctx.setMessageCapabilities(caps);
                messageFactory.createRequest(ctx, null, null, null, {
                    result: function(requestBuilder) {
                        requestBuilder.getHeader({
                            result: function(x) { request = x; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request", MslTestConstants.TIMEOUT);
            
            var response;
            runs(function() {
                expect(request.messageCapabilities).toEqual(caps);
                
                ctx.setMessageCapabilities(new MessageCapabilities(algos, null, null));
                messageFactory.createResponse(ctx, request, {
                    result: function(responseBuilder) {
                        responseBuilder.getHeader({
                            result: function(x) { response = x; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return response; }, "response", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(response.messageCapabilities).toEqual(caps);
            });
        });
        
        if("no compression algorithm in request", function() {
            var algos = [ CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW ];
            
            var ctx;
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
            
            var request;
            runs(function() {
                ctx.setMessageCapabilities(null);
                messageFactory.createRequest(ctx, null, null, null, {
                    result: function(requestBuilder) {
                        requestBuilder.getHeader({
                            result: function(x) { request = x; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return request; }, "request", MslTestConstants.TIMEOUT);
            
            var response;
            runs(function() {
                expect(request.messageCapabilities).toBeNull();
                
                ctx.setMessageCapabilities(new MessageCapabilities(algos, null, null));
                messageFactory.createResponse(ctx, request, {
                    result: function(responseBuilder) {
                        responseBuilder.getHeader({
                            result: function(x) { response = x; },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return response; }, "response", MslTestConstants.TIMEOUT);
            
            runs(function() {
                expect(response.messageCapabilities).toBeNull();
            });
        });
	});
});
