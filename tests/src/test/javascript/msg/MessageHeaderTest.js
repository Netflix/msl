/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
 * Message header unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MessageHeader", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EmailPasswordAuthenticationData = require('msl-core/userauth/EmailPasswordAuthenticationData.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MessageCapabilities = require('msl-core/msg/MessageCapabilities.js');
    var MessageHeader = require('msl-core/msg/MessageHeader.js');
    var Class = require('msl-core/util/Class.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var SymmetricWrappedExchange = require('msl-core/keyx/SymmetricWrappedExchange.js');
    var MslEncoderUtils = require('msl-core/io/MslEncoderUtils.js');
    var Arrays = require('msl-core/util/Arrays.js');
    var Header = require('msl-core/msg/Header.js');
    var SessionCryptoContext = require('msl-core/crypto/SessionCryptoContext.js');
    var MslException = require('msl-core/MslException.js');
    var MslError = require('msl-core/MslError.js');
    var MasterToken = require('msl-core/tokens/MasterToken.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslMessageException = require('msl-core/MslMessageException.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslEntityAuthException = require('msl-core/MslEntityAuthException.js');
    var MslMasterTokenException = require('msl-core/MslMasterTokenException.js');
    var MslUserAuthException = require('msl-core/MslUserAuthException.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var Base64 = require('msl-core/util/Base64.js');
    var NullCryptoContext = require('msl-core/crypto/NullCryptoContext.js');
    var PresharedAuthenticationData = require('msl-core/entityauth/PresharedAuthenticationData.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
    var MockEmailPasswordAuthenticationFactory = require('msl-tests/userauth/MockEmailPasswordAuthenticationFactory.js');
	
    /** Milliseconds per second. */
    var MILLISECONDS_PER_SECOND = 1000;
    
	/** Key entity authentication data. */
	var KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
	/** Key master token. */
	var KEY_MASTER_TOKEN = "mastertoken";
	/** Key header data. */
	var KEY_HEADERDATA = "headerdata";
	/** Key error data signature. */
	var KEY_SIGNATURE = "signature";

	// Message header data.
    /** Key timestamp. */
    var KEY_TIMESTAMP = "timestamp";
	/** Key message ID. */
	var KEY_MESSAGE_ID = "messageid";
    /** Key non-replayable ID. */
    var KEY_NON_REPLAYABLE_ID = "nonreplayableid";
	/** Key renewable flag. */
	var KEY_RENEWABLE = "renewable";
	/** Key handshake flag. */
	var KEY_HANDSHAKE = "handshake";
    /** Key capabilities. */
    var KEY_CAPABILITIES = "capabilities";
	/** Key key negotiation request. */
	var KEY_KEY_REQUEST_DATA = "keyrequestdata";
	/** Key key negotiation response. */
	var KEY_KEY_RESPONSE_DATA = "keyresponsedata";
	/** Key user authentication data. */
	var KEY_USER_AUTHENTICATION_DATA = "userauthdata";
	/** Key user ID token. */
	var KEY_USER_ID_TOKEN = "useridtoken";
	/** Key service tokens. */
	var KEY_SERVICE_TOKENS = "servicetokens";

	// Message header peer data.
	/** Key peer master token. */
	var KEY_PEER_MASTER_TOKEN = "peermastertoken";
	/** Key peer user ID token. */
	var KEY_PEER_USER_ID_TOKEN = "peeruseridtoken";
	/** Key peer service tokens. */
	var KEY_PEER_SERVICE_TOKENS = "peerservicetokens";
    
    /**
     * Checks if the given timestamp is close to "now".
     * 
     * @param {Date} timestamp the timestamp to compare.
     * @return {boolean} true if the timestamp is about now.
     */
    function isAboutNow(timestamp) {
        var now = Date.now();
        var time = timestamp.getTime();
        return (now - 1000 <= time && time <= now + 1000);
    }

    /**
     * Checks if the given timestamp is close to "now".
     * 
     * @param {number} seconds the timestamp to compare in seconds since the epoch.
     * @return {boolean} true if the timestamp is about now.
     */
    function isAboutNowSeconds(seconds) {
        var now = Date.now();
        var time = seconds * MILLISECONDS_PER_SECOND;
        return (now - 2000 <= time && time <= now + 2000);
    }

	/** MSL trusted network context. */
	var trustedNetCtx;
	/** MSL peer-to-peer context. */
	var p2pCtx;
    /** MSL encoder factory. */
    var encoder;
    /** MSL encoder format. */
    var format;

	var USER_AUTH_DATA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
	var USER_AUTH_DATA_MO;
	
    var ALGOS = [ MslConstants.CompressionAlgorithm.GZIP, MslConstants.CompressionAlgorithm.LZW ];
    var LANGUAGES = [ "en-US" ];
    var FORMATS = [ MslEncoderFormat.JSON ];
    
	var MESSAGE_ID = 1;
	var NON_REPLAYABLE_ID = 1;
	var RENEWABLE = true;
	var HANDSHAKE = false;
	
    var CAPABILITIES = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
    var CAPABILITIES_MO;

	var KEY_REQUEST_DATA = [];
	var KEY_REQUEST_DATA_MA;
	var KEY_RESPONSE_DATA, KEY_RESPONSE_DATA_MO;
	
	var ENTITY_AUTH_DATA, ENTITY_AUTH_DATA_MO;
	var PEER_ENTITY_AUTH_DATA, PEER_ENTITY_AUTH_DATA_MO;
	var MASTER_TOKEN, MASTER_TOKEN_MO;
	var USER_ID_TOKEN, USER_ID_TOKEN_MO;
	var PEER_MASTER_TOKEN, PEER_MASTER_TOKEN_MO;
	var PEER_USER_ID_TOKEN, PEER_USER_ID_TOKEN_MO;

	var PEER_KEY_REQUEST_DATA = [];
	var PEER_KEY_REQUEST_DATA_MA;
	var PEER_KEY_RESPONSE_DATA, PEER_KEY_RESPONSE_DATA_MO;
	var CRYPTO_CONTEXTS = {};

	// Shortcuts
	var HeaderData = MessageHeader.HeaderData;
	var HeaderPeerData = MessageHeader.HeaderPeerData;

    /**
     * A helper class for building message header data.
     */
	var HeaderDataBuilder = Class.create({
	    /**
         * Create a new header data builder with the default constant values
         * and a random set of service tokens that may be bound to the provided
         * master token and user ID token.
         * 
         * @param {MslContext} ctx MSL context.
         * @param {?MasterToken} masterToken message header master token. May be null.
         * @param {?UserIdToken} userIdToken message header user ID token. May be null.
         * @param {boolean|Array.<ServiceToken>} serviceTokens true to create service tokens. Otherwise the
         *        service token value will be set to null. Or the set of service tokens to use.
         * @param {result: function(HeaderDataBuilder), error: function(Error)}
         *        callback the callback will receive the header data builder or any
         *        thrown exceptions.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslException if there is an error compressing the data.
         */
        init: function init(ctx, masterToken, userIdToken, serviceTokens, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                if (typeof serviceTokens === 'boolean') {
                    if (serviceTokens) {
                        MslTestUtils.getServiceTokens(ctx, masterToken, userIdToken, {
                            result: construct,
                            error: callback.error,
                        });
                    } else {
                        construct(null);
                    }
                } else {
                    construct(serviceTokens);
                }
            }, self);
            
            function construct(tokens) {
                AsyncExecutor(callback, function() {
                    var values = [];
                    values[KEY_MESSAGE_ID] = MESSAGE_ID;
                    values[KEY_NON_REPLAYABLE_ID] = NON_REPLAYABLE_ID;
                    values[KEY_RENEWABLE] = RENEWABLE;
                    values[KEY_HANDSHAKE] = HANDSHAKE;
                    values[KEY_CAPABILITIES] = CAPABILITIES;
                    values[KEY_KEY_REQUEST_DATA] = (!ctx.isPeerToPeer()) ? KEY_REQUEST_DATA : PEER_KEY_REQUEST_DATA;
                    values[KEY_KEY_RESPONSE_DATA] = (!ctx.isPeerToPeer()) ? KEY_RESPONSE_DATA : PEER_KEY_RESPONSE_DATA;
                    values[KEY_USER_AUTHENTICATION_DATA] = USER_AUTH_DATA;
                    values[KEY_USER_ID_TOKEN] = userIdToken;
                    values[KEY_SERVICE_TOKENS] = tokens;

                    // Set properties.
                    var props = {
                        _values: { value: values, writable: false, enumerable: false, configurable: false }
                    };
                    Object.defineProperties(this, props);
                    return this;
                }, self);
            }
        },
        
        /**
         * Set the value for the specified message data field.
         * 
         * @param {string} key message header field name.
         * @param {*} value message header field value.
         * @return {HeaderDataBuilder} the builder.
         */
        set: function set(key, value) {
            this._values[key] = value;
            return this;
        },
        
        /**
         * @return {?Array.<ServiceToken>} the current set of service tokens. May be null.
         */
        getServiceTokens: function getServiceTokens() {
            return this._values[KEY_SERVICE_TOKENS];
        },
        
        /**
         * Builds a new header data container with the currently set values.
         * 
         * @return {HeaderData} the header data.
         */
        build: function build() {
            var messageId = this._values[KEY_MESSAGE_ID];
            var nonReplayableId = this._values[KEY_NON_REPLAYABLE_ID];
            var renewable = this._values[KEY_RENEWABLE];
            var handshake = this._values[KEY_HANDSHAKE];
            var capabilities = this._values[KEY_CAPABILITIES];
            var keyRequestData = this._values[KEY_KEY_REQUEST_DATA];
            var keyResponseData = this._values[KEY_KEY_RESPONSE_DATA];
            var userAuthData = this._values[KEY_USER_AUTHENTICATION_DATA];
            var userIdToken = this._values[KEY_USER_ID_TOKEN];
            var serviceTokens = this._values[KEY_SERVICE_TOKENS];
            return new HeaderData(messageId, nonReplayableId, renewable, handshake, capabilities, keyRequestData, keyResponseData, userAuthData, userIdToken, serviceTokens);
        }
	});

    /**
     * Create a new header data builder with the default constant values
     * and a random set of service tokens that may be bound to the provided
     * master token and user ID token.
     * 
     * @param {MslContext} ctx MSL context.
     * @param {?MasterToken} masterToken message header master token. May be null.
     * @param {?UserIdToken} userIdToken message header user ID token. May be null.
     * @param {boolean|Array.<ServiceToken>} serviceTokens true to create service tokens. Otherwise the
     *        service token value will be set to null. Or the set of service tokens to use.
     * @param {result: function(HeaderDataBuilder), error: function(Error)}
     *        callback the callback will receive the header data builder or any
     *        thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if there is an error compressing the data.
     */
	function HeaderDataBuilder$create(ctx, masterToken, userIdToken, serviceTokens, callback) {
	    new HeaderDataBuilder(ctx, masterToken, userIdToken, serviceTokens, callback);
	}

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
				encoder = trustedNetCtx.getMslEncoderFactory();
				MslTestUtils.getMasterToken(trustedNetCtx, 1, 1, {
					result: function(token) { MASTER_TOKEN = token; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.getMasterToken(p2pCtx, 1, 2, {
					result: function(token) { PEER_MASTER_TOKEN = token; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				trustedNetCtx.getEntityAuthenticationData(null, {
					result: function(authData) { ENTITY_AUTH_DATA = authData; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				p2pCtx.getEntityAuthenticationData(null, {
					result: function(authData) { PEER_ENTITY_AUTH_DATA = authData; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() { return MASTER_TOKEN && PEER_MASTER_TOKEN && ENTITY_AUTH_DATA && PEER_ENTITY_AUTH_DATA; }, "master tokens and entity authentication data not received", MslTestConstants.TIMEOUT);

			runs(function() {
			    format = encoder.getPreferredFormat(CAPABILITIES.encoderFormats);
			    
				MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
					result: function(token) { USER_ID_TOKEN = token; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
					result: function(token) { PEER_USER_ID_TOKEN = token; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});

				var keyRequestData = new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK);
				var factory = trustedNetCtx.getKeyExchangeFactory(keyRequestData.keyExchangeScheme);
				factory.generateResponse(trustedNetCtx, format, keyRequestData, MASTER_TOKEN, {
					result: function(keyxData) {
						KEY_REQUEST_DATA.push(keyRequestData);
						KEY_RESPONSE_DATA = keyxData.keyResponseData;
					},
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});

				var peerKeyRequestData = new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK);
				var peerFactory = p2pCtx.getKeyExchangeFactory(peerKeyRequestData.keyExchangeScheme);
				peerFactory.generateResponse(p2pCtx, format, peerKeyRequestData, PEER_MASTER_TOKEN, {
					result: function(peerKeyxData) {
						PEER_KEY_REQUEST_DATA.push(peerKeyRequestData);
						PEER_KEY_RESPONSE_DATA = peerKeyxData.keyResponseData;
					},
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() {
				return USER_ID_TOKEN && PEER_USER_ID_TOKEN && KEY_REQUEST_DATA.length > 0 &&
					KEY_RESPONSE_DATA && PEER_KEY_REQUEST_DATA.length > 0 && PEER_KEY_RESPONSE_DATA;
			}, "entity auth MSL object, user ID tokens, and key exchange data not received", MslTestConstants.TIMEOUT);
			
			runs(function() {
				MslTestUtils.toMslObject(encoder, CAPABILITIES, {
					result: function(x) { CAPABILITIES_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.toMslObject(encoder, MASTER_TOKEN, {
					result: function(x) { MASTER_TOKEN_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.toMslObject(encoder, PEER_MASTER_TOKEN, {
					result: function(x) { PEER_MASTER_TOKEN_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.toMslObject(encoder, ENTITY_AUTH_DATA, {
					result: function(x) { ENTITY_AUTH_DATA_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.toMslObject(encoder, PEER_ENTITY_AUTH_DATA, {
					result: function(x) { PEER_ENTITY_AUTH_DATA_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.toMslObject(encoder, USER_AUTH_DATA, {
					result: function(x) { USER_AUTH_DATA_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.toMslObject(encoder, USER_ID_TOKEN, {
					result: function(x) { USER_ID_TOKEN_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.toMslObject(encoder, PEER_USER_ID_TOKEN, {
					result: function(x) { PEER_USER_ID_TOKEN_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslEncoderUtils.createArray(trustedNetCtx, format, KEY_REQUEST_DATA, {
					result: function(x) { KEY_REQUEST_DATA_MA = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.toMslObject(encoder, KEY_RESPONSE_DATA, {
					result: function(x) { KEY_RESPONSE_DATA_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslEncoderUtils.createArray(p2pCtx, format, PEER_KEY_REQUEST_DATA, {
					result: function(x) { PEER_KEY_REQUEST_DATA_MA = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
				MslTestUtils.toMslObject(encoder, PEER_KEY_RESPONSE_DATA, {
					result: function(x) { PEER_KEY_RESPONSE_DATA_MO = x; },
					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
				});
			});
			waitsFor(function() {
				return CAPABILITIES_MO &&
					ENTITY_AUTH_DATA_MO && PEER_ENTITY_AUTH_DATA_MO &&
					MASTER_TOKEN_MO && PEER_MASTER_TOKEN_MO &&
					USER_AUTH_DATA_MO && USER_ID_TOKEN_MO && PEER_USER_ID_TOKEN_MO &&
					KEY_REQUEST_DATA_MA && KEY_RESPONSE_DATA_MO &&
					PEER_KEY_REQUEST_DATA_MA && PEER_KEY_RESPONSE_DATA_MO;
			}, "MSL objects and MSL arrays", MslTestConstants.TIMEOUT);
			
			runs(function() { initialized = true; });
		}
	});
	
	afterEach(function() {
        trustedNetCtx.getMslStore().clearCryptoContexts();
        trustedNetCtx.getMslStore().clearServiceTokens();
        p2pCtx.getMslStore().clearCryptoContexts();
        p2pCtx.getMslStore().clearServiceTokens();
	});

	it("ctor with entity authentication data", function() {
		// Service tokens may be created with the key response data tokens. The
		// key response data master token has the same serial number as the
		// original master token so we can use the same user ID token.
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
		    var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		runs(function() {
			expect(messageHeader.isEncrypting()).toBeTruthy();
			expect(messageHeader.nonReplayableId).toEqual(NON_REPLAYABLE_ID);
			expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
			expect(messageHeader.messageCapabilities).toEqual(CAPABILITIES);
			expect(messageHeader.cryptoContext).not.toBeNull();
			expect(messageHeader.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
			var keyRequestData = messageHeader.keyRequestData;
			expect(Arrays.contains(keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
			expect(messageHeader.keyResponseData).toEqual(KEY_RESPONSE_DATA);
			expect(messageHeader.masterToken).toBeNull();
			expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
			expect(messageHeader.messageId).toEqual(MESSAGE_ID);
			expect(messageHeader.peerMasterToken).toBeNull();
			expect(messageHeader.peerServiceTokens.length).toEqual(0);
			expect(messageHeader.peerUserIdToken).toBeNull();
			var serviceTokens = builder.getServiceTokens();
			expect(Arrays.contains(messageHeader.serviceTokens, serviceTokens)).toBeTruthy();
			expect(messageHeader.userAuthenticationData).toEqual(USER_AUTH_DATA);
			expect(messageHeader.userIdToken).toEqual(USER_ID_TOKEN);
			expect(messageHeader.user).toEqual(USER_ID_TOKEN.user);
		});
	});

    it("replayable ctor with entity authentication data", function() {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        var builder, peerServiceTokens;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
                result: function(tks) { peerServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            builder.set(KEY_NON_REPLAYABLE_ID, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.isEncrypting()).toBeTruthy();
            expect(messageHeader.nonReplayableId).toBeNull();
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
            expect(messageHeader.messageCapabilities).toEqual(CAPABILITIES);
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toEqual(ENTITY_AUTH_DATA);
            var keyRequestData = messageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
            expect(messageHeader.keyResponseData).toEqual(KEY_RESPONSE_DATA);
            expect(messageHeader.masterToken).toBeNull();
            expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toBeNull();
            expect(messageHeader.peerServiceTokens.length).toEqual(0);
            expect(messageHeader.peerUserIdToken).toBeNull();
            var serviceTokens = builder.getServiceTokens();
            expect(Arrays.contains(messageHeader.serviceTokens, serviceTokens)).toBeTruthy();
            expect(messageHeader.userAuthenticationData).toEqual(USER_AUTH_DATA);
            expect(messageHeader.userIdToken).toEqual(USER_ID_TOKEN);
            expect(messageHeader.user).toEqual(USER_ID_TOKEN.user);
        });
    });

	it("mslobject with entity authentication data is correct", function() {
		// Service tokens may be created with the key response data tokens. The
		// key response data master token has the same serial number as the
		// original master token so we can use the same user ID token.
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var cryptoContext;
		runs(function() {
			var scheme = ENTITY_AUTH_DATA.scheme;
			var factory = trustedNetCtx.getEntityAuthenticationFactory(scheme);
			cryptoContext = factory.getCryptoContext(trustedNetCtx, ENTITY_AUTH_DATA);
		});
		waitsFor(function() { return cryptoContext; }, "cryptoContext not received", MslTestConstants.TIMEOUT);
		
		var mo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { mo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var headerdata, ciphertext, signature;
        runs(function() {
            var entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
            expect(entityAuthDataMo).toEqual(ENTITY_AUTH_DATA_MO);
            expect(mo.has(KEY_MASTER_TOKEN)).toBeFalsy();
            ciphertext = mo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    headerdata = encoder.parseObject(plaintext);
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return headerdata && ciphertext && signature; }, "header data and ciphertext and signature not received", MslTestConstants.TIMEOUT);
		
		var verified;
		runs(function() {
		    cryptoContext.verify(ciphertext, signature, encoder, {
		        result: function(v) { verified = v; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return verified !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
		
		var serviceTokensMa;
		runs(function() {
			var serviceTokens = builder.getServiceTokens();
			MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens, {
				result: function(x) { serviceTokensMa = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokensMa; }, "service tokens", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(headerdata.getLong(KEY_NON_REPLAYABLE_ID)).toEqual(NON_REPLAYABLE_ID);
            expect(headerdata.getBoolean(KEY_RENEWABLE)).toEqual(RENEWABLE);
            expect(headerdata.getBoolean(KEY_HANDSHAKE)).toEqual(HANDSHAKE);
            expect(headerdata.getMslObject(KEY_CAPABILITIES, encoder)).toEqual(CAPABILITIES_MO);
            expect(headerdata.getMslArray(KEY_KEY_REQUEST_DATA)).toEqual(KEY_REQUEST_DATA_MA);
            expect(headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)).toEqual(KEY_RESPONSE_DATA_MO);
            expect(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP))).toBeTruthy();
            expect(headerdata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
            expect(headerdata.has(KEY_PEER_MASTER_TOKEN)).toBeFalsy();
            expect(headerdata.has(KEY_PEER_SERVICE_TOKENS)).toBeFalsy();
            expect(headerdata.has(KEY_PEER_USER_ID_TOKEN)).toBeFalsy();
            expect(headerdata.getMslArray(KEY_SERVICE_TOKENS)).toEqual(serviceTokensMa);
            expect(headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)).toEqual(USER_AUTH_DATA_MO);
            expect(headerdata.getMslObject(KEY_USER_ID_TOKEN, encoder)).toEqual(USER_ID_TOKEN_MO);
        });
	});

    it("replayable mslobject with entity authentication data is correct", function() {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        var builder, peerServiceTokens;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
                result: function(tks) { peerServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            builder.set(KEY_NON_REPLAYABLE_ID, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var cryptoContext;
        runs(function() {
            var scheme = ENTITY_AUTH_DATA.scheme;
            var factory = trustedNetCtx.getEntityAuthenticationFactory(scheme);
            cryptoContext = factory.getCryptoContext(trustedNetCtx, ENTITY_AUTH_DATA);
        });
        waitsFor(function() { return cryptoContext; }, "cryptoContext not received", MslTestConstants.TIMEOUT);
		
		var mo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { mo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var headerdata, ciphertext, signature;
        runs(function() {
            var entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
            expect(entityAuthDataMo).toEqual(ENTITY_AUTH_DATA_MO);
            expect(mo.has(KEY_MASTER_TOKEN)).toBeFalsy();
            ciphertext = mo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    headerdata = encoder.parseObject(plaintext);
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return headerdata && ciphertext && signature; }, "header data and ciphertext and signature not received", MslTestConstants.TIMEOUT);
        
        var verified;
        runs(function() {
            cryptoContext.verify(ciphertext, signature, encoder, {
                result: function(v) { verified = v; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return verified !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
		
		var serviceTokensMa;
		runs(function() {
			var serviceTokens = builder.getServiceTokens();
			MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens, {
				result: function(x) { serviceTokensMa = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokensMa; }, "service tokens", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(headerdata.has(KEY_NON_REPLAYABLE_ID)).toBeFalsy();
            expect(headerdata.getBoolean(KEY_RENEWABLE)).toEqual(RENEWABLE);
            expect(headerdata.getBoolean(KEY_HANDSHAKE)).toEqual(HANDSHAKE);
            expect(headerdata.getMslObject(KEY_CAPABILITIES, encoder)).toEqual(CAPABILITIES_MO);
            expect(headerdata.getMslArray(KEY_KEY_REQUEST_DATA)).toEqual(KEY_REQUEST_DATA_MA);
            expect(headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)).toEqual(KEY_RESPONSE_DATA_MO);
            expect(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP))).toBeTruthy();
            expect(headerdata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
            expect(headerdata.has(KEY_PEER_MASTER_TOKEN)).toBeFalsy();
            expect(headerdata.has(KEY_PEER_SERVICE_TOKENS)).toBeFalsy();
            expect(headerdata.has(KEY_PEER_USER_ID_TOKEN)).toBeFalsy();
            expect(headerdata.getMslArray(KEY_SERVICE_TOKENS)).toEqual(serviceTokensMa);
            expect(headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)).toEqual(USER_AUTH_DATA_MO);
            expect(headerdata.getMslObject(KEY_USER_ID_TOKEN, encoder)).toEqual(USER_ID_TOKEN_MO);
        });
    });

	it("p2p ctor with entity authentication data", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });

			// Peer service tokens may be created with the key response data master
			// token. The peer key response data master token has the same serial
			// number as the original peer master token so we can use the same peer
			// user ID token.
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);    
			MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.isEncrypting()).toBeTruthy();
            expect(messageHeader.nonReplayableId).toEqual(NON_REPLAYABLE_ID);
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
			expect(messageHeader.messageCapabilities).toEqual(CAPABILITIES);
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toEqual(PEER_ENTITY_AUTH_DATA);
            var keyRequestData = messageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, PEER_KEY_REQUEST_DATA)).toBeTruthy();
            expect(messageHeader.keyResponseData).toEqual(PEER_KEY_RESPONSE_DATA);
            expect(messageHeader.masterToken).toBeNull();
            expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toEqual(PEER_MASTER_TOKEN);
            expect(Arrays.contains(messageHeader.peerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(messageHeader.peerUserIdToken).toEqual(PEER_USER_ID_TOKEN);
            var serviceTokens = builder.getServiceTokens();
            expect(Arrays.contains(messageHeader.serviceTokens, serviceTokens)).toBeTruthy();
            expect(messageHeader.userAuthenticationData).toEqual(USER_AUTH_DATA);
            expect(messageHeader.userIdToken).toBeNull();
            expect(messageHeader.user).toBeNull();
        });
	});

    it("replayable p2p ctor with entity authentication data", function() {
        var builder, peerServiceTokens;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });

            // Peer service tokens may be created with the key response data master
            // token. The peer key response data master token has the same serial
            // number as the original peer master token so we can use the same peer
            // user ID token.
            MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
                result: function(tks) { peerServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            builder.set(KEY_NON_REPLAYABLE_ID, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);    
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.isEncrypting()).toBeTruthy();
            expect(messageHeader.nonReplayableId).toBeFalsy();
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
            expect(messageHeader.messageCapabilities).toEqual(CAPABILITIES);
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toEqual(PEER_ENTITY_AUTH_DATA);
            var keyRequestData = messageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, PEER_KEY_REQUEST_DATA)).toBeTruthy();
            expect(messageHeader.keyResponseData).toEqual(PEER_KEY_RESPONSE_DATA);
            expect(messageHeader.masterToken).toBeNull();
            expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toEqual(PEER_MASTER_TOKEN);
            expect(Arrays.contains(messageHeader.peerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(messageHeader.peerUserIdToken).toEqual(PEER_USER_ID_TOKEN);
            var serviceTokens = builder.getServiceTokens();
            expect(Arrays.contains(messageHeader.serviceTokens, serviceTokens)).toBeTruthy();
            expect(messageHeader.userAuthenticationData).toEqual(USER_AUTH_DATA);
            expect(messageHeader.userIdToken).toBeNull();
            expect(messageHeader.user).toBeNull();
        });
    });

	it("p2p mslobject with entity authentication data is correct", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });

			// Peer service tokens may be created with the key response data master
			// token. The peer key response data master token has the same serial
			// number as the original peer master token so we can use the same peer
			// user ID token.
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var cryptoContext;
		runs(function() {
			var scheme = PEER_ENTITY_AUTH_DATA.scheme;
			var factory = p2pCtx.getEntityAuthenticationFactory(scheme);
			cryptoContext = factory.getCryptoContext(p2pCtx, PEER_ENTITY_AUTH_DATA);
		});
		waitsFor(function() { return cryptoContext; }, "cryptoContext not received", MslTestConstants.TIMEOUT);
		
		var mo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { mo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

		var headerdata, ciphertext, signature;
        runs(function() {
            var entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
            expect(entityAuthDataMo).toEqual(PEER_ENTITY_AUTH_DATA_MO);
            expect(mo.has(KEY_MASTER_TOKEN)).toBeFalsy();
            ciphertext = mo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    headerdata = encoder.parseObject(plaintext);
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return headerdata && ciphertext && signature; }, "header data and ciphertext and signature not received", MslTestConstants.TIMEOUT);
		
		var verified;
		runs(function() {
		    cryptoContext.verify(ciphertext, signature, encoder, {
		        result: function(v) { verified = v; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return verified !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
		
		var serviceTokensMa, peerServiceTokensMa;
		runs(function() {
			var serviceTokens = builder.getServiceTokens();
			MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens, {
				result: function(x) { serviceTokensMa = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MslEncoderUtils.createArray(p2pCtx, format, peerServiceTokens, {
				result: function(x) { peerServiceTokensMa = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokensMa && peerServiceTokensMa; }, "service tokens", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(headerdata.getLong(KEY_NON_REPLAYABLE_ID)).toEqual(NON_REPLAYABLE_ID);
            expect(headerdata.getBoolean(KEY_RENEWABLE)).toEqual(RENEWABLE);
            expect(headerdata.getBoolean(KEY_HANDSHAKE)).toEqual(HANDSHAKE);
            expect(headerdata.getMslObject(KEY_CAPABILITIES, encoder)).toEqual(CAPABILITIES_MO);
            expect(headerdata.getMslArray(KEY_KEY_REQUEST_DATA)).toEqual(PEER_KEY_REQUEST_DATA_MA);
            expect(headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)).toEqual(PEER_KEY_RESPONSE_DATA_MO);
            expect(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP))).toBeTruthy();
            expect(headerdata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
            expect(headerdata.getMslObject(KEY_PEER_MASTER_TOKEN, encoder)).toEqual(PEER_MASTER_TOKEN_MO);
            expect(headerdata.getMslArray(KEY_PEER_SERVICE_TOKENS)).toEqual(peerServiceTokensMa);
            expect(headerdata.getMslObject(KEY_PEER_USER_ID_TOKEN, encoder)).toEqual(PEER_USER_ID_TOKEN_MO);
            expect(headerdata.getMslArray(KEY_SERVICE_TOKENS)).toEqual(serviceTokensMa);
            expect(headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA)).toEqual(USER_AUTH_DATA_MO);
            expect(headerdata.has(KEY_USER_ID_TOKEN)).toBeFalsy();
        });
	});

    it("replayable p2p mslobject with entity authentication data is correct", function() {
        var builder, peerServiceTokens;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });

            // Peer service tokens may be created with the key response data master
            // token. The peer key response data master token has the same serial
            // number as the original peer master token so we can use the same peer
            // user ID token.
            MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
                result: function(tks) { peerServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            builder.set(KEY_NON_REPLAYABLE_ID, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var cryptoContext;
        runs(function() {
            var scheme = PEER_ENTITY_AUTH_DATA.scheme;
            var factory = p2pCtx.getEntityAuthenticationFactory(scheme);
            cryptoContext = factory.getCryptoContext(p2pCtx, PEER_ENTITY_AUTH_DATA);
        });
        waitsFor(function() { return cryptoContext; }, "cryptoContext not received", MslTestConstants.TIMEOUT);
		
		var mo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { mo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var headerdata, ciphertext, signature;
        runs(function() {
            var entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
            expect(entityAuthDataMo).toEqual(PEER_ENTITY_AUTH_DATA_MO);
            expect(mo.has(KEY_MASTER_TOKEN)).toBeFalsy();
            ciphertext = mo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    headerdata = encoder.parseObject(plaintext);
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return headerdata && ciphertext && signature; }, "header data and ciphertext and signature not received", MslTestConstants.TIMEOUT);
        
        var verified;
        runs(function() {
            cryptoContext.verify(ciphertext, signature, encoder, {
                result: function(v) { verified = v; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return verified !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
		
		var serviceTokensMa, peerServiceTokensMa;
		runs(function() {
			var serviceTokens = builder.getServiceTokens();
			MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens, {
				result: function(x) { serviceTokensMa = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MslEncoderUtils.createArray(p2pCtx, format, peerServiceTokens, {
				result: function(x) { peerServiceTokensMa = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokensMa && peerServiceTokensMa; }, "service tokens", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(headerdata.has(KEY_NON_REPLAYABLE_ID)).toBeFalsy();
            expect(headerdata.getBoolean(KEY_RENEWABLE)).toEqual(RENEWABLE);
            expect(headerdata.getBoolean(KEY_HANDSHAKE)).toEqual(HANDSHAKE);
            expect(headerdata.getMslObject(KEY_CAPABILITIES, encoder)).toEqual(CAPABILITIES_MO);
            expect(headerdata.getMslArray(KEY_KEY_REQUEST_DATA)).toEqual(PEER_KEY_REQUEST_DATA_MA);
            expect(headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)).toEqual(PEER_KEY_RESPONSE_DATA_MO);
            expect(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP))).toBeTruthy();
            expect(headerdata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
            expect(headerdata.getMslObject(KEY_PEER_MASTER_TOKEN, encoder)).toEqual(PEER_MASTER_TOKEN_MO);
            expect(headerdata.getMslArray(KEY_PEER_SERVICE_TOKENS)).toEqual(peerServiceTokensMa);
            expect(headerdata.getMslObject(KEY_PEER_USER_ID_TOKEN, encoder)).toEqual(PEER_USER_ID_TOKEN_MO);
            expect(headerdata.getMslArray(KEY_SERVICE_TOKENS)).toEqual(serviceTokensMa);
            expect(headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA)).toEqual(USER_AUTH_DATA_MO);
            expect(headerdata.has(KEY_USER_ID_TOKEN)).toBeFalsy();
        });
    });

	it("ctor with master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
			// Service tokens may be created with the key response data tokens. The
			// key response data master token has the same serial number as the
			// original master token so we can use the same user ID token.
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);    
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.isEncrypting()).toBeTruthy();
            expect(messageHeader.nonReplayableId).toEqual(NON_REPLAYABLE_ID);
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
			expect(messageHeader.messageCapabilities).toEqual(CAPABILITIES);
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toBeNull();
            var keyRequestData = messageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, KEY_REQUEST_DATA)).toBeTruthy();
            expect(messageHeader.keyResponseData).toEqual(KEY_RESPONSE_DATA);
            expect(messageHeader.masterToken).toEqual(MASTER_TOKEN);
            expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toBeNull();
            expect(messageHeader.peerServiceTokens.length).toEqual(0);
            expect(messageHeader.peerUserIdToken).toBeNull();
            var serviceTokens = builder.getServiceTokens();
            expect(Arrays.contains(messageHeader.serviceTokens, serviceTokens)).toBeTruthy();
            expect(messageHeader.userAuthenticationData).toEqual(USER_AUTH_DATA);
            expect(messageHeader.userIdToken).toEqual(USER_ID_TOKEN);
            expect(messageHeader.user).toEqual(USER_ID_TOKEN.user);
        });
	});

	it("mslobject is correct with master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
			// Service tokens may be created with the key response data tokens. The
			// key response data master token has the same serial number as the
			// original master token so we can use the same user ID token.
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var mo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { mo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

        var cryptoContext, headerdata, ciphertext, signature;
        runs(function() {
            cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
            expect(mo.has(KEY_ENTITY_AUTHENTICATION_DATA)).toBeFalsy();
            var masterToken = mo.getMslObject(KEY_MASTER_TOKEN, encoder);
            expect(masterToken).toEqual(MASTER_TOKEN_MO);
            ciphertext = mo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    headerdata = encoder.parseObject(plaintext);
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return cryptoContext && headerdata && ciphertext && signature; }, "crypto context and header data and ciphertext and signature not received", MslTestConstants.TIMEOUT);
		
		var verified;
		runs(function() {
		    cryptoContext.verify(ciphertext, signature, encoder, {
		        result: function(v) { verified = v; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return verified !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
		
		var serviceTokensMa;
		runs(function() {
			var serviceTokens = builder.getServiceTokens();
			MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens, {
				result: function(x) { serviceTokensMa = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokensMa; }, "service tokens", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(headerdata.getLong(KEY_NON_REPLAYABLE_ID)).toEqual(NON_REPLAYABLE_ID);
            expect(headerdata.getBoolean(KEY_RENEWABLE)).toEqual(RENEWABLE);
            expect(headerdata.getBoolean(KEY_HANDSHAKE)).toEqual(HANDSHAKE);
            expect(headerdata.getMslObject(KEY_CAPABILITIES, encoder)).toEqual(CAPABILITIES_MO);
            expect(headerdata.getMslArray(KEY_KEY_REQUEST_DATA)).toEqual(KEY_REQUEST_DATA_MA);
            expect(headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)).toEqual(KEY_RESPONSE_DATA_MO);
            expect(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP))).toBeTruthy();
            expect(headerdata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
            expect(headerdata.has(KEY_PEER_MASTER_TOKEN)).toBeFalsy();
            expect(headerdata.has(KEY_PEER_SERVICE_TOKENS)).toBeFalsy();
            expect(headerdata.has(KEY_PEER_USER_ID_TOKEN)).toBeFalsy();
            expect(headerdata.getMslArray(KEY_SERVICE_TOKENS)).toEqual(serviceTokensMa);
            expect(headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)).toEqual(USER_AUTH_DATA_MO);
            expect(headerdata.getMslObject(KEY_USER_ID_TOKEN)).toEqual(USER_ID_TOKEN_MO);
        });
	});

	it("p2p ctor with master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
			// The key response data master token has the same serial number as
			// the original master token so we can use the same service tokens and
			// user ID token.
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			// Peer service tokens may be created with the key response data master
			// token. The peer key response data master token has the same serial
			// number as the original peer master token so we can use the same peer
			// user ID token.
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);    
			MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.isEncrypting()).toBeTruthy();
            expect(messageHeader.nonReplayableId).toEqual(NON_REPLAYABLE_ID);
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
			expect(messageHeader.messageCapabilities).toEqual(CAPABILITIES);
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toBeNull();
            var keyRequestData = messageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, PEER_KEY_REQUEST_DATA)).toBeTruthy();
            expect(messageHeader.keyResponseData).toEqual(PEER_KEY_RESPONSE_DATA);
            expect(messageHeader.masterToken).toEqual(MASTER_TOKEN);
            expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toEqual(PEER_MASTER_TOKEN);
            expect(Arrays.contains(messageHeader.peerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(messageHeader.peerUserIdToken).toEqual(PEER_USER_ID_TOKEN);
            var serviceTokens = builder.getServiceTokens();
            expect(Arrays.contains(messageHeader.serviceTokens, serviceTokens)).toBeTruthy();
            expect(messageHeader.userAuthenticationData).toEqual(USER_AUTH_DATA);
            expect(messageHeader.userIdToken).toEqual(USER_ID_TOKEN);
            expect(messageHeader.user).toEqual(USER_ID_TOKEN.user);
        });
	});

	it("p2p mslobject is correct with master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
			// The key response data master token has the same serial number as
			// the original master token so we can use the same service tokens and
			// user ID token.
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			// Peer service tokens may be created with the key response data master
			// token. The peer key response data master token has the same serial
			// number as the original peer master token so we can use the same peer
			// user ID token.
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var mo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { mo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);

		var cryptoContext, headerdata, ciphertext, signature;
        runs(function() {
            cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
            expect(mo.has(KEY_ENTITY_AUTHENTICATION_DATA)).toBeFalsy();
            var masterToken = mo.getMslObject(KEY_MASTER_TOKEN, encoder);
            expect(masterToken).toEqual(MASTER_TOKEN_MO);
            ciphertext = mo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    headerdata = encoder.parseObject(plaintext);
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            signature = mo.getBytes(KEY_SIGNATURE);
        });
        waitsFor(function() { return cryptoContext && headerdata && ciphertext && signature; }, "crypto context and header data and ciphertext and signature not received", MslTestConstants.TIMEOUT);
		
		var verified;
		runs(function() {
		    cryptoContext.verify(ciphertext, signature, encoder, {
		        result: function(v) { verified = v; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return verified !== undefined; }, "verified not received", MslTestConstants.TIMEOUT);
		
		var serviceTokensMa;
		runs(function() {
			var serviceTokens = builder.getServiceTokens();
			MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens, {
				result: function(x) { serviceTokensMa = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokensMa; }, "service tokens", MslTestConstants.TIMEOUT);
		
		var peerServiceTokensMa;
		runs(function() {
			MslEncoderUtils.createArray(trustedNetCtx, format, peerServiceTokens, {
				result: function(x) { peerServiceTokensMa = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return peerServiceTokensMa; }, "peer service tokens", MslTestConstants.TIMEOUT);
		

        runs(function() {
            expect(headerdata.getLong(KEY_NON_REPLAYABLE_ID)).toEqual(NON_REPLAYABLE_ID);
            expect(headerdata.getBoolean(KEY_RENEWABLE)).toEqual(RENEWABLE);
            expect(headerdata.getBoolean(KEY_HANDSHAKE)).toEqual(HANDSHAKE);
            expect(headerdata.getMslObject(KEY_CAPABILITIES, encoder)).toEqual(CAPABILITIES_MO);
            expect(headerdata.getMslArray(KEY_KEY_REQUEST_DATA)).toEqual(PEER_KEY_REQUEST_DATA_MA);
            expect(headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)).toEqual(PEER_KEY_RESPONSE_DATA_MO);
            expect(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP))).toBeTruthy();
            expect(headerdata.getLong(KEY_MESSAGE_ID)).toEqual(MESSAGE_ID);
            expect(headerdata.getMslObject(KEY_PEER_MASTER_TOKEN, encoder)).toEqual(PEER_MASTER_TOKEN_MO);
            expect(headerdata.getMslArray(KEY_PEER_SERVICE_TOKENS)).toEqual(peerServiceTokensMa);
            expect(headerdata.getMslObject(KEY_PEER_USER_ID_TOKEN, encoder)).toEqual(PEER_USER_ID_TOKEN_MO);
            expect(headerdata.getMslArray(KEY_SERVICE_TOKENS)).toEqual(serviceTokensMa);
            expect(headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)).toEqual(USER_AUTH_DATA_MO);
            expect(headerdata.getMslObject(KEY_USER_ID_TOKEN)).toEqual(USER_ID_TOKEN_MO);
        });
	});

	it("ctor with entity authentication data and null arguments", function() {
	    var builder;
	    runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
	    });
	    waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
	    
		var messageHeader;
		runs(function() {
	        builder.set(KEY_CAPABILITIES, null);
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
	        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
			var headerData = builder.build();
			var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.isEncrypting()).toBeTruthy();
            expect(messageHeader.nonReplayableId).toEqual(NON_REPLAYABLE_ID);
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
			expect(messageHeader.messageCapabilities).toBeNull();
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toEqual(PEER_ENTITY_AUTH_DATA);
            expect(messageHeader.keyRequestData.length).toEqual(0);
            expect(messageHeader.keyResponseData).toBeNull();
            expect(messageHeader.masterToken).toBeNull();
            expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toBeNull();
            expect(messageHeader.peerServiceTokens.length).toEqual(0);
            expect(messageHeader.peerUserIdToken).toBeNull();
            expect(messageHeader.serviceTokens.length).toEqual(0);
            expect(messageHeader.userAuthenticationData).toBeNull();
            expect(messageHeader.userIdToken).toBeNull();
            expect(messageHeader.user).toBeNull();
        });
	});

	it("ctor with entity authentication data and empty arguments", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeader;
		runs(function() {
            var serviceTokens = [];
            var keyRequestData = [];
            builder.set(KEY_CAPABILITIES, null);
            builder.set(KEY_KEY_REQUEST_DATA, keyRequestData);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            builder.set(KEY_USER_AUTHENTICATION_DATA, null);
            builder.set(KEY_SERVICE_TOKENS, serviceTokens);
            var headerData = builder.build();
			var peerServiceTokens = [];
			var peerData = new HeaderPeerData(null, null, peerServiceTokens);
			MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.isEncrypting()).toBeTruthy();
            expect(messageHeader.nonReplayableId).toEqual(NON_REPLAYABLE_ID);
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
			expect(messageHeader.messageCapabilities).toBeNull();
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toEqual(PEER_ENTITY_AUTH_DATA);
            expect(messageHeader.keyRequestData.length).toEqual(0);
            expect(messageHeader.keyResponseData).toBeNull();
            expect(messageHeader.masterToken).toBeNull();
            expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toBeNull();
            expect(messageHeader.peerServiceTokens.length).toEqual(0);
            expect(messageHeader.peerUserIdToken).toBeNull();
            expect(messageHeader.serviceTokens.length).toEqual(0);
            expect(messageHeader.userAuthenticationData).toBeNull();
            expect(messageHeader.userIdToken).toBeNull();
            expect(messageHeader.user).toBeNull();
        });
	});

	it("ctor with master token and null arguments", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeader;
		runs(function() {
            builder.set(KEY_CAPABILITIES, null);
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            builder.set(KEY_USER_AUTHENTICATION_DATA, null);
			var headerData = builder.build();
			var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(p2pCtx, null, PEER_MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.isEncrypting()).toBeTruthy();
            expect(messageHeader.nonReplayableId).toEqual(NON_REPLAYABLE_ID);
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
			expect(messageHeader.messageCapabilities).toBeNull();
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toBeNull();
            expect(messageHeader.keyRequestData.length).toEqual(0);
            expect(messageHeader.keyResponseData).toBeNull();
            expect(messageHeader.masterToken).toEqual(PEER_MASTER_TOKEN);
            expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toBeNull();
            expect(messageHeader.peerServiceTokens.length).toEqual(0);
            expect(messageHeader.peerUserIdToken).toBeNull();
            expect(messageHeader.serviceTokens.length).toEqual(0);
            expect(messageHeader.userAuthenticationData).toBeNull();
            expect(messageHeader.userIdToken).toBeNull();
            expect(messageHeader.user).toBeNull();
        });
	});

	it("ctor with master token and empty arguments", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeader;
		runs(function() {
			var serviceTokens = [];
			var keyRequestData = [];
	        builder.set(KEY_CAPABILITIES, null);
	        builder.set(KEY_KEY_REQUEST_DATA, keyRequestData);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
	        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
	        builder.set(KEY_SERVICE_TOKENS, serviceTokens);
			var headerData = builder.build();
			var peerServiceTokens = [];
			var peerData = new HeaderPeerData(null, null, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, PEER_MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.isEncrypting()).toBeTruthy();
            expect(messageHeader.nonReplayableId).toEqual(NON_REPLAYABLE_ID);
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
			expect(messageHeader.messageCapabilities).toBeNull();
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toBeNull();
            expect(messageHeader.keyRequestData.length).toEqual(0);
            expect(messageHeader.keyResponseData).toBeNull();
            expect(messageHeader.masterToken).toEqual(PEER_MASTER_TOKEN);
            expect(isAboutNow(messageHeader.timestamp)).toBeTruthy();
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toBeNull();
            expect(messageHeader.peerServiceTokens.length).toEqual(0);
            expect(messageHeader.peerUserIdToken).toBeNull();
            expect(messageHeader.serviceTokens.length).toEqual(0);
            expect(messageHeader.userAuthenticationData).toBeNull();
            expect(messageHeader.userIdToken).toBeNull();
            expect(messageHeader.user).toBeNull();
        });
	});

	it("ctor with RSA entity authentication data is not encrypting", function() {
		var rsaCtx;
		runs(function() {
		    MockMslContext.create(EntityAuthenticationScheme.RSA, false, {
		        result: function(c) { rsaCtx = c; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return rsaCtx; }, "rsaCtx", MslTestConstants.TIMEOUT);

		var entityAuthData;
		runs(function() {
			rsaCtx.getEntityAuthenticationData(null, {
				result: function(x) { entityAuthData = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return entityAuthData; }, "entityAuthData not received", MslTestConstants.TIMEOUT);

        var builder;
        runs(function() {
            HeaderDataBuilder$create(rsaCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeader;
		runs(function() {
	        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
			var headerData = builder.build();
			var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(rsaCtx, entityAuthData, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
    		expect(messageHeader.isEncrypting()).toBeFalsy();
    	});
	});

	it("ctor missing both authentication data", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
	    var exception;
	    runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with user ID token and null master token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
	    var exception;
	    runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
	        var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with user ID token and mismatched master token", function() {
		var userIdToken;
		runs(function() {
		    MslTestUtils.getUserIdToken(trustedNetCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
		        result: function(t) { userIdToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);

        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, userIdToken, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var exception;
	    runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with service token and null master token", function() {
		var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var exception;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with service token and mismatched master token", function() {
		var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, PEER_MASTER_TOKEN, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var exception;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
	        builder.set(KEY_USER_ID_TOKEN, USER_ID_TOKEN);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
		waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
		
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with service token and null user ID token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var exception;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
	        builder.set(KEY_USER_ID_TOKEN, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
        
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with service token and mismatched user ID token", function() {
		// Technically the implementation does not hit this check because it
		// will bail out earlier, but in case the implementation changes the
		// order of checks (which it should not) this test will catch it.
		//
		// We cannot construct inconsistent service tokens via the ServiceToken
		// ctor, so pass in a mismatched user ID token.
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
	        builder.set(KEY_USER_ID_TOKEN, PEER_USER_ID_TOKEN);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with peer user ID token and null peer master token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
	    var exception;
	    runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, PEER_USER_ID_TOKEN, null);
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with peer user ID token and mismatched peer master token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var peerUserIdToken;
		runs(function() {
		    MslTestUtils.getUserIdToken(p2pCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
		        result: function(t) { peerUserIdToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return peerUserIdToken; }, "peerUserIdToken not received", MslTestConstants.TIMEOUT);
		
		var exception;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, peerUserIdToken, null);
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with peer service token and null master token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var peerServiceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, null, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return peerServiceTokens; }, "peerServiceTokens not received", MslTestConstants.TIMEOUT);
		
		var exception;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, peerServiceTokens);
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with peer service token and mismatched master token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var peerServiceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, null, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return peerServiceTokens; }, "peerServiceTokens not received", MslTestConstants.TIMEOUT);
		var exception;
		
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, null, peerServiceTokens);
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with peer service token and null user ID token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var peerServiceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return peerServiceTokens; }, "peerServiceTokens not received", MslTestConstants.TIMEOUT);
		
		var exception;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, null, peerServiceTokens);
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with peer service token and mismatched user ID token", function() {
		// Technically the implementation does not hit this check because it
		// will bail out earlier, but in case the implementation changes the
		// order of checks (which it should not) this test will catch it.
		//
		// We cannot construct inconsistent service tokens via the ServiceToken
		// ctor, so pass in a mismatched user ID token.
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var peerServiceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return peerServiceTokens; }, "peerServiceTokens not received", MslTestConstants.TIMEOUT);
		
		var exception;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, USER_ID_TOKEN, peerServiceTokens);
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with untrusted master token", function() {
		var masterToken;
		runs(function() {
		    MslTestUtils.getUntrustedMasterToken(p2pCtx, {
		        result: function(t) { masterToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var exception;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
            MessageHeader.create(p2pCtx, null, masterToken, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED), MESSAGE_ID);
		});
	});

	it("ctor with unsupported entity authentication scheme", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var builder;
        runs(function() {
            HeaderDataBuilder$create(ctx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            ctx.removeEntityAuthenticationFactory(ENTITY_AUTH_DATA.scheme);

            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND), MESSAGE_ID);
		});
	});

	it("ctor with master token and cached crypto context", function() {
		// We should be okay with an untrusted master token if a crypto context
		// is associated with it.
		var masterToken;
		runs(function() {
		    MslTestUtils.getUntrustedMasterToken(p2pCtx, {
		        result: function(t) { masterToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);
		runs(function() {
            var cryptoContext = new NullCryptoContext();
            p2pCtx.getMslStore().setCryptoContext(masterToken, cryptoContext);
        });

		var userIdToken;
		runs(function() {
		    MslTestUtils.getUserIdToken(p2pCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
		        result: function(t) { userIdToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);
		
		var builder, peerServiceTokens;
		runs(function() {
		    HeaderDataBuilder$create(p2pCtx, masterToken, null, true, {
		        result: function(x) { builder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
		    builder.set(KEY_USER_ID_TOKEN, userIdToken);
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, masterToken, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeader.nonReplayableId).toEqual(NON_REPLAYABLE_ID);
            expect(messageHeader.isRenewable()).toEqual(RENEWABLE);
			expect(messageHeader.isHandshake()).toEqual(HANDSHAKE);
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(messageHeader.entityAuthenticationData).toBeNull();
            var keyRequestData = messageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, PEER_KEY_REQUEST_DATA)).toBeTruthy();
            expect(messageHeader.keyResponseData).toEqual(PEER_KEY_RESPONSE_DATA);
            expect(messageHeader.masterToken).toEqual(masterToken);
            expect(messageHeader.messageId).toEqual(MESSAGE_ID);
            expect(messageHeader.peerMasterToken).toEqual(PEER_MASTER_TOKEN);
            expect(Arrays.contains(messageHeader.peerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(messageHeader.peerUserIdToken).toEqual(PEER_USER_ID_TOKEN);
            var serviceTokens = builder.getServiceTokens();
            expect(Arrays.contains(messageHeader.serviceTokens, serviceTokens)).toBeTruthy();
            expect(messageHeader.userAuthenticationData).toEqual(USER_AUTH_DATA);
            expect(messageHeader.userIdToken).toEqual(userIdToken);
            expect(messageHeader.user).toEqual(userIdToken.user);
        });
	});

	it("parseHeader with entity authentication data", function() {
		var builder, peerServiceTokens;
		runs(function() {
			// Service tokens may be created with the key response data tokens. The
			// key response data master token has the same serial number as the
			// original master token so we can use the same user ID token.
		    HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var header;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function(h) { header = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(messageHeader.peerMasterToken).toBeNull();
            expect(messageHeader.peerServiceTokens.length).toEqual(0);
            expect(messageHeader.peerUserIdToken).toBeNull();
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).toEqual(messageHeader.user);
        });
	});

	it("p2p parseHeader with entity authentication data", function() {
		// Service tokens may be created with the key response data tokens. The
		// key response data master token has the same serial number as the
		// original master token so we can use the same user ID token.
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and peerServiceTokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var header;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function(h) { header = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toEqual(messageHeader.peerMasterToken);
            var moPeerServiceTokens = moMessageHeader.peerServiceTokens;
            expect(Arrays.contains(peerServiceTokens, moPeerServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moPeerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(moMessageHeader.peerUserIdToken).toEqual(messageHeader.peerUserIdToken);
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).not.toBeNull();
        });
	});

	it("parseHeader with master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var header;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function(h) { header = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toBeNull();
            expect(moMessageHeader.peerServiceTokens.length).toEqual(0);
            expect(moMessageHeader.peerUserIdToken).toBeNull();
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).toEqual(messageHeader.user);
        });
	});

	it("p2p parseHeader with master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
				
		var messageHeader;
		runs(function() {
            var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var header;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function(h) { header = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toEqual(messageHeader.peerMasterToken);
            var moPeerServiceTokens = moMessageHeader.peerServiceTokens;
            expect(Arrays.contains(peerServiceTokens, moPeerServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moPeerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(moMessageHeader.peerUserIdToken).toEqual(messageHeader.peerUserIdToken);
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).toEqual(messageHeader.user);
        });
	});

	it("parseHeader with user authentication data", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var header;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function(h) { header = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toBeNull();
            expect(moMessageHeader.peerServiceTokens.length).toEqual(0);
            expect(moMessageHeader.peerUserIdToken).toBeNull();
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).not.toBeNull();
        });
	});

	it("p2p parseHeader with user authentication data", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
            var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
				MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var header;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function(h) { header = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toEqual(messageHeader.peerMasterToken);
            var moPeerServiceTokens = moMessageHeader.peerServiceTokens;
            expect(Arrays.contains(peerServiceTokens, moPeerServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moPeerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(moMessageHeader.peerUserIdToken).toEqual(messageHeader.peerUserIdToken);
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).not.toBeNull();
        });
	});

	it("parseHeader with untrusted master token", function() {
		// We can first create a message header with an untrusted master token
		// by having a cached crypto context.
		var masterToken;
		runs(function() {
		    MslTestUtils.getUntrustedMasterToken(p2pCtx, {
		        result: function(t) { masterToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

		var userIdToken;
		runs(function() {
            var cryptoContext = new NullCryptoContext();
            p2pCtx.getMslStore().setCryptoContext(masterToken, cryptoContext);
            
		    MslTestUtils.getUserIdToken(p2pCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
		        result: function(t) { userIdToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);
		
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, masterToken, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
	        builder.set(KEY_USER_ID_TOKEN, userIdToken);
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
				MessageHeader.create(p2pCtx, null, masterToken, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            // Removing the cached crypto context means the master token must now
            // be trusted when parsing a message header.
            p2pCtx.getMslStore().clearCryptoContexts();

			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                result: function() {},
		                error: function(err) { exception = err; },
		            });
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED));
		});
	});

	it("parseHeader with unsupported entity authentication scheme", function() {
		// We can first create a message header when the entity authentication
		// scheme is supported.
		var ctx;
		runs(function() {
		    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
		        result: function(c) { ctx = c; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
		
		var builder;
		runs(function() {
            HeaderDataBuilder$create(ctx, null, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
		});
		waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
		
		var entityAuthData;
		runs(function() {
			ctx.getEntityAuthenticationData(null, {
				result: function(x) { entityAuthData = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return entityAuthData; }, "entityAuthData not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
			var headerData = builder.build();
			var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            // Removing support for the entity authentication scheme will now fail
            // parsing of message headers.
            ctx.removeEntityAuthenticationFactory(entityAuthData.scheme);

			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            Header.parseHeader(ctx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                result: function() {},
		                error: function(err) { exception = err; },
		            });
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND));
		});
	});

	it("parseHeader with unsupported user authentication scheme", function() {
		// We can first create a message header when the user authentication
		// scheme is supported.
		var ctx;
		runs(function() {
		    MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
		        result: function(c) { ctx = c; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(ctx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
		    builder.set(KEY_KEY_REQUEST_DATA, null);
		    builder.set(KEY_KEY_RESPONSE_DATA, null);
			var headerData = builder.build();
			var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(ctx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            // Remove support for the user authentication scheme will now fail
            // user authentication.
            ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.scheme);

			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            Header.parseHeader(ctx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                result: function() {},
		                error: function(err) { exception = err; },
		            });
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND), MESSAGE_ID);
		});
	});

	it("parseHeader with master token and cached crypto context", function() {
		// We should be okay with an untrusted master token if a crypto context
		// is associated with it.
		var masterToken;
		runs(function() {
		    MslTestUtils.getUntrustedMasterToken(p2pCtx, {
		        result: function(t) { masterToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

		var userIdToken;
		runs(function() {
            var cryptoContext = new NullCryptoContext();
            p2pCtx.getMslStore().setCryptoContext(masterToken, cryptoContext);
            
		    MslTestUtils.getUserIdToken(p2pCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
		        result: function(t) { userIdToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);
		
		var builder, peerServiceTokens;
		runs(function() {
		    HeaderDataBuilder$create(p2pCtx, masterToken, null, true, {
		        result: function(x) { builder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
		    builder.set(KEY_USER_ID_TOKEN, userIdToken);
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, masterToken, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var header;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function(h) { header = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            // The reconstructed untrusted service token won't pass tests for
            // equality.
            expect(moMessageHeader.masterToken).not.toBeNull();
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toEqual(messageHeader.peerMasterToken);
            var moPeerServiceTokens = moMessageHeader.peerServiceTokens;
            expect(Arrays.contains(peerServiceTokens, moPeerServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moPeerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(moMessageHeader.peerUserIdToken).toEqual(messageHeader.peerUserIdToken);
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).toEqual(messageHeader.user);
        });
	});

	it("parseHeader with invalid entity authentication data", function() {
	    var builder;
	    runs(function() {
	        HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
	    });
	    waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
	    
		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            messageHeaderMo.put(KEY_ENTITY_AUTHENTICATION_DATA, "x");
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function() {},
						error: function(err) { exception = err; },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
		});
	});

	it("parseHeader missing both authentication data", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            messageHeaderMo.remove(KEY_ENTITY_AUTHENTICATION_DATA);
		            messageHeaderMo.remove(KEY_MASTER_TOKEN);
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function() {},
						error: function(err) { exception = err; },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND));
		});
	});

	it("parseHeader with invalid master token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeader;
		runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            messageHeaderMo.put(KEY_MASTER_TOKEN, "x");
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function() {},
						error: function(err) { exception = err; },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
		});
	});

	it("parseHeader with missing signature", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeader;
		runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            messageHeaderMo.remove(KEY_SIGNATURE);
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function() {},
						error: function(err) { exception = err; },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
		});
	});

    it("parseHeader with invalid signature", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            messageHeaderMo.put(KEY_SIGNATURE, "x");
		            Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                result: function() {},
		                error: function(err) { exception = err; },
		            });
				},
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

	it("parseHeader with incorrect signature", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            messageHeaderMo.put(KEY_SIGNATURE, Base64.decode("AAA="));
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function() {},
						error: function(err) { exception = err; },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslCryptoException(MslError.MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED));
		});
	});

	it("parseHeader with missing headerdata", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var exception;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            messageHeaderMo.remove(KEY_HEADERDATA);
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function() {},
						error: function(err) { exception = err; },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
		});
	});

	it("parseHeader with invalid headerdata", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					messageHeaderMo.put(KEY_HEADERDATA, "x");
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function() {},
						error: function(err) { exception = err; },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
		});
	});

	it("parseHeader with corrupt headerdata", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
		            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
		            ++ciphertext[0];
		            messageHeaderMo.put(KEY_HEADERDATA, ciphertext);
					Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function() {},
						error: function(err) { exception = err; },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslCryptoException(MslError.MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED));
		});
	});

	it("p2p parseHeader with missing pairs(?) and entity authentication data", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
	        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var header;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function(h) { header = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toEqual(messageHeader.peerMasterToken);
            var peerServiceTokens = messageHeader.peerServiceTokens;
            var moPeerServiceTokens = moMessageHeader.peerServiceTokens;
            expect(Arrays.contains(peerServiceTokens, moPeerServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moPeerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(moMessageHeader.peerUserIdToken).toEqual(messageHeader.peerUserIdToken);
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).toEqual(messageHeader.user);
        });
	});

	it("p2p parseHeader with empty arrays and entity authentication data", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            builder.set(KEY_USER_AUTHENTICATION_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(p2pCtx, PEER_ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var cryptoContext;
		runs(function() {
            var scheme = PEER_ENTITY_AUTH_DATA.scheme;
            var factory = p2pCtx.getEntityAuthenticationFactory(scheme);
			cryptoContext = factory.getCryptoContext(p2pCtx, PEER_ENTITY_AUTH_DATA);
		});
		waitsFor(function() { return cryptoContext; }, "cryptoContext not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var header;
		runs(function() {
            // Before modifying the header data we need to decrypt it.
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_KEY_REQUEST_DATA, encoder.createArray());
                    headerdataMo.put(KEY_SERVICE_TOKENS, encoder.createArray());
                    headerdataMo.put(KEY_PEER_SERVICE_TOKENS, encoder.createArray());
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function(h) { header = h; },
		                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                    	},
                    	error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toEqual(messageHeader.peerMasterToken);
            var peerServiceTokens = messageHeader.peerServiceTokens;
            var moPeerServiceTokens = moMessageHeader.peerServiceTokens;
            expect(Arrays.contains(peerServiceTokens, moPeerServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moPeerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(moMessageHeader.peerUserIdToken).toEqual(messageHeader.peerUserIdToken);
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).toEqual(messageHeader.user);
        });
	});

	it("p2p parseHeader with missing pairs(?) and master token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            builder.set(KEY_USER_AUTHENTICATION_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		var header;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(messageHeaderMo) {
					Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
						result: function(h) { header = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toEqual(messageHeader.peerMasterToken);
            var peerServiceTokens = messageHeader.peerServiceTokens;
            var moPeerServiceTokens = moMessageHeader.peerServiceTokens;
            expect(Arrays.contains(peerServiceTokens, moPeerServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moPeerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(moMessageHeader.peerUserIdToken).toEqual(messageHeader.peerUserIdToken);
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).toEqual(messageHeader.user);
        });
	});

	it("p2p parseHeader with empty arrays and master token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            builder.set(KEY_USER_AUTHENTICATION_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var header;
		runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_KEY_REQUEST_DATA, encoder.createArray());
                    headerdataMo.put(KEY_SERVICE_TOKENS, encoder.createArray());
                    headerdataMo.put(KEY_PEER_SERVICE_TOKENS, encoder.createArray());
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function(h) { header = h; },
		                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
		});
		waitsFor(function() { return header; }, "header not received", 200);
		
		runs(function() {
            expect(header).not.toBeNull();
            expect(header instanceof MessageHeader).toBeTruthy();
            var moMessageHeader = header;
    
            expect(moMessageHeader.nonReplayableId).toEqual(messageHeader.nonReplayableId);
            expect(moMessageHeader.isRenewable()).toEqual(messageHeader.isRenewable());
            expect(messageHeader.cryptoContext).not.toBeNull();
            expect(moMessageHeader.entityAuthenticationData).toEqual(messageHeader.entityAuthenticationData);
            var keyRequestData = messageHeader.keyRequestData;
            var moKeyRequestData = moMessageHeader.keyRequestData;
            expect(Arrays.contains(keyRequestData, moKeyRequestData)).toBeTruthy();
            expect(Arrays.contains(moKeyRequestData, keyRequestData)).toBeTruthy();
            expect(moMessageHeader.keyResponseData).toEqual(messageHeader.keyResponseData);
            expect(moMessageHeader.masterToken).toEqual(messageHeader.masterToken);
            expect(moMessageHeader.messageId).toEqual(messageHeader.messageId);
            expect(moMessageHeader.peerMasterToken).toEqual(messageHeader.peerMasterToken);
            var peerServiceTokens = messageHeader.peerServiceTokens;
            var moPeerServiceTokens = moMessageHeader.peerServiceTokens;
            expect(Arrays.contains(peerServiceTokens, moPeerServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moPeerServiceTokens, peerServiceTokens)).toBeTruthy();
            expect(moMessageHeader.peerUserIdToken).toEqual(messageHeader.peerUserIdToken);
            var serviceTokens = messageHeader.serviceTokens;
            var moServiceTokens = moMessageHeader.serviceTokens;
            expect(Arrays.contains(serviceTokens, moServiceTokens)).toBeTruthy();
            expect(Arrays.contains(moServiceTokens, serviceTokens)).toBeTruthy();
            expect(moMessageHeader.userAuthenticationData).toEqual(messageHeader.userAuthenticationData);
            expect(moMessageHeader.userIdToken).toEqual(messageHeader.userIdToken);
            expect(moMessageHeader.user).toEqual(messageHeader.user);
        });
	});

	it("parseHeader with user ID token and null master token", function() {
		// Since removing the master token will prevent the header data from
		// getting parsed, and removing the master token from the key exchange
		// data will also prevent the header data from getting parsed, the only
		// way to simulate this is to use entity authentication data and insert
		// a user ID token.
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var cryptoContext;
		runs(function() {
            var scheme = ENTITY_AUTH_DATA.scheme;
            var factory = trustedNetCtx.getEntityAuthenticationFactory(scheme);
			cryptoContext = factory.getCryptoContext(trustedNetCtx, ENTITY_AUTH_DATA);
		});
		waitsFor(function() { return cryptoContext; }, "cryptoContext not received", MslTestConstants.TIMEOUT);
        
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(t) { userIdToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
            // Before modifying the header data we need to decrypt it.
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_USER_ID_TOKEN, userIdToken);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                }, error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                    	},
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        }); 
		waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with user ID token and mismatched master token", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(trustedNetCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(t) { userIdToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_USER_ID_TOKEN, userIdToken);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
		waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});
	
	it("parseHeader with user ID token and mismatched user authentication data", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(trustedNetCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(t) { userIdToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    var userAuthData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL_2, MockEmailPasswordAuthenticationFactory.PASSWORD_2);
                    headerdataMo.put(KEY_USER_AUTHENTICATION_DATA, userAuthData);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH), MESSAGE_ID);
        });
	});
    
	it("p2p parseHeader with peer user ID token and missing peer master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
		    HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
		        result: function(x) { builder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens  received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
		    builder.set(KEY_KEY_REQUEST_DATA, null);
		    builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.remove(KEY_PEER_MASTER_TOKEN);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("p2p parseHeader with peer user ID token and mismatched peer master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_PEER_MASTER_TOKEN, MASTER_TOKEN);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslException(MslError.NONE));
        });
    });

	it("parseHeader with service token and mismatched master token", function() {
		var builder, mismatchedTokens;
		runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, null, {
				result: function(tks) { mismatchedTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && mismatchedTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {            
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    var serviceTokens = builder.getServiceTokens();
                    mismatchedTokens.forEach(function(mismatchedToken) {
                        serviceTokens.push(mismatchedToken);
                    }, this);
                    headerdataMo.put(KEY_SERVICE_TOKENS, serviceTokens);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with service token and mismatched user ID token", function() {
        var userIdToken;
		runs(function() {
		    MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
		        result: function(t) { userIdToken = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);

		var builder, mismatchedTokens;
		runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, userIdToken, {
				result: function(tks) { mismatchedTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && mismatchedTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);

		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

		var exception;
		runs(function() {
		    // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    var serviceTokens = builder.getServiceTokens();
                    mismatchedTokens.forEach(function(mismatchedToken) {
                        serviceTokens.push(mismatchedToken);
                    }, this);
                    headerdataMo.put(KEY_SERVICE_TOKENS, serviceTokens);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
		waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("p2p parseHeader with peer service token and missing peer master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, null, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, null, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.remove(KEY_PEER_MASTER_TOKEN);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
                    		cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                    	},
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with peer service token and mismatched peer master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, null, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
		    builder.set(KEY_KEY_REQUEST_DATA, null);
		    builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, null, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_PEER_MASTER_TOKEN, MASTER_TOKEN);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("p2p parseHeader with peer service token and mismatched peer user ID token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
        
        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(t) { userIdToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);

                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_PEER_USER_ID_TOKEN, userIdToken);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("missing timestamp", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            builder.set(KEY_USER_AUTHENTICATION_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
        
        var header;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.remove(KEY_TIMESTAMP);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function(x) { header = x; },
		                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return header; }, "header", 300);
    });

    it("invalid timestamp", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            builder.set(KEY_USER_AUTHENTICATION_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_TIMESTAMP, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(e) { exception = e; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });

	it("p2p parseHeader with missing message ID", function() {
		var builder, peerServiceTokens;
		runs(function() {
		    HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
		        result: function(x) { builder = x; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);

		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.remove(KEY_MESSAGE_ID);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
		});
	});

	it("p2p parseHeader with invalid message ID", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_MESSAGE_ID, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
		});
	});

	it("ctor with negative message ID", function() {
	    var builder;
	    runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
	    });
	    waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
	    
	    var exception;
	    runs(function() {
	        builder.set(KEY_MESSAGE_ID, -1);
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("ctor with too large message ID", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
	    var exception;
	    runs(function() {
	        builder.set(KEY_MESSAGE_ID, MslConstants.MAX_LONG_VALUE + 2);
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function() {},
                error: function(err) { exception = err; },
            });
        });
        waitsFor(function() { return exception; }, "exception not received", MslTestConstants.TIMEOUT);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslInternalException());
		});
	});

	it("parseHeader with negative message ID", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_MESSAGE_ID, -1);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE));
		});
	});

	it("parseHeader with too large message ID", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_MESSAGE_ID, MslConstants.MAX_LONG_VALUE + 2);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE));
		});
	});

	it("parseHeader with invalid non-replayable", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_NON_REPLAYABLE_ID, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR), MESSAGE_ID);
		});
	});

	it("parseHeader with missing renewable", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.remove(KEY_RENEWABLE);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid renewable", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_RENEWABLE, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR), MESSAGE_ID);
		});
	});

    // FIXME It is okay for the handshake flag to be missing for now.
	it("parseHeader with missing handshake", function() {
	    var builder, peerServiceTokens;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
                result: function(tks) { peerServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
            MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
        
        var header;
        //var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.remove(KEY_HANDSHAKE);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function(x) { header = x; },
		                                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        //waitsFor(function() { return exception; }, "exception not received", 300);
        waitsFor(function() { return header; }, "header not received", 300);
        
        runs(function() {
            //var f = function() { throw exception; };
            //expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR), MESSAGE_ID);
            expect(header.isHandshake()).toBeFalsy();
        });
	});
	
	it("parseHeader with invalid handshake", function() {
	    var builder, peerServiceTokens;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
                result: function(tks) { peerServiceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            builder.set(KEY_KEY_REQUEST_DATA, null);
            builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
            MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function(token) { messageHeader = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_HANDSHAKE, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR), MESSAGE_ID);
        });
	});
	
	it("parseHeader with invalid capabilities", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_CAPABILITIES, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid key request data array", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_KEY_REQUEST_DATA, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid key request data", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    var a = encoder.createArray();
                    a.put(-1, "x");
                    headerdataMo.put(KEY_PEER_SERVICE_TOKENS, a);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid service tokens array", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_SERVICE_TOKENS, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid service token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    var a = encoder.createArray();
                    a.put(-1, "x");
                    headerdataMo.put(KEY_SERVICE_TOKENS, a);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid peer service tokens array", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_PEER_SERVICE_TOKENS, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid peer service token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    var a = encoder.createArray();
                    a.put(-1, "x");
                    headerdataMo.put(KEY_PEER_SERVICE_TOKENS, a);
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid peer master token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_PEER_MASTER_TOKEN, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
                    		cryptoContext.encrypt(plaintext, encoder, format, {
                    			result: function(headerdata) {
                    				messageHeaderMo.put(KEY_HEADERDATA, headerdata);

                    				// The header data must be signed or it will not be processed.
                    				cryptoContext.sign(headerdata, encoder, format, {
                    					result: function(signature) {
                    						messageHeaderMo.put(KEY_SIGNATURE, signature);
                    						Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
                    							result: function() {},
                    							error: function(err) { exception = err; },
                    						});
                    					},
                    					error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    				});
                    			},
                    			error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    		});
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid peer user ID token", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_PEER_USER_ID_TOKEN, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslException(MslError.NONE), MESSAGE_ID);
		});
	});

	it("parseHeader with invalid user authentication data", function() {
		var builder, peerServiceTokens;
		runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, null, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return builder && peerServiceTokens; }, "builder and service tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeader;
		runs(function() {
	        builder.set(KEY_KEY_REQUEST_DATA, null);
	        builder.set(KEY_KEY_RESPONSE_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderMo;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeader, {
				result: function(x) { messageHeaderMo = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
		
		var exception;
        runs(function() {
            // Before modifying the header data we need to decrypt it.
            var cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
            var ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            cryptoContext.decrypt(ciphertext, encoder, {
                result: function(plaintext) {
                    var headerdataMo = encoder.parseObject(plaintext);
        
                    // After modifying the header data we need to encrypt it.
                    headerdataMo.put(KEY_USER_AUTHENTICATION_DATA, "x");
                    encoder.encodeObject(headerdataMo, format, {
                    	result: function(plaintext) {
		                    cryptoContext.encrypt(plaintext, encoder, format, {
		                        result: function(headerdata) {
		                            messageHeaderMo.put(KEY_HEADERDATA, headerdata);
		                    
		                            // The header data must be signed or it will not be processed.
		                            cryptoContext.sign(headerdata, encoder, format, {
		                                result: function(signature) {
		                                    messageHeaderMo.put(KEY_SIGNATURE, signature);
		                                    Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
		                                        result: function() {},
		                                        error: function(err) { exception = err; },
		                                    });
		                                },
		                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		                            });
		                        },
		                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
		                    });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return exception; }, "exception not received", 300);
		runs(function() {
			var f = function() { throw exception; };
			expect(f).toThrow(new MslEncodingException(MslError.NONE), MESSAGE_ID);
		});
	});
	
	it("ctor with unencrypted user authentication data", function() {
	    var rsaCtx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.RSA, false, {
                result: function(c) { rsaCtx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return rsaCtx; }, "rsaCtx", MslTestConstants.TIMEOUT);
	    
        var entityAuthData;
        runs(function() {
            rsaCtx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(rsaCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(rsaCtx, entityAuthData, null, headerData, peerData, {
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

	it("parseHeader with unencrypted user authentication data", function() {
        var rsaCtx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.RSA, false, {
                result: function(c) { rsaCtx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return rsaCtx; }, "rsaCtx", MslTestConstants.TIMEOUT);
        
        var entityAuthData;
        runs(function() {
            rsaCtx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(rsaCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeader;
        runs(function() {
            builder.set(KEY_USER_AUTHENTICATION_DATA, null);
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(rsaCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader", MslTestConstants.TIMEOUT);
        
        var messageHeaderMo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, messageHeader, {
                result: function(x) { messageHeaderMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeaderMo; }, "messageHeaderMo", MslTestConstants.TIMEOUT);
        
        var headerdata;
        runs(function() {
            // The header data is not encrypted.
            var plaintext = messageHeaderMo.getBytes(KEY_HEADERDATA);
            var headerdataMo = encoder.parseObject(plaintext);
            headerdataMo.put(KEY_USER_AUTHENTICATION_DATA, USER_AUTH_DATA);
            encoder.encodeObject(headerdataMo, format, {
                result: function(x) { headerdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return headerdata; }, "headerdata", MslTestConstants.TIMEOUT);
        
        var signature;
        runs(function() {
            messageHeaderMo.put(KEY_HEADERDATA, headerdata);

            // The header data must be signed or it will not be processed.
            var factory = rsaCtx.getEntityAuthenticationFactory(entityAuthData.scheme);
            var cryptoContext = factory.getCryptoContext(rsaCtx, entityAuthData);
            cryptoContext.sign(headerdata, encoder, format, {
                result: function(x) { signature = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return signature; }, "signature", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            messageHeaderMo.put(KEY_SIGNATURE, signature);
            
            Header.parseHeader(rsaCtx, messageHeaderMo, CRYPTO_CONTEXTS, {
                result: function() {},
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.UNENCRYPTED_MESSAGE_WITH_USERAUTHDATA), MESSAGE_ID);
        });
	});

	xit("equals master token", function() {
	    var builder;
	    runs(function() {
	        HeaderDataBuilder$create(trustedNetCtx, null, null, false, {
	            result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
	        });
	    });
	    waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
	    
		var masterTokenA, masterTokenB;
		runs(function() {
		    MslTestUtils.getMasterToken(trustedNetCtx, 1, 1, {
		        result: function(t) { masterTokenA = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		    MslTestUtils.getMasterToken(trustedNetCtx, 1, 2, {
		        result: function(t) { masterTokenB = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return masterTokenA && masterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);
		
		var messageHeaderA, messageHeaderB;
		runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, masterTokenA, headerData, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, masterTokenB, headerData, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
        waitsFor(function() { return messageHeaderA && messageHeaderB; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals entity authentication data", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeaderA, messageHeaderB;
		runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);    
            var entityAuthDataA = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
            var entityAuthDataB = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN2);
			MessageHeader.create(trustedNetCtx, entityAuthDataA, null, headerData, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, entityAuthDataB, null, headerData, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
        waitsFor(function() { return messageHeaderA && messageHeaderB; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals master token and entity authentication data", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeaderA, messageHeaderB;
		runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderA && messageHeaderB; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});
    
    xit("equals timestamp", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder.create(trustedNetCtx, null, null, false, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
        var messageHeaderA, messageHeaderB;
        runs(function() {
            var headerData = builder.build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
                result: function(token) { messageHeaderA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            setTimeout(MILLISECONDS_PER_SECOND, function() {
                MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
                    result: function(token) { messageHeaderB = token; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
        });
        waitsFor(function() { return messageHeaderA && messageHeaderB; }, "message headers not received", 2000);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
    });

	xit("equals message ID", function() {
		var serviceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
				result: function(tks) { serviceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, USER_ID_TOKEN, serviceTokens, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

		var messageHeaderA, messageHeaderB;
		runs(function() {
            var headerDataA = builder.set(KEY_MESSAGE_ID, 1).build();
            var headerDataB = builder.set(KEY_MESSAGE_ID, 2).build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
        waitsFor(function() { return messageHeaderA && messageHeaderB; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals non-replayable", function() {
		var serviceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
				result: function(tks) { serviceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, USER_ID_TOKEN, serviceTokens, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

		var messageHeaderA, messageHeaderB;
		runs(function() {
            var headerDataA = builder.set(KEY_NON_REPLAYABLE_ID, 1).build();
            var headerDataB = builder.set(KEY_NON_REPLAYABLE_ID, 2).build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderA && messageHeaderB; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals renewable", function() {
		var serviceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
				result: function(tks) { serviceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, USER_ID_TOKEN, serviceTokens, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

		var messageHeaderA, messageHeaderB;
		runs(function() {
            var headerDataA = builder.set(KEY_RENEWABLE, true).build();
            var headerDataB = builder.set(KEY_RENEWABLE, false).build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
        waitsFor(function() { return messageHeaderA && messageHeaderB; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});
	
	xit("equals handshake", function() {
        var serviceTokens;
        runs(function() {
            MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
                result: function(tks) { serviceTokens = tks; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, USER_ID_TOKEN, serviceTokens, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

        var messageHeaderA, messageHeaderB;
        runs(function() {
            var headerDataA = builder.set(KEY_HANDSHAKE, true).build();
            var headerDataB = builder.set(KEY_HANDSHAKE, false).build();
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
                result: function(token) { messageHeaderA = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
                result: function(token) { messageHeaderB = token; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeaderA && messageHeaderB; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
    });

	xit("equals capabilities", function() {
		var serviceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
				result: function(tks) { serviceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, USER_ID_TOKEN, serviceTokens, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

		var messageHeaderA, messageHeaderB;
		runs(function() {
			var capsA = new MessageCapabilities(ALGOS, LANGUAGES);
	        var capsB = new MessageCapabilities(null, null);
            var headerDataA = builder.set(KEY_CAPABILITIES, capsA).build();
            var headerDataB = builder.set(KEY_CAPABILITIES, capsB).build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
        waitsFor(function() { return messageHeaderA && messageHeaderB; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals key request data", function() {
		var serviceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
				result: function(tks) { serviceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, USER_ID_TOKEN, serviceTokens, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

		var messageHeaderA, messageHeaderB, messageHeaderC;
		runs(function() {
            var keyRequestDataA = [];
            keyRequestDataA.add(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.SESSION));
            var keyRequestDataB = [];
            keyRequestDataB.add(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK));
            var headerDataA = builder.set(KEY_KEY_REQUEST_DATA, keyRequestDataA).build();
            var headerDataB = builder.set(KEY_KEY_REQUEST_DATA, keyRequestDataB).build();
            var headerDataC = builder.set(KEY_KEY_REQUEST_DATA, null).build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData, {
				result: function(token) { messageHeaderC = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderA && messageHeaderB && messageHeaderC; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderC)).toBeFalsy();
            expect(messageHeaderC.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderC.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals key response data", function() {
		var serviceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, {
				result: function(tks) { serviceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
		
		var keyxDataA, keyxDataB;
		runs(function() {
            var keyRequestData = KEY_REQUEST_DATA[0];
            var factory = trustedNetCtx.getKeyExchangeFactory(keyRequestData.getKeyExchangeScheme());		
			factory.generateResponse(trustedNetCtx, format, keyRequestData, MASTER_TOKEN, {
				result: function(x) { keyxDataA = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			factory.generateResponse(trustedNetCtx, format, keyRequestData, MASTER_TOKEN, {
				result: function(x) { keyxDataB = x; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return keyxDataA && keyxDataB; }, "key exchange data not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, USER_ID_TOKEN, serviceTokens, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
		
        var messageHeaderA, messageHeaderB, messageHeaderC;
		runs(function() {
            var keyResponseDataA = keyxDataA.keyResponseData;
            var keyResponseDataB = keyxDataB.keyResponseData;
            var headerDataA = builder.set(KEY_KEY_RESPONSE_DATA, keyResponseDataA).build();
            var headerDataB = builder.set(KEY_KEY_RESPONSE_DATA, keyResponseDataB).build();
            var headerDataC = builder.set(KEY_KEY_RESPONSE_DATA, null).build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData, {
				result: function(token) { messageHeaderC = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
        waitsFor(function() { return messageHeaderA && messageHeaderB && messageHeaderC; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);
		
        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderC)).toBeFalsy();
            expect(messageHeaderC.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderC.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals user authentication data", function() {
		var serviceTokens;
		runs(function() {
			MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null, {
				result: function(tks) { serviceTokens = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return serviceTokens; }, "serviceTokens not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, null, serviceTokens, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

		var messageHeaderA, messageHeaderB, messageHeaderC;
		runs(function() {
            var userAuthDataA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "A", MockEmailPasswordAuthenticationFactory.PASSWORD);
            var userAuthDataB = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "B", MockEmailPasswordAuthenticationFactory.PASSWORD);
            var headerDataA = builder.set(KEY_USER_AUTHENTICATION_DATA, userAuthDataA).build();
            var headerDataB = builder.set(KEY_USER_AUTHENTICATION_DATA, userAuthDataB).build();
            var headerDataC = builder.set(KEY_USER_AUTHENTICATION_DATA, null).build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData, {
				result: function(token) { messageHeaderC = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderA && messageHeaderB && messageHeaderC; }, "message headers not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderC)).toBeFalsy();
            expect(messageHeaderC.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderC.uniqueKey()).toBeTruthy();
    
            // This test does not include a parsed header to avoid requiring user
            // authentication to succeed.
        });
	});

	xit("equals user ID token", function() {
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
		waitsFor(function() { return userIdTokenA && userIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);
        
        var builderA, builderB, builderC;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, null, userIdTokenA, null, {
                result: function(x) { builderA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            HeaderDataBuilder$create(trustedNetCtx, null, userIdTokenB, null, {
                result: function(x) { builderB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            HeaderDataBuilder$create(trustedNetCtx, null, null, null, {
                result: function(x) { builderC = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builderA && builderB && builderC; }, "builders", MslTestConstants.TIMEOUT);

		var messageHeaderA, messageHeaderB, messageHeaderC;
		runs(function() {
            var headerDataA = builderA.build();
            var headerDataB = builderB.build();
            var headerDataC = builderC.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData, {
				result: function(token) { messageHeaderC = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderA && messageHeaderB && messageHeaderC; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderC)).toBeFalsy();
            expect(messageHeaderC.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderC.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals service tokens", function() {
        var builderA, builderB, builderC;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builderA = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builderB = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false, {
                result: function(x) { builderC = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builderA && builderB && builderC; }, "builders", MslTestConstants.TIMEOUT);
        
		var messageHeaderA, messageHeaderB, messageHeaderC;
		runs(function() {
            var headerDataA = builderA.build();
            var headerDataB = builderB.build();
            var headerDataC = builderC.build();
            var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData, {
				result: function(token) { messageHeaderC = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderA && messageHeaderB && messageHeaderC; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(trustedNetCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderC)).toBeFalsy();
            expect(messageHeaderC.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderC.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals peer master token", function() {
		var peerMasterTokenA, peerMasterTokenB;
		runs(function() {
		    MslTestUtils.getMasterToken(p2pCtx, 1, 1, {
		        result: function(t) { peerMasterTokenA = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		    MslTestUtils.getMasterToken(p2pCtx, 1, 2, {
		        result: function(t) { peerMasterTokenB = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return peerMasterTokenA && peerMasterTokenB; }, "master tokens not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeaderA, messageHeaderB, messageHeaderC;
		runs(function() {
            var headerData = builder.build();
            var peerDataA = new HeaderPeerData(peerMasterTokenA, null, null);
            var peerDataB = new HeaderPeerData(peerMasterTokenB, null, null);
            var peerDataC = new HeaderPeerData(null, null, null);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerDataA, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerDataB, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerDataC, {
				result: function(token) { messageHeaderC = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
        waitsFor(function() { return messageHeaderA; }, "messageHeaderA not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(p2pCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderC)).toBeFalsy();
            expect(messageHeaderC.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderC.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals peer user ID token", function() {
		var peerUserIdTokenA, peerUserIdTokenB;
		runs(function() {
		    MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER, {
		        result: function(t) { peerUserIdTokenA = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		    MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER, {
		        result: function(t) { peerUserIdTokenB = t; },
		        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
		    });
		});
		waitsFor(function() { return peerUserIdTokenA && peerUserIdTokenB; }, "user ID tokens not received", MslTestConstants.TIMEOUT);
        
        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);

		var messageHeaderA, messageHeaderB, messageHeaderC;
		runs(function() {
            var headerData = builder.build();
            var peerDataA = new HeaderPeerData(PEER_MASTER_TOKEN, peerUserIdTokenA, null);
            var peerDataB = new HeaderPeerData(PEER_MASTER_TOKEN, peerUserIdTokenB, null);
            var peerDataC = new HeaderPeerData(PEER_MASTER_TOKEN, null, null);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerDataA, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerDataB, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerDataC, {
				result: function(token) { messageHeaderC = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderA && messageHeaderB && messageHeaderC; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(p2pCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderC)).toBeFalsy();
            expect(messageHeaderC.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderC.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
        });
	});

	xit("equals peer service tokens", function() {
		var peerServiceTokensA, peerServiceTokensB;
		runs(function() {
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokensA = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, {
				result: function(tks) { peerServiceTokensB = tks; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return peerServiceTokensA && peerServiceTokensB; }, "service tokens not received", MslTestConstants.TIMEOUT);

        var builder;
        runs(function() {
            HeaderDataBuilder$create(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
		
		var messageHeaderA, messageHeaderB, messageHeaderC;
		runs(function() {
            var headerData = builder.build();
            var peerDataA = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokensA);
            var peerDataB = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokensB);
            var peerDataC = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerDataA, {
				result: function(token) { messageHeaderA = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerDataB, {
				result: function(token) { messageHeaderB = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
			MessageHeader.create(p2pCtx, null, MASTER_TOKEN, headerData, peerDataC, {
				result: function(token) { messageHeaderC = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeaderA && messageHeaderB && messageHeaderC; }, "message headers not received", MslTestConstants.TIMEOUT);
		var messageHeaderA2;
		runs(function() {
			MslTestUtils.toMslObject(encoder, messageHeaderA, {
				result: function(mo) {
					Header.parseHeader(p2pCtx, mo, CRYPTO_CONTEXTS, {
						result: function(h) { messageHeaderA2 = h; },
						error: function(e) { expect(function() { throw e; }).not.toThrow(); },
					});
				},
				error: function(e) { expect(function() { throw e; }).not.toThrow(); },
			});
		});
		waitsFor(function() { return messageHeaderA2; }, "parsed header not received", MslTestConstants.TIMEOUT);
		
        runs(function() {
            expect(messageHeaderA.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
    
            expect(messageHeaderA.equals(messageHeaderB)).toBeFalsy();
            expect(messageHeaderB.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderB.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderC)).toBeFalsy();
            expect(messageHeaderC.equals(messageHeaderA)).toBeFalsy();
            expect(messageHeaderA.uniqueKey() != messageHeaderC.uniqueKey()).toBeTruthy();
    
            expect(messageHeaderA.equals(messageHeaderA2)).toBeTruthy();
            expect(messageHeaderA2.equals(messageHeaderA)).toBeTruthy();
            expect(messageHeaderA2.uniqueKey()).toEqual(messageHeaderA.uniqueKey());
		});
	});

	xit("equals object", function() {
        var builder;
        runs(function() {
            HeaderDataBuilder$create(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true, {
                result: function(x) { builder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return builder; }, "builder", MslTestConstants.TIMEOUT);
        
		var messageHeader;
		runs(function() {
			var headerData = builder.build();
			var peerData = new HeaderPeerData(null, null, null);
			MessageHeader.create(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData, {
				result: function(token) { messageHeader = token; },
				error: function(e) { expect(function() { throw e; }).not.toThrow(); }
			});
		});
		waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

		runs(function() {
			expect(messageHeader.equals(null)).toBeFalsy();
			expect(messageHeader.equals(MASTER_TOKEN)).toBeFalsy();
			expect(messageHeader.uniqueKey() != MASTER_TOKEN.uniqueKey()).toBeTruthy();
		});
	});
});
