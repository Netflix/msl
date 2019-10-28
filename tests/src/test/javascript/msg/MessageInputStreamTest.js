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
 * Message input stream unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MessageInputStream", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var Random = require('msl-core/util/Random.js');
    var MessageHeader = require('msl-core/msg/MessageHeader.js');
    var NullCryptoContext = require('msl-core/crypto/NullCryptoContext.js');
    var SessionCryptoContext = require('msl-core/crypto/SessionCryptoContext.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var ByteArrayOutputStream = require('msl-core/io/ByteArrayOutputStream.js');
    var ByteArrayInputStream = require('msl-core/io/ByteArrayInputStream.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var PresharedAuthenticationData = require('msl-core/entityauth/PresharedAuthenticationData.js');
    var RsaAuthenticationData = require('msl-core/entityauth/RsaAuthenticationData.js');
    var UnauthenticatedAuthenticationData = require('msl-core/entityauth/UnauthenticatedAuthenticationData.js');
    var ErrorHeader = require('msl-core/msg/ErrorHeader.js');
    var SymmetricWrappedExchange = require('msl-core/keyx/SymmetricWrappedExchange.js');
    var SymmetricCryptoContext = require('msl-core/crypto/SymmetricCryptoContext.js');
    var SecretKey = require('msl-core/crypto/SecretKey.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var PayloadChunk = require('msl-core/msg/PayloadChunk.js');
    var MessageInputStream = require('msl-core/msg/MessageInputStream.js');
    var MslEntityAuthException = require('msl-core/MslEntityAuthException.js');
    var MslUserIdTokenException = require('msl-core/MslUserIdTokenException.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    var MslKeyExchangeException = require('msl-core/MslKeyExchangeException.js');
    var MasterToken = require('msl-core/tokens/MasterToken.js');
    var MslMessageException = require('msl-core/MslMessageException.js');
    var MslMasterTokenException = require('msl-core/MslMasterTokenException.js');
    var MslError = require('msl-core/MslError.js');
    var Arrays = require('msl-core/util/Arrays.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    var MockUnauthenticatedAuthenticationFactory = require('msl-tests/entityauth/MockUnauthenticatedAuthenticationFactory.js');
    var MockTokenFactory = require('msl-tests/tokens/MockTokenFactory.js');
    var MockEmailPasswordAuthenticationFactory = require('msl-tests/userauth/MockEmailPasswordAuthenticationFactory.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
    var MockRsaAuthenticationFactory = require('msl-tests/entityauth/MockRsaAuthenticationFactory.js');

    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Maximum number of payload chunks to generate. */
    var MAX_PAYLOAD_CHUNKS = 12;
    /** Maximum payload chunk data size in bytes. */
    var MAX_DATA_SIZE = 100; //10 * 1024;
    /** Non-replayable ID acceptance window. */
    var NON_REPLAYABLE_ID_WINDOW = 65536;
    /** I/O operation timeout in milliseconds. */
    var TIMEOUT = 1000;
    /** Maximum read length. */
    var MAX_READ_LEN = MAX_PAYLOAD_CHUNKS * MAX_DATA_SIZE;

    /** Random. */
    var random = new Random();
    /** Trusted network MSL context. */
    var trustedNetCtx;
    /** Peer-to-peer MSL context. */
    var p2pCtx;
    /** MSL encoder factory. */
    var encoder;
    /** Header service token crypto contexts. */
    var cryptoContexts = [];
    /** Message payloads (initially empty). */
    var payloads = [];

    var MESSAGE_HEADER;
    var ERROR_HEADER;
    var ENTITY_AUTH_DATA;
    var KEY_REQUEST_DATA = [];
    var KEY_RESPONSE_DATA;
    var KEYX_CRYPTO_CONTEXT, ALT_MSL_CRYPTO_CONTEXT;

    var SEQ_NO = 1;
    var MSG_ID = 42;
    var END_OF_MSG = true;
    var DATA = new Uint8Array(32);
    random.nextBytes(DATA);

    var UNAUTHENTICATED_ESN = "MOCKUNAUTH-ESN";

    // Shortcuts.
    var HeaderData = MessageHeader.HeaderData;
    var HeaderPeerData = MessageHeader.HeaderPeerData;

    /**
     * A crypto context that always returns false for verify. The other crypto
     * operations are no-ops.
     */
    var RejectingCryptoContext = NullCryptoContext.extend({
        /** @inheritDoc */
        verify: function verify(data, signature, encoder, callback) {
            callback.result(false);
        },
    });

    /**
     * Increments the provided non-replayable ID by 1, wrapping around to zero
     * if the provided value is equal to {@link MslConstants#MAX_LONG_VALUE}.
     * 
     * @param {number} id the non-replayable ID to increment.
     * @return {number} the non-replayable ID + 1.
     * @throws MslInternalException if the provided non-replayable ID is out of
     *         range.
     */
    function incrementNonReplayableId(id) {
        if (id < 0 || id > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Non-replayable ID " + id + " is outside the valid range.");
        return (id == MslConstants.MAX_LONG_VALUE) ? 0 : id + 1;
    }

    /**
     * Create a new input stream containing a MSL message constructed from the
     * provided header and payloads.
     * 
     * @param {Header} header message or error header.
     * @param {Array.<PayloadChunk>} payloads zero or more payload chunks.
     * @param {result: function(InputStream), error: function(Error)} callback
     *        the callback that will receive the input stream containing the
     *        MSL message.
     * @throws IOException if there is an error creating the input stream.
     * @throws MslEncoderException if there is an error encoding the data.
     */
    function generateInputStream(header, payloads, callback) {
        AsyncExecutor(callback, function() {
            var baos = new ByteArrayOutputStream();
            header.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(headerBytes) {
                    baos.write(headerBytes, 0, headerBytes.length, TIMEOUT, {
                        result: function(numWritten) { writePayload(baos, 0, callback); },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        function writePayload(baos, index, callback) {
            AsyncExecutor(callback, function() {
                if (index == payloads.length)
                    return new ByteArrayInputStream(baos.toByteArray());

                var payload = payloads[index];
                payload.toMslEncoding(encoder, ENCODER_FORMAT, {
                    result: function(payloadBytes) {
                        baos.write(payloadBytes, 0, payloadBytes.length, TIMEOUT, {
                            result: function(numWritten) {
                                writePayload(baos, ++index, callback);
                            },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
        }
    }

    var initialized = false;
    beforeEach(function() {
        payloads = [];

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
                trustedNetCtx.getEntityAuthenticationData(null, {
                    result: function(x) { ENTITY_AUTH_DATA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ENTITY_AUTH_DATA; }, "entityAuthData", MslTestConstants.TIMEOUT);

            runs(function() {
                var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null, null);
                var peerData = new HeaderPeerData(null, null, null);
                MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                    result: function(x) { MESSAGE_HEADER = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                ErrorHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, 1, MslConstants.ResponseCode.FAIL, 3, "errormsg", "usermsg", {
                    result: function(x) { ERROR_HEADER = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return MESSAGE_HEADER && ERROR_HEADER; }, "headers", MslTestConstants.TIMEOUT);

            var keyxData, encryptionKey, hmacKey, wrappingKey;
            runs(function() {
                var keyRequest = new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK);
                KEY_REQUEST_DATA.push(keyRequest);
                var factory = trustedNetCtx.getKeyExchangeFactory(keyRequest.keyExchangeScheme);
                factory.generateResponse(trustedNetCtx, ENCODER_FORMAT, keyRequest, ENTITY_AUTH_DATA, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });

                var mke = new Uint8Array(16);
                var mkh = new Uint8Array(32);
                var mkw = new Uint8Array(16);
                random.nextBytes(mke);
                random.nextBytes(mkh);
                random.nextBytes(mkw);
                SecretKey.import(mke, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(x) { encryptionKey = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                SecretKey.import(mkh, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function(x) { hmacKey = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                SecretKey.import(mkw, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                    result: function(x) { wrappingKey = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return encryptionKey && hmacKey && wrappingKey && keyxData; }, "keys and keyxData", MslTestConstants.TIMEOUT);

            runs(function() {
                KEY_RESPONSE_DATA = keyxData.keyResponseData;
                KEYX_CRYPTO_CONTEXT = keyxData.cryptoContext;

                ALT_MSL_CRYPTO_CONTEXT = new SymmetricCryptoContext(trustedNetCtx, "clientMslCryptoContext", encryptionKey, hmacKey, wrappingKey);

                initialized = true;
            });
        }
    });

    it("empty message", function() {
        // An end-of-message payload is expected.
        var chunk;
        runs(function() {
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            PayloadChunk.create(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, new Uint8Array(0), cryptoContext, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            payloads.push(chunk);
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var buffer;
        runs(function() {
            mis.read(MAX_READ_LEN, TIMEOUT, {
                result: function(x) { buffer = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return buffer !== undefined; }, "buffer", TIMEOUT);

        var closed;
        runs(function() {
            expect(mis.getErrorHeader()).toBeNull();
            expect(mis.getMessageHeader()).toEqual(MESSAGE_HEADER);
            expect(mis.markSupported()).toBeTruthy();
            expect(buffer).toBeNull();
            mis.mark();
            mis.reset();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("message with data", function() {
        // An end-of-message payload is expected.
        var chunk;
        runs(function() {
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            PayloadChunk.create(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContext, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            payloads.push(chunk);
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var buffer;
        runs(function() {
            mis.read(MAX_READ_LEN, TIMEOUT, {
                result: function(x) { buffer = new Uint8Array(x); },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return buffer !== undefined; }, "buffer", TIMEOUT);

        var closed;
        runs(function() {
            expect(buffer.length).toEqual(DATA.length);
            expect(buffer).toEqual(DATA);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("identity with entity authentication data", function() {
        var entityAuthData;
        runs(function() {
            trustedNetCtx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(mis.getIdentity()).toEqual(entityAuthData.identity);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("identity with master token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(trustedNetCtx, 1, 1, {
                result: function(t) { masterToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(mis.getIdentity()).toEqual(masterToken.identity);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("identity for error header", function() {
        var entityAuthData;
        runs(function() {
            trustedNetCtx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData", MslTestConstants.TIMEOUT);

        var errorHeader;
        runs(function() {
            ErrorHeader.create(trustedNetCtx, entityAuthData, 1, MslConstants.ResponseCode.FAIL, 3, "errormsg", "usermsg", {
                result: function(x) { errorHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return errorHeader; }, "errorHeader", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(errorHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(mis.getIdentity()).toEqual(entityAuthData.identity);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("revoked entity", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.NONE, false, {
                result: function(x) { ctx = x; },
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
        waitsFor(function() { return entityAuthData; }, "entityAuthData", MslTestConstants.TIMEOUT);

        var factory, messageHeader;
        runs(function() {
            factory = new MockUnauthenticatedAuthenticationFactory();
            ctx.addEntityAuthenticationFactory(factory);

            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            factory.setRevokedIdentity(entityAuthData.getIdentity());
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITY_REVOKED));
        });
    });

    it("revoked master token", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var factory, masterToken;
        runs(function() {
            factory = new MockTokenFactory();
            ctx.setTokenFactory(factory);

            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(t) { masterToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return factory && masterToken; }, "factory and master token", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            factory.setRevokedMasterToken(masterToken);
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMasterTokenException(MslError.MASTERTOKEN_IDENTITY_REVOKED));
        });
    });

    it("user with no user ID token", function() {
        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(mis.getUser()).toBeNull();

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("user with user ID token", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(trustedNetCtx, 1, 1, {
                result: function(t) { masterToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(trustedNetCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(t) { userIdToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, userIdToken, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(mis.getUser()).toEqual(userIdToken.user);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("revoked user ID token", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var factory, masterToken;
        runs(function() {
            factory = new MockTokenFactory();
            ctx.setTokenFactory(factory);

            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(t) { masterToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(t) { userIdToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, userIdToken, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            factory.setRevokedUserIdToken(userIdToken);
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserIdTokenException(MslError.USERIDTOKEN_REVOKED));
        });
    });

    it("untrusted user ID token", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var factory, masterToken;
        runs(function() {
            factory = new MockTokenFactory();
            ctx.setTokenFactory(factory);

            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(t) { masterToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var userIdToken;
        runs(function() {
            MslTestUtils.getUntrustedUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER, {
                result: function(t) { userIdToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userIdToken; }, "userIdToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, userIdToken, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            factory.setRevokedUserIdToken(userIdToken);
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslUserIdTokenException(MslError.NONE), MSG_ID);
        });
    });

    // FIXME This can be removed once the old handshake logic is removed.
    it("explicit handshake message", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, true, true, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var handshake;
        runs(function() {
            mis.isReady({
                result: function(r) {
                    mis.isHandshake(TIMEOUT, {
                        result: function(x) { handshake = x; },
                        timeout: function() { expect(function() { throw new Error("Timed out waiting for handshake."); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return handshake; }, "handshake", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(handshake).toBeTruthy();

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    // FIXME This can be removed once the old handshake logic is removed.
    it("inferred handshake message", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var chunk;
        runs(function() {
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            PayloadChunk.create(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, new Uint8Array(0), cryptoContext, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            payloads.push(chunk);
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var handshake;
        runs(function() {
            mis.isReady({
                result: function(r) {
                    mis.isHandshake(TIMEOUT, {
                        result: function(x) { handshake = x; },
                        timeout: function() { expect(function() { throw new Error("Timed out waiting for handshake."); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return handshake; }, "handshake", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(handshake).toBeTruthy();

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    // FIXME This can be removed once the old handshake logic is removed.
    it("not a handshake message", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var chunk;
        runs(function() {
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            PayloadChunk.create(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContext, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            payloads.push(chunk);
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var handshake;
        runs(function() {
            mis.isReady({
                result: function(r) {
                    mis.isHandshake(TIMEOUT, {
                        result: function(x) { handshake = x; },
                        timeout: function() { expect(function() { throw new Error("Timed out waiting for handshake."); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return handshake !== undefined; }, "handshake", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(handshake).toBeFalsy();

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("message with key response data", function() {
        var entityAuthData;
        runs(function() {
            trustedNetCtx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        // Encrypt the payload with the key exchange crypto context.
        var chunk;
        runs(function() {
            PayloadChunk.create(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, KEYX_CRYPTO_CONTEXT, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            payloads.push(chunk);
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var buffer;
        runs(function() {
            mis.read(MAX_READ_LEN, TIMEOUT, {
                result: function(x) { buffer = new Uint8Array(x); },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return buffer !== undefined; }, "buffer", TIMEOUT);

        var closed;
        runs(function() {
            expect(buffer.length).toEqual(DATA.length);
            expect(buffer).toEqual(DATA);
            expect(mis.getKeyExchangeCryptoContext()).toEqual(mis.getPayloadCryptoContext());

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("p2p message with key response data", function() {
        var entityAuthData;
        runs(function() {
            p2pCtx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(p2pCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        // Encrypt the payload with the key exchange crypto context.
        var chunk;
        runs(function() {
            var cryptoContext = messageHeader.cryptoContext;
            PayloadChunk.create(p2pCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContext, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", MslTestConstants.TIMEOUT);
        var is;
        runs(function() {
            payloads.push(chunk);
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var buffer;
        runs(function() {
            mis.read(MAX_READ_LEN, TIMEOUT, {
                result: function(x) { buffer = new Uint8Array(x); },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return buffer !== undefined; }, "buffer", TIMEOUT);

        var closed;
        runs(function() {
            expect(buffer.length).toEqual(DATA.length);
            expect(buffer).toEqual(DATA);
            expect(mis.getPayloadCryptoContext()).not.toEqual(mis.getKeyExchangeCryptoContext());

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("message with unsupported key exchange scheme", function() {
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
            ctx.removeKeyExchangeFactories(KeyExchangeScheme.SYMMETRIC_WRAPPED);
            ctx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);


        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND), MSG_ID);
        });
    });

    it("missing key request data for message with key response data", function() {
        // We need to replace the MSL crypto context before parsing the message
        // so create a local MSL context.
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx not received", MslTestConstants.TIMEOUT);

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
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            ctx.setMslCryptoContext(new RejectingCryptoContext());
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            var keyRequestData = [];
            MessageInputStream.create(ctx, is, keyRequestData, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH), MSG_ID);
        });
    });

    it("incompatible key request data for message with key response data", function() {
        var keyRequestData = [];
        keyRequestData.push(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.MGK));
        keyRequestData.push(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.SESSION));

        // We need to replace the MSL crypto context before parsing the message
        // so create a local MSL context.
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx not received", MslTestConstants.TIMEOUT);

        var entityAuthData;
        runs(function() {
            ctx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData not received", MslTestConstants.TIMEOUT);

        var keyExchangeData;
        runs(function() {
            var keyRequest = new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK);
            var factory = ctx.getKeyExchangeFactory(keyRequest.keyExchangeScheme);
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequest, entityAuthData, {
                result: function(x) { keyExchangeData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return keyExchangeData; }, "keyExchangeData not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var keyResponseData = keyExchangeData.keyResponseData;
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, keyResponseData, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            ctx.setMslCryptoContext(new RejectingCryptoContext());
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, keyRequestData, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH), MSG_ID);
        });
    });

    it("one compatible key request data for message with key response data", function() {
        // Populate the key request data such that the compatible data requires
        // iterating through one of the incompatible ones.
        var keyRequestData = [];
        var keyRequest = new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK);
        keyRequestData.push(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.MGK));
        keyRequestData.push(keyRequest);
        keyRequestData.push(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.MGK));

        var entityAuthData;
        runs(function() {
            trustedNetCtx.getEntityAuthenticationData(null, {
                result: function(x) { entityAuthData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthData; }, "entityAuthData not received", MslTestConstants.TIMEOUT);

        var keyExchangeData;
        runs(function() {
            var factory = trustedNetCtx.getKeyExchangeFactory(keyRequest.keyExchangeScheme);
            factory.generateResponse(trustedNetCtx, ENCODER_FORMAT, keyRequest, entityAuthData, {
                result: function(x) { keyExchangeData = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return keyExchangeData; }, "keyExchangeData not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var keyResponseData = keyExchangeData.keyResponseData;
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, keyResponseData, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, keyRequestData, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("expired renewable client message with key request data", function() {
        var masterToken;
        runs(function() {
            var renewalWindow = new Date(Date.now() - 20000);
            var expiration = new Date(Date.now() - 10000);
            MasterToken.create(trustedNetCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("expired renewable peer message with key request data", function() {
        var masterToken;
        runs(function() {
            var renewalWindow = new Date(Date.now() - 20000);
            var expiration = new Date(Date.now() - 10000);
            MasterToken.create(p2pCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(p2pCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("expired non-renewable client message", function() {
        // Expired messages received by a trusted network server should be
        // rejected.
        var masterToken;
        runs(function() {
            var renewalWindow = new Date(Date.now() - 20000);
            var expiration = new Date(Date.now() - 10000);
            MasterToken.create(trustedNetCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.MESSAGE_EXPIRED_NOT_RENEWABLE), MSG_ID);
        });
    });

    it("expired renewable client message without key request data", function() {
        // Expired renewable messages received by a trusted network server
        // with no key request data should be rejected.
        var masterToken;
        runs(function() {
            var renewalWindow = new Date(Date.now() - 20000);
            var expiration = new Date(Date.now() - 10000);
            MasterToken.create(trustedNetCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, true, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.MESSAGE_EXPIRED_NO_KEYREQUEST_DATA), MSG_ID);
        });
    });

    it("expired non-renewable server message", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var masterToken;
        runs(function() {
            var renewalWindow = new Date(Date.now() - 20000);
            var expiration = new Date(Date.now() - 10000);
            MasterToken.create(ctx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        // Expired messages received by a trusted network client should not be
        // rejected.
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            // The master token's crypto context must be cached, as if the client
            // constructed it after a previous message exchange.
            var cryptoContext = new SessionCryptoContext(ctx, masterToken);
            ctx.getMslStore().setCryptoContext(masterToken, cryptoContext);

            // Generate the input stream. This will encode the message.
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            // Change the MSL crypto context so the master token can no longer be
            // verified or decrypted.
            ctx.setMslCryptoContext(ALT_MSL_CRYPTO_CONTEXT);

            // Now "receive" the message with a master token that we cannot verify
            // or decrypt, but for which a cached crypto context exists.
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("expired renewable peer message without key request data", function() {
        var masterToken;
        runs(function() {
            var renewalWindow = new Date(Date.now() - 20000);
            var expiration = new Date(Date.now() - 10000);
            MasterToken.create(p2pCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, true, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(p2pCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.MESSAGE_EXPIRED_NO_KEYREQUEST_DATA), MSG_ID);
        });
    });

    it("expired non-renewable peer message", function() {
        var masterToken;
        runs(function() {
            var renewalWindow = new Date(Date.now() - 20000);
            var expiration = new Date(Date.now() - 10000);
            MasterToken.create(p2pCtx, renewalWindow, expiration, 1, 1, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(p2pCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.MESSAGE_EXPIRED_NOT_RENEWABLE), MSG_ID);
        });
    });

    it("non-renewable handshake message", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, 1, false, true, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.HANDSHAKE_DATA_MISSING), MSG_ID);
        });
    });

    it("handshake message without key request data", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, 1, true, true, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.HANDSHAKE_DATA_MISSING), MSG_ID);
        });
    });

    it("non-replayable client message without master token", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, 1, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.INCOMPLETE_NONREPLAYABLE_MESSAGE), MSG_ID);
        });
    });

    it("non-replayable peer message without master token", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, 1, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(p2pCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.INCOMPLETE_NONREPLAYABLE_MESSAGE), MSG_ID);
        });
    });

    it("non-replayable with equal non-replayable ID", function() {
        var nonReplayableId = 1;
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            var factory = new MockTokenFactory();
            factory.setLargestNonReplayableId(nonReplayableId);
            ctx.setTokenFactory(factory);
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, nonReplayableId, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.MESSAGE_REPLAYED), MSG_ID);
        });
    });

    it("non-replayable with smaller non-replayable ID", function() {
        var nonReplayableId = 2;
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            var factory = new MockTokenFactory();
            factory.setLargestNonReplayableId(nonReplayableId);
            ctx.setTokenFactory(factory);
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, nonReplayableId - 1, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.MESSAGE_REPLAYED), MSG_ID);
        });
    });

    it("non-replayable with non-replayable ID outside acceptance window", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var factory = new MockTokenFactory();
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ctx.setTokenFactory(factory);
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT);

        var complete = false;
        runs(function() {
            iterate();
        });
        waitsFor(function() { return complete; }, "complete", 300);

        var largestNonReplayableId = MslConstants.MAX_LONG_VALUE - NON_REPLAYABLE_ID_WINDOW - 1;
        var nonReplayableId = MslConstants.MAX_LONG_VALUE;
        var i = 0, max = 2;
        function iterate() {
            if (i == max) {
                complete = true;
                return;
            }

            factory.setLargestNonReplayableId(largestNonReplayableId);

            var headerData = new HeaderData(MSG_ID, nonReplayableId, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(messageHeader) { generate(messageHeader); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        }
        function generate(messageHeader) {
            generateInputStream(messageHeader, payloads, {
                result: function(is) { create(is); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        }
        function create(is) {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(mis) { ready(mis); },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(exception) { check(exception); }
            });
        }
        function ready(mis) {
            mis.isReady({
                result: function() { throw new Error(i + ": Non-replayable ID " + nonReplayableId + " accepted with largest non-replayable ID " + largestNonReplayableId); },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(exception) { check(exception); }
            });
        }
        function check(exception) {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.MESSAGE_REPLAYED_UNRECOVERABLE), MSG_ID);

            largestNonReplayableId = incrementNonReplayableId(largestNonReplayableId);
            nonReplayableId = incrementNonReplayableId(nonReplayableId);
            ++i;
            iterate();
        }
    });

    it("non-replayable with non-replayable ID inside acceptance window", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var factory = new MockTokenFactory();
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            ctx.setTokenFactory(factory);
        });
        waitsFor(function() { return masterToken; }, "masterToken", MslTestConstants.TIMEOUT);

        var complete = false;
        runs(function() {
            var largestNonReplayableIdA = MslConstants.MAX_LONG_VALUE - NON_REPLAYABLE_ID_WINDOW;
            var nonReplayableIdA = MslConstants.MAX_LONG_VALUE;
            iterate(0, nonReplayableIdA, largestNonReplayableIdA);
        });
        waitsFor(function() { return complete; }, "complete (wraparound)", 10000);

        runs(function() {
            complete = false;
            var largestNonReplayableIdB = MslConstants.MAX_LONG_VALUE;
            var nonReplayableIdB = NON_REPLAYABLE_ID_WINDOW - 1;
            iterate(0, nonReplayableIdB, largestNonReplayableIdB);
        });
        waitsFor(function() { return complete; }, "complete (sequential)", 10000);

        var max = 2;
        function iterate(i, nonReplayableId, largestNonReplayableId) {
            if (i == max) {
                complete = true;
                return;
            }

            factory.setLargestNonReplayableId(largestNonReplayableId);

            var headerData = new HeaderData(MSG_ID, nonReplayableId, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(messageHeader) { generate(messageHeader, i, nonReplayableId, largestNonReplayableId); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        }
        function generate(messageHeader, i, nonReplayableId, largestNonReplayableId) {
            generateInputStream(messageHeader, payloads, {
                result: function(is) { create(is, i, nonReplayableId, largestNonReplayableId); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        }
        function create(is, i, nonReplayableId, largestNonReplayableId) {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(mis) { ready(mis, i, nonReplayableId, largestNonReplayableId); },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        }
        function ready(mis, i, nonReplayableId, largestNonReplayableId) {
            mis.isReady({
                result: function(ready) { check(ready, i, nonReplayableId, largestNonReplayableId); },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw new Error(i + ": Non-replayable ID " + nonReplayableId + " rejected with largest non-replayable ID " + largestNonReplayableId); }).not.toThrow(); }
            });
        }
        function check(ready, i, nonReplayableId, largestNonReplayableId) {
            expect(ready).toBeTruthy();

            largestNonReplayableId = incrementNonReplayableId(largestNonReplayableId);
            nonReplayableId = incrementNonReplayableId(nonReplayableId);
            iterate(i + 1, nonReplayableId, largestNonReplayableId);
        }
    });

    it("replayed client message", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(t) { masterToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var factory = new MockTokenFactory();
            factory.setLargestNonReplayableId(1);
            ctx.setTokenFactory(factory);

            var headerData = new HeaderData(MSG_ID, 1, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.MESSAGE_REPLAYED), MSG_ID);
        });
    });

    it("replayed peer message", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, true, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(t) { masterToken = t; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "masterToken not received", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            var factory = new MockTokenFactory();
            factory.setLargestNonReplayableId(1);
            ctx.setTokenFactory(factory);

            var headerData = new HeaderData(MSG_ID, 1, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(ctx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.isReady({
                result: function() {},
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslMessageException(MslError.MESSAGE_REPLAYED), MSG_ID);
        });
    });

    it("error header", function() {
        var is;
        runs(function() {
            generateInputStream(ERROR_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(mis.getErrorHeader()).toEqual(ERROR_HEADER);
            expect(mis.getMessageHeader()).toBeNull();
            expect(mis.markSupported()).toBeTruthy();

            mis.mark(0);
            mis.reset();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("read from error header", function() {
        var is;
        runs(function() {
            generateInputStream(ERROR_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "ready", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mis.read(MAX_READ_LEN, TIMEOUT, {
                result: function() {},
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });

    it("read from handshake message", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, true, true, null, KEY_REQUEST_DATA, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(trustedNetCtx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader not received", MslTestConstants.TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "ready", MslTestConstants.TIMEOUT);

        var read;
        runs(function() {
            mis.read(MAX_READ_LEN, TIMEOUT, {
                result: function(x) { read = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return read !== undefined; }, "read", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(read).toBeNull();
        });
    });

    it("missing end of message", function() {
        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var buffer;
        runs(function() {
            mis.read(MAX_READ_LEN, TIMEOUT, {
                result: function(x) { buffer = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return buffer !== undefined; }, "buffer", TIMEOUT);

        var closed;
        runs(function() {
            // If there's nothing left we'll receive end of message anyway.
            expect(buffer).toBeNull();

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("entity authentication scheme encrypts", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.encryptsPayloads()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("entity authentication scheme does not encrypt", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.encryptsPayloads()).toBeFalsy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("entity authentication scheme integrity protects", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.protectsPayloadIntegrity()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("entity authentication scheme does not integrity protect", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.protectsPayloadIntegrity()).toBeFalsy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("entity authentication scheme with keyx encrypts", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.encryptsPayloads()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("entity authentication scheme with keyx integrity protects", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.protectsPayloadIntegrity()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("entity authentication scheme does not but keyx encrypts", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.encryptsPayloads()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("entity authentication scheme does not but keyx integrity protects", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(trustedNetCtx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.protectsPayloadIntegrity()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("master token encrypts", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(trustedNetCtx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT)
        
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(trustedNetCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.encryptsPayloads()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("master token integrity protects", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(trustedNetCtx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT)
        
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(trustedNetCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.protectsPayloadIntegrity()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("master token with keyx encrypts", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(trustedNetCtx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT)
        
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(trustedNetCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.encryptsPayloads()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("master token with keyx integrity protects", function() {
        var masterToken;
        runs(function() {
            MslTestUtils.getMasterToken(trustedNetCtx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT)
        
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(trustedNetCtx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT)
        
        var is;
        runs(function() {
            generateInputStream(messageHeader, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);
        
        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mis.protectsPayloadIntegrity()).toBeTruthy();
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("premature end of message", function() {
        var baos = new ByteArrayOutputStream();
        var i = 0;
        runs(function() {
            // Payloads after an end of message are ignored.
            var extraPayloads = MAX_PAYLOAD_CHUNKS / 2;
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            function writePayload() {
                if (i == MAX_PAYLOAD_CHUNKS)
                    return;

                var data = new Uint8Array(random.nextInt(MAX_DATA_SIZE) + 1);
                random.nextBytes(data);
                if (i < extraPayloads) {
                    PayloadChunk.create(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == extraPayloads - 1), null, data, cryptoContext, {
                        result: function(chunk) {
                            payloads.push(chunk);
                            baos.write(data, 0, data.length, TIMEOUT, {
                                result: function(success) {
                                    ++i;
                                    writePayload();
                                },
                                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                            });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                } else {
                    PayloadChunk.create(trustedNetCtx, SEQ_NO + i, MSG_ID, null, null, data, cryptoContext, {
                        result: function(chunk) {
                            payloads.push(chunk);
                            ++i;
                            writePayload();
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                }
            }
            writePayload();
        });
        waitsFor(function() { return i == MAX_PAYLOAD_CHUNKS; }, "payloads to be written", TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var buffer;
        runs(function() {
            mis.read(MAX_READ_LEN, TIMEOUT, {
                result: function(x) { buffer = new Uint8Array(x); },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return buffer !== undefined; }, "buffer", TIMEOUT);

        var closed;
        runs(function() {
            // Read everything. We shouldn't get any of the extra payloads.
            var appdata = baos.toByteArray();
            expect(buffer.length).toEqual(appdata.length);
            expect(buffer).toEqual(appdata);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("payload with mismatched message ID", function() {
        var badPayloads = 0;
        var baos = new ByteArrayOutputStream();
        var i = 0;
        runs(function() {
            // Payloads with an incorrect message ID should be skipped.
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            var sequenceNumber = SEQ_NO;
            function writePayload() {
                if (i == MAX_PAYLOAD_CHUNKS)
                    return;

                var data = new Uint8Array(random.nextInt(MAX_DATA_SIZE) + 1);
                random.nextBytes(data);
                if (random.nextBoolean()) {
                    PayloadChunk.create(trustedNetCtx, sequenceNumber++, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext, {
                        result: function(chunk) {
                            payloads.push(chunk);
                            baos.write(data, 0, data.length, TIMEOUT, {
                                result: function(success) {
                                    ++i;
                                    writePayload();
                                },
                                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                            });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                } else {
                    PayloadChunk.create(trustedNetCtx, sequenceNumber, 2 * MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext, {
                        result: function(chunk) {
                            payloads.push(chunk);
                            ++badPayloads;
                            ++i;
                            writePayload();
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                }
            }
            writePayload();
        });
        waitsFor(function() { return i == MAX_PAYLOAD_CHUNKS; }, "payloads to be written", TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        // Read everything. Each bad payload should throw an exception.
        var buffer = new ByteArrayOutputStream();
        var caughtExceptions = 0;
        var eom = false;
        runs(function() {
            function nextRead() {
                mis.read(MAX_READ_LEN, TIMEOUT, {
                    result: function(x) {
                        if (!x) {
                            eom = true;
                            return;
                        }

                        buffer.write(x, 0, x.length, TIMEOUT, {
                            result: function(numWritten) { nextRead(); },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                    error: function(e) {
                        ++caughtExceptions;
                        nextRead();
                    }
                });
            }
            nextRead();
        });
        waitsFor(function() { return eom; }, "eom", TIMEOUT);

        var closed;
        runs(function() {
            expect(caughtExceptions).toEqual(badPayloads);
            var readdata = buffer.toByteArray();
            var appdata = baos.toByteArray();
            expect(readdata).toEqual(appdata);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("payload with incorrect sequence number", function() {
        var badPayloads = 0;
        var baos = new ByteArrayOutputStream();
        var i = 0;
        runs(function() {
            // Payloads with an incorrect sequence number should be skipped.
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            var sequenceNumber = SEQ_NO;
            function writePayload() {
                if (i == MAX_PAYLOAD_CHUNKS)
                    return;

                var data = new Uint8Array(random.nextInt(MAX_DATA_SIZE) + 1);
                random.nextBytes(data);
                if (random.nextBoolean()) {
                    PayloadChunk.create(trustedNetCtx, sequenceNumber++, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext, {
                        result: function(chunk) {
                            payloads.push(chunk);
                            baos.write(data, 0, data.length, TIMEOUT, {
                                result: function(success) {
                                    ++i;
                                    writePayload();
                                },
                                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                            });
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                } else {
                    PayloadChunk.create(trustedNetCtx, 2 * sequenceNumber + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext, {
                        result: function(chunk) {
                            payloads.push(chunk);
                            ++badPayloads;
                            ++i;
                            writePayload();
                        },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                }
            }
            writePayload();
        });
        waitsFor(function() { return i == MAX_PAYLOAD_CHUNKS; }, "payloads to be written", TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        // Read everything. Each bad payload should throw an exception.
        var buffer = new ByteArrayOutputStream();
        var caughtExceptions = 0;
        var eom = false;
        runs(function() {
            function nextRead() {
                mis.read(MAX_READ_LEN, TIMEOUT, {
                    result: function(x) {
                        if (!x) {
                            eom = true;
                            return;
                        }

                        buffer.write(x, 0, x.length, TIMEOUT, {
                            result: function(numWritten) { nextRead(); },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                    error: function(e) {
                        ++caughtExceptions;
                        nextRead();
                    }
                });
            }
            nextRead();
        });
        waitsFor(function() { return eom; }, "eom", TIMEOUT);

        var closed;
        runs(function() {
            expect(caughtExceptions).toEqual(badPayloads);
            var readdata = buffer.toByteArray();
            var appdata = baos.toByteArray();
            expect(readdata).toEqual(appdata);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("read all available", function() {
        var baos;
        var i = 0;
        runs(function() {
            baos = new ByteArrayOutputStream();
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            function writePayload() {
                if (i == MAX_PAYLOAD_CHUNKS)
                    return;

                var data = new Uint8Array(random.nextInt(MAX_DATA_SIZE) + 1);
                random.nextBytes(data);
                PayloadChunk.create(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext, {
                    result: function(chunk) {
                        payloads.push(chunk);
                        baos.write(data, 0, data.length, TIMEOUT, {
                            result: function(success) {
                                ++i;
                                writePayload();
                            },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            writePayload();
        });
        waitsFor(function() { return i == MAX_PAYLOAD_CHUNKS; }, "payloads to be written", TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var firstdata;
        runs(function() {
            mis.read(-1, TIMEOUT, {
                result: function(x) {
                    firstdata = new Uint8Array(x.length);
                    firstdata.set(x, 0);
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return firstdata; }, "read all", TIMEOUT);

        var closed;
        runs(function() {
            // We should have read the first payload's data.
            expect(firstdata).toEqual(payloads[0].data);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", 300);
    });

    it("mark/reset with read all", function() {
        var baos;
        var i = 0;
        runs(function() {
            baos = new ByteArrayOutputStream();
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            function writePayload() {
                if (i == MAX_PAYLOAD_CHUNKS)
                    return;

                var data = new Uint8Array(random.nextInt(MAX_DATA_SIZE) + 1);
                random.nextBytes(data);
                PayloadChunk.create(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext, {
                    result: function(chunk) {
                        payloads.push(chunk);
                        baos.write(data, 0, data.length, TIMEOUT, {
                            result: function(success) {
                                ++i;
                                writePayload();
                            },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            writePayload();
        });
        waitsFor(function() { return i == MAX_PAYLOAD_CHUNKS; }, "payloads to be written", TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var appdata, buffer;
        var firstRead = 0;
        var beginningOffset, beginningLength;
        runs(function() {
            buffer = new Uint8Array(MAX_READ_LEN);
            appdata = baos.toByteArray();

            // Mark and reset to the beginning.
            beginningOffset = 0;
            beginningLength = Math.floor(appdata.length / 4);
            mis.mark();
            mis.read(beginningLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, beginningOffset);
                    firstRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return firstRead > 0; }, "first read", TIMEOUT);

        var secondRead = 0;
        var expectedBeginning;
        runs(function() {
            expectedBeginning = Arrays.copyOf(appdata, beginningOffset, beginningLength);
            expect(firstRead).toEqual(expectedBeginning.length);
            var actualBeginning = Arrays.copyOf(buffer, beginningOffset, beginningLength);
            expect(actualBeginning).toEqual(expectedBeginning);

            mis.reset();
            mis.read(beginningLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, beginningOffset);
                    secondRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return secondRead > 0; }, "second read", TIMEOUT);

        var thirdRead = 0;
        var middleOffset, middleLength;
        runs(function() {
            expect(secondRead).toEqual(expectedBeginning.length);
            var actualBeginning = Arrays.copyOf(buffer, beginningOffset, beginningLength);
            expect(actualBeginning).toEqual(expectedBeginning);

            // Mark and reset from where we are.
            middleOffset = beginningOffset + beginningLength;
            middleLength = Math.floor(appdata.length / 4);
            mis.mark();
            mis.read(middleLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, middleOffset);
                    thirdRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return thirdRead > 0; }, "third read", TIMEOUT);

        var fourthRead = 0;
        var expectedMiddle;
        runs(function() {
            expectedMiddle = Arrays.copyOf(appdata, middleOffset, middleLength);
            expect(thirdRead).toEqual(expectedMiddle.length);
            var actualMiddle = Arrays.copyOf(buffer, middleOffset, middleLength);
            expect(actualMiddle).toEqual(expectedMiddle);

            mis.reset();
            mis.read(middleLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, middleOffset);
                    fourthRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return fourthRead > 0; }, "fourth read", TIMEOUT);

        var fifthRead = 0;
        var endingOffset, endingLength;
        runs(function() {
            expect(fourthRead).toEqual(expectedMiddle.length);
            var actualMiddle = Arrays.copyOf(buffer, middleOffset, middleLength);
            expect(actualMiddle).toEqual(expectedMiddle);

            // Mark and reset the remainder.
            endingOffset = middleOffset + middleLength;
            endingLength = appdata.length - middleLength - beginningLength;
            mis.mark();
            mis.read(endingLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, endingOffset);
                    fifthRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return fifthRead > 0; }, "fifth read", TIMEOUT);

        var sixthRead = 0;
        var expectedEnding;
        runs(function() {
            expectedEnding = Arrays.copyOf(appdata, endingOffset, endingLength);
            expect(fifthRead).toEqual(expectedEnding.length);
            var actualEnding = Arrays.copyOf(buffer, endingOffset, endingLength);
            expect(actualEnding).toEqual(expectedEnding);

            mis.reset();
            mis.read(endingLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, endingOffset);
                    sixthRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return sixthRead > 0; }, "sixth read", TIMEOUT);

        var seventhRead = 0;
        runs(function() {
            mis.reset();
            mis.read(-1, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, endingOffset);
                    seventhRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return seventhRead > 0; }, "seventh read", TIMEOUT);

        var closed;
        runs(function() {
            expect(sixthRead).toEqual(expectedEnding.length);
            expect(seventhRead).toEqual(sixthRead);
            var actualEnding = Arrays.copyOf(buffer, endingOffset, endingLength);
            expect(actualEnding).toEqual(expectedEnding);

            // Confirm equality.
            var actualdata = Arrays.copyOf(buffer, 0, appdata.length);
            expect(actualdata).toEqual(appdata);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("mark/reset with short mark", function() {
        var baos;
        var i = 0;
        runs(function() {
            baos = new ByteArrayOutputStream();
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            function writePayload() {
                if (i == MAX_PAYLOAD_CHUNKS)
                    return;

                var data = new Uint8Array(random.nextInt(MAX_DATA_SIZE) + 1);
                random.nextBytes(data);
                PayloadChunk.create(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext, {
                    result: function(chunk) {
                        payloads.push(chunk);
                        baos.write(data, 0, data.length, TIMEOUT, {
                            result: function(success) {
                                ++i;
                                writePayload();
                            },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            writePayload();
        });
        waitsFor(function() { return i == MAX_PAYLOAD_CHUNKS; }, "payloads to be written", TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var appdata, buffer;
        var firstRead = 0;
        var beginningOffset, beginningLength;
        runs(function() {
            buffer = new Uint8Array(MAX_READ_LEN);
            appdata = baos.toByteArray();

            // Mark and reset to the beginning.
            beginningOffset = 0;
            beginningLength = Math.floor(appdata.length / 2);
            mis.mark();
            mis.read(beginningLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, beginningOffset);
                    firstRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return firstRead > 0; }, "first read", TIMEOUT);

        var reread, rereadLength;
        var expectedBeginning;
        runs(function() {
            expectedBeginning = Arrays.copyOf(appdata, beginningOffset, beginningLength);
            expect(firstRead).toEqual(expectedBeginning.length);
            var actualBeginning = Arrays.copyOf(buffer, beginningOffset, beginningLength);
            expect(actualBeginning).toEqual(expectedBeginning);

            mis.reset();

            // Read a little bit, and mark again so we drop one or more payloads
            // but are likely to have more than one payload remaining.
            rereadLength = Math.floor(appdata.length / 4);
            mis.read(rereadLength, TIMEOUT, {
                result: function(x) {
                    reread = x;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return reread; }, "reread", TIMEOUT);

        var secondRead;
        var endingOffset, endingLength;
        runs(function() {
            expect(reread.length).toEqual(rereadLength);

            // Read the remainder, reset, and re-read to confirm.
            mis.mark();
            endingOffset = reread.length;
            endingLength = appdata.length - endingOffset;
            mis.read(endingLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, endingOffset);
                    secondRead = x.length;
                },timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return secondRead; }, "second read", TIMEOUT);

        var finalRead;
        var expectedEnding;
        runs(function() {
            expectedEnding = Arrays.copyOf(appdata, endingOffset, endingLength);
            expect(secondRead).toEqual(expectedEnding.length);
            var actualEnding = Arrays.copyOf(buffer, endingOffset, endingLength);
            expect(actualEnding).toEqual(expectedEnding);

            mis.reset();
            mis.read(endingLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, endingOffset);
                    finalRead = x.length;
                },timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return finalRead; }, "final read", TIMEOUT);

        var closed;
        runs(function() {
            expect(finalRead).toEqual(expectedEnding.length);
            var actualEnding = Arrays.copyOf(buffer, endingOffset, endingLength);
            expect(actualEnding).toEqual(expectedEnding);

            // Confirm equality.
            var actualdata = Arrays.copyOf(buffer, 0, appdata.length);
            expect(actualdata).toEqual(appdata);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("mark/reset with read limit of 1", function() {
        var baos;
        var i = 0;
        runs(function() {
            baos = new ByteArrayOutputStream();
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            function writePayload() {
                if (i == MAX_PAYLOAD_CHUNKS)
                    return;

                var data = new Uint8Array(random.nextInt(MAX_DATA_SIZE) + 1);
                random.nextBytes(data);
                PayloadChunk.create(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext, {
                    result: function(chunk) {
                        payloads.push(chunk);
                        baos.write(data, 0, data.length, TIMEOUT, {
                            result: function(success) {
                                ++i;
                                writePayload();
                            },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            writePayload();
        });
        waitsFor(function() { return i == MAX_PAYLOAD_CHUNKS; }, "payloads to be written", TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var appdata, buffer;
        var oneRead = 0;
        runs(function() {
            buffer = new Uint8Array(MAX_READ_LEN);
            appdata = baos.toByteArray();
            
            // Mark one byte and reset to the beginning.
            mis.mark(1);
            mis.read(1, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, 0);
                    oneRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return oneRead > 0; }, "one read", TIMEOUT);
        
        var beginningRead = 0;
        var beginningOffset, beginningLength;
        runs(function() {
            var expectedOne = appdata[0];
            expect(buffer[0]).toEqual(expectedOne);
            mis.reset();
            
            // Read a little bit and reset (which should not work).
            beginningOffset = 0;
            beginningLength = Math.floor(appdata.length / 2);
            mis.read(beginningLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, beginningOffset);
                    beginningRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return beginningRead > 0; }, "beginning read", TIMEOUT);
        
        var endingRead = 0;
        var endingOffset, endingLength;
        runs(function() {
            var expectedBeginning = Arrays.copyOf(appdata, beginningOffset, beginningLength);
            expect(beginningRead).toEqual(expectedBeginning.length);
            var actualBeginning = Arrays.copyOf(buffer, beginningOffset, beginningLength);
            expect(actualBeginning).toEqual(expectedBeginning);
            mis.reset();
            
            // Read the remainder.
            endingOffset = beginningLength;
            endingLength = appdata.length - endingOffset;
            mis.read(endingLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, endingOffset);
                    endingRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return endingRead > 0; }, "ending read", TIMEOUT);

        var eos;
        runs(function() {
            var expectedEnding = Arrays.copyOf(appdata, endingOffset, endingLength);
            expect(endingRead).toEqual(expectedEnding.length);
            var actualEnding = Arrays.copyOf(buffer, endingOffset, endingLength);
            expect(actualEnding).toEqual(expectedEnding);
            
            // Confirm equality.
            var actualdata = Arrays.copyOf(buffer, 0, appdata.length);
            expect(actualdata).toEqual(appdata);
            
            // Confirm end-of-stream.
            mis.read(-1, TIMEOUT, {
                result: function(x) {
                    eos = x;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return eos == null; }, "end-of-stream", TIMEOUT);
        
        var closed;
        runs(function() {
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
    
    it("mark/reset with read limit", function() {
        var baos;
        var i = 0;
        runs(function() {
            baos = new ByteArrayOutputStream();
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            function writePayload() {
                if (i == MAX_PAYLOAD_CHUNKS)
                    return;

                var data = new Uint8Array(random.nextInt(MAX_DATA_SIZE) + 1);
                random.nextBytes(data);
                PayloadChunk.create(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext, {
                    result: function(chunk) {
                        payloads.push(chunk);
                        baos.write(data, 0, data.length, TIMEOUT, {
                            result: function(success) {
                                ++i;
                                writePayload();
                            },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            writePayload();
        });
        waitsFor(function() { return i == MAX_PAYLOAD_CHUNKS; }, "payloads to be written", TIMEOUT);

        var is;
        runs(function() {
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var appdata, buffer;
        var beginningRead = 0;
        var beginningOffset, beginningLength;
        runs(function() {
            buffer = new Uint8Array(MAX_READ_LEN);
            appdata = baos.toByteArray();
            
            // Read a little bit and mark with a short read limit.
            beginningOffset = 0;
            beginningLength = Math.floor(appdata.length / 4);
            mis.read(beginningLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, beginningOffset);
                    beginningRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return beginningRead > 0; }, "beginning read", TIMEOUT);
        
        var readlimit;
        var readRead = 0;
        var readOffset, readLength;
        runs(function() {
            var expectedBeginning = Arrays.copyOf(appdata, beginningOffset, beginningLength);
            expect(beginningRead).toEqual(expectedBeginning.length);
            var actualBeginning = Arrays.copyOf(buffer, beginningOffset, beginningLength);
            expect(actualBeginning).toEqual(expectedBeginning);
            readlimit = Math.floor(appdata.length / 8);
            mis.mark(readlimit);
            
            // Read up to the read limit.
            readOffset = beginningLength;
            readLength = readlimit;
            mis.read(readLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, readOffset);
                    readRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return readRead > 0; }, "read read", TIMEOUT);
        
        var expectedRead;
        runs(function() {
            expectedRead = Arrays.copyOf(appdata, readOffset, readLength);
            expect(readRead).toEqual(expectedRead.length);
            var actualRead = Arrays.copyOf(buffer, readOffset, readLength);
            expect(actualRead).toEqual(expectedRead);
            
            // Reset and re-read.
            readRead = 0;
            mis.reset();
            mis.read(readLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, readOffset);
                    readRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return readRead > 0; }, "re-read read", TIMEOUT);
        
        runs(function() {
            expect(readRead).toEqual(expectedRead.length);
            var actualRead = Arrays.copyOf(buffer, readOffset, readLength);
            expect(actualRead).toEqual(expectedRead);
            
            // Reset and re-read.
            readRead = 0;
            mis.reset();
            mis.read(readLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, readOffset);
                    readRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return readRead > 0; }, "re-re-read read", TIMEOUT);
        
        var readPastRead = 0;
        var readPastOffset, readPastLength;
        runs(function() {
            expect(readRead).toEqual(expectedRead.length);
            var actualRead = Arrays.copyOf(buffer, readOffset, readLength);
            expect(actualRead).toEqual(expectedRead);

            // Reset and read past the read limit.
            mis.reset();
            readPastOffset = beginningLength;
            readPastLength = readlimit + 1;
            mis.read(readPastLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, readPastOffset);
                    readPastRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return readPastRead > 0; }, "read past read", TIMEOUT);
        
        var endingRead;
        var endingOffset, endingLength;
        runs(function() {
            var expectedReadPast = Arrays.copyOf(appdata, readPastOffset, readPastLength);
            expect(readPastRead).toEqual(expectedReadPast.length);
            var actualReadPast = Arrays.copyOf(buffer, readPastOffset, readPastLength);
            expect(actualReadPast).toEqual(expectedReadPast);

            // Reset and confirm it did not work.
            mis.reset();
            endingOffset = readPastOffset + readPastLength;
            endingLength = appdata.length - endingOffset;
            mis.read(endingLength, TIMEOUT, {
                result: function(x) {
                    buffer.set(x, endingOffset);
                    endingRead = x.length;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return endingRead > 0; }, "ending read", TIMEOUT);
        
        runs(function() {
            var expectedEnding = Arrays.copyOf(appdata, endingOffset, endingLength);
            expect(endingRead).toEqual(expectedEnding.length);
            var actualEnding = Arrays.copyOf(buffer, endingOffset, endingLength);
            expect(actualEnding).toEqual(expectedEnding);

            // Confirm equality.
            var actualdata = Arrays.copyOf(buffer, 0, appdata.length);
            expect(actualdata).toEqual(appdata);
            
            // Confirm end-of-stream.
            mis.read(-1, TIMEOUT, {
                result: function(x) {
                    eos = x;
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return eos == null; }, "end-of-stream", TIMEOUT);
        
        var closed;
        runs(function() {
            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("large payload", function() {
        var data = new Uint8Array(250 * 1024);
        random.nextBytes(data);

        var chunk;
        runs(function() {
            var cryptoContext = MESSAGE_HEADER.cryptoContext;
            PayloadChunk.create(trustedNetCtx, SEQ_NO, MSG_ID, true, null, data, cryptoContext, {
                result: function(x) { chunk = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return chunk; }, "chunk", TIMEOUT);

        var is;
        runs(function() {
            payloads.push(chunk);
            generateInputStream(MESSAGE_HEADER, payloads, {
                result: function(x) { is = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return is; }, "is", MslTestConstants.TIMEOUT);

        var mis;
        runs(function() {
            MessageInputStream.create(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", MslTestConstants.TIMEOUT);

        var ready = false;
        runs(function() {
            mis.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mis ready", MslTestConstants.TIMEOUT);

        var buffer;
        runs(function() {
            mis.read(data.length, TIMEOUT, {
                result: function(x) { buffer = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return buffer !== undefined; }, "buffer", TIMEOUT);

        var extra;
        runs(function() {
            mis.read(1, TIMEOUT, {
                result: function(x) { extra = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return extra !== undefined; }, "extra", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            expect(buffer.length).toEqual(data.length);
            expect(extra).toBeNull();
            expect(buffer).toEqual(data);

            mis.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });
});
