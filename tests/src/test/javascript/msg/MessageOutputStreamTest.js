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
 * Message output stream unit tests.
 *
 * These tests assume the MessageOutputStream does not construct the header
 * data but delegates that to the Header. Likewise for PayloadChunks. So there
 * are no checks for proper encoding.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("MessageOutputStream", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var Random = require('msl-core/util/Random.js');
    var ByteArrayOutputStream = require('msl-core/io/ByteArrayOutputStream.js');
    var MessageHeader = require('msl-core/msg/MessageHeader.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var UnauthenticatedAuthenticationData = require('msl-core/entityauth/UnauthenticatedAuthenticationData.js');
    var PresharedAuthenticationData = require('msl-core/entityauth/PresharedAuthenticationData.js');
    var RsaAuthenticationData = require('msl-core/entityauth/RsaAuthenticationData.js');
    var ErrorHeader = require('msl-core/msg/ErrorHeader.js');
    var MessageOutputStream = require('msl-core/msg/MessageOutputStream.js');
    var ByteArrayInputStream = require('msl-core/io/ByteArrayInputStream.js');
    var Header = require('msl-core/msg/Header.js');
    var PayloadChunk = require('msl-core/msg/PayloadChunk.js');
    var MslObject = require('msl-core/io/MslObject.js');
    var Arrays = require('msl-core/util/Arrays.js');
    var InterruptibleExecutor = require('msl-core/util/InterruptibleExecutor.js');
    var MessageFactory = require('msl-core/msg/MessageFactory.js');
    var MessageCapabilities = require('msl-core/msg/MessageCapabilities.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var MslError = require('msl-core/MslError.js');
    var MslIoException = require('msl-core/MslIoException.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');
    var SymmetricWrappedExchange = require('msl-core/keyx/SymmetricWrappedExchange.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockRsaAuthenticationFactory = require('msl-tests/entityauth/MockRsaAuthenticationFactory.js');
    var MockPresharedAuthenticationFactory = require('msl-tests/entityauth/MockPresharedAuthenticationFactory.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');

    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Message factory. */
    var messageFactory = new MessageFactory();

    /** Maximum number of payload chunks to generate. */
    var MAX_PAYLOAD_CHUNKS = 10;
    /** Maximum payload chunk data size in bytes. */
    var MAX_DATA_SIZE = 10 * 1024;
    /** Compressible data. */
    var COMPRESSIBLE_DATA = TextEncoding.getBytes(
            "Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me." +
            "Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me." +
            "Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me."
    );
    /** I/O operation timeout in milliseconds. */
    var TIMEOUT = 20;

    /** Random. */
    var random = new Random();
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    /** Destination output stream. */
    var destination = new ByteArrayOutputStream();
    /** Payload crypto context. */
    var PAYLOAD_CRYPTO_CONTEXT;
    /** Header service token crypto contexts. */
    var cryptoContexts = [];

    var ENTITY_AUTH_DATA;
    var MESSAGE_HEADER;
    var ERROR_HEADER;
    var KEY_REQUEST_DATA = [];
    var KEY_RESPONSE_DATA;
    var KEYX_CRYPTO_CONTEXT;

    var UNAUTHENTICATED_ESN = "MOCKUNAUTH-ESN";

    // Shortcuts.
    var HeaderData = MessageHeader.HeaderData;
    var HeaderPeerData = MessageHeader.HeaderPeerData;
    var CompressionAlgorithm = MslConstants.CompressionAlgorithm;
    var KeyId = SymmetricWrappedExchange.KeyId;

    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);

            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                ctx.getEntityAuthenticationData(null, {
                    result: function(x) { ENTITY_AUTH_DATA = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ENTITY_AUTH_DATA; }, "entity authentication data", MslTestConstants.TIMEOUT);

            runs(function() {
                var headerData = new HeaderData(1, null, false, false, ctx.getMessageCapabilities(), null, null, null, null, null);
                var peerData = new HeaderPeerData(null, null, null);
                MessageHeader.create(ctx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                    result: function(x) { MESSAGE_HEADER = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
                ErrorHeader.create(ctx, ENTITY_AUTH_DATA, 1, MslConstants.ResponseCode.FAIL, 3, "errormsg", "usermsg", {
                    result: function(x) { ERROR_HEADER = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return MESSAGE_HEADER && ERROR_HEADER; }, "message header and error header", MslTestConstants.TIMEOUT);
            
            var keyxData;
            runs(function() {
                PAYLOAD_CRYPTO_CONTEXT = MESSAGE_HEADER.cryptoContext;
                var keyRequest = new SymmetricWrappedExchange.RequestData(KeyId.PSK);
                KEY_REQUEST_DATA.push(keyRequest);
                var factory = ctx.getKeyExchangeFactory(keyRequest.keyExchangeScheme);
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequest, ENTITY_AUTH_DATA, {
                    result: function(x) { keyxData = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return keyxData; }, "key exchange data", MslTestConstants.TIMEOUT);
            
            runs(function() {
                KEY_RESPONSE_DATA = keyxData.keyResponseData;
                KEYX_CRYPTO_CONTEXT = keyxData.cryptoContext;
                initialized = true;
            });
        }
    });

    afterEach(function() {
        destination = new ByteArrayOutputStream();
    });

    it("message header stream", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var tokenizer;
        runs(function() {
            mos.close(TIMEOUT, {
                result: function(success) {
                    var mslMessage = new ByteArrayInputStream(destination.toByteArray());
                    encoder.createTokenizer(mslMessage, null, TIMEOUT, {
                        result: function(x) { tokenizer = x; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenizer; }, "tokenizer", MslTestConstants.TIMEOUT);

        var more;
        runs(function() {
            // There should be one header.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more !== undefined; }, "more", MslTestConstants.TIMEOUT);

        var first;
        runs(function() {
            expect(more).toBeTruthy();
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { first = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return first; }, "first", MslTestConstants.TIMEOUT);

        var header;
        runs(function() {
            expect(first instanceof MslObject).toBeTruthy();
            var headerMo = first;

            // The reconstructed header should be equal to the original.
            Header.parseHeader(ctx, headerMo, cryptoContexts, {
                result: function(x) { header = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return header; }, "header", MslTestConstants.TIMEOUT);

        var messageHeader, more2;
        runs(function() {
            expect(header instanceof MessageHeader).toBeTruthy();
            messageHeader = header;
            expect(messageHeader).toEqual(MESSAGE_HEADER);

            // There should be one payload with no data indicating end of message.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more2 = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more2 !== undefined; }, "more2", MslTestConstants.TIMEOUT);

        var second;
        runs(function() {
            expect(more2).toBeTruthy();
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { second = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return second; }, "second", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            expect(second instanceof MslObject).toBeTruthy();
            var payloadMo = second;

            // Verify the payload.
            var cryptoContext = messageHeader.cryptoContext;
            expect(cryptoContext).not.toBeNull();
            PayloadChunk.parse(ctx, payloadMo, cryptoContext, {
                result: function(x) { payload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload not received", MslTestConstants.TIMEOUT);

        var more3;
        runs(function() {
            expect(payload.isEndOfMessage()).toBeTruthy();
            expect(payload.sequenceNumber).toEqual(1);
            expect(payload.messageId).toEqual(MESSAGE_HEADER.messageId);
            expect(payload.data.length).toEqual(0);

            // There should be nothing else.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more3 = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more3 !== undefined; }, "more3", MslTestConstants.TIMEOUT);

        var tokenizerClosed = false;
        runs(function() {
            expect(more3).toBeFalsy();

            // Verify cached payloads.
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0]).toEqual(payload);

            // Close tokenizer.
            tokenizer.close(-1, {
                result: function(x) { tokenizerClosed = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return tokenizerClosed; }, "tokenizer closed", MslTestConstants.TIMEOUT);
    });

    it("error header stream", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, ERROR_HEADER, null, ENCODER_FORMAT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var tokenizer;
        runs(function() {
            mos.close(TIMEOUT, {
                result: function(success) {
                    var mslMessage = new ByteArrayInputStream(destination.toByteArray());
                    encoder.createTokenizer(mslMessage, null, TIMEOUT, {
                        result: function(x) { tokenizer = x; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenizer; }, "tokenizer", MslTestConstants.TIMEOUT);

        var more;
        runs(function() {
            // There should be one header.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more !== undefined; }, "more", MslTestConstants.TIMEOUT);

        var first;
        runs(function() {
            expect(more).toBeTruthy();
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { first = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return first; }, "first", MslTestConstants.TIMEOUT);

        var header;
        runs(function() {
            expect(first instanceof MslObject).toBeTruthy();
            var headerMo = first;

            // The reconstructed header should be equal to the original.
            Header.parseHeader(ctx, headerMo, cryptoContexts, {
                result: function(x) { header = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return header; }, "header", MslTestConstants.TIMEOUT);

        var more2;
        runs(function() {
            expect(header instanceof ErrorHeader).toBeTruthy();
            expect(header).toEqual(ERROR_HEADER);

            // There should be no payloads.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more2 = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more2 !== undefined; }, "more2", MslTestConstants.TIMEOUT);

        var tokenizerClosed = false;
        runs(function() {
            expect(more2).toBeFalsy();

            // Verify cached payloads.
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(0);

            // Close tokenizer.
            tokenizer.close(-1, {
                result: function(x) { tokenizerClosed = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return tokenizerClosed; }, "tokenizer closed", MslTestConstants.TIMEOUT);
    });
    
    it("entity authentication scheme encrypts", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            var cryptoContext = messageHeader.cryptoContext;
            MessageOutputStream.create(ctx, destination, messageHeader, cryptoContext, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.encryptsPayloads()).toBeTruthy();
            mos.close(TIMEOUT, {
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
            var headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            var cryptoContext = messageHeader.cryptoContext;
            MessageOutputStream.create(ctx, destination, messageHeader, cryptoContext, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.encryptsPayloads()).toBeFalsy();
            mos.close(TIMEOUT, {
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
            var headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            var cryptoContext = messageHeader.cryptoContext;
            MessageOutputStream.create(ctx, destination, messageHeader, cryptoContext, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.protectsPayloadIntegrity()).toBeTruthy();
            mos.close(TIMEOUT, {
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
            var headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            var cryptoContext = messageHeader.cryptoContext;
            MessageOutputStream.create(ctx, destination, messageHeader, cryptoContext, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.protectsPayloadIntegrity()).toBeFalsy();
            mos.close(TIMEOUT, {
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
            var headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.encryptsPayloads()).toBeTruthy();
            mos.close(TIMEOUT, {
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
            var headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.protectsPayloadIntegrity()).toBeTruthy();
            mos.close(TIMEOUT, {
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
            var headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.encryptsPayloads()).toBeTruthy();
            mos.close(TIMEOUT, {
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
            var headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(ctx, entityAuthData, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.protectsPayloadIntegrity()).toBeTruthy();
            mos.close(TIMEOUT, {
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
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT)
        
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            var cryptoContext = messageHeader.cryptoContext;
            MessageOutputStream.create(ctx, destination, messageHeader, cryptoContext, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.encryptsPayloads()).toBeTruthy();
            mos.close(TIMEOUT, {
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
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT)
        
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            var cryptoContext = messageHeader.cryptoContext;
            MessageOutputStream.create(ctx, destination, messageHeader, cryptoContext, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.protectsPayloadIntegrity()).toBeTruthy();
            mos.close(TIMEOUT, {
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
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT)
        
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.encryptsPayloads()).toBeTruthy();
            mos.close(TIMEOUT, {
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
            MslTestUtils.getMasterToken(ctx, 1, 1, {
                result: function(x) { masterToken = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return masterToken; }, "master token", MslTestConstants.TIMEOUT)
        
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            var entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
            MessageHeader.create(ctx, null, masterToken, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);
        
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "message output stream", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mis ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);
        
        var closed;
        runs(function() {
            expect(mos.protectsPayloadIntegrity()).toBeTruthy();
            mos.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);
    });

    it("write with offsets", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var data = new Uint8Array(32);
        random.nextBytes(data);
        var from = 8;
        var length = 8;
        var to = from + length; // exclusive
        var written = false;
        runs(function() {
            mos.write(data, from, length, TIMEOUT, {
                result: function(success) {
                    mos.close(TIMEOUT, {
                        result: function(success) { written = success; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return written; }, "written", MslTestConstants.TIMEOUT);

        var tokenizer;
        runs(function() {
            var mslMessage = new ByteArrayInputStream(destination.toByteArray());
            encoder.createTokenizer(mslMessage, null, TIMEOUT, {
                result: function(x) { tokenizer = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenizer; }, "tokenizer", MslTestConstants.TIMEOUT);

        var more;
        runs(function() {
            // There should be one header.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more !== undefined; }, "more", MslTestConstants.TIMEOUT);

        var first;
        runs(function() {
            expect(more).toBeTruthy();
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { first = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return first; }, "first", MslTestConstants.TIMEOUT);

        var header;
        runs(function() {
            // There should be one header.
            expect(first instanceof MslObject).toBeTruthy();
            var headerMo = first;

            // We assume the reconstructed header is equal to the original.
            Header.parseHeader(ctx, headerMo, cryptoContexts, {
                result: function(x) { header = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return header; }, "header", MslTestConstants.TIMEOUT);

        var messageHeader, more2;
        runs(function() {
            expect(header instanceof MessageHeader).toBeTruthy();
            messageHeader = header;

            // There should be one payload.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more2 = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more2 !== undefined; }, "more2", MslTestConstants.TIMEOUT);

        var second;
        runs(function() {
            expect(more2).toBeTruthy();
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { second = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return second; }, "second", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            expect(second instanceof MslObject).toBeTruthy();
            var payloadMo = second;

            // Verify the payload.
            var cryptoContext = messageHeader.cryptoContext;
            expect(cryptoContext).not.toBeNull();
            PayloadChunk.parse(ctx, payloadMo, cryptoContext, {
                result: function(x) { payload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var more3;
        runs(function() {
            expect(payload.isEndOfMessage()).toBeTruthy();
            expect(payload.sequenceNumber).toEqual(1);
            expect(payload.messageId).toEqual(MESSAGE_HEADER.messageId);
            expect(payload.data).toEqual(new Uint8Array(data.subarray(from, to)));

            // There should be nothing else.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more3 = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more3 !== undefined; }, "more3", MslTestConstants.TIMEOUT);

        var tokenizerClosed = false;
        runs(function() {
            expect(more3).toBeFalsy();

            // Verify cached payloads.
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0]).toEqual(payload);

            // Close tokenizer.
            tokenizer.close(-1, {
                result: function(x) { tokenizerClosed = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return tokenizerClosed; }, "tokenizer closed", MslTestConstants.TIMEOUT);
    });

    it("write", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var data = new Uint8Array(32);
        random.nextBytes(data);
        var written = false;
        runs(function() {
            mos.write(data, 0, data.length, TIMEOUT, {
                result: function(success) {
                    expect(success).toBeTruthy();
                    mos.close(TIMEOUT, {
                        result: function(success) { written = true; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return written; }, "written", MslTestConstants.TIMEOUT);

        var tokenizer;
        runs(function() {
            var mslMessage = new ByteArrayInputStream(destination.toByteArray());
            encoder.createTokenizer(mslMessage, null, TIMEOUT, {
                result: function(x) { tokenizer = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenizer; }, "tokenizer", MslTestConstants.TIMEOUT);

        var more;
        runs(function() {
            // There should be one header.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more !== undefined; }, "more", MslTestConstants.TIMEOUT);

        var first;
        runs(function() {
            expect(more).toBeTruthy();
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { first = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return first; }, "first", MslTestConstants.TIMEOUT);

        var header;
        runs(function() {
            expect(first instanceof MslObject).toBeTruthy();
            var headerMo = first;

            // We assume the reconstructed header is equal to the original.
            Header.parseHeader(ctx, headerMo, cryptoContexts, {
                result: function(x) { header = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return header; }, "header", MslTestConstants.TIMEOUT);

        var messageHeader, more2;
        runs(function() {
            expect(header instanceof MessageHeader).toBeTruthy();
            messageHeader = header;

            // There should be one payload.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more2 = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more2 !== undefined; }, "more2", MslTestConstants.TIMEOUT);

        var second;
        runs(function() {
            expect(more2).toBeTruthy();
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { second = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return second; }, "second", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            expect(second instanceof MslObject).toBeTruthy();
            var payloadMo = second;

            // Verify the payload.
            var cryptoContext = messageHeader.cryptoContext;
            expect(cryptoContext).not.toBeNull();
            PayloadChunk.parse(ctx, payloadMo, cryptoContext, {
                result: function(x) { payload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload not received", MslTestConstants.TIMEOUT);

        var more3;
        runs(function() {
            expect(payload.isEndOfMessage()).toBeTruthy();
            expect(payload.sequenceNumber).toEqual(1);
            expect(payload.messageId).toEqual(MESSAGE_HEADER.messageId);
            expect(payload.data).toEqual(data);

            tokenizer.more(TIMEOUT, {
                result: function(x) { more3 = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more3 !== undefined; }, "more3", MslTestConstants.TIMEOUT);

        var tokenizerClosed = false;
        runs(function() {
            expect(more3).toBeFalsy();

            // Verify cached payloads.
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0]).toEqual(payload);

            // Close tokenizer.
            tokenizer.close(-1, {
                result: function(x) { tokenizerClosed = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return tokenizerClosed; }, "tokenizer closed", MslTestConstants.TIMEOUT);
    });

    it("write with compression", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var first = Arrays.copyOf(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length);
        var secondA = Arrays.copyOf(first, 0, 2 * first.length);
        secondA.set(first, first.length);
        var secondB = Arrays.copyOf(first, 0, 3 * first.length);
        secondB.set(first, first.length);
        secondB.set(first, 2 * first.length);

        var written = false;
        runs(function() {
            // Write the first payload.
            mos.setCompressionAlgorithm(null, TIMEOUT, {
                result: function(success) {
                    expect(success).toBeTruthy();
                    mos.write(first, 0, first.length, TIMEOUT, {
                        result: function() { written = true; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "first", MslTestConstants.TIMEOUT);

        runs(function() {
            written = false;
            // Changing the compressed value should result in a new payload.
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) {
                    expect(success).toBeTruthy();
                    mos.write(secondA, 0, secondA.length, TIMEOUT, {
                        result: function() { written = true; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "secondA", MslTestConstants.TIMEOUT);

        runs(function() {
            written = false;
            // Setting the compressed value to the same should maintain the same
            // payload.
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) {
                    expect(success).toBeTruthy();
                    mos.write(secondB, 0, secondB.length, TIMEOUT, {
                        result: function() { written = true; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "secondB", MslTestConstants.TIMEOUT);

        var closed = false;
        runs(function() {
            // Changing the compressed value should flush the second payload.
            mos.setCompressionAlgorithm(null, TIMEOUT, {
                result: function(success) {
                    expect(success).toBeTruthy();
                    // Closing should create a final payload.
                    mos.close(TIMEOUT, {
                        result: function(success) { closed = success; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);

        var tokenizer;
        runs(function() {
            var mslMessage = new ByteArrayInputStream(destination.toByteArray());
            encoder.createTokenizer(mslMessage, null, TIMEOUT, {
                result: function(x) { tokenizer = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenizer; }, "tokenizer", MslTestConstants.TIMEOUT);

        var headerMo;
        runs(function() {
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { headerMo = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return headerMo; }, "headerMo", MslTestConstants.TIMEOUT);

        var payloadMos = [];
        var noMore = false;
        runs(function() {
            function loop() {
                tokenizer.more(TIMEOUT, {
                    result: function(more) {
                        if (!more) {
                            noMore = true;
                            return;
                        }

                        tokenizer.nextObject(TIMEOUT, {
                            result: function(mo) {
                                payloadMos.push(mo);
                                loop();
                            },
                            timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            loop();
        });
        waitsFor(function() { return noMore; }, "no more", MslTestConstants.TIMEOUT);
        
        var tokenizerClosed = false;
        runs(function() {
            tokenizer.close(-1, {
                result: function(x) { tokenizerClosed = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return tokenizerClosed; }, "tokenizer closed", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            // Verify the number and contents of the payloads.
            Header.parseHeader(ctx, headerMo, cryptoContexts, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "messageHeader", MslTestConstants.TIMEOUT);

        var firstPayload, secondPayload, thirdPayload;
        runs(function() {
            var cryptoContext = messageHeader.cryptoContext;
            expect(payloadMos.length).toEqual(3);
            PayloadChunk.parse(ctx, payloadMos[0], cryptoContext, {
                result: function(x) { firstPayload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.parse(ctx, payloadMos[1], cryptoContext, {
                result: function(x) { secondPayload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.parse(ctx, payloadMos[2], cryptoContext, {
                result: function(x) { thirdPayload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return firstPayload && secondPayload && thirdPayload; }, "payloads", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(firstPayload.data).toEqual(first);
            expect(Arrays.copyOf(secondPayload.data, 0, secondA.length)).toEqual(secondA);
            expect(Arrays.copyOf(secondPayload.data, secondA.length, secondB.length)).toEqual(secondB);
            expect(thirdPayload.data.length).toEqual(0);
            expect(thirdPayload.isEndOfMessage()).toBeTruthy();

            // Verify cached payloads.
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(payloadMos.length);
            expect(payloads[0]).toEqual(firstPayload);
            expect(payloads[1]).toEqual(secondPayload);
            expect(payloads[2]).toEqual(thirdPayload);
        });
    });

    it("flush", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var first = new Uint8Array(10);
        random.nextBytes(first);
        var secondA = new Uint8Array(20);
        random.nextBytes(secondA);
        var secondB = new Uint8Array(30);
        random.nextBytes(secondB);

        var write = false;
        runs(function() {
            // Write the first payload.
            mos.write(first, 0, first.length, TIMEOUT, {
                result: function() { write = true; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return write; }, "write", MslTestConstants.TIMEOUT);

        var flush = false;
        runs(function() {
            // Flushing should result in a new payload.
            mos.flush(TIMEOUT, {
                result: function() { flush = true; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return flush; }, "flush", MslTestConstants.TIMEOUT);

        var writeA = false;
        runs(function() {
            mos.write(secondA, 0, secondA.length, TIMEOUT, {
                result: function() { writeA = true; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return writeA; }, "writeA", MslTestConstants.TIMEOUT);

        var writeB = false;
        runs(function() {
            // Not flushing should maintain the same payload.
            mos.write(secondB, 0, secondB.length, TIMEOUT, {
                result: function() { writeB = true; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return writeB; }, "writeB", MslTestConstants.TIMEOUT);

        var finalFlush = false;
        runs(function() {
            // Flush the second payload.
            mos.flush(TIMEOUT, {
                result: function() { finalFlush = true; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return finalFlush; }, "finalFlush", MslTestConstants.TIMEOUT);

        var written;
        runs(function() {
            // Closing should create a final payload.
            mos.close(TIMEOUT, {
                result: function(success) { written = success; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            }); 
        });
        waitsFor(function() { return written; }, "written", MslTestConstants.TIMEOUT);

        var tokenizer;
        runs(function() {
            // Grab the MSL objects.
            var mslMessage = new ByteArrayInputStream(destination.toByteArray());
            encoder.createTokenizer(mslMessage, null, TIMEOUT, {
                result: function(x) { tokenizer = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenizer; }, "tokenizer", MslTestConstants.TIMEOUT);

        var headerMo;
        runs(function() {
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { headerMo = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return headerMo; }, "headerMo", MslTestConstants.TIMEOUT);

        var payloadMos = [];
        var noMore = false;
        runs(function() {
            function loop() {
                tokenizer.more(TIMEOUT, {
                    result: function(more) {
                        if (!more) {
                            noMore = true;
                            return;
                        }

                        tokenizer.nextObject(TIMEOUT, {
                            result: function(mo) {
                                payloadMos.push(mo);
                                loop();
                            },
                            timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            loop();
        });
        waitsFor(function() { return noMore; }, "no more", MslTestConstants.TIMEOUT);
        
        var tokenizerClosed = false;
        runs(function() {
            tokenizer.close(-1, {
                result: function(x) { tokenizerClosed = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return tokenizerClosed; }, "tokenizer closed", MslTestConstants.TIMEOUT);

        var messageHeader;
        runs(function() {
            // Verify the number and contents of the payloads.
            Header.parseHeader(ctx, headerMo, cryptoContexts, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader && payloadMos; }, "messageHeader and payloadMos", MslTestConstants.TIMEOUT);

        var firstPayload, secondPayload, thirdPayload;
        runs(function() {
            var cryptoContext = messageHeader.cryptoContext;
            expect(payloadMos.length).toEqual(3);
            PayloadChunk.parse(ctx, payloadMos[0], cryptoContext, {
                result: function(x) { firstPayload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.parse(ctx, payloadMos[1], cryptoContext, {
                result: function(x) { secondPayload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            PayloadChunk.parse(ctx, payloadMos[2], cryptoContext, {
                result: function(x) { thirdPayload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return firstPayload && secondPayload && thirdPayload; }, "payloads", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(Arrays.copyOf(secondPayload.data, 0, secondA.length)).toEqual(secondA);
            expect(Arrays.copyOf(secondPayload.data, secondA.length, secondB.length)).toEqual(secondB);
            expect(firstPayload.data).toEqual(first);

            expect(thirdPayload.data.length).toEqual(0);
            expect(thirdPayload.isEndOfMessage()).toBeTruthy();

            // Verify cached payloads.
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(payloadMos.length);
            expect(payloads[0]).toEqual(firstPayload);
            expect(payloads[1]).toEqual(secondPayload);
            expect(payloads[2]).toEqual(thirdPayload);
        });
    });

    it("write to an error header stream", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, ERROR_HEADER, null, ENCODER_FORMAT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var data = new Uint8Array(0);
            mos.write(data, 0, data.length, TIMEOUT, {
                result: function() {},
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            mos.close(TIMEOUT, {
                result: function() {},
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function() {}
            });
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });

    it("write to a handshake message", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(1, null, false, true, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);

        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, messageHeader, messageHeader.cryptoContext, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            var data = new Uint8Array(0);
            mos.write(data, 0, data.length, TIMEOUT, {
                result: function() {},
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { exception = e; }
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            mos.close(TIMEOUT, {
                result: function() {},
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function() {}
            });
            var f = function() { throw exception; };
            expect(f).toThrow(new MslInternalException(MslError.NONE));
        });
    });

    it("closed", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var exception;
        runs(function() {
            mos.close(TIMEOUT, {
                result: function() {
                    var data = new Uint8Array(0);
                    mos.write(data, 0, data.length, TIMEOUT, {
                        result: function() {},
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { exception = e; }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslIoException());
        });
    });

    it("flush an error header stream", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, ERROR_HEADER, null, ENCODER_FORMAT, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var flushed = false;
        runs(function() {
            // No data so this should be a no-op.
            mos.flush(TIMEOUT, {
                result: function(success) {
                    flushed = success;
                    mos.close(TIMEOUT, {
                        result: function(success) { flushed &= success; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return flushed; }, "flushed", MslTestConstants.TIMEOUT);
    });

    it("stop caching", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var first = new Uint8Array(10);
        random.nextBytes(first);
        var second = new Uint8Array(20);
        random.nextBytes(second);

        var wroteFirst = false;
        runs(function() {
            // Write the first payload.
            mos.write(first, 0, first.length, TIMEOUT, {
                result: function() {
                    mos.flush(TIMEOUT, {
                        result: function() { wroteFirst = true; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return wroteFirst; }, "wroteFirst", MslTestConstants.TIMEOUT);

        var wroteSecond = false;
        runs(function() {
            // Verify one payload.
            var onePayload = mos.getPayloads();
            expect(onePayload.length).toEqual(1);

            // Stop caching.
            mos.stopCaching();
            var zeroPayload = mos.getPayloads();
            expect(zeroPayload.length).toEqual(0);

            // Write the second payload.
            mos.write(second, 0, second.length, TIMEOUT, {
                result: function() {
                    mos.flush(TIMEOUT, {
                        result: function() { wroteSecond = true; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return wroteSecond; }, "wroteSecond", MslTestConstants.TIMEOUT);

        runs(function() {
            // Verify zero payloads.
            var twoPayload = mos.getPayloads();
            expect(twoPayload.length).toEqual(0);

            // Close.
            mos.close(TIMEOUT, {
                result: function() {},
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
    });

    it("call close multiple times", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { throw new Error("Timed out waiting for mos."); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var closed = false;
        runs(function() {
            mos.close(TIMEOUT, {
                result: function(success) {
                    closed = success;
                    mos.close(TIMEOUT, {
                        result: function(success) { closed = success; },
                        timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);

        var tokenizer;
        runs(function() {
            var mslMessage = new ByteArrayInputStream(destination.toByteArray());
            encoder.createTokenizer(mslMessage, null, TIMEOUT, {
                result: function(x) { tokenizer = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenizer; }, "tokenizer", MslTestConstants.TIMEOUT);

        var more;
        runs(function() {
            // There should be one header.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more !== undefined; }, "more", MslTestConstants.TIMEOUT);

        var first;
        runs(function() {
            expect(more).toBeTruthy();
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { first = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return first; }, "first", MslTestConstants.TIMEOUT);

        var header;
        runs(function() {
            expect(first instanceof MslObject).toBeTruthy();
            var headerMo = first;

            // We assume the reconstructed header is equal to the original.
            Header.parseHeader(ctx, headerMo, cryptoContexts, {
                result: function(x) { header = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return header; }, "header", MslTestConstants.TIMEOUT);

        var messageHeader, more2;
        runs(function() {
            expect(header instanceof MessageHeader).toBeTruthy();
            messageHeader = header;

            // There should be one payload with no data indicating end of message.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more2 = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more2 !== undefined; }, "more2", MslTestConstants.TIMEOUT);

        var second;
        runs(function() {
            expect(more2).toBeTruthy();
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { second = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return second; }, "second", MslTestConstants.TIMEOUT);

        var payload;
        runs(function() {
            expect(second instanceof MslObject).toBeTruthy();
            var payloadMo = second;

            // Verify the payload.
            var cryptoContext = messageHeader.cryptoContext;
            expect(cryptoContext).not.toBeNull();
            PayloadChunk.parse(ctx, payloadMo, cryptoContext, {
                result: function(x) { payload = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return payload; }, "payload", MslTestConstants.TIMEOUT);

        var more3;
        runs(function() {
            expect(payload.isEndOfMessage()).toBeTruthy();
            expect(payload.sequenceNumber).toEqual(1);
            expect(payload.messageId).toEqual(MESSAGE_HEADER.messageId);
            expect(payload.data.length).toEqual(0);

            // There should be nothing else.
            tokenizer.more(TIMEOUT, {
                result: function(x) { more3 = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return more3 !== undefined; }, "more3", MslTestConstants.TIMEOUT);

        var tokenizerClosed = false;
        runs(function() {
            expect(more3).toBeFalsy();

            // Verify cached payloads.
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0]).toEqual(payload);

            // Close tokenizer.
            tokenizer.close(-1, {
                result: function(x) { tokenizerClosed = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return tokenizerClosed; }, "tokenizer closed", MslTestConstants.TIMEOUT);
    });

    it("stress write", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var noCompression = false;
        runs(function() {
            mos.setCompressionAlgorithm(null, TIMEOUT, {
                result: function(success) { noCompression = success; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return noCompression; }, "no compression", MslTestConstants.TIMEOUT);

        // This may take a while to finish.
        var message = new ByteArrayOutputStream();
        var written = false;
        runs(function() {
            // Generate some payload chunks, keeping track of what we're writing.
            var count = random.nextInt(MAX_PAYLOAD_CHUNKS) + 1;
            function randomWrite(callback) {
                InterruptibleExecutor(callback, function() {
                    if (count-- == 0) {
                        mos.close(TIMEOUT, callback);
                        return;
                    }

                    function writeData(callback) {
                        var data = new Uint8Array(MAX_DATA_SIZE);
                        random.nextBytes(data);
                        mos.write(data, 0, data.length, TIMEOUT, {
                            result: function(success) {
                                message.write(data, 0, data.length, TIMEOUT, callback);
                            },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    }
                    function setCompressionAlgo(callback) {
                        mos.setCompressionAlgorithm(random.nextBoolean() ? CompressionAlgorithm.LZW : null, TIMEOUT, {
                            result: function(success) {
                                writeData(callback);
                            },
                            timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    }
                    function flush(callback) {
                        if (random.nextBoolean()) {
                            mos.flush(TIMEOUT, {
                                result: function(success) {
                                    setCompressionAlgo(callback);
                                },
                                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
                            });
                        } else {
                            setCompressionAlgo(callback);
                        }
                    }
                    flush({
                        result: function(success) { randomWrite(callback); },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                });
            }
            randomWrite({
                result: function(success) { written = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", 3000);

        var tokenizer;
        runs(function() {
            // The destination should have received the message header followed by
            // one or more payload chunks.
            var mslMessage = new ByteArrayInputStream(destination.toByteArray());
            encoder.createTokenizer(mslMessage, null, TIMEOUT, {
                result: function(x) { tokenizer = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return tokenizer; }, "tokenizer", MslTestConstants.TIMEOUT);

        var headerMo;
        runs(function() {
            tokenizer.nextObject(TIMEOUT, {
                result: function(x) { headerMo = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return headerMo; }, "headerMo", MslTestConstants.TIMEOUT);

        var payloadMos = [];
        var noMore = false;
        runs(function() {
            function loop() {
                tokenizer.more(TIMEOUT, {
                    result: function(more) {
                        if (!more) {
                            noMore = true;
                            return;
                        }

                        tokenizer.nextObject(TIMEOUT, {
                            result: function(mo) {
                                payloadMos.push(mo);
                                loop();
                            },
                            timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                        });
                    },
                    timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            loop();
        });
        waitsFor(function() { return noMore; }, "no more", MslTestConstants.TIMEOUT);
        
        var tokenizerClosed = false;
        runs(function() {
            tokenizer.close(-1, {
                result: function(x) { tokenizerClosed = x; },
                timeout: function() { expect(function() { throw new Error("timeout"); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return tokenizerClosed; }, "tokenizer closed", MslTestConstants.TIMEOUT);

        var header;
        runs(function() {
            Header.parseHeader(ctx, headerMo, cryptoContexts, {
                result: function(x) { header = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return header; }, "header and payloadMos", MslTestConstants.TIMEOUT);

        // This may take a while to finish.
        var parsedPayloads = [];
        runs(function() {
            expect(header instanceof MessageHeader).toBeTruthy();
            var cryptoContext = header.cryptoContext;

            function parse(index) {
                PayloadChunk.parse(ctx, payloadMos[index], cryptoContext, {
                    result: function(x) { parsedPayloads[index] = x; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            for (var i = 0; i < payloadMos.length; ++i)
                parse(i);
        });
        waitsFor(function() {
            if (parsedPayloads.length != payloadMos.length) return false;
            for (var i = 0; i < parsedPayloads.length; ++i)
                if (!parsedPayloads[i]) return false;
            return true;
        }, "payloads", 3000);

        runs(function() {
            // Verify payloads, cached payloads, and aggregate data.
            var sequenceNumber = 1;
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(payloadMos.length);
            var data = new ByteArrayOutputStream();
            var index = 0;
            function verifyPayload() {
                if (index == parsedPayloads.length) {
                    expect(data.toByteArray()).toEqual(message.toByteArray());
                    return;
                }

                var payload = parsedPayloads[index];
                expect(payload.sequenceNumber).toEqual(sequenceNumber++);
                expect(payload.messageId).toEqual(header.messageId);
                expect(payload.isEndOfMessage()).toEqual(index == payloadMos.length - 1);
                expect(payloads[index]).toEqual(payload);
                data.write(payload.data, 0, payload.data.length, TIMEOUT, {
                    result: function(success) {
                        ++index;
                        verifyPayload();
                    },
                    timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            }
            verifyPayload();
        });
    });

    it("no context compression algorithms", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);

        var responseBuilder;
        runs(function() {
            ctx.setMessageCapabilities(null);

            // The intersection of compression algorithms is computed when a
            // response header is generated.
            messageFactory.createResponse(ctx, MESSAGE_HEADER, {
                result: function(x) { responseBuilder = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return responseBuilder; }, "responseBuilder", MslTestConstants.TIMEOUT);

        var responseHeader;
        runs(function() {
            responseBuilder.getHeader({
                result: function(x) { responseHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return responseHeader; }, "responseHeader", MslTestConstants.TIMEOUT);

        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, responseHeader, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var lzw;
        runs(function() {
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) { lzw = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return lzw === false; }, "lzw", MslTestConstants.TIMEOUT);

        var written = false;
        runs(function() {
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function() {
                    mos.close(TIMEOUT, {
                        result: function(success) { written = success; },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", MslTestConstants.TIMEOUT);

        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0].compressionAlgo).toBeNull();
        });
    });

    it("no request compression algorithms", function() {
        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);

        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, messageHeader, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var lzw;
        runs(function() {
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) { lzw = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return lzw === false; }, "lzw", MslTestConstants.TIMEOUT);

        var written = false;
        runs(function() {
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function() {
                    mos.close(TIMEOUT, {
                        result: function(success) { written = success; },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", MslTestConstants.TIMEOUT);

        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0].compressionAlgo).toBeNull();
        });
    });

    it("best compression algorithm", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var written = false;
        runs(function() {
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function() {
                    mos.close(TIMEOUT, {
                        result: function(success) { written = success; },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", MslTestConstants.TIMEOUT);

        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);

            var capabilities = ctx.getMessageCapabilities();
            var algos = capabilities.compressionAlgorithms;
            var bestAlgo = CompressionAlgorithm.getPreferredAlgorithm(algos);
            expect(payloads[0].compressionAlgo).toEqual(bestAlgo);
        });
    });

    it("set compression algorithm", function() {
        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var lzw;
        runs(function() {
            mos.setCompressionAlgorithm(CompressionAlgorithm.LZW, TIMEOUT, {
                result: function(success) { lzw = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return lzw; }, "lzw", 300);

        var written;
        runs(function() {
            written = false;
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function(success) { written = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", MslTestConstants.TIMEOUT);

        var closed;
        runs(function() {
            mos.close(TIMEOUT, {
                result: function(success) { closed = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", MslTestConstants.TIMEOUT);

        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0].compressionAlgo).toEqual(CompressionAlgorithm.LZW);
        });
    });

    it("one supported compression algorithm", function() {
        var algos = [ CompressionAlgorithm.LZW ];
        var capabilities = new MessageCapabilities(algos, null, null);

        var messageHeader;
        runs(function() {
            var headerData = new HeaderData(1, null, false, false, capabilities, null, null, null, null, null);
            var peerData = new HeaderPeerData(null, null, null);
            MessageHeader.create(ctx, ENTITY_AUTH_DATA, null, headerData, peerData, {
                result: function(x) { messageHeader = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return messageHeader; }, "message header", MslTestConstants.TIMEOUT);

        var mos;
        runs(function() {
            MessageOutputStream.create(ctx, destination, messageHeader, PAYLOAD_CRYPTO_CONTEXT, null, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", MslTestConstants.TIMEOUT);
        
        var ready = false;
        runs(function() {
            mos.isReady({
                result: function(r) { ready = r; },
                timeout: function() { expect(function() { throw new Error("Timed out waiting for mos ready."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "mos ready", MslTestConstants.TIMEOUT);

        var gzip;
        runs(function() {
            mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP, TIMEOUT, {
                result: function(success) { gzip = success; },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return gzip === false; }, "gzip", MslTestConstants.TIMEOUT);

        var written = false;
        runs(function() {
            mos.write(COMPRESSIBLE_DATA, 0, COMPRESSIBLE_DATA.length, TIMEOUT, {
                result: function() {
                    mos.close(TIMEOUT, {
                        result: function(success) { written = success; },
                        timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                timeout: function() { expect(function() { throw new Error('timedout'); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return written; }, "written", MslTestConstants.TIMEOUT);

        runs(function() {
            var payloads = mos.getPayloads();
            expect(payloads.length).toEqual(1);
            expect(payloads[0].compressionAlgo).toEqual(CompressionAlgorithm.LZW);
        });
    });
});
