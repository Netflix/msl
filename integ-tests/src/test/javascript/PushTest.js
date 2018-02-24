/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
 * <p>Tests of the {@link MslControl} push methods.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("PushTest", function() {
    var MslConstants = require('msl-core/MslConstants.js');
    var Url = require('msl-core/io/Url.js');
    var Xhr = require('msl-core/io/Xhr.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    var MessageOutputStream = require('msl-core/msg/MessageOutputStream.js');
    var MslControl = require('msl-core/msg/MslControl.js');
    var UserAuthenticationScheme = require('msl-core/userauth/UserAuthenticationScheme.js');
    var MslContext = require('msl-core/util/MslContext.js');
    var MslStore = require('msl-core/util/MslStore.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var AsymmetricWrappedExchange = require('msl-core/keyx/AsymmetricWrappedExchange.js');
    var UnauthenticatedAuthenticationData = require('msl-core/entityauth/UnauthenticatedAuthenticationData.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');
    
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMessageContext = require('msl-tests/msg/MockMessageContext.js');
    var NodeHttpLocation = require('msl-tests/io/NodeHttpLocation.js');
    var MockRsaAuthenticationFactory = require('msl-tests/entityauth/MockRsaAuthenticationFactory.js');
    
    var http = require('http');
    var url = require('url');

    /**
     * A message context that will write data without requiring encryption or
     * integrity protection.
     */
    var WriteMessageContext = MockMessageContext.extend({
        /**
         * Create a new write message context.
         * 
         * @param {MockMslContext} ctx MSL context.
         * @param {?string} userId user ID. May be {@code null}.
         * @param {?UserAuthenticationScheme} scheme user authentication scheme. May be {@code null}.
         * @param {Uint8Array} data the data to write.
         * @param {result: function(WriteMessageContext), error: function(Error)}
         *        callback the callback that will receive the new message context
         *        or any thrown exceptions.
         * @throws NoSuchAlgorithmException if a key generation algorithm is not
         *         found.
         * @throws InvalidAlgorithmParameterException if key generation parameters
         *         are invalid.
         * @throws CryptoException if there is an error creating a key.
         */
        init: function init(ctx, userId, scheme, data, callback) {
            var self = this;

            init.base.call(this, ctx, userId, scheme, {
                result: function(msgCtx) {
                    AsyncExecutor(callback, function() {
                        // The properties.
                        var props = {
                            _data: { value: data, writable: false, enumerable: false, configurable: false },
                        };
                        Object.defineProperties(this, props);
                        return this;
                    }, self);
                },
                error: callback.error
            });
        },
        
        /** @inheritDoc */
        write: function write(output, timeout, callback) {
            AsyncExecutor(callback, function() {
                output.write(this._data, 0, this._data.length, timeout, callback);
            }, this);
        },
    });
    
    /**
     * Create a new write message context.
     * 
     * @param {MockMslContext} ctx MSL context.
     * @param {string} userId user ID.
     * @param {UserAuthenticationScheme} scheme user authentication scheme.
     * @param {Uint8Array} data the data to write.
     * @param {result: function(WriteMessageContext), error: function(Error)}
     *        callback the callback that will receive the new message context
     *        or any thrown exceptions.
     * @throws NoSuchAlgorithmException if a key generation algorithm is not
     *         found.
     * @throws InvalidAlgorithmParameterException if key generation parameters
     *         are invalid.
     * @throws CryptoException if there is an error creating a key.
     */
    WriteMessageContext.create = function WriteMessageContext$create(ctx, userId, scheme, data, callback) {
        new WriteMessageContext(ctx, userId, scheme, data, callback);
    };
    
    /** Local entity identity. */
    var ENTITY_IDENTITY = "push-test";

    /** Server host. */
    var HOST = "localhost:8080";
    /** Server base path. */
    var BASE_PATH = "/msl-integ-tests";
    /** Network timeout in milliseconds. */
    var TIMEOUT = 2000;

    /** MSL control. */
    var ctrl = new MslControl();
    /** MSL context. */
    var ctx;
    
    var initialized = false;
    beforeEach(function() {
        if (initialized) return;
        
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.NONE, false, {
                result: function(x) { ctx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT_CTX);
        
        runs(function() {
            ctx.setEntityAuthenticationData(new UnauthenticatedAuthenticationData(ENTITY_IDENTITY));
            initialized = true;
        });
    });
    
    afterEach(function() {
        var store = ctx.getMslStore();
        store.clearCryptoContexts();
        store.clearUserIdTokens();
        store.clearServiceTokens();
    });
    
    it("public push", function() {
        // Prepare.
        var uri = "http://" + HOST + BASE_PATH + "/public-push";
        var location = new NodeHttpLocation(uri);
        var remoteEntity = new Url(location, TIMEOUT);
        var output = new Uint8Array(16);
        ctx.getRandom().nextBytes(output);

        // Open connection.
        var conn = remoteEntity.openConnection();
        
        // Create message context.
        var msgCtx;
        runs(function() {
            WriteMessageContext.create(ctx, null, null, output, {
                result: function(x) { msgCtx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgCtx; }, "msgCtx", MslTestConstants.TIMEOUT);
        
        // Send message.
        var mos;
        runs(function() {
            // Do not require encryption or integrity protection.
            msgCtx.setEncrypted(false);
            msgCtx.setIntegrityProtected(false);

            // Clear the key request data.
            msgCtx.setKeyRequestData([]);
            
            ctrl.send(ctx, msgCtx, conn.input, conn.output, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", TIMEOUT);
        
        // Wait until ready.
        var ready;
        runs(function() {
            mos.isReady({
                result: function(x) { ready = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "ready", TIMEOUT);
        
        // Close message output stream.
        var closed;
        runs(function() {
            var messageHeader = mos.getMessageHeader();
            expect(messageHeader).not.toBeNull();
            expect(messageHeader.masterToken).toBeNull();
            
            mos.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", TIMEOUT);
        
        // Receive message.
        var mis;
        runs(function() {
            ctrl.receive(ctx, msgCtx, conn.input, conn.output, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", TIMEOUT);
        
        // We expect to receive the output data back.
        var input;
        runs(function() {
            expect(mis.getMessageHeader()).not.toBeNull();
            mis.read(output.length, TIMEOUT, {
                result: function(x) { input = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return input; }, "input", TIMEOUT);

        runs(function() {
            // Confirm data.
            expect(input).toEqual(output); 
        });
    });
    
    it("secret push", function() {
        // Prepare.
        var uri = "http://" + HOST + BASE_PATH + "/secret-push";
        var location = new NodeHttpLocation(uri);
        var remoteEntity = new Url(location, TIMEOUT);
        var output = new Uint8Array(16);
        ctx.getRandom().nextBytes(output);
        
        // Open connection.
        var conn = remoteEntity.openConnection();
        
        // Create message context.
        var msgCtx;
        runs(function() {
            WriteMessageContext.create(ctx, null, null, output, {
                result: function(x) { msgCtx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgCtx; }, "msgCtx", MslTestConstants.TIMEOUT);
        
        // Send message.
        var mos;
        runs(function() {
            // Do not require encryption or integrity protection.
            msgCtx.setEncrypted(false);
            msgCtx.setIntegrityProtected(false);

            // Clear the key request data.
            msgCtx.setKeyRequestData([]);
            
            ctrl.send(ctx, msgCtx, conn.input, conn.output, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", TIMEOUT);
        
        // Wait until ready.
        var ready;
        runs(function() {
            mos.isReady({
                result: function(x) { ready = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "ready", TIMEOUT);
        
        // Close message output stream.
        var closed;
        runs(function() {
            var messageHeader = mos.getMessageHeader();
            expect(messageHeader).not.toBeNull();
            expect(messageHeader.masterToken).toBeNull();
            
            mos.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", TIMEOUT);
        
        // Receive message.
        var mis;
        runs(function() {
            ctrl.receive(ctx, msgCtx, conn.input, conn.output, TIMEOUT, {
                result: function(x) { mis = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mis; }, "mis", TIMEOUT);
        
        // We expect to receive an error indicating key exchange is required.
        runs(function() {
            var errorHeader = mis.getErrorHeader();
            expect(errorHeader).not.toBeNull();
            var responseCode = errorHeader.errorCode;
            expect(responseCode).toEqual(MslConstants.ResponseCode.KEYX_REQUIRED);
        });
    });

    it("multi push", function() {
        // Prepare.
        var uri = "http://" + HOST + BASE_PATH + "/multi-push";
        var location = new NodeHttpLocation(uri);
        var remoteEntity = new Url(location, TIMEOUT);
        var output = new Uint8Array(16);
        ctx.getRandom().nextBytes(output);
        
        // Open connection.
        var conn = remoteEntity.openConnection();
        
        // Create message context.
        var msgCtx;
        runs(function() {
            WriteMessageContext.create(ctx, null, null, output, {
                result: function(x) { msgCtx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgCtx; }, "msgCtx", MslTestConstants.TIMEOUT);
        
        // Send message.
        var mos;
        runs(function() {
            // Do not require encryption or integrity protection.
            msgCtx.setEncrypted(false);
            msgCtx.setIntegrityProtected(false);

            // Clear the key request data.
            msgCtx.setKeyRequestData([]);
            
            ctrl.send(ctx, msgCtx, conn.input, conn.output, TIMEOUT, {
                result: function(x) { mos = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mos; }, "mos", TIMEOUT);
        
        // Wait until ready.
        var ready;
        runs(function() {
            mos.isReady({
                result: function(x) { ready = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ready; }, "ready", TIMEOUT);
        
        // Close message output stream.
        var closed;
        runs(function() {
            var messageHeader = mos.getMessageHeader();
            expect(messageHeader).not.toBeNull();
            expect(messageHeader.masterToken).toBeNull();
            
            mos.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", TIMEOUT);
        
        // Receive message.
        //
        // We expect to receive the output data back three times.
        var count = 3;
        runs(function() {
            function recv() {
                // Exit if done.
                if (count == 0)
                    return;
                
                // Receive message.
                ctrl.receive(ctx, msgCtx, conn.input, conn.output, TIMEOUT, {
                    result: function(mis) {
                        expect(mis.getMessageHeader()).not.toBeNull();
                        mis.read(output.length, TIMEOUT, {
                            result: function(input) {
                                // Confirm data.
                                expect(input).toEqual(output);
                                --count;
                                mis.close(TIMEOUT, {
                                    result: function(success) {
                                        recv();
                                    },
                                    timeout: function() { expect(function() { throw new MslIoException("Close timed out."); }).not.toThrow(); },
                                    error: function(e) { expect(function() { throw e.requestCause; throw e; }).not.toThrow(); }
                                });
                            },
                            timeout: function() { expect(function() { throw new MslIoException("Read timed out."); }).not.toThrow(); },
                            error: function(e) { expect(function() { throw e.requestCause; throw e; }).not.toThrow(); }
                        });
                    },
                    timeout: function() { expect(function() { throw new MslIoException("Receive timed out."); }).not.toThrow(); },
                    error: function(e) { expect(function() { throw e.requestCause; throw e; }).not.toThrow(); }
                });
            }
            recv();
        });
        waitsFor(function() { return count == 0; }, "recv", 3 * TIMEOUT);
    });
});