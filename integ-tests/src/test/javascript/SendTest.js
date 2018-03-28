/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
 * <p>Tests of the {@link MslControl} send methods.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("SendTest", function() {
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
    var ENTITY_IDENTITY = "send-test";

    /** Server host. */
    var HOST = "localhost:8080";
    /** Server path. */
    var PATH = "/msl-integ-tests/log";
    /** Report query string. */
    var REPORT = "report";
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

    /**
     * <p>Query the server for the reported string.</p>
     * 
     * @param {{result: function(string), timeout: function(), error: function(Error)}}
     *        callback the callback that will receive the response body, be
     *        notified of timeout, or any thrown errors.
     * @return the string returned by a report query.
     */
    function report(callback) {
        // Prepare the request.
        var options = url.parse("http://" + HOST + PATH + "?" + REPORT);
        options.timeout = TIMEOUT;

        // Buffer and then deliver the accumulated data. Only
        // allow the callback to be triggered once, in case
        // events keep arriving after the data has been
        // delivered or after an error has occurred.
        var buffer = "";
        var delivered = false;
        var request = http.get(options, function(message) {
            message.on('data', function(chunk) {
                try {
                    if (typeof chunk === 'string')
                        buffer += chunk;
                    else
                        buffer += chunk.toString();
                } catch (e) {
                    if (!delivered)
                        callback.error(e);
                    delivered = true;
                }
            });
            message.on('end', function() {
                if (!delivered)
                    callback.result(buffer);
                delivered = true;
            });
        });
        request.on('timeout', function() {
            if (!delivered)
                callback.timeout();
            delivered = true;
        });
        request.on('error', function(e) {
            if (!delivered)
                callback.error(e);
            delivered = true;
        });
    }
    
    it("send", function() {
        // Prepare.
        var message = "handshake";
        var messageBytes = TextEncoding.getBytes(message);
        var uri = "http://" + HOST + PATH;
        var location = new NodeHttpLocation(uri);
        var remoteEntity = new Url(location, TIMEOUT);
        
        // Create message context.
        var msgCtx;
        runs(function() {
            WriteMessageContext.create(ctx, null, null, messageBytes, {
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
            
            ctrl.send(ctx, msgCtx, remoteEntity, TIMEOUT, {
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
        
        // Query receipt.
        var result;
        runs(function() {
            report({
                result: function(x) { result = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return result; }, "report", TIMEOUT);
        
        runs(function() {
            expect(result).toEqual(message);
        });
    });
    
    it("send handshake", function() {
        // Prepare.
        var message = "handshake";
        var messageBytes = TextEncoding.getBytes(message);
        var uri = "http://" + HOST + PATH;
        var location = new NodeHttpLocation(uri);
        var remoteEntity = new Url(location, TIMEOUT);
        
        // Create message context.
        var msgCtx;
        runs(function() {
            WriteMessageContext.create(ctx, null, null, messageBytes, {
                result: function(x) { msgCtx = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return msgCtx; }, "msgCtx", MslTestConstants.TIMEOUT);
        
        // Send message.
        var mos;
        runs(function() {
            // Require encryption and integrity protection.
            msgCtx.setEncrypted(true);
            msgCtx.setIntegrityProtected(true);
            
            // Set the key request data.
            var publicKey = MockRsaAuthenticationFactory.RSA_PUBKEY;
            var privateKey = MockRsaAuthenticationFactory.RSA_PRIVKEY;
            var requestData = new AsymmetricWrappedExchange.RequestData("rsaKeypairId", AsymmetricWrappedExchange.Mechanism.JWE_RSA, publicKey, privateKey);
            var keyxRequestData = [ requestData ];
            msgCtx.setKeyRequestData(keyxRequestData);
            
            ctrl.send(ctx, msgCtx, remoteEntity, TIMEOUT, {
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
            expect(messageHeader.masterToken).not.toBeNull();
            
            mos.close(TIMEOUT, {
                result: function(x) { closed = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return closed; }, "closed", TIMEOUT);
        
        // Query receipt.
        var result;
        runs(function() {
            report({
                result: function(x) { result = x; },
                timeout: function() { expect(function() { throw new MslIoException("Request timed out."); }).not.toThrow(); },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return result; }, "report", TIMEOUT);
        
        runs(function() {
            expect(result).toEqual(message);
        });
    });
});
