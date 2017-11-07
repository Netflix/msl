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
 * Key request data unit tests.
 * 
 * Successful calls to
 * {@link KeyRequestData#create(com.netflix.msl.util.MslContext, org.json.JSONObject)}
 * covered in the individual key request data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("KeyRequestData", function() {
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    var KeyRequestData = require('msl-core/keyx/KeyRequestData.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslKeyExchangeException = require('msl-core/MslKeyExchangeException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    
    /** Key key exchange scheme. */
    var KEY_SCHEME = "scheme";
    /** Key key request data. */
    var KEY_KEYDATA = "keydata";
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;

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
            	initialized = true;
            });
        }
    });
    
    it("no scheme", function() {
        var exception;
        runs(function() {
            var mo = encoder.createObject();
            mo.put(KEY_SCHEME + "x", KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
            mo.put(KEY_KEYDATA, encoder.createObject());
            KeyRequestData.parse(ctx, mo, {
                result: function(x) {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("no keydata", function() {
        var exception;
        runs(function() {
            var mo = encoder.createObject();
            mo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
            mo.put(KEY_KEYDATA + "x", encoder.createObject());
            KeyRequestData.parse(ctx, mo, {
                result: function(x) {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("unidentified scheme", function() {
        var exception;
        runs(function() {
            var mo = encoder.createObject();
            mo.put(KEY_SCHEME, "x");
            mo.put(KEY_KEYDATA, encoder.createObject());
            KeyRequestData.parse(ctx, mo, {
                result: function(x) {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_SCHEME));
        });
    });
    
    it("keyx factory not found", function() {
        var ctx;
        runs(function() {
            MockMslContext.create(EntityAuthenticationScheme.PSK, false, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", MslTestConstants.TIMEOUT);
        var exception;
        runs(function() {
            ctx.removeKeyExchangeFactories(KeyExchangeScheme.ASYMMETRIC_WRAPPED);

            var mo = encoder.createObject();
            mo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
            mo.put(KEY_KEYDATA, encoder.createObject());
            KeyRequestData.parse(ctx, mo, {
                result: function(x) {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND));
        });
    });
});