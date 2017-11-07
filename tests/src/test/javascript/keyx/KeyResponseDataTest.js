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
 * Key response data unit tests.
 * 
 * Successful calls to
 * {@link KeyResponseData#create(com.netflix.msl.util.MslContext, org.json.JSONObject)}
 * covered in the individual key response data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("KeyResponseData", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    var KeyResponseData = require('msl-core/keyx/KeyResponseData.js');
    var SymmetricWrappedExchange = require('msl-core/keyx/SymmetricWrappedExchange.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslKeyExchangeException = require('msl-core/MslKeyExchangeException.js');
    var MslError = require('msl-core/MslError.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key master token. */
    var KEY_MASTER_TOKEN = "mastertoken";
    /** Key key exchange scheme. */
    var KEY_SCHEME = "scheme";
    /** Key key request data. */
    var KEY_KEYDATA = "keydata";
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    
    var MASTER_TOKEN;
    var MASTER_TOKEN_MO;

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
                MslTestUtils.getMasterToken(ctx, 1, 1, {
                    result: function(masterToken) { MASTER_TOKEN = masterToken; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return MASTER_TOKEN; }, "master token", MslTestConstants.TIMEOUT);
            
            runs(function() {
            	MslTestUtils.toMslObject(encoder, MASTER_TOKEN, {
            		result: function(x) { MASTER_TOKEN_MO = x; },
            		error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            	});
            });
            waitsFor(function() { return MASTER_TOKEN_MO; }, "master token MSL object", MslTestConstants.TIMEOUT);
            
            runs(function() { initialized = true; });
        }
    });
    
    it("no master token", function() {
        var exception;
        runs(function() {
            var mo = encoder.createObject();
            mo.put(KEY_MASTER_TOKEN + "x", MASTER_TOKEN_MO);
            mo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
            mo.put(KEY_KEYDATA, encoder.createObject());
            KeyResponseData.parse(ctx, mo, {
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
    
    it("no scheme", function() {
        var exception;
        runs(function() {
            var mo = encoder.createObject();
            mo.put(KEY_MASTER_TOKEN, MASTER_TOKEN_MO);
            mo.put(KEY_SCHEME + "x", KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
            mo.put(KEY_KEYDATA, encoder.createObject());
            KeyResponseData.parse(ctx, mo, {
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
            mo.put(KEY_MASTER_TOKEN, MASTER_TOKEN_MO);
            mo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
            mo.put(KEY_KEYDATA + "x", encoder.createObject());
            KeyResponseData.parse(ctx, mo, {
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
    
    it("invalid master token", function() {
        var encryptionKey = new Uint8Array(0);
        var hmacKey = new Uint8Array(0);
        var response = new SymmetricWrappedExchange.ResponseData(MASTER_TOKEN, SymmetricWrappedExchange.KeyId.PSK, encryptionKey, hmacKey);
        
        var keydata;
        runs(function() {
        	response.getKeydata(encoder, ENCODER_FORMAT, {
        		result: function(x) { keydata = x; },
                error: function(e) { exception = e; },
        	});
        });
        waitsFor(function() { return keydata; }, "keydata", MslTestConstants.TIMEOUT);
        
        var exception;
        runs(function() {
            var mo = encoder.createObject();
            mo.put(KEY_MASTER_TOKEN, encoder.createObject());
            mo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
            mo.put(KEY_KEYDATA, keydata);
            KeyResponseData.parse(ctx, mo, {
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
            mo.put(KEY_MASTER_TOKEN, MASTER_TOKEN_MO);
            mo.put(KEY_SCHEME, "x");
            mo.put(KEY_KEYDATA, encoder.createObject());
            KeyResponseData.parse(ctx, mo, {
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
            mo.put(KEY_MASTER_TOKEN, MASTER_TOKEN_MO);
            mo.put(KEY_SCHEME, KeyExchangeScheme.ASYMMETRIC_WRAPPED.name);
            mo.put(KEY_KEYDATA, encoder.createObject());
            KeyResponseData.parse(ctx, mo, {
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
