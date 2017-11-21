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
 * Entity authentication data unit tests.
 * 
 * Successful calls to
 * {@link EntityAuthenticationData#create(MslContext, MslObject)} covered in
 * the individual entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("EntityAuthenticationData", function() {
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var MslObject = require('msl-core/io/MslObject.js');
    var EntityAuthenticationData = require('msl-core/entityauth/EntityAuthenticationData.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslError = require('msl-core/MslError.js');
    var MslEntityAuthException = require('msl-core/MslEntityAuthException.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    
    /** Key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** Key entity authentication data. */
    var KEY_AUTHDATA = "authdata";

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
	        mo.put(KEY_SCHEME + "x", EntityAuthenticationScheme.NONE.name);
	        mo.put(KEY_AUTHDATA, new MslObject());
	        EntityAuthenticationData.parse(ctx, mo, {
	            result: function() {},
	            error: function(e) { exception = e; },
	        });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
    	
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
        });
    });
    
    it("no authdata", function() {
        var exception;
        runs(function() {
	        var mo = encoder.createObject();
	        mo.put(KEY_SCHEME, EntityAuthenticationScheme.NONE.name);
	        mo.put(KEY_AUTHDATA + "x", new MslObject());
            EntityAuthenticationData.parse(ctx, mo, {
                result: function() {},
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
	        mo.put(KEY_AUTHDATA, new MslObject());
            EntityAuthenticationData.parse(ctx, mo, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);
        
        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEntityAuthException(MslError.UNIDENTIFIED_ENTITYAUTH_SCHEME));
        });
    });
    
    it("authentication factory not found", function() {
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
            ctx.removeEntityAuthenticationFactory(EntityAuthenticationScheme.NONE);
            var mo = encoder.createObject();
            mo.put(KEY_SCHEME, EntityAuthenticationScheme.NONE.name);
            mo.put(KEY_AUTHDATA, new MslObject());
            EntityAuthenticationData.parse(ctx, mo, {
                result: function() {},
                error: function(e) { exception = e; },
            });
        });
        waitsFor(function() { return exception; }, "exception", MslTestConstants.TIMEOUT);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND));
        });
    });
});
