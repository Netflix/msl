/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
    const EntityAuthenticationScheme = require('../../../../../core/src/main/javascript/entityauth/EntityAuthenticationScheme.js');
    const MslObject = require('../../../../../core/src/main/javascript/io/MslObject.js');
    const EntityAuthenticationData = require('../../../../../core/src/main/javascript/entityauth/EntityAuthenticationData.js');
    const MslEncodingException = require('../../../../../core/src/main/javascript/MslEncodingException.js');
    const MslError = require('../../../../../core/src/main/javascript/MslError.js');
    const MslEntityAuthException = require('../../../../../core/src/main/javascript/MslEntityAuthException.js');

    const MockMslContext = require('../../../main/javascript/util/MockMslContext.js');
    
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
            waitsFor(function() { return ctx; }, "ctx", 900);
            
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
        waitsFor(function() { return exception; }, "exception", 100);
    	
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
        waitsFor(function() { return exception; }, "exception", 100);
        
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
        waitsFor(function() { return exception; }, "exception", 100);
        
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
        waitsFor(function() { return ctx; }, "ctx", 100);

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
        waitsFor(function() { return exception; }, "exception", 100);

        runs(function() {
            var f = function() { throw exception; };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND));
        });
    });
});
