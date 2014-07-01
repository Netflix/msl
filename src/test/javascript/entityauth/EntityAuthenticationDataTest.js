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
 * {@link EntityAuthenticationData#create(MslContext, JSONObject)} covered in
 * the individual entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("EntityAuthenticationData", function() {
    /** JSON key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    var KEY_AUTHDATA = "authdata";

    /** MSL context. */
    var ctx;
    beforeEach(function() {
        if (!ctx) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
        }
    });
    
    it("no scheme", function() {
    	var f = function() {
	        var jo = {};
	        jo[KEY_SCHEME + "x"] = EntityAuthenticationScheme.NONE;
	        jo[KEY_AUTHDATA] = {};
	        EntityAuthenticationData$parse(ctx, jo);
    	};
    	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });
    
    it("no authdata", function() {
    	var f = function() {
	        var jo = {};
	        jo[KEY_SCHEME] = EntityAuthenticationScheme.NONE;
	        jo[KEY_AUTHDATA + "x"] = {};
	        EntityAuthenticationData$parse(ctx, jo);
    	};
    	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });
    
    it("unidentified scheme", function() {
    	var f = function() {
	        var jo = {};
	        jo[KEY_SCHEME] = "x";
	        jo[KEY_AUTHDATA] = {};
	        EntityAuthenticationData$parse(ctx, jo);
    	};
    	expect(f).toThrow(new MslEntityAuthException(MslError.UNIDENTIFIED_ENTITYAUTH_SCHEME));
    });
    
    it("authentication factory not found", function() {
        var ctx;
        runs(function() {
            MockMslContext$create(EntityAuthenticationScheme.PSK, false, {
                result: function(c) { ctx = c; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return ctx; }, "ctx", 100);

        runs(function() {
            var f = function() {
                ctx.removeEntityAuthenticationFactory(EntityAuthenticationScheme.NONE);
                var jo = {};
                jo[KEY_SCHEME] = EntityAuthenticationScheme.NONE.name;
                jo[KEY_AUTHDATA] = {};
                EntityAuthenticationData$parse(ctx, jo);
            };
            expect(f).toThrow(new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND));
        });
    });
});
