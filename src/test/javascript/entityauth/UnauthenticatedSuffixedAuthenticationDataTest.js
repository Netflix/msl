/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
 * Unauthenticated suffixed entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UnauthenticatedSuffixedAuthenticationData", function() {
    /** JSON key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    var KEY_AUTHDATA = "authdata";
    
    /** JSON key entity root. */
    var KEY_ROOT = "root";
    /** JSON key entity suffix. */
    var KEY_SUFFIX = "suffix";
    
    /** Identity concatenation character. */
    var CONCAT_CHAR = ".";
    
    var ROOT = "root";
    var SUFFIX = "suffix";
    
    /** MSL context. */
    var ctx;
    beforeEach(function() {
        if (!ctx) {
            runs(function() {
                MockMslContext$create(EntityAuthenticationScheme.X509, false, {
                    result: function(c) { ctx = c; },
                    error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                });
            });
            waitsFor(function() { return ctx; }, "ctx", 100);
        }
    });

    it("ctors", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
        expect(data.getIdentity()).toEqual(ROOT + CONCAT_CHAR + SUFFIX);
        expect(data.root).toEqual(ROOT);
        expect(data.suffix).toEqual(SUFFIX);
        expect(data.scheme).toEqual(EntityAuthenticationScheme.NONE_SUFFIXED);
        var authdata = data.getAuthData();
        expect(authdata).not.toBeNull();
        var jsonString = JSON.stringify(data);
        expect(jsonString).not.toBeNull();
        
        var joData = UnauthenticatedSuffixedAuthenticationData$parse(authdata);
        expect(joData.getIdentity()).toEqual(data.getIdentity());
        expect(joData.root).toEqual(data.root);
        expect(joData.suffix).toEqual(data.suffix);
        expect(joData.scheme).toEqual(data.scheme);
        var joAuthdata = joData.getAuthData();
        expect(joAuthdata).not.toBeNull();
        expect(joAuthdata).toEqual(authdata);
        var joJsonString = JSON.stringify(joData);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("json is correct", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
        var jo = JSON.parse(JSON.stringify(data));
        expect(jo[KEY_SCHEME]).toEqual(EntityAuthenticationScheme.NONE_SUFFIXED.name);
        var authdata = jo[KEY_AUTHDATA];
        expect(authdata[KEY_ROOT]).toEqual(ROOT);
        expect(authdata[KEY_SUFFIX]).toEqual(SUFFIX);
    });
    
    it("create", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
        var jsonString = JSON.stringify(data);
        var jo = JSON.parse(jsonString);
        var entitydata = EntityAuthenticationData$parse(ctx, jo);
        expect(entitydata).not.toBeNull();
        expect(entitydata instanceof UnauthenticatedSuffixedAuthenticationData).toBeTruthy();
        
        var joData = entitydata;
        expect(joData.getIdentity()).toEqual(data.getIdentity());
        expect(joData.root).toEqual(data.root);
        expect(joData.suffix).toEqual(data.suffix);
        expect(joData.scheme).toEqual(data.scheme);
        var joAuthdata = joData.getAuthData();
        expect(joAuthdata).not.toBeNull();
        expect(joAuthdata).toEqual(data.getAuthData());
        var joJsonString = JSON.stringify(joData);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("missing root", function() {
    	var f = function() {
	        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
	        var authdata = data.getAuthData();
	        delete authdata[KEY_ROOT];
	        UnauthenticatedSuffixedAuthenticationData$parse(authdata);
    	};
    	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });
    
    it("missing suffix", function() {
        var f = function() {
            var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
            var authdata = data.getAuthData();
            delete authdata[KEY_SUFFIX];
            UnauthenticatedSuffixedAuthenticationData$parse(authdata);
        };
        expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });

    it("equals root", function() {
        var dataA = new UnauthenticatedSuffixedAuthenticationData(ROOT + "A", SUFFIX);
        var dataB = new UnauthenticatedSuffixedAuthenticationData(ROOT + "B", SUFFIX);
        var dataA2 = EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)));
        
        expect(dataA.equals(dataA)).toBeTruthy();
        
        expect(dataA.equals(dataB)).toBeFalsy();
        expect(dataB.equals(dataA)).toBeFalsy();
        
        expect(dataA.equals(dataA2)).toBeTruthy();
        expect(dataA2.equals(dataA)).toBeTruthy();
    });

    it("equals suffix", function() {
        var dataA = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX + "A");
        var dataB = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX + "B");
        var dataA2 = EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)));
        
        expect(dataA.equals(dataA)).toBeTruthy();
        
        expect(dataA.equals(dataB)).toBeFalsy();
        expect(dataB.equals(dataA)).toBeFalsy();
        
        expect(dataA.equals(dataA2)).toBeTruthy();
        expect(dataA2.equals(dataA)).toBeTruthy();
    });
    
    it("equals object", function() {
        var data = new UnauthenticatedSuffixedAuthenticationData(ROOT, SUFFIX);
        expect(data.equals(null)).toBeFalsy();
        expect(data.equals(KEY_ROOT)).toBeFalsy();
    });
});
