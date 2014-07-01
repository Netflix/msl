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
 * Unauthenticated entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("UnauthenticatedAuthenticationData", function() {
    /** JSON key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    var KEY_AUTHDATA = "authdata";
    /** JSON key entity identity. */
    var KEY_IDENTITY = "identity";

    var IDENTITY = "identity";
    
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
        var data = new UnauthenticatedAuthenticationData(IDENTITY);
        expect(data.identity).toEqual(IDENTITY);
        expect(data.scheme).toEqual(EntityAuthenticationScheme.NONE);
        var authdata = data.getAuthData();
        expect(authdata).not.toBeNull();
        var jsonString = JSON.stringify(data);
        expect(jsonString).not.toBeNull();
        
        var joData = UnauthenticatedAuthenticationData$parse(authdata);
        expect(joData.identity).toEqual(data.identity);
        expect(joData.scheme).toEqual(data.scheme);
        var joAuthdata = joData.getAuthData();
        expect(joAuthdata).not.toBeNull();
        expect(joAuthdata).toEqual(authdata);
        var joJsonString = JSON.stringify(joData);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("json is correct", function() {
        var data = new UnauthenticatedAuthenticationData(IDENTITY);
        var jo = JSON.parse(JSON.stringify(data));
        expect(jo[KEY_SCHEME]).toEqual(EntityAuthenticationScheme.NONE.name);
        var authdata = jo[KEY_AUTHDATA];
        expect(authdata[KEY_IDENTITY]).toEqual(IDENTITY);
    });
    
    it("create", function() {
        var data = new UnauthenticatedAuthenticationData(IDENTITY);
        var jsonString = JSON.stringify(data);
        var jo = JSON.parse(jsonString);
        var entitydata = EntityAuthenticationData$parse(ctx, jo);
        expect(entitydata).not.toBeNull();
        expect(entitydata instanceof UnauthenticatedAuthenticationData).toBeTruthy();
        
        var joData = entitydata;
        expect(joData.identity).toEqual(data.identity);
        expect(joData.scheme).toEqual(data.scheme);
        var joAuthdata = joData.getAuthData();
        expect(joAuthdata).not.toBeNull();
        expect(joAuthdata).toEqual(data.getAuthData());
        var joJsonString = JSON.stringify(joData);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("missing identity", function() {
    	var f = function() {
	        var data = new UnauthenticatedAuthenticationData(IDENTITY);
	        var authdata = data.getAuthData();
	        delete authdata[KEY_IDENTITY];
	        UnauthenticatedAuthenticationData$parse(authdata);
    	};
    	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });

    it("equals identity", function() {
        var identityA = IDENTITY + "A";
        var identityB = IDENTITY + "B";
        var dataA = new UnauthenticatedAuthenticationData(identityA);
        var dataB = new UnauthenticatedAuthenticationData(identityB);
        var dataA2 = EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)));
        
        expect(dataA.equals(dataA)).toBeTruthy();
        
        expect(dataA.equals(dataB)).toBeFalsy();
        expect(dataB.equals(dataA)).toBeFalsy();
        
        expect(dataA.equals(dataA2)).toBeTruthy();
        expect(dataA2.equals(dataA)).toBeTruthy();
    });
    
    it("equals object", function() {
        var data = new UnauthenticatedAuthenticationData(IDENTITY);
        expect(data.equals(null)).toBeFalsy();
        expect(data.equals(KEY_IDENTITY)).toBeFalsy();
    });
});
