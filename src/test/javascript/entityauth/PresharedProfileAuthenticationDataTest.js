/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
 * Preshared keys profile entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("PresharedProfileAuthenticationData", function() {
    /** JSON key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    var KEY_AUTHDATA = "authdata";
    /** JSON key entity preshared keys identity. */
    var KEY_PSKID = "pskid";
    /** JSON key entity profile. */
    var KEY_PROFILE = "profile";

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
        var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        expect(data.getIdentity()).toEqual(MockPresharedProfileAuthenticationFactory.PSK_ESN + ":" + MockPresharedProfileAuthenticationFactory.PROFILE);
        expect(data.presharedKeysId).toEqual(MockPresharedProfileAuthenticationFactory.PSK_ESN);
        expect(data.profile).toEqual(MockPresharedProfileAuthenticationFactory.PROFILE);
        expect(data.scheme).toEqual(EntityAuthenticationScheme.PSK_PROFILE);
        var authdata = data.getAuthData();
        expect(authdata).not.toBeNull();
        var jsonString = JSON.stringify(data);
        expect(jsonString).not.toBeNull();
        
        var joData = PresharedProfileAuthenticationData$parse(authdata);
        expect(joData.identity).toEqual(data.identity);
        expect(joData.presharedKeysId).toEqual(data.presharedKeysId);
        expect(joData.profile).toEqual(data.profile);
        expect(joData.scheme).toEqual(data.scheme);
        var joAuthdata = joData.getAuthData();
        expect(joAuthdata).not.toBeNull();
        expect(joAuthdata).toEqual(authdata);
        var joJsonString = JSON.stringify(joData);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("json is correct", function() {
        var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        var jo = JSON.parse(JSON.stringify(data));
        expect(jo[KEY_SCHEME]).toEqual(EntityAuthenticationScheme.PSK_PROFILE.name);
        var authdata = jo[KEY_AUTHDATA];
        expect(authdata[KEY_PSKID]).toEqual(MockPresharedProfileAuthenticationFactory.PSK_ESN);
        expect(authdata[KEY_PROFILE]).toEqual(MockPresharedProfileAuthenticationFactory.PROFILE);
    });
    
    it("create", function() {
        var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        var jsonString = JSON.stringify(data);
        var jo = JSON.parse(jsonString);
        var entitydata = EntityAuthenticationData$parse(ctx, jo);
        expect(entitydata).not.toBeNull();
        expect(entitydata instanceof PresharedProfileAuthenticationData).toBeTruthy();
        
        var joData = entitydata;
        expect(joData.getIdentity()).toEqual(data.getIdentity());
        expect(joData.presharedKeysId).toEqual(data.presharedKeysId);
        expect(joData.profile).toEqual(data.profile);
        expect(joData.scheme).toEqual(data.scheme);
        var joAuthdata = joData.getAuthData();
        expect(joAuthdata).not.toBeNull();
        expect(joAuthdata).toEqual(data.getAuthData());
        var joJsonString = JSON.stringify(joData);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("missing preshared keys ID", function() {
        var f = function() {
            var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
            var authdata = data.getAuthData();
            delete authdata[KEY_PSKID];
            PresharedProfileAuthenticationData$parse(authdata);
        };
        expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });
    
    it("missing profile", function() {
        var f = function() {
            var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
            var authdata = data.getAuthData();
            delete authdata[KEY_PROFILE];
            PresharedProfileAuthenticationData$parse(authdata);
        };
        expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });

    it("equals preshared keys ID", function() {
        var pskIdA = MockPresharedProfileAuthenticationFactory.PSK_ESN + "A";
        var pskIdB = MockPresharedProfileAuthenticationFactory.PSK_ESN + "B";
        var dataA = new PresharedProfileAuthenticationData(pskIdA, MockPresharedProfileAuthenticationFactory.PROFILE);
        var dataB = new PresharedProfileAuthenticationData(pskIdB, MockPresharedProfileAuthenticationFactory.PROFILE);
        var dataA2 = EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)));
        
        expect(dataA.equals(dataA)).toBeTruthy();
        
        expect(dataA.equals(dataB)).toBeFalsy();
        expect(dataB.equals(dataA)).toBeFalsy();
        
        expect(dataA.equals(dataA2)).toBeTruthy();
        expect(dataA2.equals(dataA)).toBeTruthy();
    });

    it("equals profile", function() {
        var profileA = MockPresharedProfileAuthenticationFactory.PROFILE + "A";
        var profileB = MockPresharedProfileAuthenticationFactory.PROFILE + "B";
        var dataA = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, profileA);
        var dataB = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, profileB);
        var dataA2 = EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)));
        
        expect(dataA.equals(dataA)).toBeTruthy();
        
        expect(dataA.equals(dataB)).toBeFalsy();
        expect(dataB.equals(dataA)).toBeFalsy();
        
        expect(dataA.equals(dataA2)).toBeTruthy();
        expect(dataA2.equals(dataA)).toBeTruthy();
    });
    
    it("equals object", function() {
        var data = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        expect(data.equals(null)).toBeFalsy();
        expect(data.equals(KEY_PSKID)).toBeFalsy();
    });
});