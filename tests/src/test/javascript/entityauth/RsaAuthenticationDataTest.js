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
 * RSA entity authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("RsaAuthenticationData", function() {
    /** JSON key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    var KEY_AUTHDATA = "authdata";
    /** JSON key entity identity. */
    var KEY_IDENTITY = "identity";
    /** JSON key public key ID. */
    var KEY_PUBKEY_ID = "pubkeyid";

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
        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        expect(data.identity).toEqual(MockRsaAuthenticationFactory.RSA_ESN);
        expect(data.publicKeyId).toEqual(MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        expect(data.scheme).toEqual(EntityAuthenticationScheme.RSA);
        var authdata = data.getAuthData();
        expect(authdata).not.toBeNull();
        var jsonString = JSON.stringify(data);
        expect(jsonString).not.toBeNull();
        
        var joData = RsaAuthenticationData$parse(authdata);
        expect(joData.identity).toEqual(data.identity);
        expect(joData.publicKeyId).toEqual(data.publicKeyId);
        expect(joData.scheme).toEqual(data.scheme);
        var joAuthdata = joData.getAuthData();
        expect(joAuthdata).not.toBeNull();
        expect(joAuthdata).toEqual(authdata);
        var joJsonString = JSON.stringify(joData);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("json is correct", function() {
        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        var jo = JSON.parse(JSON.stringify(data));
        expect(jo[KEY_SCHEME]).toEqual(EntityAuthenticationScheme.RSA.name);
        var authdata = jo[KEY_AUTHDATA];
        expect(authdata[KEY_IDENTITY]).toEqual(MockRsaAuthenticationFactory.RSA_ESN);
        expect(authdata[KEY_PUBKEY_ID]).toEqual(MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
    });
    
    it("create", function() {
        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        var jsonString = JSON.stringify(data);
        var jo = JSON.parse(jsonString);
        
        var entitydata;
        runs(function() {
            EntityAuthenticationData$parse(ctx, jo, {
                result: function(x) { entitydata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return entitydata }, "entitydata", 100);
        
        runs(function() {
            expect(entitydata).not.toBeNull();
            expect(entitydata instanceof RsaAuthenticationData).toBeTruthy();
            
            var joData = entitydata;
            expect(joData.identity).toEqual(data.identity);
            expect(joData.publicKeyId).toEqual(data.publicKeyId);
            expect(joData.scheme).toEqual(data.scheme);
            var joAuthdata = joData.getAuthData();
            expect(joAuthdata).not.toBeNull();
            expect(joAuthdata).toEqual(data.getAuthData());
            var joJsonString = JSON.stringify(joData);
            expect(joJsonString).not.toBeNull();
            expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("missing identity", function() {
        var f = function() {
	        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
	        var authdata = data.getAuthData();
	        expect(authdata[KEY_IDENTITY]).not.toBeNull();
	        delete authdata[KEY_IDENTITY];
	        RsaAuthenticationData$parse(authdata);
	    };
        expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });

    it("missing pubkey id", function() {
        var f = function() {
	        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
	        var authdata = data.getAuthData();
	        expect(authdata[KEY_PUBKEY_ID]).not.toBeNull();
	        delete authdata[KEY_PUBKEY_ID];
	        RsaAuthenticationData$parse(authdata);
	    };
        expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });
    
    it("equals identity", function() {
        var dataA, dataB, dataA2;
        runs(function() {
            var identityA = MockRsaAuthenticationFactory.RSA_ESN + "A";
            var identityB = MockRsaAuthenticationFactory.RSA_ESN + "B";
            dataA = new RsaAuthenticationData(identityA, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            dataB = new RsaAuthenticationData(identityB, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
            EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)), {
                result: function(x) { dataA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return dataA && dataB && dataA2; }, "data", 100);
        
        runs(function() {
            expect(dataA.equals(dataA)).toBeTruthy();
            
            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();
            
            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
        });
    });
    
    it("equals pubkeyid", function() {
        var dataA, dataB, dataA2;
        runs(function() {
            var pubkeyidA = MockRsaAuthenticationFactory.RSA_PUBKEY_ID + "A";
            var pubkeyidB = MockRsaAuthenticationFactory.RSA_PUBKEY_ID + "B";
            dataA = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, pubkeyidA);
            dataB = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, pubkeyidB);
            EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)), {
                result: function(x) { dataA2 = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return dataA && dataB && dataA2; }, "data", 100);
        
        runs(function() {
            expect(dataA.equals(dataA)).toBeTruthy();

            expect(dataA.equals(dataB)).toBeFalsy();
            expect(dataB.equals(dataA)).toBeFalsy();

            expect(dataA.equals(dataA2)).toBeTruthy();
            expect(dataA2.equals(dataA)).toBeTruthy();
        });
    });
    
    it("equals object", function() {
        var data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        expect(data.equals(null)).toBeFalsy();
        expect(data.equals(KEY_IDENTITY)).toBeFalsy();
    });
});
