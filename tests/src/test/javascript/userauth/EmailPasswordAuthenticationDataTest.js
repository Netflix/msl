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
 * Email/password user authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("EmailPasswordAuthenticationData", function() {
    /** JSON key user authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key user authentication data. */
    var KEY_AUTHDATA = "authdata";
    /** JSON email key. */
    var KEY_EMAIL = "email";
    /** JSON password key. */
    var KEY_PASSWORD = "password";

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
        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        expect(data.scheme).toEqual(UserAuthenticationScheme.EMAIL_PASSWORD);
        expect(data.email).toEqual(MockEmailPasswordAuthenticationFactory.EMAIL);
        expect(data.password).toEqual(MockEmailPasswordAuthenticationFactory.PASSWORD);
        var authdata = data.getAuthData();
        expect(authdata).not.toBeNull();
        var jsonString = JSON.stringify(data);
        
        var joData = EmailPasswordAuthenticationData$parse(authdata);
        expect(joData.scheme).toEqual(data.scheme);
        expect(joData.email).toEqual(data.email);
        expect(joData.password).toEqual(data.password);
        var joAuthdata = joData.getAuthData();
        expect(joAuthdata).not.toBeNull();
        expect(joAuthdata).toEqual(authdata);
        var joJsonString = JSON.stringify(joData);
        expect(joJsonString).not.toBeNull();
        expect(joJsonString).toEqual(jsonString);
    });
    
    it("json is correct", function() {
        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        var jo = JSON.parse(JSON.stringify(data));
        expect(jo[KEY_SCHEME]).toEqual(UserAuthenticationScheme.EMAIL_PASSWORD.name);
        var authdata = jo[KEY_AUTHDATA];
        expect(authdata[KEY_EMAIL]).toEqual(MockEmailPasswordAuthenticationFactory.EMAIL);
        expect(authdata[KEY_PASSWORD]).toEqual(MockEmailPasswordAuthenticationFactory.PASSWORD);
    });
    
    it("create", function() {
        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        var jsonString = JSON.stringify(data);
        var jo = JSON.parse(jsonString);
        var userdata;
        runs(function() {
            UserAuthenticationData$parse(ctx, null, jo, {
                result: function(x) { userdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return userdata; }, "userdata", 100);

        runs(function() {
            expect(userdata).not.toBeNull();
            expect(userdata instanceof EmailPasswordAuthenticationData).toBeTruthy();

            var joData = userdata;
            expect(joData.scheme).toEqual(data.scheme);
            expect(joData.email).toEqual(data.email);
            expect(joData.password).toEqual(data.password);
            var joAuthdata = joData.getAuthData();
            expect(joAuthdata).not.toBeNull();
            expect(joAuthdata).toEqual(data.getAuthData());
            var joJsonString = JSON.stringify(joData);
            expect(joJsonString).not.toBeNull();
            expect(joJsonString).toEqual(jsonString);
        });
    });
    
    it("missing email", function() {
    	var f = function() {
	        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
	        var authdata = data.getAuthData();
	        delete authdata[KEY_EMAIL];
	        EmailPasswordAuthenticationData$parse(authdata);
    	};
    	expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });
    
    it("missing password", function() {
    	var f = function() {
	        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
	        var authdata = data.getAuthData();
	        delete authdata[KEY_PASSWORD];
	        EmailPasswordAuthenticationData$parse(authdata);
	    };
	    expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
    });
    
    it("equals email", function() {
        var dataA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "A", MockEmailPasswordAuthenticationFactory.PASSWORD);
        var dataB = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "B", MockEmailPasswordAuthenticationFactory.PASSWORD);
        var dataA2 = EmailPasswordAuthenticationData$parse(dataA.getAuthData());
        
        expect(dataA.equals(dataA)).toBeTruthy();
        
        expect(dataA.equals(dataB)).toBeFalsy();
        expect(dataB.equals(dataA)).toBeFalsy();
        
        expect(dataA.equals(dataA2)).toBeTruthy();
        expect(dataA2.equals(dataA)).toBeTruthy();
    });
    
    it("equals password", function() {
        var dataA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD + "A");
        var dataB = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD + "B");
        var dataA2 = EmailPasswordAuthenticationData$parse(dataA.getAuthData());
        
        expect(dataA.equals(dataA)).toBeTruthy();
        
        expect(dataA.equals(dataB)).toBeFalsy();
        expect(dataB.equals(dataA)).toBeFalsy();
        
        expect(dataA.equals(dataA2)).toBeTruthy();
        expect(dataA2.equals(dataA)).toBeTruthy();
    });
    
    it("equals object", function() {
        var data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        expect(data.equals(null)).toBeFalsy();
        expect(data.equals(KEY_EMAIL)).toBeFalsy();
    });
});
