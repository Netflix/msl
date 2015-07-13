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
describe("X509AuthenticationData", function() {
    /** X.509 expired resource certificate. */
    var X509_EXPIRED_CERT =
    	"-----BEGIN CERTIFICATE-----\n" +
    	"MIIDvzCCAyigAwIBAgIJAIpdBwf5QFWrMA0GCSqGSIb3DQEBBQUAMIGcMQswCQYD\n" +
    	"VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJTG9zIEdhdG9z\n" +
    	"MRYwFAYDVQQKEw1OZXRmbGl4LCBJbmMuMRUwEwYDVQQLEwxQUEQgU2VjdXJpdHkx\n" +
    	"EzARBgNVBAMTCm1zbGV4cGlyZWQxIDAeBgkqhkiG9w0BCQEWEXdtaWF3QG5ldGZs\n" +
    	"aXguY29tMB4XDTEyMDgxMTIzMDQ1N1oXDTEyMDgyMTIzMDQ1N1owgZwxCzAJBgNV\n" +
    	"BAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlMb3MgR2F0b3Mx\n" +
    	"FjAUBgNVBAoTDU5ldGZsaXgsIEluYy4xFTATBgNVBAsTDFBQRCBTZWN1cml0eTET\n" +
    	"MBEGA1UEAxMKbXNsZXhwaXJlZDEgMB4GCSqGSIb3DQEJARYRd21pYXdAbmV0Zmxp\n" +
    	"eC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK76718Ufj57o0DLAf1N\n" +
    	"2qcRaeY7aCPJBaq9Hdg51jE/gy9jZE4tjZxWUHzw6sA0Iyx8yNQ3SIy+qcIfSEcm\n" +
    	"br3AN83T7okKNMt/IrjA+fBT/ttfl1p+mxalLG9VAJ/BcKuiPdCYtxUg+9bOFvMF\n" +
    	"aMKwj3bc3koLfFIA739HpKvlAgMBAAGjggEFMIIBATAdBgNVHQ4EFgQU/9+Ccpyn\n" +
    	"zk5oJnFYQgSo2UH6+UEwgdEGA1UdIwSByTCBxoAU/9+Ccpynzk5oJnFYQgSo2UH6\n" +
    	"+UGhgaKkgZ8wgZwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIw\n" +
    	"EAYDVQQHEwlMb3MgR2F0b3MxFjAUBgNVBAoTDU5ldGZsaXgsIEluYy4xFTATBgNV\n" +
    	"BAsTDFBQRCBTZWN1cml0eTETMBEGA1UEAxMKbXNsZXhwaXJlZDEgMB4GCSqGSIb3\n" +
    	"DQEJARYRd21pYXdAbmV0ZmxpeC5jb22CCQCKXQcH+UBVqzAMBgNVHRMEBTADAQH/\n" +
    	"MA0GCSqGSIb3DQEBBQUAA4GBADO9XDbmGyeJuoEmcQhcX8k+VIkgEkl3eMtRLiaP\n" +
    	"BE2rZuoviZ+9zvM04lg8QhYLdI6cCrAPU3hF6cdhmzH4F9B+sFi3OYPfEPUSoOpG\n" +
    	"73OV/Ge88xjjNyileam7az8ioYeoq2zFg8kF2kb1Eg/WQ1ueiM3X0iiNb042X96/\n" +
    	"dvvz\n" +
    	"-----END CERTIFICATE-----";
    
    /** JSON key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    var KEY_AUTHDATA = "authdata";
    /** JSON key entity X.509 certificate. */
    var KEY_X509_CERT = "x509certificate";

    /** Expired X.509 certificate. */
    var expiredCert = new X509();
    expiredCert.readCertPEM(X509_EXPIRED_CERT);
    
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
    
    it("ctor is correct", function() {
    	var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
    	expect(data.scheme).toBe(EntityAuthenticationScheme.X509);
    	expect(data.x509cert).toEqual(MockX509AuthenticationFactory.X509_CERT);
    	expect(data.identity).toEqual(MockX509AuthenticationFactory.X509_CERT.getSubjectString());
    });
	
	it("json is correct", function() {
		var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
		var json = JSON.stringify(data);
		var certWords = CryptoJS.enc.Hex.parse(MockX509AuthenticationFactory.X509_CERT.hex);
		var certB64 = CryptoJS.enc.Base64.stringify(certWords); 
		expect(json).toEqual('{"scheme":"' + EntityAuthenticationScheme.X509.name + '","authdata":{"x509certificate":"' + certB64 + '"}}');
	});
	
	it("X509AuthenticationData.create", function() {
		var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
		var authdata = data.getAuthData();
    	expect(authdata).not.toBeNull();
    	var json = JSON.stringify(data);
    	expect(json).not.toBeNull();
    	
    	var joData = new X509AuthenticationData$parse(authdata);
    	expect(joData.scheme).toEqual(data.scheme);
    	expect(joData.x509cert.hex).toEqual(data.x509cert.hex);
    	expect(joData.identity).toEqual(data.identity);
    	var joAuthdata = joData.getAuthData();
    	expect(joAuthdata).not.toBeNull();
    	expect(joAuthdata).toEqual(authdata);
    	var joJson = JSON.stringify(joData);
    	expect(joJson).not.toBeNull();
    	expect(joJson).toEqual(json);
	});
	
	it("EntityAuthenticationData.create", function() {
		var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
    	var json = JSON.stringify(data);
    	var jo = JSON.parse(json);
    	
    	var entitydata = EntityAuthenticationData$parse(ctx, jo);
    	expect(entitydata).not.toBeNull();
    	expect(entitydata instanceof X509AuthenticationData).toBeTruthy();
    	
    	var joData = entitydata;
    	expect(joData.scheme).toEqual(data.scheme);
    	expect(joData.x509cert.hex).toEqual(data.x509cert.hex);
    	expect(joData.identity).toEqual(data.identity);
    	var joAuthdata = joData.getAuthData();
    	expect(joAuthdata).not.toBeNull();
    	expect(joAuthdata).toEqual(data.getAuthData());
    	var joJson = JSON.stringify(joData);
    	expect(joJson).not.toBeNull();
    	expect(joJson).toEqual(json);
	});
	
	it("missing X.509 cert", function() {
		var f = function() {
			var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
			var authdata = data.getAuthData();
			delete authdata[KEY_X509_CERT];
			X509AuthenticationData$parse(authdata);
		};
		expect(f).toThrow(new MslEncodingException(MslError.JSON_PARSE_ERROR));
	});

	// the jsrsasign X.509 parser does not validate
	xit("corrupt X.509 cert", function() {
		var f = function() {
			var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
			var authdata = data.getAuthData();
			var x509b64 = authdata[KEY_X509_CERT];
			var x509raw = base64$decode(x509b64);
			++x509raw[0];
			authdata[KEY_X509_CERT] = base64$encode(x509b64);
			X509AuthenticationData$parse(authdata);
		};
		expect(f).toThrow(new MslCryptoException(MslError.X509CERT_PARSE_ERROR));
	});
    
	it("equals identity", function() {
		var dataA = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        var dataB = new X509AuthenticationData(expiredCert);
        var dataA2 = EntityAuthenticationData$parse(ctx, JSON.parse(JSON.stringify(dataA)));
        
        expect(dataA.equals(dataA)).toBeTruthy();
        
        expect(dataB.equals(dataA)).toBeFalsy();
        expect(dataA.equals(dataB)).toBeFalsy();
        
        expect(dataA2.equals(dataA)).toBeTruthy();
        expect(dataA.equals(dataA2)).toBeTruthy();
	});
    
	it("equals object", function() {
		var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
		expect(data.equals(null)).toBeFalsy();
		expect(data.equals(KEY_X509_CERT)).toBeFalsy();
	});
});