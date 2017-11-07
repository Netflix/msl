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
describe("X509AuthenticationData", function() {
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var EntityAuthenticationData = require('msl-core/entityauth/EntityAuthenticationData.js');
    var X509AuthenticationData = require('msl-core/entityauth/X509AuthenticationData.js');
    var Base64 = require('msl-core/util/Base64.js');
    var MslEncodingException = require('msl-core/MslEncodingException.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslError = require('msl-core/MslError.js');
    var X509 = require('msl-core/crypto/X509.js');

    var MslTestConstants = require('msl-tests/MslTestConstants.js');
    var MockMslContext = require('msl-tests/util/MockMslContext.js');
    var MockX509AuthenticationFactory = require('msl-tests/entityauth/MockX509AuthenticationFactory.js');
    var MslTestUtils = require('msl-tests/util/MslTestUtils.js');

    var hex2b64 = require('jsrsasign').hex2b64;
    
    /** MSL encoder format. */
    var ENCODER_FORMAT = MslEncoderFormat.JSON;
    
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
    
    /** Key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** Key entity authentication data. */
    var KEY_AUTHDATA = "authdata";
    /** Key entity X.509 certificate. */
    var KEY_X509_CERT = "x509certificate";

    /** Expired X.509 certificate. */
    var expiredCert = new X509();
    expiredCert.readCertPEM(X509_EXPIRED_CERT);
    
    /** MSL context. */
    var ctx;
    /** MSL encoder factory. */
    var encoder;
    
    var initialized = false;
    beforeEach(function() {
        if (!initialized) {
            runs(function() {
                MockMslContext.create(EntityAuthenticationScheme.X509, false, {
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
    
    it("ctor is correct", function() {
    	var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
    	expect(data.scheme).toBe(EntityAuthenticationScheme.X509);
    	expect(data.x509cert).toEqual(MockX509AuthenticationFactory.X509_CERT);
    	expect(data.identity).toEqual(MockX509AuthenticationFactory.X509_CERT.getSubjectString());
        
        var authdata;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var encode;
        runs(function() {
            expect(authdata).not.toBeNull();
            data.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var moData, moAuthdata;
        runs(function() {
            expect(encode).not.toBeNull();
            
            moData = new X509AuthenticationData.parse(authdata);
            expect(moData.scheme).toEqual(data.scheme);
            expect(moData.x509cert.hex).toEqual(data.x509cert.hex);
            expect(moData.getIdentity()).toEqual(data.getIdentity());
            moData.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { moAuthdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moAuthdata; }, "moAuthdata", MslTestConstants.TIMEOUT);

        var moEncode;
        runs(function() {
            expect(moAuthdata).not.toBeNull();
            expect(moAuthdata).toEqual(authdata);
            moData.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);

        runs(function() {
            expect(moEncode).not.toBeNull();
            expect(moEncode).toEqual(encode);
        });
    });
	
	it("mslobject is correct", function() {
		var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, data, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(mo.getString(KEY_SCHEME)).toEqual(EntityAuthenticationScheme.X509.name);
            var authdata = mo.getMslObject(KEY_AUTHDATA, encoder);
            var x509certificate = authdata.getString(KEY_X509_CERT);
            var certB64 = hex2b64(MockX509AuthenticationFactory.X509_CERT.hex);
            expect(x509certificate).toEqual(certB64);
        });
	});
	
	it("create", function() {
		var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        
        var encode;
        runs(function() {
            data.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { encode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return encode; }, "encode", MslTestConstants.TIMEOUT);
        
        var mo;
        runs(function() {
            MslTestUtils.toMslObject(encoder, data, {
                result: function(x) { mo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return mo; }, "mo", MslTestConstants.TIMEOUT);
        
        var entitydata;
        runs(function() {
            EntityAuthenticationData.parse(ctx, mo, {
                result: function(x) { entitydata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return entitydata; }, "entitydata", MslTestConstants.TIMEOUT);

        var moData, moAuthdata;
        runs(function() {
            expect(entitydata).not.toBeNull();
        	expect(entitydata instanceof X509AuthenticationData).toBeTruthy();
        	
        	moData = entitydata;
        	expect(moData.scheme).toEqual(data.scheme);
        	expect(moData.x509cert.hex).toEqual(data.x509cert.hex);
        	expect(moData.getIdentity()).toEqual(data.getIdentity());
            moData.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { moAuthdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moAuthdata; }, "moAuthdata", MslTestConstants.TIMEOUT);
        
        var authdata;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        var moEncode;
        runs(function() {
            expect(moAuthdata).not.toBeNull();
            expect(moAuthdata).toEqual(authdata);
            moData.toMslEncoding(encoder, ENCODER_FORMAT, {
                result: function(x) { moEncode = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return moEncode; }, "moEncode", MslTestConstants.TIMEOUT);
        
        runs(function() {
            expect(moEncode).not.toBeNull();
            expect(moEncode).toEqual(encode);
        });
	});
	
	it("missing X.509 cert", function() {
        var authdata;
        runs(function() {
			var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        runs(function() {
			authdata.remove(KEY_X509_CERT);
			var f = function() {
			    X509AuthenticationData.parse(authdata);
			};
            expect(f).toThrow(new MslEncodingException(MslError.MSL_PARSE_ERROR));
		});
	});

	// the jsrsasign X.509 parser does not validate
	xit("corrupt X.509 cert", function() {
        var authdata;
        runs(function() {
			var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); },
            });
        });
        waitsFor(function() { return authdata; }, "authdata", MslTestConstants.TIMEOUT);
        
        runs(function() {
			var x509b64 = authdata.getString(KEY_X509_CERT);
			var x509raw = Base64.decode(x509b64);
			++x509raw[0];
			authdata.put(KEY_X509_CERT, Base64.encode(x509b64));
			var f = function() {
			    X509AuthenticationData.parse(authdata);
			};
			expect(f).toThrow(new MslCryptoException(MslError.X509CERT_PARSE_ERROR));
        });
	});
    
	it("equals identity", function() {
	    var dataA, dataB, dataA2;
	    runs(function() {
    		dataA = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
            dataB = new X509AuthenticationData(expiredCert);
            MslTestUtils.toMslObject(encoder, dataA, {
                result: function(mo) {
                    EntityAuthenticationData.parse(ctx, mo, {
                        result: function(x) { dataA2 = x; },
                        error: function(e) { expect(function() { throw e; }).not.toThrow(); }
                    });
                },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
	    });
	    waitsFor(function() { return dataA && dataB && dataA2; }, "data", MslTestConstants.TIMEOUT);
        
	    runs(function() {
            expect(dataA.equals(dataA)).toBeTruthy();
            
            expect(dataB.equals(dataA)).toBeFalsy();
            expect(dataA.equals(dataB)).toBeFalsy();
            
            expect(dataA2.equals(dataA)).toBeTruthy();
            expect(dataA.equals(dataA2)).toBeTruthy();
	    });
	});
    
	it("equals object", function() {
		var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
		expect(data.equals(null)).toBeFalsy();
		expect(data.equals(KEY_X509_CERT)).toBeFalsy();
	});
});