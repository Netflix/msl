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
 * X.509 asymmetric keys entity authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
describe("X509AuthenticationFactory", function() {
    const MslEncoderFormat = require('../../../../../core/src/main/javascript/io/MslEncoderFormat.js');
    const X509Store = require('../../../../../core/src/main/javascript/entityauth/X509Store.js');
    const X509AuthenticationFactory = require('../../../../../core/src/main/javascript/entityauth/X509AuthenticationFactory.js');
    const EntityAuthenticationScheme = require('../../../../../core/src/main/javascript/entityauth/EntityAuthenticationScheme.js');
    const MslEncoderUtils = require('../../../../../core/src/main/javascript/io/MslEncoderUtils.js');
    const MslEncodingException = require('../../../../../core/src/main/javascript/MslEncodingException.js');
    const MslEntityAuthException = require('../../../../../core/src/main/javascript/MslEntityAuthException.js');
    const MslError = require('../../../../../core/src/main/javascript/MslError.js');

    const MockX509AuthenticationFactory = require('../../../main/javascript/entityauth/MockX509AuthenticationFactory.js');
    const MockMslContext = require('../../../main/javascript/util/MockMslContext.js');
    const MslTestUtils = require('../../../main/javascript/util/MslTestUtils.js');

    const X509 = require('jsrsasign').X509;
    
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
    /** X.509 untrusted resource certificate. */
    var X509_UNTRUSTED_CERT =
    	"-----BEGIN CERTIFICATE-----\n" +
    	"MIIDxTCCAy6gAwIBAgIJAIwHyKMJZOHOMA0GCSqGSIb3DQEBBQUAMIGeMQswCQYD\n" +
    	"VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJTG9zIEdhdG9z\n" +
    	"MRYwFAYDVQQKEw1OZXRmbGl4LCBJbmMuMRUwEwYDVQQLEwxQUEQgU2VjdXJpdHkx\n" +
    	"FTATBgNVBAMTDG1zbHVudHJ1c3RlZDEgMB4GCSqGSIb3DQEJARYRd21pYXdAbmV0\n" +
    	"ZmxpeC5jb20wHhcNMTIwODExMjMwNTM0WhcNMzkxMjI3MjMwNTM0WjCBnjELMAkG\n" +
    	"A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCUxvcyBHYXRv\n" +
    	"czEWMBQGA1UEChMNTmV0ZmxpeCwgSW5jLjEVMBMGA1UECxMMUFBEIFNlY3VyaXR5\n" +
    	"MRUwEwYDVQQDEwxtc2x1bnRydXN0ZWQxIDAeBgkqhkiG9w0BCQEWEXdtaWF3QG5l\n" +
    	"dGZsaXguY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDehUPdtnYCKFdY\n" +
    	"Uz0jWPxsE7hKH59QF5ab9RQHQJlZfOf2rQ0ekKWM01sn6vGKtXiWLca+2i+1chw0\n" +
    	"4cdBZBlzxD2Dvn1eZaAdzHoATsWXlVo95NkBuIDzsbA/UXITiEe4dCpXnBkucyAg\n" +
    	"9Dbdd77TW04oofUnA3hO48AG6lz4/wIDAQABo4IBBzCCAQMwHQYDVR0OBBYEFGy+\n" +
    	"kqysUJyxtrmQirU3zuS0pZaLMIHTBgNVHSMEgcswgciAFGy+kqysUJyxtrmQirU3\n" +
    	"zuS0pZaLoYGkpIGhMIGeMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p\n" +
    	"YTESMBAGA1UEBxMJTG9zIEdhdG9zMRYwFAYDVQQKEw1OZXRmbGl4LCBJbmMuMRUw\n" +
    	"EwYDVQQLEwxQUEQgU2VjdXJpdHkxFTATBgNVBAMTDG1zbHVudHJ1c3RlZDEgMB4G\n" +
    	"CSqGSIb3DQEJARYRd21pYXdAbmV0ZmxpeC5jb22CCQCMB8ijCWThzjAMBgNVHRME\n" +
    	"BTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBALfDXjXCJgRyM5DE3v1PXk0Wgj3TDFxk\n" +
    	"EPcHXpv2O5Fjgkk60rsi/LZPmbmWG37OHNp3m/y5pDjqEPki1DKHaAdDerWyRQXG\n" +
    	"BfIjbq7uKehV5jdxW0akxAAE9NpB6Gxj7q8i6L+XK/2tOY0krGR/gj/j8NITcBpC\n" +
    	"zT6XbGJFn+CX\n" +
    	"-----END CERTIFICATE-----";

    /** Key entity X.509 certificate. */
    var KEY_X509_CERT = "x509certificate";

    /** X.509 store. */
    var caStore = new X509Store();
    caStore.addCert(MockX509AuthenticationFactory.X509_CERT);
    
    /** Entity authentication factory. */
    var factory = new X509AuthenticationFactory(caStore);
    
    /** Expired X.509 certificate. */
    var expiredCert = new X509();
    expiredCert.readCertPEM(X509_EXPIRED_CERT);
    
    /** Untrusted X.509 certificate. */
    var untrustedCert = new X509();
    untrustedCert.readCertPEM(X509_UNTRUSTED_CERT);

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
            waitsFor(function() { return ctx; }, "ctx", 900);
            runs(function() {
                encoder = ctx.getMslEncoderFactory();
                ctx.addEntityAuthenticationFactory(factory);
                initialized = true;
            });
        }
    });
    
    it("createData", function() {
        var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);

        var entityAuthMo;
        runs(function() {
            data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { entityAuthMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthMo; }, "entityAuthMo", 100);

        var authdata;
        runs(function() {
            factory.createData(ctx, entityAuthMo, {
                result: function(x) { authdata = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return authdata; }, "authdata", 100);

        var dataMo, authdataMo;
        runs(function() {
            expect(authdata).not.toBeNull();
            expect(authdata instanceof X509AuthenticationData).toBeTruthy();
            
            MslTestUtils.toMslObject(encoder, data, {
                result: function(x) { dataMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
            MslTestUtils.toMslObject(encoder, authdata, {
                result: function(x) { authdataMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return dataMo && authdataMo; }, "dataMo && authdataMo", 100);

        runs(function() {
            expect(MslEncoderUtils.equalObjects(dataMo, authdataMo)).toBeTruthy();
        });
    });
    
    it("encode exception", function() {
        var entityAuthMo;
        runs(function() {
	        var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
	        data.getAuthData(encoder, ENCODER_FORMAT, {
                result: function(x) { entityAuthMo = x; },
                error: function(e) { expect(function() { throw e; }).not.toThrow(); }
            });
        });
        waitsFor(function() { return entityAuthMo; }, "entityAuthMo", 100);
        
        var exception;
        runs(function() {
	        entityAuthMo.remove(KEY_X509_CERT);
            factory.createData(ctx, entityAuthMo, {
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
    
    xit("crypto context", function() {
        var data = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        var cryptoContext = factory.getCryptoContext(ctx, data);
        expect(cryptoContext).not.toBeNull();
    });
    
    it("untrusted cert", function() {
        var f = function() {
	        var data = new X509AuthenticationData(untrustedCert);
	        factory.getCryptoContext(ctx, data);
	    };
        expect(f).toThrow(new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED));
    });
    
    xit("expired cert", function() {
        var f = function() {
	        var data = new X509AuthenticationData(expiredCert);
	        factory.getCryptoContext(ctx, data);
	    };
        expect(f).toThrow(new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED));
    });
});
