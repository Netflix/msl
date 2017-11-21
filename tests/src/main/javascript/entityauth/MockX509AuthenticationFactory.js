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
(function(require, module) {
    "use strict";
    
    var X509 = require('msl-core/crypto/X509.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var X509AuthenticationFactory = require('msl-core/entityauth/X509AuthenticationFactory.js');
    var X509AuthenticationData = require('msl-core/entityauth/X509AuthenticationData.js');
    var RsaCryptoContext = require('msl-core/crypto/RsaCryptoContext.js');
    var MslCryptoException = require('msl-core/MslCryptoException.js');
    var MslError = require('msl-core/MslError.js');
    
	/** X.509 private key. */
    var X509_PRIVATE_KEY =
    	"-----BEGIN RSA PRIVATE KEY-----\n" +
    	"MIICXQIBAAKBgQC6HO/RzCGSbz4Tbb3rOLIoy7ckmCawoatOhjXY45B/rwvqCflP\n" +
    	"MoLnSQsbYifWVz1I0BkaIzq0mVBNLB/pIayy+39PgOMGqRS4WTTwv7lPRUeBx5UP\n" +
    	"TH7pDTIQ4qV018jCJolSuLZCJtZ0eUjj6gz6UPCIEdcGmIatPpv3UiO6EwIDAQAB\n" +
    	"AoGBAJ67/28Yg6m5Z2B6wPjWKl3RIir7+kO8H7ehkFuj+6JrUeYTC6gYlL1e9zIr\n" +
    	"zX5qecKYelBoq7FM8chgUfcs2XV473v6e2YpHfljym2oN77g6bDD99YBQ/otBQy4\n" +
    	"S2Aenv3HQddjOmvm1P58khmgitNi89O6gt6IwpPNrnOyYwyBAkEA6n9v0DoUT275\n" +
    	"VjpDE91oa5v7cNerxXEAD2BvVClS4d3GKD9vMHyJmS9AeVjv5BKwrZ9Wpc0Ziz7m\n" +
    	"t0TcbgAsawJBAMstuVHNnq58S6A35XYMKPtEDBVoq1X8KS3ktlfkQpjk9JBDFH7y\n" +
    	"iM5teLpt9vFBiI7gPVZkKgo79Om+WUjLEvkCQEGY5pFsPdQ+qfcqEyuSayx3FO5r\n" +
    	"Fn0D8E1c36e+a5YNcOo/XH5GyEMWycVoUKsPY2ceRKHa7wNZ1DZ+R99powMCQQCd\n" +
    	"6yoRFNpzEBTPsOJegFESCu/BbBtPt7BiBVRcuAOzRrF3t0uk5+nBWIDvlizLk34K\n" +
    	"XuwNy8iJL9TKILLQy1YxAkBR5gVVZTJOW95lK6P/agsOAMtDeTBgBAG6BObkhjzQ\n" +
    	"8/l85d8tM+2zFHbVXR0TZ9Rse6hxqLiBJqCyWNcqDEe4\n" +
    	"-----END RSA PRIVATE KEY-----";
    /** X.509 self-signed resource certificate. */
    var X509_SELF_SIGNED_CERT =
    	"-----BEGIN CERTIFICATE-----\n" +
    	"MIIDqDCCAxGgAwIBAgIJAKxMVjhnZIh6MA0GCSqGSIb3DQEBBQUAMIGVMQswCQYD\n" +
    	"VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJTG9zIEdhdG9z\n" +
    	"MRYwFAYDVQQKEw1OZXRmbGl4LCBJbmMuMRUwEwYDVQQLEwxQUEQgU2VjdXJpdHkx\n" +
    	"DDAKBgNVBAMTA21zbDEgMB4GCSqGSIb3DQEJARYRd21pYXdAbmV0ZmxpeC5jb20w\n" +
    	"HhcNMTIwODExMjMwNDM4WhcNMzkxMjI3MjMwNDM4WjCBlTELMAkGA1UEBhMCVVMx\n" +
    	"EzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCUxvcyBHYXRvczEWMBQGA1UE\n" +
    	"ChMNTmV0ZmxpeCwgSW5jLjEVMBMGA1UECxMMUFBEIFNlY3VyaXR5MQwwCgYDVQQD\n" +
    	"EwNtc2wxIDAeBgkqhkiG9w0BCQEWEXdtaWF3QG5ldGZsaXguY29tMIGfMA0GCSqG\n" +
    	"SIb3DQEBAQUAA4GNADCBiQKBgQC6HO/RzCGSbz4Tbb3rOLIoy7ckmCawoatOhjXY\n" +
    	"45B/rwvqCflPMoLnSQsbYifWVz1I0BkaIzq0mVBNLB/pIayy+39PgOMGqRS4WTTw\n" +
    	"v7lPRUeBx5UPTH7pDTIQ4qV018jCJolSuLZCJtZ0eUjj6gz6UPCIEdcGmIatPpv3\n" +
    	"UiO6EwIDAQABo4H9MIH6MB0GA1UdDgQWBBTr2CcZwW1c+G3zLSi4dmzEXGQ2mjCB\n" +
    	"ygYDVR0jBIHCMIG/gBTr2CcZwW1c+G3zLSi4dmzEXGQ2mqGBm6SBmDCBlTELMAkG\n" +
    	"A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCUxvcyBHYXRv\n" +
    	"czEWMBQGA1UEChMNTmV0ZmxpeCwgSW5jLjEVMBMGA1UECxMMUFBEIFNlY3VyaXR5\n" +
    	"MQwwCgYDVQQDEwNtc2wxIDAeBgkqhkiG9w0BCQEWEXdtaWF3QG5ldGZsaXguY29t\n" +
    	"ggkArExWOGdkiHowDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQABGT2y\n" +
    	"MdAdhCgt48HtQcRmn3sYT8K4BxSZ5rAJ9Ks9lCEyL5rKfShXqaBncRO9ybr89Xu4\n" +
    	"qKgnMxjK/eFOXwgEH33mfgzZWIVpsp3B689Cay6hpK1O2m2K2zLZhL7U3vNBQesB\n" +
    	"fk8SjxFv79piknm0xE1kPJFvvwtiMRGj4FsPYQ==\n" +
    	"-----END CERTIFICATE-----";
    
    /**
     * X.509 ESN.
     * @const
     * @type {string}
     */
    var X509_ESN;
    /**
     * X509Cert.
     * @const
     * @type {X509}
     */
    var X509_CERT;
    /**
     * Private key.
     * @const
     * @type {PrivateKey}
     */
    var X509_PRIVKEY;
    
    try {
        X509_CERT = new X509();
        X509_CERT.readCertPEM(X509_SELF_SIGNED_CERT);
        X509_ESN = X509_CERT.getSubjectString();

        // TODO: implement
        // var rsaPrivKey = new RSAKey();
        // rsaPrivKey.readPrivateKeyFromPEMString(X509_PRIVATE_KEY);
        // X509_PRIVKEY = PrivateKey$create(rsaPrivKey, {result: });
    } catch (e) {
        throw new MslInternalException("Hard-coded X.509 private key and self-signed certificate failure.", e);
    }

    /**
     * Test X.509 asymmetric keys authentication factory.
     * 
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var MockX509AuthenticationFactory = module.exports = X509AuthenticationFactory.extend({
        /**
	     * Create a new test X.509 authentication factory.
	     */
	    init: function init() {
	        init.base.call(this);
	    },
    
	    /** @inheritDoc */
	    getCryptoContext: function getCryptoContext(ctx, authdata) {
	        // Try to return the test crypto context.
	        if (authdata instanceof X509AuthenticationData) {
	            var identity = authdata.getIdentity();
	            try {
	                if (X509_CERT.getSubjectString() == identity)
	                    return new RsaCryptoContext(ctx, identity, X509_PRIVKEY, X509_CERT.subjectPublicKeyRSA, RsaCryptoContext.Mode.SIGN_VERIFY);
	            } catch (e) {
	                throw new MslCryptoException(MslError.X509CERT_PARSE_ERROR, X509_CERT.hex, e);
	            }
	        }
	        return getCryptoContext.base.call(this, ctx, authdata);
	    }
    });
    
    // Expose public static properties.
    module.exports.X509_ESN = X509_ESN;
    module.exports.X509_CERT = X509_CERT;
    module.exports.X509_PRIVKEY = X509_PRIVKEY;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockX509AuthenticationFactory'));
