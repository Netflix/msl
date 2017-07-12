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
(function(require, module) {
    "use strict";
    
    const ConditionVariable = require('../../../../../core/src/main/javascript/util/ConditionVariable.js');
    const RsaAuthenticationFactory = require('../../../../../core/src/main/javascript/entityauth/RsaAuthenticationFactory.js');
    const AsyncExecutor = require('../../../../../core/src/main/javascript/util/AsyncExecutor.js');
    const MslInternalException = require('../../../../../core/src/main/javascript/MslInternalException.js');
    const RsaAuthenticationData = require('../../../../../core/src/main/javascript/entityauth/RsaAuthenticationData.js');
    const RsaCryptoContext = require('../../../../../core/src/main/javascript/crypto/RsaCryptoContext.js');
    const WebCryptoAlgorithm = require('../../../../../core/src/main/javascript/crypto/WebCryptoAlgorithm.js');
    const WebCryptoUsage = require('../../../../../core/src/main/javascript/crypto/WebCryptoUsage.js');
    const Base64 = require('../../../../../core/src/main/javascript/util/Base64.js');
    const PublicKey = require('../../../../../core/src/main/javascript/crypto/PublicKey.js');
    const PrivateKey = require('../../../../../core/src/main/javascript/crypto/PrivateKey.js');
    const KeyFormat = require('../../../../../core/src/main/javascript/crypto/KeyFormat.js');
    
    const MslTestUtils = require('../util/MslTestUtils.js');
    
    /** 1024-bit RSA public key. */
   	var RSA_PUBKEY_B64 =
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALeJpiH5nikd3XeAo2rHjLJVVChM/p6l" +
        "VnQHyFh77w0Efbppi1P1pNy8BxJ++iFKt2dV/4ZKkUKqtlIu3KX19kcCAwEAAQ==";
    /** 1024-bit RSA private key. */
    var RSA_PRIVKEY_B64 =
        "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAt4mmIfmeKR3dd4Cj" +
        "aseMslVUKEz+nqVWdAfIWHvvDQR9ummLU/Wk3LwHEn76IUq3Z1X/hkqRQqq2Ui7c" +
        "pfX2RwIDAQABAkEAlB6YXq7uv0wE4V6Fg7VLjNhkNKn+itXwMW/eddp/D8cC4QbH" +
        "+0Ejt0e3F+YcY0RBsTUk7hz89VW7BtpjXRrU0QIhAOyjvUsihGzImq+WDiEWvnXX" +
        "lVaUaJXaaNElE37V/BE1AiEAxo25k2z2SDbFC904Zk020kISi95KNNv5ceEFcGu0" +
        "dQsCIQDUgj7uCHNv1b7ETDcoE+q6nP2poOFDIb7bgzY8wyH4uQIgf+02YO82auam" +
        "5HL+8KLVLHkXm/h31UDZoe66Y2lxlmsCIQC+cKulQATpKNnMV1RVtpH07A0+X72s" +
        "wpu2pmaRSYgw/w==";
	
	/**
	 * RSA ESN.
	 * @const
	 * @type {string}
	 */
    var RSA_ESN = "RSAPREFIX-ESN";
    /**
     * RSA public key ID.
     * @const
     * @type {string}
     */
    var RSA_PUBKEY_ID = "mockRSAKeyId";
    /**
     * RSA public key.
     * @const
     * @type {PublicKey}
     */
    var RSA_PUBKEY;
    /**
     * RSA private key.
     * @const
     * @type {PrivateKey}
     */
    var RSA_PRIVKEY;
    var keysDefined = new ConditionVariable();
    
    /**
     * Test RSA asymmetric keys authentication factory.
     * 
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var MockRsaAuthenticationFactory = module.exports = RsaAuthenticationFactory.extend({
    	/**
    	 * Create a new test RSA authentication factory.
    	 * 
    	 * @param store RSA key store.
         * @param {result: function(MockRsaAuthenticationFactory), error: function(Error)}
         *        callback the callback functions that will receive the factory
         *        or any thrown exceptions.
    	 */
    	init: function init(store, callback) {
    		init.base.call(this, null, store);
    		
    		var self = this;
            AsyncExecutor(callback, function() {
                // We have to block until RSA_PUBKEY and RSA_PRIVKEY exist.
                if (RSA_PUBKEY && RSA_PRIVKEY) return this;
                
                function retry() {
                    keysDefined.wait(-1, {
                        result: function() {
                            AsyncExecutor(callback, function() {
                                if (RSA_PUBKEY && RSA_PRIVKEY) return this;
                                retry();
                            }, self);
                        },
                        timeout: function() {
                            callback.error(new MslInternalException("Timed out waiting for hard-coded RSA key pair."));
                        },
                        error: function(e) {
                            callback.error(new MslInternalException("Error waiting for hard-coded RSA key pair.", e));
                        }
                    });
                }
                retry();
            }, this);
    	},
    	
    	/** @inheritDoc */
    	getCryptoContext: function getCryptoContext(ctx, authdata) {
            if (authdata instanceof RsaAuthenticationData) {
                var pubkeyid = authdata.publicKeyId;
                if (RSA_PUBKEY_ID == pubkeyid) {
                    var identity = authdata.identity;
                    return new RsaCryptoContext(ctx, identity, RSA_PRIVKEY, RSA_PUBKEY, RsaCryptoContext.Mode.SIGN_VERIFY);
                }
            }
            return getCryptoContext.base.call(this, ctx, authdata);
        },
    });
    
    /**
     * Create a new test RSA authentication factory.
     * 
     * @param store RSA key store.
     * @param {result: function(MockRsaAuthenticationFactory), error: function(Error)}
     *        callback the callback functions that will receive the factory
     *        or any thrown exceptions.
     */
    var MockRsaAuthenticationFactory$create = function MockRsaAuthenticationFactory$create(store, callback) {
        new MockRsaAuthenticationFactory(store, callback);
    };
    
    // Exports.
    module.exports.create = MockRsaAuthenticationFactory$create;
    
    // Expose public static properties.
    module.exports.RSA_ESN = RSA_ESN;
    module.exports.RSA_PUBKEY_ID = RSA_PUBKEY_ID;
    
    (function() {
        var pubKeyEncoded = Base64.decode(RSA_PUBKEY_B64);
        var privKeyEncoded = Base64.decode(RSA_PRIVKEY_B64);
                
        PublicKey.import(pubKeyEncoded, WebCryptoAlgorithm.RSASSA, WebCryptoUsage.VERIFY, KeyFormat.SPKI, {
            result: function (pubkey) {
                RSA_PUBKEY = module.exports.RSA_PUBKEY = pubkey;
                keysDefined.signalAll();
            },
            error: function(e) {
                throw new MslInternalException("Hard-coded RSA key failure.", e);
            }
        });
        PrivateKey.import(privKeyEncoded, WebCryptoAlgorithm.RSASSA, WebCryptoUsage.SIGN, KeyFormat.PKCS8, {
            result: function (privkey) {
                RSA_PRIVKEY = module.exports.RSA_PRIVKEY = privkey;
                keysDefined.signalAll();
            },
            error: function(e) {
                throw new MslInternalException("Hard-coded RSA key failure.", e);
            }
        });
    })();
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockRsaAuthenticationFactory'));
