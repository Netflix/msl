/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
    const EccAuthenticationFactory = require('../../../../../core/src/main/javascript/entityauth/EccAuthenticationFactory.js');
    const AsyncExecutor = require('../../../../../core/src/main/javascript/util/AsyncExecutor.js');
    const EccAuthenticationData = require('../../../../../core/src/main/javascript/entityauth/EccAuthenticationData.js');
    const EccCryptoContext = require('../../../../../core/src/main/javascript/crypto/EccCryptoContext.js');
    const WebCryptoAlgorithm = require('../../../../../core/src/main/javascript/crypto/WebCryptoAlgorithm.js');
    const WebCryptoUsage = require('../../../../../core/src/main/javascript/crypto/WebCryptoUsage.js');
    const KeyFormat = require('../../../../../core/src/main/javascript/crypto/KeyFormat.js');
    const MslInternalException = require('../../../../../core/src/main/javascript/MslInternalException.js');
    const Base64 = require('../../../../../core/src/main/javascript/util/Base64.js');
    const PublicKey = require('../../../../../core/src/main/javascript/crypto/PublicKey.js');
    const PrivateKey = require('../../../../../core/src/main/javascript/crypto/PrivateKey.js');

    /** ECC public key. */
    var ECC_PUBKEY_B64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExgY6uU5xZkvDLVlo5PpKjhRJnyqS" +
        "j4+LNcQ+x+kdPbZf1GwiJy2sRiJwghsXl9X8ffRpUqiLeNW0oOE/+dG2iw==";

    /** ECC private key. */
    var ECC_PRIVKEY_B64 =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrNqzpcZOpGRqlVGZ" +
        "nelA4i7N/E96nJ8Ntk1ZXhPzKcChRANCAATGBjq5TnFmS8MtWWjk+kqOFEmfKpKP" +
        "j4s1xD7H6R09tl/UbCInLaxGInCCGxeX1fx99GlSqIt41bSg4T/50baL";

	/**
	 * ECC ESN.
	 * @const
	 * @type {string}
	 */
    var ECC_ESN = "ECCPREFIX-ESN";
    /**
     *  ECC public key ID.
     * @const
     * @type {string}
     */
    var ECC_PUBKEY_ID = "mockECCKeyId";
    /**
     * ECC public key.
     * @const
     * @type {PublicKey}
     */
    var ECC_PUBKEY;
    /**
     * ECC private key.
     * @const
     * @type {PrivateKey}
     */
    var ECC_PRIVKEY;
    var keysDefined = new ConditionVariable();
    
    /**
     * Test ECC asymmetric keys authentication factory.
     * 
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var MockEccAuthenticationFactory = module.exports = EccAuthenticationFactory.extend({
    	/**
    	 * Create a new test ECC authentication factory.
    	 * 
    	 * @param store ECC key store.
         * @param {result: function(MockEccAuthenticationFactory), error: function(Error)}
         *        callback the callback functions that will receive the factory
         *        or any thrown exceptions.
    	 */
    	init: function init(store, callback) {
    		init.base.call(this, null, store);
    		
    		var self = this;
            AsyncExecutor(callback, function() {
                // We have to block until ECC_PUBKEY and ECC_PRIVKEY exist.
                if (ECC_PUBKEY && ECC_PRIVKEY) return this;
                
                function retry() {
                    keysDefined.wait(-1, {
                        result: function() {
                            AsyncExecutor(callback, function() {
                                if (ECC_PUBKEY && ECC_PRIVKEY) return this;
                                retry();
                            }, self);
                        },
                        timeout: function() {
                            callback.error(new MslInternalException("Timed out waiting for hard-coded ECC key pair."));
                        },
                        error: function(e) {
                            callback.error(new MslInternalException("Error waiting for hard-coded ECC key pair.", e));
                        }
                    });
                }
                retry();
            }, this);
    	},
    	
    	/** @inheritDoc */
    	getCryptoContext: function getCryptoContext(ctx, authdata) {
            if (authdata instanceof EccAuthenticationData) {
                var pubkeyid = authdata.publicKeyId;
                if (ECC_PUBKEY_ID == pubkeyid) {
                    var identity = authdata.identity;
                    return new EccCryptoContext(ctx, ECC_PRIVKEY, ECC_PUBKEY);
                }
            }
            return getCryptoContext.base.call(this, ctx, authdata);
        },
    });
    
    /**
     * Create a new test ECC authentication factory.
     * 
     * @param store ECC key store.
     * @param {result: function(MockEccAuthenticationFactory), error: function(Error)}
     *        callback the callback functions that will receive the factory
     *        or any thrown exceptions.
     */
    var MockEccAuthenticationFactory$create = function MockEccAuthenticationFactory$create(store, callback) {
        new MockEccAuthenticationFactory(store, callback);
    };
    
    // Exports.
    module.exports.create = MockEccAuthenticationFactory$create;
    
    // Expose public static properties.
    module.exports.ECC_ESN = ECC_ESN;
    module.exports.ECC_PUBKEY_ID = ECC_PUBKEY_ID;

    (function() {
        var _algo = WebCryptoAlgorithm.ECDSA_SHA256;
        _algo['namedCurve'] = 'P-256';
        var pubKeyEncoded = Base64.decode(ECC_PUBKEY_B64);
        var privKeyEncoded = Base64.decode(ECC_PRIVKEY_B64);
        
        PublicKey.import(pubKeyEncoded, _algo, WebCryptoUsage.VERIFY, KeyFormat.SPKI, {
            result: function (pubkey) {
                ECC_PUBKEY = module.exports.ECC_PUBKEY = pubkey;
                keysDefined.signalAll();
            },
            error: function(e) {
                throw new MslInternalException("Hard-coded ECC key failure.", e);
            }
        });
        PrivateKey.import(privKeyEncoded, _algo, WebCryptoUsage.SIGN, KeyFormat.PKCS8, {
            result: function (privkey) {
                ECC_PRIVKEY = module.exports.ECC_PRIVKEY = privkey;
                keysDefined.signalAll();
            },
            error: function(e) {
                throw new MslInternalException("Hard-coded ECC key failure.", e);
            }
        });
    })();
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockEccAuthenticationFactory'));
