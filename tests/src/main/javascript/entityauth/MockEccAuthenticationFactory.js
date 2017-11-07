/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
    
    var ConditionVariable = require('msl-core/util/ConditionVariable.js');
    var EccAuthenticationFactory = require('msl-core/entityauth/EccAuthenticationFactory.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var EccAuthenticationData = require('msl-core/entityauth/EccAuthenticationData.js');
    var EccCryptoContext = require('msl-core/crypto/EccCryptoContext.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var WebCryptoNamedCurve = require('msl-core/crypto/WebCryptoNamedCurve.js');
    var KeyFormat = require('msl-core/crypto/KeyFormat.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var Base64 = require('msl-core/util/Base64.js');
    var PublicKey = require('msl-core/crypto/PublicKey.js');
    var PrivateKey = require('msl-core/crypto/PrivateKey.js');
    
    /** ECC public key. */
    var ECC_PUBKEY_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x":   "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":   "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "use": "sig",
        "kid": "A"
    };
    /** ECC private key. */
    var ECC_PRIVKEY_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x":   "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":   "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "d":   "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
        "use": "sig",
        "kid": "Apriv"
    };

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
        _algo['namedCurve'] = WebCryptoNamedCurve.P_256;
        
        PublicKey.import(ECC_PUBKEY_JWK, _algo, WebCryptoUsage.VERIFY, KeyFormat.JWK, {
            result: function (pubkey) {
                ECC_PUBKEY = module.exports.ECC_PUBKEY = pubkey;
                keysDefined.signalAll();
            },
            error: function(e) {
                throw new MslInternalException("Hard-coded ECC key failure.", e);
            }
        });
        PrivateKey.import(ECC_PRIVKEY_JWK, _algo, WebCryptoUsage.SIGN, KeyFormat.JWK, {
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
