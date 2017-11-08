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
(function (require, module) {
    "use strict";
    
    var ConditionVariable = require('msl-core/util/ConditionVariable.js');
    var PresharedAuthenticationFactory = require('msl-core/entityauth/PresharedAuthenticationFactory.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var MslInternalException = require('msl-core/MslInternalException.js');
    var PresharedAuthenticationData = require('msl-core/entityauth/PresharedAuthenticationData.js');
    var SymmetricCryptoContext = require('msl-core/crypto/SymmetricCryptoContext.js');
    var MslEntityAuthException = require('msl-core/MslEntityAuthException.js');
    var MslError = require('msl-core/MslError.js');
    var SecretKey = require('msl-core/crypto/SecretKey.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    
    var MockKeySetStore = require('../entityauth/MockKeySetStore.js');
    var MockAuthenticationUtils = require('../util/MockAuthenticationUtils.js');
    var MslTestUtils = require('../util/MslTestUtils.js');
    
	/**
	 * PSK ESN.
	 * @const
	 * @type {string}
	 */
    var PSK_ESN = "PSK-ESN";
    /**
     * PSK Kpe.
     * @const
     * @type {Uint8Array}
     */
    var PSK_KPE = "kzWYEtKSsPI8dOW5YyoILQ==";
    /**
     * PSK Kph.
     * @const
     * @type {Uint8Array}
     */
    var PSK_KPH = "VhxNUK7bYIcCV4wLE2YK90do1X3XqhPeMwwllmNh8Jw=";
    /**
     * PSK ESN 2.
     * @const
     * @type {string}
     */
    var PSK_ESN2 = "PSK-ESN2";
    /**
     * PSK Kpe 2.
     * @const
     * @type {Uint8Array}
     */
    var PSK_KPE2 = "lzWYEtKSsPI8dOW5YyoILQ==";
    /**
     * PSK Kph 2.
     * @const
     * @type {Uint8Array}
     */
    var PSK_KPH2 = "WhxNUK7bYIcCV4wLE2YK90do1X3XqhPeMwwllmNh8Jw=";

    /**
     * Kpe/Kph/Kpw #1.
     * @type {SecretKey}
     */
    var KPE, KPH, KPW;
    /**
     * Kpe/Kph/Kpw #2.
     * @type {SecretKey}
     */
    var KPE2, KPH2, KPW2;
    var keysDefined = new ConditionVariable();

    /**
     * Test pre-shared keys authentication factory.
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var MockPresharedAuthenticationFactory = module.exports = PresharedAuthenticationFactory.extend({
	    /**
	     * Create a new test pre-shared keys authentication factory.
	     *
         * @param {result: function(MockPresharedAuthenticationFactory), error: function(Error)}
         *        callback the callback functions that will receive the factory
         *        or any thrown exceptions.
	     */
		init: function init(callback) {
            init.base.call(this, new MockKeySetStore(), new MockAuthenticationUtils());

            var self = this;
            AsyncExecutor(callback, function() {
                // We have to block until keys exist.
                if (KPE && KPH && KPW && KPE2 && KPH2 && KPW2) return this;

                function retry() {
                    keysDefined.wait(-1, {
                        result: function() {
                            AsyncExecutor(callback, function() {
                                if (KPE && KPH && KPW && KPE2 && KPH2 && KPW2) return this;
                                retry();
                            }, self);
                        },
                        timeout: function() {
                            callback.error(new MslInternalException("Timed out waiting for hard-coded Kpe/Kph/Kpw."));
                        },
                        error: function(e) {
                            callback.error(new MslInternalException("Error waiting for hard-coded Kpe/Kph/Kpw.", e));
                        }
                    });
                }
                retry();
            }, this);
		},

		/** @inheritDoc */
		getCryptoContext: function getCryptoContext(ctx, authdata) {
	        // Make sure we have the right kind of entity authentication data.
	        if (!(authdata instanceof PresharedAuthenticationData))
	            throw new MslInternalException("Incorrect authentication data type " + authdata + ".");
	        var pad = authdata;

	        // Try to return the test crypto context.
	        var identity = pad.getIdentity();
	        if (PSK_ESN == identity)
	            return new SymmetricCryptoContext(ctx, identity, KPE, KPH, KPW);
	        if (PSK_ESN2 == identity)
	            return new SymmetricCryptoContext(ctx, identity, KPE2, KPH2, KPW2);

	        // Entity not found.
	        throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "psk " + identity).setEntityAuthenticationData(pad);
	    },
    });

    /**
     * Create a new test pre-shared keys authentication factory.
     *
     * @param {result: function(MockPresharedAuthenticationFactory), error: function(Error)}
     *        callback the callback functions that will receive the factory
     *        or any thrown exceptions.
     */
    var MockPresharedAuthenticationFactory$create = function MockPresharedAuthenticationFactory$create(callback) {
        new MockPresharedAuthenticationFactory(callback);
    };

    // Exports.
    module.exports.create = MockPresharedAuthenticationFactory$create;
    
    // Expose public static properties.
    module.exports.PSK_ESN = PSK_ESN;
    SecretKey.import(PSK_KPE, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
        result: function (key) {
            KPE = module.exports.KPE = key;
            keysDefined.signalAll();
        },
        error: function (e) {
            throw new MslInternalException("Hard-coded Kpe key failure.", e);
        }
    });
    SecretKey.import(PSK_KPH, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
        result: function (key) {
            KPH = module.exports.KPH = key;
            keysDefined.signalAll();
        },
        error: function (e) {
            throw new MslInternalException("Hard-coded Kph key failure.", e);
        }
    });
    MslTestUtils.deriveWrappingKey(PSK_KPE, PSK_KPH, {
        result: function(psk_kpw) {
            SecretKey.import(psk_kpw, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                result: function(key) {
                    KPW = module.exports.KPW = key;
                    keysDefined.signalAll();
                },
                error: function (e) {
                    throw new MslInternalException("Hard-coded Kpw key failure.", e);
                }
            });
        },
        error: function(e) {
            throw new MslInternalException("Hard-coded Kpw key failure.", e);
        }
    });
    module.exports.PSK_ESN2 = PSK_ESN2;
    SecretKey.import(PSK_KPE2, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
        result: function (key) {
            KPE2 = module.exports.KPE2 = key;
            keysDefined.signalAll();
        },
        error: function (e) {
            throw new MslInternalException("Hard-coded Kpe key failure.", e);
        }
    });
    SecretKey.import(PSK_KPH2, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
        result: function (key) {
            KPH2 = module.exports.KPH2 = key;
            keysDefined.signalAll();
        },
        error: function (e) {
            throw new MslInternalException("Hard-coded Kph key failure.", e);
        }
    });
    MslTestUtils.deriveWrappingKey(PSK_KPE2, PSK_KPH2, {
        result: function(psk_kpw) {
            SecretKey.import(psk_kpw, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                result: function(key) {
                    KPW2 = module.exports.KPW2 = key;
                    keysDefined.signalAll();
                },
                error: function (e) {
                    throw new MslInternalException("Hard-coded Kpw key failure.", e);
                }
            });
        },
        error: function(e) {
            throw new MslInternalException("Hard-coded Kpw key failure.", e);
        }
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockPresharedAuthenticationFactory'));
