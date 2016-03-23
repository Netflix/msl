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
var MockPresharedAuthenticationFactory;
var MockPresharedAuthenticationFactory$create;

(function () {
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
     * @type {CipherKey}
     */
    var KPE, KPH, KPW;
    /**
     * Kpe/Kph/Kpw #2.
     * @type {CipherKey}
     */
    var KPE2, KPH2, KPW2;
    var keysDefined = new ConditionVariable();

    /**
     * Test pre-shared keys authentication factory.
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    MockPresharedAuthenticationFactory = PresharedAuthenticationFactory.extend({
	    /**
	     * Create a new test pre-shared keys authentication factory.
	     *
         * @param {result: function(MockPresharedAuthenticationFactory), error: function(Error)}
         *        callback the callback functions that will receive the factory
         *        or any thrown exceptions.
	     */
		init: function init(callback) {
            init.base.call(this);

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
	            throw new MslInternalException("Incorrect authentication data type " + JSON.stringify(authdata) + ".");
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
    MockPresharedAuthenticationFactory$create = function MockPresharedAuthenticationFactory$create(callback) {
        new MockPresharedAuthenticationFactory(callback);
    };

    // Expose public static properties.
    MockPresharedAuthenticationFactory.PSK_ESN = PSK_ESN;
    CipherKey$import(PSK_KPE, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
        result: function (key) {
            KPE = MockPresharedAuthenticationFactory.KPE = key;
            keysDefined.signalAll();
        },
        error: function (e) {
            throw new MslInternalException("Hard-coded Kpe key failure.", e);
        }
    });
    CipherKey$import(PSK_KPH, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
        result: function (key) {
            KPH = MockPresharedAuthenticationFactory.KPH = key;
            keysDefined.signalAll();
        },
        error: function (e) {
            throw new MslInternalException("Hard-coded Kph key failure.", e);
        }
    });
    MslTestUtils.deriveWrappingKey(PSK_KPE, PSK_KPH, {
        result: function(psk_kpw) {
            CipherKey$import(psk_kpw, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                result: function(key) {
                    KPW = MockPresharedAuthenticationFactory.KPW = key;
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
    MockPresharedAuthenticationFactory.PSK_ESN2 = PSK_ESN2;
    CipherKey$import(PSK_KPE2, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
        result: function (key) {
            KPE2 = MockPresharedAuthenticationFactory.KPE2 = key;
            keysDefined.signalAll();
        },
        error: function (e) {
            throw new MslInternalException("Hard-coded Kpe key failure.", e);
        }
    });
    CipherKey$import(PSK_KPH2, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
        result: function (key) {
            KPH2 = MockPresharedAuthenticationFactory.KPH2 = key;
            keysDefined.signalAll();
        },
        error: function (e) {
            throw new MslInternalException("Hard-coded Kph key failure.", e);
        }
    });
    MslTestUtils.deriveWrappingKey(PSK_KPE2, PSK_KPH2, {
        result: function(psk_kpw) {
            CipherKey$import(psk_kpw, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                result: function(key) {
                    KPW2 = MockPresharedAuthenticationFactory.KPW2 = key;
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
})();
