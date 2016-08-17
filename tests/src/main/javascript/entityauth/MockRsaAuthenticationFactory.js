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
var MockRsaAuthenticationFactory;
var MockRsaAuthenticationFactory$create;

(function() {
    "use strict";
    
	// PKCS#1 RSA Public Key Format
	var publicKeyData =
    	"-----BEGIN PUBLIC KEY-----\n" +
		"MIGJAoGBAJ5lBbaR2rylOL6/7PQAKQBC1XPmiG//Zxk45cASIacSEcxHWNP87a5Q\n" +
		"OxWeljxj6oMATSslVXo0mcH63HMDXdh3kwAZF+eQLIMoKSmZ3b0HOaA3X8Bg28v3\n" +
		"0NsV0RmdlLPPFPh1hSgnfHHZ+eZXsThWHyQkwl9u6zDZr53/JEPTAgMBAAE=\n" +
		"-----END PUBLIC KEY-----";
	var privateKeyData =
		"-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIICWwIBAAKBgQCeZQW2kdq8pTi+v+z0ACkAQtVz5ohv/2cZOOXAEiGnEhHMR1jT\n" +
		"/O2uUDsVnpY8Y+qDAE0rJVV6NJnB+txzA13Yd5MAGRfnkCyDKCkpmd29BzmgN1/A\n" +
		"YNvL99DbFdEZnZSzzxT4dYUoJ3xx2fnmV7E4Vh8kJMJfbusw2a+d/yRD0wIDAQAB\n" +
		"AoGAQpM/lX80qzne4f4VgHFYym1M/owVKM327ZkGqHZ2gpyLsosCgQe8dxnt26Zu\n" +
		"iy+L8Ef+J3ZnuRfG0Mu6QPVXSe2hS/wzvFlEcEidI/97fOUWRHRmZn0WKmDnYqzq\n" +
		"4trC+0VTTzvnUpVtS5rHj6Xn15rLN1kqxRsP0LR6FftRZmECQQDJ5oz/MyyWU83s\n" +
		"L7KQ5mXhmuHQdZP4pPV7O5duGb7RydYJY55RydGVlRPFR8tysO89Tudmz1Dx4smI\n" +
		"I0oUiN6ZAkEAyNYpoYtu0Ll8Xdhy2N4YfAoNIXcl9k5yy000vte3h8PlVZaxaczJ\n" +
		"cyStPhjQN3CJm1fKpp8dYNPg7mDw9tyVSwJALM8XQdhIsABfdmjLl68as2xda5d8\n" +
		"xLVPqg76t7vNBuBluWW7kGlbM3iHj8Q0Wfr8zb2CS+X9EAIGOkmiulX6GQJAYAA3\n" +
		"UDgVVYKEl1tispWfgJNRaYDJza38I4AZSWxWF3ilhD8POTKhzP9oLHmx9f4+WNoj\n" +
		"TXhbk7BUIb6HEImqdwJACY4w5EpkWXquA2EJu/MpTIzROi1bDD0hNToKbTPKWtw8\n" +
		"pXmFVRGmEZmcJIEnPfu9y7TMgRjCPIz4CswGOu2zbg==\n" +
		"-----END RSA PRIVATE KEY-----";
	
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
    MockRsaAuthenticationFactory = RsaAuthenticationFactory.extend({
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
                    return new RsaCryptoContext(ctx, identity, RSA_PRIVKEY, RSA_PUBKEY, RsaCryptoContext$Mode.SIGN_VERIFY);
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
    MockRsaAuthenticationFactory$create = function MockRsaAuthenticationFactory$create(store, callback) {
        new MockRsaAuthenticationFactory(store, callback);
    };
    
    // Expose public static properties.
    MockRsaAuthenticationFactory.RSA_ESN = RSA_ESN;
    MockRsaAuthenticationFactory.RSA_PUBKEY_ID = RSA_PUBKEY_ID;
    // FIXME: Use the hard-coded RSA keys.
    MslTestUtils.generateRsaKeys(WebCryptoAlgorithm.RSASSA, WebCryptoUsage.SIGN_VERIFY, 2048, {
        result: function(publicKey, privateKey) {
            RSA_PUBKEY = MockRsaAuthenticationFactory.RSA_PUBKEY = publicKey;
            RSA_PRIVKEY = MockRsaAuthenticationFactory.RSA_PRIVKEY = privateKey;
            keysDefined.signalAll();
        },
        error: function(e) {
            throw new MslInternalException("Hard-coded RSA key failure.", e);
        }
    });
})();
