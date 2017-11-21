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

/**
 * MSL context for unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var MslContext = require('msl-core/util/MslContext.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var UserAuthenticationScheme = require('msl-core/userauth/UserAuthenticationScheme.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    
	/** MSL encryption key. */
    var MSL_ENCRYPTION_KEY = "HVjzuPdH0Wqxk8TApiTqzw==";
    /** MSL HMAC key. */
    var MSL_HMAC_KEY = "166/1YebsOCtAWpM88s5gvW6Jg2lICRbtCJ1vXlHNww=";
    /** MSL wrapping key. */
    var MSL_WRAPPING_KEY = "g7aaFYDTI6LnndmyJiaz9g==";
	
	var MockMslContext = module.exports = MslContext.extend({
		/**
	     * Create a new test MSL context.
	     * 
	     * @param {EntityAuthenticationScheme} scheme entity authentication scheme.
	     * @param {boolean} peerToPeer true if the context should operate in peer-
	     *        to-peer mode.
	     * @param {result: function(MockMslContext), error: function(Error)}
	     *        callback the callback that will receive the mock MSL context or
	     *        any thrown exceptions.
	     * @throws CryptoException if the MSL crypto keys cannot be created.
	     * @throws MslCryptoException if there is an error signing or creating the
	     *         entity authentication data.
	     * @throws MslEncodingException if there is an error creating the entity
	     *         authentication data.
	     */
		init: function init(scheme, peerToPeer, callback) {
		    var UnauthenticatedAuthenticationFactory = require('msl-core/entityauth/UnauthenticatedAuthenticationFactory.js');
		    var UnauthenticatedSuffixedAuthenticationFactory = require('msl-core/entityauth/UnauthenticatedSuffixedAuthenticationFactory.js');
		    var MasterTokenProtectedAuthenticationFactory = require('msl-core/entityauth/MasterTokenProtectedAuthenticationFactory.js');
		    var ProvisionedAuthenticationFactory = require('msl-core/entityauth/ProvisionedAuthenticationFactory.js');
		    var SecretKey = require('msl-core/crypto/SecretKey.js');
		    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
		    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
		    var MslInternalException = require('msl-core/MslInternalException.js');
		    var PresharedAuthenticationData = require('msl-core/entityauth/PresharedAuthenticationData.js');
		    var PresharedProfileAuthenticationData = require('msl-core/entityauth/PresharedProfileAuthenticationData.js');
		    var X509AuthenticationData = require('msl-core/entityauth/X509AuthenticationData.js');
		    var RsaAuthenticationData = require('msl-core/entityauth/RsaAuthenticationData.js');
		    var EccAuthenticationData = require('msl-core/entityauth/EccAuthenticationData.js');
		    var UnauthenticatedAuthenticationData = require('msl-core/entityauth/UnauthenticatedAuthenticationData.js');
		    var UnauthenticatedSuffixedAuthenticationData = require('msl-core/entityauth/UnauthenticatedSuffixedAuthenticationData.js');
		    var MessageCapabilities = require('msl-core/msg/MessageCapabilities.js');
		    var MslConstants = require('msl-core/MslConstants.js');
		    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
		    var SymmetricCryptoContext = require('msl-core/crypto/SymmetricCryptoContext.js');
		    var AsymmetricWrappedExchange = require('msl-core/keyx/AsymmetricWrappedExchange.js');
		    var SymmetricWrappedExchange = require('msl-core/keyx/SymmetricWrappedExchange.js');
		    var DiffieHellmanExchange = require('msl-core/keyx/DiffieHellmanExchange.js');
		    var SimpleMslStore = require('msl-core/util/SimpleMslStore.js');
		    var DefaultMslEncoderFactory = require('msl-core/io/DefaultMslEncoderFactory.js');
		    var Random = require('msl-core/util/Random.js');
		    
		    var MockAuthenticationUtils = require('../util/MockAuthenticationUtils.js');
            var MockIdentityProvisioningService = require('../entityauth/MockIdentityProvisioningService.js');
		    var MockPresharedAuthenticationFactory = require('../entityauth/MockPresharedAuthenticationFactory.js');
		    var MockPresharedProfileAuthenticationFactory = require('../entityauth/MockPresharedProfileAuthenticationFactory.js');
		    var MockRsaAuthenticationFactory = require('../entityauth/MockRsaAuthenticationFactory.js');
		    var MockEccAuthenticationFactory = require('../entityauth/MockEccAuthenticationFactory.js');
		    var MockX509AuthenticationFactory = require('../entityauth/MockX509AuthenticationFactory.js');
		    var MockUnauthenticatedAuthenticationFactory = require('../entityauth/MockUnauthenticatedAuthenticationFactory.js');
		    var MockEmailPasswordAuthenticationFactory = require('../userauth/MockEmailPasswordAuthenticationFactory.js');
		    var MockUserIdTokenAuthenticationFactory = require('../userauth/MockUserIdTokenAuthenticationFactory.js');
		    var MockTokenFactory = require('../tokens/MockTokenFactory.js');
		    var MockDiffieHellmanParameters = require('../keyx/MockDiffieHellmanParameters.js');
		    
		    var self = this;

		    // Set up entity authentication factories.
		    AsyncExecutor(callback, function pskAuthFactory() {
                var authutils = new MockAuthenticationUtils();
		        var entityAuthFactories = {};
		        MockPresharedAuthenticationFactory.create({
		            result: function(factory) {
		                AsyncExecutor(callback, function() {
		                    entityAuthFactories[EntityAuthenticationScheme.PSK.name] = factory;
		                    pskProfileAuthFactory(authutils, entityAuthFactories);
		                }, self);
		            },
		            error: callback.error,
		        });
		    });
		    function pskProfileAuthFactory(authutils, entityAuthFactories) {
		        MockPresharedProfileAuthenticationFactory.create({
                    result: function(factory) {
                        AsyncExecutor(callback, function() {
                            entityAuthFactories[EntityAuthenticationScheme.PSK_PROFILE.name] = factory;
                            rsaAuthFactory(authutils, entityAuthFactories);
                        }, self);
                    },
                    error: callback.error,
                });
		    }
		    function rsaAuthFactory(authutils, entityAuthFactories) {
		        MockRsaAuthenticationFactory.create(null, {
		            result: function(factory) {
		                AsyncExecutor(callback, function() {
		                    entityAuthFactories[EntityAuthenticationScheme.RSA.name] = factory;
		                    eccAuthFactory(authutils, entityAuthFactories);
		                }, self);
		            },
		            error: callback.error,
		        });
		    }
		    function eccAuthFactory(authutils, entityAuthFactories) {
                MockEccAuthenticationFactory.create(null, {
                    result: function(factory) {
                        AsyncExecutor(callback, function() {
                            entityAuthFactories[EntityAuthenticationScheme.ECC.name] = factory;
                            syncEntityAuthFactories(authutils, entityAuthFactories);
                        }, self);
                    },
                    error: callback.error,
                });
		    }
		    function syncEntityAuthFactories(authutils, entityAuthFactories) {
		        entityAuthFactories[EntityAuthenticationScheme.X509.name] = new MockX509AuthenticationFactory();
		        entityAuthFactories[EntityAuthenticationScheme.NONE.name] = new MockUnauthenticatedAuthenticationFactory();
		        entityAuthFactories[EntityAuthenticationScheme.NONE_SUFFIXED.name] = new UnauthenticatedSuffixedAuthenticationFactory();
		        entityAuthFactories[EntityAuthenticationScheme.MT_PROTECTED.name] = new MasterTokenProtectedAuthenticationFactory(authutils);
		        entityAuthFactories[EntityAuthenticationScheme.PROVISIONED.name] = new ProvisionedAuthenticationFactory(new MockIdentityProvisioningService(this));
                syncUserAuthFactories(authutils, entityAuthFactories);
		    }
		    function syncUserAuthFactories(authutils, entityAuthFactories) {
		        var userAuthFactories = {};
		        userAuthFactories[UserAuthenticationScheme.EMAIL_PASSWORD.name] = new MockEmailPasswordAuthenticationFactory();
		        userAuthFactories[UserAuthenticationScheme.USER_ID_TOKEN.name] = new MockUserIdTokenAuthenticationFactory();
                mslCryptoContext(authutils, entityAuthFactories, userAuthFactories);
		    }
		    function mslCryptoContext(authutils, entityAuthFactories, userAuthFactories) {
		        SecretKey.import(MSL_ENCRYPTION_KEY, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
		            result: function (mslEncryptionKey) {
		                SecretKey.import(MSL_HMAC_KEY, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
		                    result: function (mslHmacKey) {
		                        SecretKey.import(MSL_WRAPPING_KEY, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
		                            result: function(mslWrappingKey) {
		                                finish(authutils, entityAuthFactories, userAuthFactories, mslEncryptionKey, mslHmacKey, mslWrappingKey);
		                            },
		                            error: function(e) {
		                                callback.error(new MslInternalException("Unable to create MSL wrap key.", e));
		                            }
		                        });
		                    },
		                    error: function (e) {
		                        callback.error(new MslInternalException("Unable to create MSL HMAC key.", e));
		                    }
		                });
		            },
		            error: function (e) {
		                callback.error(new MslInternalException("Unable to create MSL encryption key.", e));
		            }
		        });
		    }
		    function finish(authutils, entityAuthFactories, userAuthFactories, mslEncryptionKey, mslHmacKey, mslWrapKey) {
		        AsyncExecutor(callback, function() {
		            // Set up entity authentication data.
		            var entityAuthData;
		            if (EntityAuthenticationScheme.PSK == scheme) {
		                entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
		            } else if (EntityAuthenticationScheme.PSK_PROFILE == scheme) {
		                entityAuthData = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
		            } else if (EntityAuthenticationScheme.X509 == scheme) {
		                entityAuthData = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
		            } else if (EntityAuthenticationScheme.RSA == scheme) {
		                entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
		            } else if (EntityAuthenticationScheme.ECC == scheme) {
		                entityAuthData = new EccAuthenticationData(MockRsaAuthenticationFactory.ECC_ESN, MockRsaAuthenticationFactory.ECC_PUBKEY_ID);
		            } else if (EntityAuthenticationScheme.NONE == scheme) {
		                entityAuthData = new UnauthenticatedAuthenticationData("MOCKUNAUTH-ESN");
		            } else if (EntityAuthenticationScheme.NONE_SUFFIXED == scheme) {
		                entityAuthData = new UnauthenticatedSuffixedAuthenticationData("MOCKUNAUTH-ROOT", "MOCKUNAUTH-SUFFIX");
		            } else {
		                throw new MslInternalException("Unsupported authentication type: " + scheme);
		            }

		            // Set message capabilities.
		            var capabilities = new MessageCapabilities([MslConstants.CompressionAlgorithm.LZW], [ "en-US" ], [MslEncoderFormat.JSON]);

		            // Set the MSL crypto context.
		            var mslCryptoContext = new SymmetricCryptoContext(this, "TestMslKeys", mslEncryptionKey, mslHmacKey, mslWrapKey);

		            // Set up token factory.
		            var tokenFactory = new MockTokenFactory();

		            // Set up Diffie-Hellman parameter specifications.
		            var paramSpecs = MockDiffieHellmanParameters.getDefaultParameters();

		            // Set up key exchange factories.
		            var keyxFactories = [];
		            keyxFactories.push(new AsymmetricWrappedExchange(authutils));
		            keyxFactories.push(new SymmetricWrappedExchange(authutils));
		            keyxFactories.push(new DiffieHellmanExchange(paramSpecs, authutils));

		            // Set up the MSL store.
		            var store = new SimpleMslStore();
		            
		            // Set up the MSL encoder factory.
		            var encoderFactory = new DefaultMslEncoderFactory();

		            // The properties.
		            var props = {
		                _random: { value: new Random(), writable: false, enumerable: false, configurable: false },
		                _mslCryptoContext: { value: mslCryptoContext, writable: true, enumerable: false, configurable: false },
		                _peerToPeer: { value: peerToPeer, writable: false, enumerable: false, configurable: false },
		                _capabilities: { value: capabilities, writable: true, enumerable: false, configurable: false },
		                _entityAuthData: { value: entityAuthData, writable: true, enumerable: false, configurable: false },
		                _entityAuthFactories: { value: entityAuthFactories, writable: false, enumerable: false, configurable: false },
		                _userAuthFactories: { value: userAuthFactories, writable: false, enumerable: false, configurable: false },
		                _tokenFactory: { value: tokenFactory, writable: true, enumerable: false, configurable: false },
		                _paramSpecs: { value: paramSpecs, writable: false, enumerable: false, configurable: false },
		                _keyxFactories: { value: keyxFactories, writable: false, enumerable: false, configurable: false },
		                _store: { value: store, writable: true, enumerable: false, configurable: false },
		                _encoderFactory: { value: encoderFactory, writable: true, enumerable: false, configurable: false },
		            };
		            Object.defineProperties(this, props);

		            // Return the mock MSL context.
		            return this;
		        }, self);
		    }
		},
		
		/** @inheritDoc */
		getTime: function getTime() {
			return Date.now();
		},

		/** @inheritDoc */
		getRandom: function getRandom() {
			return this._random;
		},

		/** @inheritDoc */
		isPeerToPeer: function isPeerToPeer() {
			return this._peerToPeer;
		},
		
	    /**
	     * Set the message capabilities.
	     * 
	     * @param {MessageCapabilities} capabilities the new message capabilities.
	     */
	    setMessageCapabilities: function setMessageCapabilities(capabilities) {
	        this._capabilities = capabilities;
	    },
		
		/** @inheritDoc */
		getMessageCapabilities: function getMessageCapabilities() {
			return this._capabilities;
		},

		setEntityAuthenticationData: function setEntityAuthenticationData(entityAuthData) {
			this._entityAuthData = entityAuthData;
		},
		
		/** @inheritDoc */
		getEntityAuthenticationData: function getEntityAuthenticationData(reauthCode, callback) {
			callback.result(this._entityAuthData);
		},
		
	    /**
	     * Set the MSL crypto context.
	     * 
	     * @param {ICryptoContext} cryptoContext the new MSL crypto context.
	     */
	    setMslCryptoContext: function setMslCryptoContext(cryptoContext) {
	        this._mslCryptoContext = cryptoContext;
	    },

		/** @inheritDoc */
		getMslCryptoContext: function getMslCryptoContext() {
			return this._mslCryptoContext;
		},
        
        /** @inheritDoc */
		getEntityAuthenticationScheme: function getEntityAuthenticationScheme(name) {
		    return EntityAuthenticationScheme.getScheme(name);
		},

		/**
		 * Adds or replaces the entity authentication factory associated with the
		 * entity authentication scheme of the provided factory.
		 * 
		 * @param {EntityAuthenticationFactory} factory entity authentication factory.
		 */
		addEntityAuthenticationFactory: function addEntityAuthenticationFactory(factory) {
			this._entityAuthFactories[factory.scheme.name] = factory;
		},

		/**
		 * Removes the entity authentication factory associated with the specified
		 * entity authentication scheme.
		 * 
		 * @param {EntityAuthenticationScheme} scheme entity authentication scheme.
		 */
		removeEntityAuthenticationFactory: function removeEntityAuthenticationFactory(scheme) {
			delete this._entityAuthFactories[scheme.name];
		},

		/** @inheritDoc */
		getEntityAuthenticationFactory: function getEntityAuthenticationFactory(scheme) {
			return this._entityAuthFactories[scheme.name];
		},
		
		/** @inheritDoc */
		getUserAuthenticationScheme: function getUserAuthenticationScheme(name) {
		    return UserAuthenticationScheme.getScheme(name);
		},

		/**
		 * Adds or replaces the user authentication factory associated with the
		 * user authentication scheme of the provided factory.
		 * 
		 * @param {UserAuthenticationFactory} factory user authentication factory.
		 */
		addUserAuthenticationFactory: function addUserAuthenticationFactory(factory) {
			this._userAuthFactories[factory.scheme.name] = factory;
		},

		/**
		 * Removes the user authentication factory associated with the specified
		 * user authentication scheme.
		 * 
		 * @param {UserAuthenticationScheme} scheme user authentication scheme.
		 */
		removeUserAuthenticationFactory: function removeUserAuthenticationFactory(scheme) {
			delete this._userAuthFactories[scheme.name];
		},

		/** @inheritDoc */
		getUserAuthenticationFactory: function getUserAuthenticationFactory(scheme) {
			return this._userAuthFactories[scheme.name];
		},
	    
	    /**
	     * Sets the token factory.
	     * 
	     * @param {TokenFactory} factory the token factory.
	     */
	    setTokenFactory: function setTokenFactory(factory) {
	        this._tokenFactory = factory;
	    },

		/** @inheritDoc */
		getTokenFactory: function getTokenFactory() {
			return this._tokenFactory;
		},
		
		/**
		 * @return {Object.<string,DhParameterSpec>} the Diffie-Hellman
		 *         parameter specifications supported by the Diffie-Hellman
		 *         key exchange factory.
		 */
		getDhParameterSpecs: function getDhParameterSpecs() {
			return this._paramSpecs;
		},
		
		/** @inheritDoc */
		getKeyExchangeScheme: function getKeyExchangeScheme(name) {
		    return KeyExchangeScheme.getScheme(name);
		},

        /**
         * Adds a key exchange factory to the end of the preferred set.
         * 
         * @param {KeyExchangeFactory} factory key exchange factory.
         */
        addKeyExchangeFactory: function addKeyExchangeFactory(factory) {
            this._keyxFactories.push(factory);
        },

        /**
         * Removes all key exchange factories associated with the specified key
         * exchange scheme.
         * 
         * @param {KeyExchangeScheme} scheme key exchange scheme.
         */
        removeKeyExchangeFactories: function removeKeyExchangeFactories(scheme) {
            for (var i = 0; i < this._keyxFactories.length; ++i) {
                var factory = this._keyxFactories[i];
                if (factory.scheme == scheme) {
                    this._keyxFactories.splice(i, 1);
                    --i;
                }
            }
        },

		/** @inheritDoc */
		getKeyExchangeFactory: function getKeyExchangeFactory(scheme) {
			for (var i = 0; i < this._keyxFactories.length; ++i) {
				var factory = this._keyxFactories[i];
				if (factory.scheme == scheme)
					return factory;
			}
			return undefined;
		},

		/** @inheritDoc */
		getKeyExchangeFactories: function getKeyExchangeFactories(scheme) {
			return this._keyxFactories;
		},
		
		/**
		 * Sets the MSL store.
		 * 
		 * @param {MslStore} store the MSL store.
		 */
		setMslStore: function setMslStore(store) {
		    this._store = store;
		},

		/** @inheritDoc */
		getMslStore: function getMslStore() {
			return this._store;
		},
		
		/**
		 * Sets the MSL encoder factory.
		 * 
		 * @param {MslEncoderFactory} encoderFactory the MSL encoder factory.
		 */
		setMslEncoderFactory: function setMslEncoderFactory(encoderFactory) {
		    this._encoderFactory = encoderFactory;
		},
		
		/** @inheritDoc */
		getMslEncoderFactory: function getMslEncoderFactory() {
		    return this._encoderFactory;
		},
	});
	
    /**
     * Create a new test MSL context.
     * 
     * @param {EntityAuthenticationScheme} scheme entity authentication scheme.
     * @param {boolean} peerToPeer true if the context should operate in peer-
     *        to-peer mode.
     * @param {result: function(MockMslContext), error: function(Error)}
     *        callback the callback that will receive the mock MSL context or
     *        any thrown exceptions.
     * @throws CryptoException if the MSL crypto keys cannot be created.
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data.
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     */
	var MockMslContext$create = function MockMslContext$create(scheme, peerToPeer, callback) {
	    new MockMslContext(scheme, peerToPeer, callback);
	};
	
	// Exports.
	module.exports.create = MockMslContext$create;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockMslContext'));
