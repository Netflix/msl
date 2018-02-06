/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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

    var AsymmetricWrappedExchange = require('msl-core/keyx/AsymmetricWrappedExchange.js');
    var AuthenticationUtils = require('msl-core/util/AuthenticationUtils.js');
    var ClientMslCryptoContext = require('msl-core/crypto/ClientMslCryptoContext.js');
    var ClientTokenFactory = require('msl-core/tokens/ClientTokenFactory.js');
    var DefaultMslEncoderFactory = require('msl-core/io/DefaultMslEncoderFactory.js');
    var EntityAuthenticationScheme = require('msl-core/entityauth/EntityAuthenticationScheme.js');
    var KeyExchangeScheme = require('msl-core/keyx/KeyExchangeScheme.js');
    var MessageCapabilities = require('msl-core/msg/MessageCapabilities.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var MslContext = require('msl-core/util/MslContext.js');
    var MslEncoderFormat = require('msl-core/io/MslEncoderFormat.js');
    var MslUser = require('msl-core/tokens/MslUser.js');
    var Random = require('msl-core/util/Random.js');
    var RsaAuthenticationFactory = require('msl-core/entityauth/RsaAuthenticationFactory.js');
    var UnauthenticatedAuthenticationData = require('msl-core/entityauth/UnauthenticatedAuthenticationData.js');
    var UnauthenticatedAuthenticationFactory = require('msl-core/entityauth/UnauthenticatedAuthenticationFactory.js');
    var UserAuthenticationScheme = require('msl-core/userauth/UserAuthenticationScheme.js');

    var SimpleKeyxMslStore = require('../util/SimpleKeyxMslStore.js');

    /**
     * Local authentication utils that only permits the unauthenticated entity
     * authentication scheme to be used by the local entity identity.
     */
    var LocalAuthenticationUtils = AuthenticationUtils.extend({
        /**
         * Create a new authentication utils that is aware of the local entity
         * identity.
         * 
         * @param {string} clientId local entity identity.
         */
        init: function init(clientId) {
            init.base.call(this);
            
            // The properties.
            var props = {
                clientId: { value: clientId, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        isEntityRevoked: function isEntityRevoked(identity) {
            return false;
        },
        
        /** @inheritDoc */
        isSchemePermitted: function isSchemePermitted(identity, arg1, arg2) {
            var user, scheme;
            if (arg1 instanceof MslUser) {
                user = arg1;
                scheme = arg2;
            } else {
                user = null;
                scheme = arg1;
            }
            
            // Form 2: entity + user => user auth scheme
            if (user) {
                return true;
            }
            
            // Form 1: entity => entity auth scheme
            if (scheme instanceof EntityAuthenticationScheme) {
                if (scheme == EntityAuthenticationScheme.NONE)
                    return (identity == this.clientId);
                return true;
            }

            // Form 1: entity => user auth scheme
            if (scheme instanceof UserAuthenticationScheme) {
                return true;
            }

            // Form 1: entity => key exchange scheme
            if (scheme instanceof KeyExchangeScheme) {
                return true;
            }
        },
    });

    /**
     * <p>The example client MSL context.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var SimpleMslContext = module.exports =  MslContext.extend({
        /**
         * <p>Create a new client MSL context.</p>
         *
         * @param {string} local client entity identity.
         * @param {RsaStore} remove server entity RSA store.
         * @param {SimpleKeyxManager} keyxMgr key exchange manager.
         * @param {function(string|Error)} errorCallback key manager generation
         *        error callback.
         */
        init: function init(clientId, rsaStore, keyxMgr, errorCallback) {
            // Message capabilities.
            var compressionAlgos = [ MslConstants.CompressionAlgorithm.LZW ];
            var languages = [ "US_en" ];
            var encoderFormats = [ MslEncoderFormat.JSON ];
            var msgCaps = new MessageCapabilities(compressionAlgos, languages, encoderFormats);

            // Entity authentication data.
            var entityAuthData = new UnauthenticatedAuthenticationData(clientId);
            
            // Entity authentication factories.
            var entityAuthFactories = {};
            entityAuthFactories[EntityAuthenticationScheme.RSA] = new RsaAuthenticationFactory(null, rsaStore);
            var authutils = new LocalAuthenticationUtils(clientId);
            entityAuthFactories[EntityAuthenticationScheme.NONE] = new UnauthenticatedAuthenticationFactory(authutils);

            // Key exchange factories.
            var keyxFactories = {};
            keyxFactories[KeyExchangeScheme.ASYMMETRIC_WRAPPED] = new AsymmetricWrappedExchange();

            // MSL store.
            var store = new SimpleKeyxMslStore(keyxMgr, errorCallback);
            
            // MSL encoder factory.
            var encoder = new DefaultMslEncoderFactory();

            // Set properties.
            var props = {
                _random: { value: new Random(), writable: false, enumerable: false, configurable: false },
                _msgCaps: { value: msgCaps, writable: false, enumerable: false, configurable: false },
                _entityAuthData: { value: entityAuthData, writable: false, enumerable: false, configurable: false },
                _mslCryptoContext: { value: new ClientMslCryptoContext(), writable: false, enumerable: false, configurable: false },
                _entityAuthFactories: { value: entityAuthFactories, writable: false, enumerable: false, configurable: false },
                _tokenFactory: { value: new ClientTokenFactory(), writable: false, enumerable: false, configurable: false },
                _keyxFactories: { value: keyxFactories, writable: false, enumerable: false, configurable: false },
                _store: { value: store, writable: false, enumerable: false, configurable: false },
                _encoder: { value: encoder, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getTime: function getTime() {
            return new Date().getTime();
        },

        /** @inheritDoc */
        getRandom: function getRandom() {
            return this._random;
        },

        /** @inheritDoc */
        isPeerToPeer: function isPeerToPeer() {
            return false;
        },

        /** @inheritDoc */
        getMessageCapabilities: function getMessageCapabilities() {
            return this._msgCaps;
        },

        /** @inheritDoc */
        getEntityAuthenticationData: function getEntityAuthenticationData(reauthCode, callback) {
            callback.result(this._entityAuthData);
        },
        
        /** @inheritDoc */
        getMslCryptoContext: function getMslCryptoContext() {
            return this._mslCryptoContext;
        },

        /** @inheritDoc */
        getEntityAuthenticationScheme: function getEntityAuthenticationScheme(name) {
            return EntityAuthenticationScheme.getScheme(name);
        },

        /** @inheritDoc */
        getEntityAuthenticationFactory: function getEntityAuthenticationFactory(scheme) {
            if (this._entityAuthFactories[scheme])
                return this._entityAuthFactories[scheme];
            return null;
        },

        /** @inheritDoc */
        getUserAuthenticationScheme: function getUserAuthenticationScheme(name) {
            return UserAuthenticationScheme.getScheme(name);
        },

        /** @inheritDoc */
        getUserAuthenticationFactory: function getUserAuthenticationFactory(scheme) {
            return null;
        },

        /** @inheritDoc */
        getTokenFactory: function getTokenFactory() {
            return this._tokenFactory;
        },

        /** @inheritDoc */
        getKeyExchangeScheme: function getKeyExchangeScheme(name) {
            return KeyExchangeScheme.getScheme(name);
        },

        /** @inheritDoc */
        getKeyExchangeFactory: function getKeyExchangeFactory(scheme) {
            if (this._keyxFactories[scheme])
                return this._keyxFactories[scheme];
            return null;
        },

        /** @inheritDoc */
        getKeyExchangeFactories: function getKeyExchangeFactories() {
            var factories = [];
            for (var scheme in this._keyxFactories)
                factories.push(this._keyxFactories[scheme]);
            return factories;
        },

        /** @inheritDoc */
        getMslStore: function getMslStore() {
            return this._store;
        },
        
        /** @inheritDoc */
        getMslEncoderFactory: function getMslEncoderFactory() {
            return this._encoder;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleMslContext'));
