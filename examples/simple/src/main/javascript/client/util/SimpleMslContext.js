/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
var SimpleMslContext;

(function() {
    "use strict";

    /**
     * <p>The example client MSL context.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    SimpleMslContext = MslContext.extend({
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
            var compressionAlgos = [ MslConstants$CompressionAlgorithm.LZW ];
            var languages = [ "US_en" ];
            var msgCaps = new MessageCapabilities(compressionAlgos, languages);

            // Entity authentication data.
            var entityAuthData = new UnauthenticatedAuthenticationData(clientId);

            // Entity authentication factories.
            var entityAuthFactories = {};
            entityAuthFactories[EntityAuthenticationScheme.RSA] = new RsaAuthenticationFactory(null, rsaStore);
            entityAuthFactories[EntityAuthenticationScheme.NONE] = new UnauthenticatedAuthenticationFactory();

            // Key exchange factories.
            var keyxFactories = {};
            keyxFactories[KeyExchangeScheme.ASYMMETRIC_WRAPPED] = new AsymmetricWrappedExchange();

            // MSL store.
            var store = new SimpleKeyxMslStore(keyxMgr, errorCallback);

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
        setEntityIdentity: function setEntityIdentity() {
        },

        /** @inheritDoc */
        getMslCryptoContext: function getMslCryptoContext() {
            return this._mslCryptoContext;
        },

        /** @inheritDoc */
        getEntityAuthenticationScheme: function getEntityAuthenticationScheme(name) {
            return EntityAuthenticationScheme$getScheme(name);
        },

        /** @inheritDoc */
        getEntityAuthenticationFactory: function getEntityAuthenticationFactory(scheme) {
            if (this._entityAuthFactories[scheme])
                return this._entityAuthFactories[scheme];
            return null;
        },

        /** @inheritDoc */
        getUserAuthenticationScheme: function getUserAuthenticationScheme(name) {
            return UserAuthenticationScheme$getScheme(name);
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
            return KeyExchangeScheme$getScheme(name);
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
    });
})();
