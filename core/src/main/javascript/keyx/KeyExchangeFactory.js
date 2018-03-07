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
 * A key exchange factory creates key request and response data instances for
 * a specific key exchange scheme.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var SecretKey = require('../crypto/SecretKey.js');
	var WebCryptoAlgorithm = require('../crypto/WebCryptoAlgorithm.js');
	var WebCryptoUsage = require('../crypto/WebCryptoUsage.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var MslError = require('../MslError.js');
	
    /**
     * The key exchange data struct contains key response data and a crypto
     * context for the exchanged keys.
     */
    var KeyExchangeData = Class.create({
        /**
         * Create a new key key exhange data struct with the provided key
         * response data, master token, and crypto context.
         *
         * @param {KeyResponseData} keyResponseData the key response data.
         * @param {ICryptoContext} cryptoContext the crypto context.
         */
        init: function init(keyResponseData, cryptoContext) {
            // The properties.
            var props = {
                keyResponseData: { value: keyResponseData, writable: false, configurable: false },
                cryptoContext: { value: cryptoContext, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    });

    var KeyExchangeFactory = module.exports = Class.create({
        /**
         * Create a new key exchange factory for the specified scheme.
         *
         * @param {KeyExchangeScheme} scheme the key exchange scheme.
         */
        init: function init(scheme) {
            var props = {
                scheme: { value: scheme, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * Construct a new key request data instance from the provided MSL object.
         *
         * @param {MslContext} ctx MSL context.
         * @param {MslObject} keyRequestMo the JSON object.
         * @param {{result: function(KeyRequestData), error: function(Error)}}
         *        callback the callback will receive the key request data or
         *        any thrown exceptions.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslKeyExchangeException if there is an error creating the key
         *         request data.
         * @throws MslCryptoException if the keying material cannot be created.
         */
        createRequestData: function(ctx, keyRequestMo, callback) {},

        /**
         * Construct a new key response data instance from the provided MSL object.
         *
         * @param {MslContext} ctx MSL context.
         * @param {MasterToken} masterToken the master token for the new key response data.
         * @param {MslObject} keyDataMo the MSL object.
         * @param {{result: function(KeyResponseData), error: function(Error)}}
         *        callback the callback will receive the key response data or
         *        any thrown exceptions.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslKeyExchangeException if there is an error creating the key
         *         response data.
         */
        createResponseData: function(ctx, masterToken, keyDataMo, callback) {},

        /**
         * <p>Generate a new key response data instance and crypto context in
         * response to the provided key request data. The key request data will be
         * from the the remote entity.</p>
         * 
         * <p>If a master token is provided then it should be renewed by
         * incrementing its sequence number but maintaining its serial number
         * by using the MSL context's token factory.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {MslEncoderFormat} format MSL encoder format.
         * @param {KeyRequestData} keyRequestData the key request data.
         * @param {MasterToken|EntityAuthenticationData} entityToken the master token to renew or
         *        the entity authentication data.
         * @param {{result: function(KeyExchangeData), error: function(Error)}}
         *        callback the callback functions that will receive the key
         *        response data and crypto context, or {@code null} if the
         *        factory chooses not to perform key exchange, or any thrown
         *        exception.
         * @throws MslKeyExchangeException if there is an error with the key
         *         request data or the key response data cannot be created.
         * @throws MslCryptoException if the crypto context cannot be created.
         * @throws MslEncodingException if there is an error parsing or encoding
         *         the JSON.
         * @throws MslMasterTokenException if the master token is not trusted and
         *         needs to be.
         * @throws MslEntityAuthException if there is a problem with the master
         *         token identity.
         */
        generateResponse: function(ctx, format, keyRequestData, entityToken, callback) {},

        /**
         * Create a crypto context from the provided key request data and key
         * response data. The key request data will be from the local entity and
         * the key response data from the remote entity.
         *
         * @param {MslContext} ctx MSL context.
         * @param {KeyRequestData} keyRequestData the key request data.
         * @param {KeyResponseData} keyResponseData the key response data.
         * @param {MasterToken} masterToken the current master token (not the one inside the key
         *        response data). May be null.
         * @param {{result: function(ICryptoContext), error: function(Error)}}
         *        callback the callback functions that will receive the crypto
         *        context or any thrown exception.
         * @throws MslKeyExchangeException if there is an error with the key
         *         request data or key response data.
         * @throws MslCryptoException if the crypto context cannot be created.
         * @throws MslEncodingException if there is an error parsing the JSON.
         * @throws MslMasterTokenException if the master token is not trusted and
         *         needs to be.
         * @throws MslEntityAuthException if there is a problem with the master
         *         token identity.
         */
        getCryptoContext: function(ctx, keyRequestData, keyResponseData, masterToken, callback) {},

        /**
         * Generate a new pair of AES-128 CBC and HMAC-SHA256 encryption and HMAC
         * session keys.
         *
         * @param {MslContext} ctx MSL context.
         * @param {{result: function({encryptionKey: SecretKey, hmacKey: SecretKey}), error: function(Error)}}
         *        callback the callback will receive the new session keys
         *        (encryption key, HMAC key) or any thrown exceptions.
         * @throws MslCryptoException if there is an error creating the session
         *         keys.
         */
        generateSessionKeys: function generateSessionKeys(ctx, callback) {
            AsyncExecutor(callback, function() {
                var encryptionBytes = new Uint8Array(16);
                var hmacBytes = new Uint8Array(32);
                ctx.getRandom().nextBytes(encryptionBytes);
                ctx.getRandom().nextBytes(hmacBytes);
                SecretKey.import(encryptionBytes, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                    result: function(encryptionKey) {
                        SecretKey.import(hmacBytes, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                            result: function(hmacKey) {
                                callback.result({encryptionKey: encryptionKey, hmacKey: hmacKey});
                            },
                            error: function(e) {
                                callback.error(new MslCryptoException(MslError.SESSION_KEY_CREATION_FAILURE, null, e));
                            }
                        });
                    },
                    error: function(e) {
                        callback.error(new MslCryptoException(MslError.SESSION_KEY_CREATION_FAILURE, null, e));
                    }
                });
            });
        },

        /**
         * Import a new pair of AES-128 CBC and HMAC-SHA256 encryption and HMAC
         * session keys.
         *
         * @param {Uint8Array} encryptionBytes AES-128 raw key data.
         * @param {Uint8Array} hmacBytes HMAC-SHA256 raw key data.
         * @param {{result: function({encryptionKey: SecretKey, hmacKey: SecretKey}), error: function(Error)}}
         *        callback the callback that will receive the imported session
         *        keys or any thrown exceptions.
         * @throws MslCryptoException if the key data is invalid.
         */
        importSessionKeys: function importSessionKeys(encryptionBytes, hmacBytes, callback) {
            SecretKey.import(encryptionBytes, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                result: function(encryptionKey) {
                    SecretKey.import(hmacBytes, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                        result: function(hmacKey) {
                            callback.result({ encryptionKey: encryptionKey, hmacKey: hmacKey });
                        },
                        error: callback.error,
                    });
                },
                error: callback.error,
            });
        },
    });

    // Expose KeyExchangeData.
    module.exports.KeyExchangeData = KeyExchangeData;
})(require, (typeof module !== 'undefined') ? module : mkmodule('KeyExchangeFactory'));
