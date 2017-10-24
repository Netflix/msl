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
 * <p>Service tokens are service-defined tokens carried as part of any MSL
 * message. These tokens should be used to carry service state.</p>
 *
 * <p>Service tokens are optionally bound to a specific master token and user
 * ID token by their serial numbers.</p>
 *
 * <p>Service tokens are either verified or encrypted. Verified tokens carry
 * their data in the clear but are accompanied by a signature allowing the
 * issuer to ensure the data has not been tampered with. Encrypted tokens
 * encrypt their data as well as contain a signature.</p>
 *
 * <p>Service tokens should use application- or service-specific crypto
 * contexts and not the crypto context associated with the entity credentials
 * or master token.</p>
 *
 * <p>Service tokens are represented as
 * {@code
 * servicetoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the service token data (servicetokendata)</li>
 * <li>{@code signature} is the verification data of the service token data</li>
 * </ul></p>
 *
 * <p>The token data is represented as
 * {@code
 * servicetokendata = {
 *   "#mandatory" : [ "name", "mtserialnumber", "uitserialnumber", "encrypted", "servicedata" ],
 *   "name" : "string",
 *   "mtserialnumber" : "int64(0,-)",
 *   "uitserialnumber" : "int64(0,-)",
 *   "encrypted" : "boolean",
 *   "compressionalgo" : "enum(GZIP|LZW)",
 *   "servicedata" : "binary"
 * }} where:
 * <ul>
 * <li>{@code name} is the token name</li>
 * <li>{@code mtserialnumber} is the master token serial number or -1 if unbound</li>
 * <li>{@code utserialnumber} is the user ID token serial number or -1 if unbound</li>
 * <li>{@code encrypted} indicates if the service data is encrypted or not</li>
 * <li>{@code compressionalgo} indicates the algorithm used to compress the data</li>
 * <li>{@code servicedata} is the optionally encrypted service data</li>
 * </ul></p>
 *
 * <p>Service token names should follow a reverse fully-qualified domain
 * hierarchy. e.g. {@literal com.netflix.service.tokenname}.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var MslEncodingException = require('../MslEncodingException.js');
	var MslError = require('../MslError.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodable = require('../io/MslEncodable.js');
	var MslInternalException = require('../MslInternalException.js');
	var MasterToken = require('../tokens/MasterToken.js');
	var UserIdToken = require('../tokens/UserIdToken.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslException = require('../MslException.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var ICryptoContext = require('../crypto/ICryptoContext.js');
	var MslConstants = require('../MslConstants.js');
	var Base64 = require('../util/Base64.js');
	var MslCompression = require('../util/MslCompression.js');
	
    /**
     * Key token data.
     * @const
     * @type {string}
     */
    var KEY_TOKENDATA = "tokendata";
    /**
     * Key signature
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";

    // tokendata
    /**
     * Key token name
     * @const
     * @type {string}
     */
    var KEY_NAME = "name";
    /**
     * Key master token serial number
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /**
     * Key user ID token serial number
     * @const
     * @type {string}
     */
    var KEY_USER_ID_TOKEN_SERIAL_NUMBER = "uitserialnumber";
    /**
     * Key encrypted
     * @const
     * @type {string}
     */
    var KEY_ENCRYPTED = "encrypted";
    /**
     * Key compression algorithm.
     * @const
     * @type {string}
     */
    var KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /**
     * Key service data
     * @const
     * @type {string}
     */
    var KEY_SERVICEDATA = "servicedata";

    /**
     * <p>Select the appropriate crypto context for the service token
     * represented by the provided MSL object.</p>
     * 
     * <p>If the service token name exists as a key in the map of crypto
     * contexts, the mapped crypto context will be returned. Otherwise the
     * default crypto context mapped from the empty string key will be
     * returned. If no explicit or default crypto context exists null will be
     * returned.</p>
     *
     * @param {MslEncoderFactory} encoder the MSL encoder factory.
     * @param {MslObject} serviceTokenMo the MSL object.
     * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @return {ICryptoContext} the correct crypto context for the service token or null.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslException if the token data is invalid.
     */
    function selectCryptoContext(encoder, serviceTokenMo, cryptoContexts) {
        try {
            var tokendata = serviceTokenMo.getBytes(KEY_TOKENDATA);
            if (tokendata.length == 0)
                throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_MISSING, "servicetoken " + serviceTokenMo);
            var tokenDataMo = encoder.parseObject(tokendata);
            var name = tokenDataMo.getString(KEY_NAME);
            if (cryptoContexts[name])
                return cryptoContexts[name];
            return cryptoContexts[''];
        } catch (e) {
            if (e instanceof MslEncoderException)
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "servicetoken " + serviceTokenMo, e);
            throw e;
        }
    }

    /**
     * Create a new token data container object.
     *
     * @param {Uint8Array} tokendataBytes raw tokendata.
     * @param {Uint8Array} signatureBytes raw signature.
     * @param {boolean} verified true if verified.
     * @constructor
     */
    function CreationData(tokendataBytes, signatureBytes, verified) {
        this.tokendataBytes = tokendataBytes;
        this.signatureBytes = signatureBytes;
        this.verified = verified;
    }

    var ServiceToken = module.exports = MslEncodable.extend({
        /**
         * <p>Construct a new service token with the specified name and data. If a
         * master token is provided, the service token is bound to the master
         * token's serial number. If a user ID token is provided, the service token
         * is bound to the user ID token's serial number.</p>
         *
         * <p>For encrypted tokens, the token data is encrypted using the provided
         * crypto context. For verified tokens, the token data is signed using the
         * provided crypto context.</p>
         *
         * @param {MslContext} ctx the MSL context.
         * @param {string} name the service token name--must be unique.
         * @param {Uint8Array} data the service token data (unencrypted).
         * @param {MasterToken} masterToken the master token. May be null.
         * @param {UserIdToken} userIdToken the user ID token. May be null.
         * @param {boolean} encrypted true if the token should be encrypted.
         * @param {MslConstants.CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {ICryptoContext} cryptoContext the crypto context.
         * @param {?CreationData} creationData optional creation data.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         */
        init: function init(ctx, name, data, masterToken, userIdToken, encrypted, compressionAlgo, cryptoContext, creationData) {
            // If both master token and user ID token are provided the user ID
            // token must be bound to the master token.
            if (masterToken && userIdToken && !userIdToken.isBoundTo(masterToken))
                throw new MslInternalException("Cannot construct a service token bound to a master token and user ID token where the user ID token is not bound to the same master token.");
           
            // Grab the master token and user ID token serial numbers.
            var mtSerialNumber = (masterToken) ? masterToken.serialNumber : -1;
            var uitSerialNumber = (userIdToken) ? userIdToken.serialNumber : -1;
            
            // Construct the token data.
            var compressedServicedata, tokendataBytes, signatureBytes, verified;
            if (!creationData) {
                // The crypto context may not be null.
                if (!cryptoContext)
                    throw new TypeError("Crypto context may not be null.");
                
                // Optionally compress the service data.
                var plaintext;
                if (compressionAlgo) {
                    var compressed = MslCompression.compress(compressionAlgo, data);

                    // Only use compression if the compressed data is smaller than the
                    // uncompressed data.
                    if (compressed && compressed.length < data.length) {
                        compressedServicedata = compressed;
                    } else {
                        compressionAlgo = null;
                        compressedServicedata = data;
                    }
                } else {
                    compressionAlgo = null;
                    compressedServicedata = data;
                }
                
                tokendataBytes = null;
                signatureBytes = null;
                verified = true;
            } else {
                tokendataBytes = creationData.tokendataBytes;
                signatureBytes = creationData.signatureBytes;
                verified = creationData.verified;
            }
            
            // The properties.
            var props = {
                /**
                 * MSL context.
                 * @type {MslContext}
                 */
                ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                /**
                 * Service token crypto context.
                 * @type {ICryptoContext}
                 */
                cryptoContext: { value: cryptoContext, writable: false, enumerable: false, configurable: false },
                /**
                 * The service token name.
                 * @type {string}
                 */
                name: { value: name, writable: false, configurable: false },
                /**
                 * The service token master token serial number.
                 * @type {number}
                 */
                mtSerialNumber: { value: mtSerialNumber, writable: false, configurable: false },
                /**
                 * The service token user ID token serial number.
                 * @type {number}
                 */
                uitSerialNumber: { value: uitSerialNumber, writable: false, configurable: false },
                /**
                 * Service token data is encrypted.
                 * @type {boolean}
                 */
                encrypted: { value: encrypted, writable: false, enumerable: false, configurable: false },
                /**
                 * Compression algorithm.
                 * @type {MslConstants.CompressionAlgorithm}
                 */
                compressionAlgo: { value: compressionAlgo, writable: false, configurable: false },
                /**
                 * The service token data.
                 * @type {Uint8Array}
                 */
                servicedata: { value: data, writable: false, enumerable: false, configurable: false },
                /**
                 * The compressed service token data.
                 * @type {Uint8Array}
                 */
                compressedServicedata: { value: compressedServicedata, writable: false, enumerable: false, configurable: false },
                /**
                 * Token data bytes.
                 * @type {Uint8Array}
                 */
                tokendataBytes: { value: tokendataBytes, writable: false, enumerable: false, configurable: false },
                /**
                 * Signature bytes.
                 * @type {Uint8Array}
                 */
                signatureBytes: { value: signatureBytes, writable: false, enumerable: false, configurable: false },
                /**
                 * Token is verified.
                 * @type {boolean}
                 */
                verified: { value: verified, writable: false, enumerable: false, configurable: false },
                /**
                 * Cached encodings.
                 * @type {Object<MslEncoderFormat,Uint8Array>}
                 */
                encodings: { value: {}, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {boolean} true if the content is encrypted.
         */
        isEncrypted: function isEncrypted() {
            return this.encrypted;
        },

        /**
         * @return {boolean} true if the decrypted content is available. (Implies verified.)
         */
        isDecrypted: function isDecrypted() {
            return (this.servicedata) ? true : false;
        },

        /**
         * @return {boolean} true if the token has been verified.
         */
        isVerified: function isVerified() {
            return this.verified;
        },

        /**
         * @return {boolean} true if this token has been marked for deletion.
         * @see #getData()
         */
        isDeleted: function isDeleted() {
            return this.servicedata && this.servicedata.length == 0;
        },

        /**
         * Returns the service data if the token data was not encrypted or we were
         * able to decrypt it.
         * 
         * Zero-length data indicates this token should be deleted.
         * 
         * @return {?Uint8Array} the service data or null if we don't have it.
         * @see #isDeleted()
         */
        get data() {
            return this.servicedata;
        },

        /**
         * Returns the serial number of the master token this service token is
         * bound to.
         * 
         * @return {number} the master token serial number or -1 if unbound.
         */
        get masterTokenSerialNumber() {
            return this.mtSerialNumber;
        },
        
        /**
         * @return {boolean} true if this token is bound to a master token.
         */
        isMasterTokenBound: function isMasterTokenBound() {
            return this.mtSerialNumber != -1;
        },

        /**
         * @param {MasterToken|UserIdToken} token master token or user ID token. May be null.
         * @return {boolean} true if this token is bound to the provided master token.
         */
        isBoundTo: function isBoundTo(token) {
            if (!token) return false;
            if (token instanceof MasterToken)
                return token.serialNumber == this.mtSerialNumber;
            if (token instanceof UserIdToken)
                return token.serialNumber == this.uitSerialNumber;
            return false;
        },

        /**
         * Returns the serial number of the user ID token this service token is
         * bound to.
         * 
         * @return {number} the user ID token serial number or -1 if unbound.
         */
        get userIdTokenSerialNumber() {
            return this.uitSerialNumber;
        },
        
        /**
         * Returns true if this token is bound to a user ID token. This implies the
         * token is bound to a master token as well.
         *
         * @return {boolean} true if this token is bound to a user ID token.
         */
        isUserIdTokenBound: function isUserIdTokenBound() {
            return this.uitSerialNumber != -1;
        },

        /**
         * @return {boolean} true if this token is not bound to a master token or user ID
         *         token.
         */
        isUnbound: function isUnbound() {
            return this.mtSerialNumber == -1 && this.uitSerialNumber == -1;
        },

        /** @inheritDoc */
        toMslEncoding: function toMslEncoding(encoder, format, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Return any cached encoding.
                if (this.encodings[format])
                    return this.encodings[format];
                
                // If we parsed this token (i.e. did not create it from scratch) then
                // we should not re-encrypt or re-sign as there is no guarantee out MSL
                // crypto context is capable of encrypting and signing with the same
                // keys, even if it is capable of decrypting and verifying.
                if (this.tokendataBytes != null || this.signatureBytes != null) {
                    encodeToken(this.tokendataBytes, this.signatureBytes);
                }
                //
                // Otherwise create the token data and signature.
                else {
                    // Encrypt the service data if the length is > 0. Otherwise encode
                    // as empty data to indicate this token should be deleted.
                    if (this.encrypted && this.compressedServicedata.length > 0) {
                        this.cryptoContext.encrypt(this.compressedServicedata, encoder, format, {
                            result: constructToken,
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslCryptoException)
                                        throw new MslEncoderException("Error encrypting the service data.", e);
                                    throw e;
                                }, self);
                            },
                        });
                    } else {
                        constructToken(this.compressedServicedata);
                    }
                }
            }, self);
            
            function constructToken(ciphertext) {
                AsyncExecutor(callback, function() {
                    // Construct the token data.
                    var tokendata = encoder.createObject();
                    tokendata.put(KEY_NAME, this.name);
                    if (this.mtSerialNumber != -1) tokendata.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, this.mtSerialNumber);
                    if (this.uitSerialNumber != -1) tokendata.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, this.uitSerialNumber);
                    tokendata.put(KEY_ENCRYPTED, this.encrypted);
                    if (this.compressionAlgo) tokendata.put(KEY_COMPRESSION_ALGORITHM, this.compressionAlgo);
                    tokendata.put(KEY_SERVICEDATA, ciphertext);

                    // Sign the token data.
                    encoder.encodeObject(tokendata, format, {
                    	result: function(data) {
                    		AsyncExecutor(callback, function() {
			                    this.cryptoContext.sign(data, encoder, format, {
			                        result: function(signature) {
			                            encodeToken(data, signature);
			                        },
			                        error: function(e) {
			                            AsyncExecutor(callback, function() {
			                                if (e instanceof MslCryptoException)
			                                    throw new MslEncoderException("Error signing the token data.", e);
			                                throw e;
			                            }, self);
			                        }
			                    });
                    		}, self);
                    	},
                    	error: callback.error,
                    });
                }, self);
            }
            
            function encodeToken(data, signature) {
                AsyncExecutor(callback, function() {
                    // Encode the token.
                    var token = encoder.createObject();
                    token.put(KEY_TOKENDATA, data);
                    token.put(KEY_SIGNATURE, signature);
                    encoder.encodeObject(token, format, {
                    	result: function(encoding) {
                    		AsyncExecutor(callback, function() {
                                // Cache and return the encoding.
                                this.encodings[format] = encoding;
                                return encoding;
                    		}, self);
                    	},
                    	error: callback.error,
                    });
                }, self);
            }
        },
        
        /** @inheritDoc */
        toString: function toString() {
            var encoder = this.ctx.getMslEncoderFactory();
            
            var tokendata = encoder.createObject();
            tokendata.put(KEY_NAME, this.name);
            tokendata.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, this.mtSerialNumber);
            tokendata.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, this.uitSerialNumber);
            tokendata.put(KEY_SERVICEDATA, "(redacted)");

            var token = encoder.createObject();
            token.put(KEY_TOKENDATA, tokendata);
            token.put(KEY_SIGNATURE, (this.signatureBytes) ? this.signatureBytes : "(null)");
            return token.toString();
        },

        /**
         * <p>Returns true if the other object is a service token with the same
         * name and bound to the same tokens.</p>
         * 
         * <p>This function is designed for use with sets and maps to guarantee
         * uniqueness of individual service tokens.</p>
         * 
         * @param {?} that the reference object with which to compare.
         * @return {boolean} true if the other object is a service token with the same name
         *         and bound to the same tokens.
         * @see #uniqueKey
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof ServiceToken)) return false;
            return this.name == that.name &&
                this.mtSerialNumber == that.mtSerialNumber &&
                this.uitSerialNumber == that.uitSerialNumber;
        },

        /**
         * @return {string} a string that uniquely identifies this master token.
         * @see #equals(that)
         */
        uniqueKey: function uniqueKey() {
            return this.name + ':' + this.mtSerialNumber + ':' + this.uitSerialNumber;
        },
    });

    /**
     * <p>Construct a new service token with the specified name and data. If a
     * master token is provided, the service token is bound to the master
     * token's serial number. If a user ID token is provided, the service token
     * is bound to the user ID token's serial number.</p>
     *
     * <p>For encrypted tokens, the token data is encrypted using the provided
     * crypto context. For verified tokens, the token data is signed using the
     * provided crypto context.</p>
     *
     * @param {MslContext} ctx the MSL context.
     * @param {string} name the service token name--must be unique.
     * @param {Uint8Array} data the service token data (unencrypted).
     * @param {MasterToken} masterToken the master token. May be null.
     * @param {UserIdToken} userIdToken the user ID token. May be null.
     * @param {boolean} encrypted true if the token should be encrypted.
     * @param {MslConstants.CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @param {ICryptoContext} cryptoContext the crypto context.
     * @param {{result: function(ServiceToken), error: function(Error)}}
     *        callback the callback functions that will receive the service
     *        token or any thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if there is an error compressing the data.
     */
    var ServiceToken$create = function ServiceToken$create(ctx, name, data, masterToken, userIdToken, encrypted, compressionAlgo, cryptoContext, callback) {
        AsyncExecutor(callback, function() {
            return new ServiceToken(ctx, name, data, masterToken, userIdToken, encrypted, compressionAlgo, cryptoContext, null);
        });
    };

    /**
     * <p>Construct a new service token from the provided JSON object.</p>
     *
     * <p>If a single crypto context is provided, the token data will be
     * decrypted and its signature verified using that crypto context.</p>
     *
     * <p>If a map of crypto contexts is provided then attempt to decrypt and
     * verified the signature of the service token using the appropriate crypto
     * context. If the service token name exists as a key in the map of crypto
     * contexts, the mapped crypto context will be used. Otherwise the default
     * crypto context mapped from the empty string key will be used.</p>
     *
     * <p>If the data cannot be decrypted or the signature cannot be verified,
     * the token will still be created.</p>
     *
     * <p>If the service token is bound to a master token or user ID token it
     * will be verified against the provided master token or user ID tokens
     * which must not be null.</p>
     *
     * @param {MslContext} ctx the MSL context.
     * @param {MslObject} serviceTokenMo the MSL object.
     * @param {MasterToken} masterToken the master token. May be null.
     * @param {UserIdToken} userIdToken the user ID token. May be null.
     * @param {ICryptoContext|Object.<string,ICryptoContext>} cryptoContext the
     *        crypto context. May be null. Or a map of service token names onto
     *        crypto contexts.
     * @param {{result: function(ServiceToken), error: function(Error)}}
     *        callback the callback functions that will receive the service
     *        token or any thrown exceptions.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the token data.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslException if the service token is bound to a master token or
     *         user ID token and the provided tokens are null or the serial
     *         numbers do not match, or if bound to a user ID token but not to
     *         a master token, or if the service data is missing, or if the
     *         service token master token serial number is out of range, or if
     *         the service token user ID token serial number is out of range,
     *         or if the token data or signature is invalid, or if the
     *         compression algorithm is not known or there is an error
     *         uncompressing the data.
     */
    var ServiceToken$parse = function ServiceToken$parse(ctx, serviceTokenMo, masterToken, userIdToken, cryptoContext, callback) {
        AsyncExecutor(callback, function() {
            var encoder = ctx.getMslEncoderFactory();
            
            // Grab the crypto context.
            if (cryptoContext && !(cryptoContext instanceof ICryptoContext))
                cryptoContext = selectCryptoContext(encoder, serviceTokenMo, cryptoContext);

            // Verify the data representation.
            var tokendataBytes, signatureBytes;
            try {
                tokendataBytes = serviceTokenMo.getBytes(KEY_TOKENDATA);
                if (tokendataBytes.length == 0)
                    throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_MISSING, "servicetoken " + serviceTokenMo).setMasterToken(masterToken).setUserIdToken(userIdToken);
                signatureBytes = serviceTokenMo.getBytes(KEY_SIGNATURE);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "servicetoken " + serviceTokenMo, e).setMasterToken(masterToken).setUserIdToken(userIdToken);
                throw e;
            }
            if (cryptoContext) {
                cryptoContext.verify(tokendataBytes, signatureBytes, encoder, {
                    result: function(verified) {
                        parseToken(encoder, tokendataBytes, signatureBytes, verified);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            if (e instanceof MslCryptoException)
                                e.setMasterToken(masterToken);
                            throw e;
                        });
                    }
                });
            } else {
                parseToken(encoder, tokendataBytes, signatureBytes, false);
            }
        });
        
        function parseToken(encoder, tokendataBytes, signatureBytes, verified) {
            AsyncExecutor(callback, function() {
                var name, mtSerialNumber, uitSerialNumber, encrypted, compressionAlgo, data;
                try {
                	// Pull the token data.
                    var tokendata = encoder.parseObject(tokendataBytes);
                    name = tokendata.getString(KEY_NAME);
                    if (tokendata.has(KEY_MASTER_TOKEN_SERIAL_NUMBER)) {
                        mtSerialNumber = tokendata.getLong(KEY_MASTER_TOKEN_SERIAL_NUMBER);
                        if (mtSerialNumber < 0 || mtSerialNumber > MslConstants.MAX_LONG_VALUE)
                            throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "servicetokendata " + tokendata).setMasterToken(masterToken).setUserIdToken(userIdToken);
                    } else {
                        mtSerialNumber = -1;
                    }
                    if (tokendata.has(KEY_USER_ID_TOKEN_SERIAL_NUMBER)) {
                        uitSerialNumber = tokendata.getLong(KEY_USER_ID_TOKEN_SERIAL_NUMBER);
                        if (uitSerialNumber < 0 || uitSerialNumber > MslConstants.MAX_LONG_VALUE)
                            throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "servicetokendata " + tokendata).setMasterToken(masterToken).setUserIdToken(userIdToken);
                    } else {
                        uitSerialNumber = -1;
                    }
                    // There has to be a master token serial number if there is a
                    // user ID token serial number.
                    
                    encrypted = tokendata.getBoolean(KEY_ENCRYPTED);
                    if (tokendata.has(KEY_COMPRESSION_ALGORITHM)) {
                        var algoName = tokendata.getString(KEY_COMPRESSION_ALGORITHM);
                        if (!MslConstants.CompressionAlgorithm[algoName])
                            throw new MslException(MslError.UNIDENTIFIED_COMPRESSION, algoName);
                        compressionAlgo = MslConstants.CompressionAlgorithm[algoName];
                    } else {
                        compressionAlgo = null;
                    }
                    
                    data = tokendata.getBytes(KEY_SERVICEDATA);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "servicetokendata " + Base64.encode(tokendataBytes), e).setMasterToken(masterToken).setUserIdToken(userIdToken);
                    throw e;
                }
                
                // If encrypted, and we were able to verify the data then we better
                // be able to decrypt it. (An exception is thrown if decryption
                // fails.)
                var servicedata, compressedServicedata;
                if (verified) {
                    var ciphertext = data;
                    if (encrypted && ciphertext.length > 0) {
                        cryptoContext.decrypt(ciphertext, encoder, {
                            result: function(compressedServicedata) {
                                servicedata = (compressionAlgo)
                                    ? MslCompression.uncompress(compressionAlgo, compressedServicedata)
                                    : compressedServicedata;
                                reconstruct(encoder, tokendataBytes, signatureBytes, verified,
                                    name, mtSerialNumber, uitSerialNumber, encrypted, compressionAlgo,
                                    compressedServicedata, servicedata);
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslCryptoException) {
                                        e.setMasterToken(masterToken);
                                        e.setUserIdToken(userIdToken);
                                    }
                                    throw e;
                                });
                            },
                        });
                    } else {
                        compressedServicedata = ciphertext;
                        servicedata = (compressionAlgo)
                            ? MslCompression.uncompress(compressionAlgo, compressedServicedata)
                            : compressedServicedata;
                        reconstruct(encoder, tokendataBytes, signatureBytes, verified,
                            name, mtSerialNumber, uitSerialNumber, encrypted, compressionAlgo,
                            compressedServicedata, servicedata);
                    }
                } else {
                    compressedServicedata = data;
                    servicedata = (data.length == 0) ? new Uint8Array(0) : null;
                    reconstruct(encoder, tokendataBytes, signatureBytes, verified,
                        name, mtSerialNumber, uitSerialNumber, encrypted, compressionAlgo,
                        compressedServicedata, servicedata);
                }
            });
        }
            
        function reconstruct(encoder, tokendataBytes, signatureBytes, verified,
                name, mtSerialNumber, uitSerialNumber, encrypted, compressionAlgo,
                compressedServicedata, servicedata)
        {
            AsyncExecutor(callback, function() {
                // Verify serial numbers.
                if (mtSerialNumber != -1 && (!masterToken || mtSerialNumber != masterToken.serialNumber))
                    throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH, "st mtserialnumber " + mtSerialNumber + "; mt " + masterToken).setMasterToken(masterToken).setUserIdToken(userIdToken);
                if (uitSerialNumber != -1 && (!userIdToken || uitSerialNumber != userIdToken.serialNumber))
                    throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH, "st uitserialnumber " + uitSerialNumber + "; uit " + userIdToken).setMasterToken(masterToken).setUserIdToken(userIdToken);
                
                // Return the new service token.
                var creationData = new CreationData(tokendataBytes, signatureBytes, verified);
                return new ServiceToken(ctx, name, servicedata, (mtSerialNumber != -1) ? masterToken : null, (uitSerialNumber != -1) ? userIdToken : null, encrypted, compressionAlgo, cryptoContext, creationData);
            });
        }
    };
    
    // Exports.
    module.exports.create = ServiceToken$create;
    module.exports.parse = ServiceToken$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('ServiceToken'));
