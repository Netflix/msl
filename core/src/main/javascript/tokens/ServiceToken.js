/**
 * Copyright (c) 2012-2015 Netflix, Inc.  All rights reserved.
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
 *   "tokendata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the Base64-encoded service token data (servicetokendata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the service token data</li>
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
 *   "servicedata" : "base64"
 * }} where:
 * <ul>
 * <li>{@code name} is the token name</li>
 * <li>{@code mtserialnumber} is the master token serial number or -1 if unbound</li>
 * <li>{@code utserialnumber} is the user ID token serial number or -1 if unbound</li>
 * <li>{@code encrypted} indicates if the service data is encrypted or not</li>
 * <li>{@code compressionalgo} indicates the algorithm used to compress the data</li>
 * <li>{@code servicedata} is the Base64-encoded optionally encrypted service data</li>
 * </ul></p>
 *
 * <p>Service token names should follow a reverse fully-qualified domain
 * hierarchy. e.g. {@literal com.netflix.service.tokenname}.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var ServiceToken;
var ServiceToken$create;
var ServiceToken$parse;

(function() {
    /**
     * JSON key token data.
     * @const
     * @type {string}
     */
    var KEY_TOKENDATA = "tokendata";
    /**
     * JSON key signature
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";

    // tokendata
    /**
     * JSON key token name
     * @const
     * @type {string}
     */
    var KEY_NAME = "name";
    /**
     * JSON key master token serial number
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /**
     * JSON key user ID token serial number
     * @const
     * @type {string}
     */
    var KEY_USER_ID_TOKEN_SERIAL_NUMBER = "uitserialnumber";
    /**
     * JSON key encrypted
     * @const
     * @type {string}
     */
    var KEY_ENCRYPTED = "encrypted";
    /**
     * JSON key compression algorithm.
     * @const
     * @type {string}
     */
    var KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /**
     * JSON key service data
     * @const
     * @type {string}
     */
    var KEY_SERVICEDATA = "servicedata";

    /**
     * <p>Select the appropriate crypto context for the service token
     * represented by the provided JSON object.</p>
     *
     * <p>If the service token name exists as a key in the map of crypto
     * contexts, the mapped crypto context will be returned. Otherwise the
     * default crypto context mapped from the empty string key will be
     * returned. If no explicit or default crypto context exists null will be
     * returned.</p>
     *
     * @param {Object} serviceTokenJO the JSON object.
     * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @return {ICryptoContext} the correct crypto context for the service token or null.
     * @throws MslEncodingException if there is a problem parsing the JSON.
     * @throws MslException if the token data is invalid.
     */
    function selectCryptoContext(serviceTokenJO, cryptoContexts) {
        // Grab the tokendata.
        var tokendataB64 = serviceTokenJO[KEY_TOKENDATA];
        if (typeof tokendataB64 !== 'string')
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "servicetoken " + JSON.stringify(serviceTokenJO));
        var tokendata;
        try {
            tokendata = base64$decode(tokendataB64);
        } catch (e) {
            throw new MslException(MslError.SERVICETOKEN_TOKENDATA_INVALID, "servicetoken " + JSON.stringify(serviceTokenJO), e);
        }
        if (!tokendata || tokendata.length == 0)
            throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_MISSING, "servicetoken " + JSON.stringify(serviceTokenJO));

        // Extract the service token name.
        var name;
        try {
            var tokenDataJO = JSON.parse(textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET));
            name = tokenDataJO[KEY_NAME];
        } catch (e) {
            if (e instanceof SyntaxError)
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "servicetoken " + JSON.stringify(serviceTokenJO), e);
            throw e;
        }
        if (!name)
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "servicetoken " + JSON.stringify(serviceTokenJO));

        // Return the crypto context.
        if (cryptoContexts[name])
            return cryptoContexts[name];
        return cryptoContexts[''];
    };

    /**
     * Create a new token data container object.
     *
     * @param {Uint8Array} tokendata raw tokendata.
     * @param {Uint8Array} signature raw signature.
     * @param {boolean} verified true if verified.
     * @constructor
     */
    function CreationData(tokendata, signature, verified) {
        this.tokendata = tokendata;
        this.signature = signature;
        this.verified = verified;
    };

    ServiceToken = util.Class.create({
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
         * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {ICryptoContext} cryptoContext the crypto context.
         * @param {?CreationData} creationData optional creation data.
         * @param {{result: function(ServiceToken), error: function(Error)}}
         *        callback the callback functions that will receive the service
         *        token or any thrown exceptions.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         */
        init: function init(ctx, name, data, masterToken, userIdToken, encrypted, compressionAlgo, cryptoContext, creationData, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // If both master token and user ID token are provided the user ID
                // token must be bound to the master token.
                if (masterToken && userIdToken && !userIdToken.isBoundTo(masterToken))
                    throw new MslInternalException("Cannot construct a service token bound to a master token and user ID token where the user ID token is not bound to the same master token.");

                // Grab the master token and user ID token serial numbers.
                var mtSerialNumber = (masterToken) ? masterToken.serialNumber : -1;
                var uitSerialNumber = (userIdToken) ? userIdToken.serialNumber : -1;

                // Construct the token data.
                if (!creationData) {
                    // Optionally compress the service data.
                    var plaintext;
                    if (compressionAlgo) {
                        var compressed = MslUtils$compress(compressionAlgo, data);

                        // Only use compression if the compressed data is smaller than the
                        // uncompressed data.
                        if (compressed.length < data.length) {
                            plaintext = compressed;
                        } else {
                            compressionAlgo = null;
                            plaintext = data;
                        }
                    } else {
                        compressionAlgo = null;
                        plaintext = data;
                    }

                    // Start constructing the token data.
                    var tokenDataJO = {};
                    tokenDataJO[KEY_NAME] = name;
                    if (mtSerialNumber != -1)
                        tokenDataJO[KEY_MASTER_TOKEN_SERIAL_NUMBER] = mtSerialNumber;
                    if (uitSerialNumber != -1)
                        tokenDataJO[KEY_USER_ID_TOKEN_SERIAL_NUMBER] = uitSerialNumber;
                    tokenDataJO[KEY_ENCRYPTED] = encrypted;
                    if (compressionAlgo)
                        tokenDataJO[KEY_COMPRESSION_ALGORITHM] = compressionAlgo;

                    // Encrypt the service data if the length is > 0. Otherwise encode
                    // as empty data to indicate this token should be deleted.
                    if (encrypted && plaintext.length > 0) {
                        cryptoContext.encrypt(plaintext, {
                            result: function(ciphertext) {
                                AsyncExecutor(callback, function() {
                                    // Finish constructing the token data.
                                    tokenDataJO[KEY_SERVICEDATA] = base64$encode(ciphertext);
                                    var tokendata = textEncoding$getBytes(JSON.stringify(tokenDataJO), MslConstants$DEFAULT_CHARSET);

                                    // Sign the token data.
                                    cryptoContext.sign(tokendata, {
                                        result: function(signature) {
                                            AsyncExecutor(callback, function() {
                                                var verified = true;

                                                // The properties.
                                                var props = {
                                                    ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                                                    name: { value: name, writable: false, configurable: false },
                                                    mtSerialNumber: { value: mtSerialNumber, writable: false, configurable: false },
                                                    uitSerialNumber: { value: uitSerialNumber, writable: false, configurable: false },
                                                    data: { value: data, writable: false, configurable: false },
                                                    encrypted: { value: encrypted, writable: false, enumerable: false, configurable: false },
                                                    compressionAlgo: { value: compressionAlgo, writable: false, configurable: false },
                                                    verified: { value: verified, writable: false, enumerable: false, configurable: false },
                                                    tokendata: { value: tokendata, writable: false, enumerable: false, configurable: false },
                                                    signature: { value: signature, writable: false, enumerable: false, configurable: false },
                                                };
                                                Object.defineProperties(this, props);
                                                return this;
                                            }, self);
                                        },
                                        error: function(e) {
                                            AsyncExecutor(callback, function() {
                                                if (e instanceof MslException) {
                                                    e.setEntity(masterToken);
                                                    e.setUserIdTokenIdToken(userIdToken);
                                                }
                                                throw e;
                                            });
                                        }
                                    });
                                }, self);
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException) {
                                        e.setEntity(masterToken);
                                        e.setUserIdToken(userIdToken);
                                    }
                                    throw e;
                                });
                            }
                        });
                    } else {
                        var ciphertext = plaintext;

                        // Finish constructing the token data.
                        tokenDataJO[KEY_SERVICEDATA] = base64$encode(ciphertext);
                        var tokendata = textEncoding$getBytes(JSON.stringify(tokenDataJO), MslConstants$DEFAULT_CHARSET);

                        // Sign the token data.
                        cryptoContext.sign(tokendata, {
                            result: function(signature) {
                                AsyncExecutor(callback, function() {
                                    var verified = true;

                                    // The properties.
                                    var props = {
                                        ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                                        name: { value: name, writable: false, configurable: false },
                                        mtSerialNumber: { value: mtSerialNumber, writable: false, configurable: false },
                                        uitSerialNumber: { value: uitSerialNumber, writable: false, configurable: false },
                                        data: { value: data, writable: false, configurable: false },
                                        encrypted: { value: encrypted, writable: false, enumerable: false, configurable: false },
                                        compressionAlgo: { value: compressionAlgo, writable: false, configurable: false },
                                        verified: { value: verified, writable: false, enumerable: false, configurable: false },
                                        tokendata: { value: tokendata, writable: false, enumerable: false, configurable: false },
                                        signature: { value: signature, writable: false, enumerable: false, configurable: false },
                                    };
                                    Object.defineProperties(this, props);
                                    return this;
                                }, self);
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException) {
                                        e.setEntity(masterToken);
                                        e.setUserIdToken(userIdToken);
                                    }
                                    throw e;
                                });
                            }
                        });
                    }
                } else {
                    var tokendata = creationData.tokendata;
                    var signature = creationData.signature;
                    var verified = creationData.verified;

                    // The properties.
                    var props = {
                        ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                        name: { value: name, writable: false, configurable: false },
                        mtSerialNumber: { value: mtSerialNumber, writable: false, configurable: false },
                        uitSerialNumber: { value: uitSerialNumber, writable: false, configurable: false },
                        data: { value: data, writable: false, configurable: false },
                        encrypted: { value: encrypted, writable: false, enumerable: false, configurable: false },
                        compressionAlgo: { value: compressionAlgo, writable: false, configurable: false },
                        verified: { value: verified, writable: false, enumerable: false, configurable: false },
                        tokendata: { value: tokendata, writable: false, enumerable: false, configurable: false },
                        signature: { value: signature, writable: false, enumerable: false, configurable: false },
                    };
                    Object.defineProperties(this, props);
                    return this;
                }
            }, this);
        },

        /**
         * @return {boolean} true if the content is encrypted.
         */
        isEncrypted: function isEncrypted() {
            return this.encrypted;
        },

        /**
         * @return {boolean} true if the token has been verified.
         */
        isVerified: function isVerified() {
            return this.verified;
        },

        /**
         * @return {boolean} true if the decrypted content is available. (Implies verified.)
         */
        isDecrypted: function isDecrypted() {
            return (this.data) ? true : false;
        },

        /**
         * @return {boolean} true if this token has been marked for deletion.
         */
        isDeleted: function isDeleted() {
            return this.data && this.data.length == 0;
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
        toJSON: function toJSON() {
            var jsonObj = {};
            jsonObj[KEY_TOKENDATA] = base64$encode(this.tokendata);
            jsonObj[KEY_SIGNATURE] = base64$encode(this.signature);
            return jsonObj;
        },

        /**
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
     * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
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
    ServiceToken$create = function ServiceToken$create(ctx, name, data, masterToken, userIdToken, encrypted, compressionAlgo, cryptoContext, callback) {
        new ServiceToken(ctx, name, data, masterToken, userIdToken, encrypted, compressionAlgo, cryptoContext, null, callback);
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
     * @param {Object} serviceTokenJO the JSON object.
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
     * @throws MslEncodingException if there is a problem parsing the JSON.
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
    ServiceToken$parse = function ServiceToken$parse(ctx, serviceTokenJO, masterToken, userIdToken, cryptoContext, callback) {
        AsyncExecutor(callback, function() {
            // Grab the crypto context.
            if (cryptoContext && !(cryptoContext instanceof ICryptoContext))
                cryptoContext = selectCryptoContext(serviceTokenJO, cryptoContext);

            // Verify the JSON representation.
            var tokendataB64 = serviceTokenJO[KEY_TOKENDATA];
            var signatureB64 = serviceTokenJO[KEY_SIGNATURE];
            if (typeof tokendataB64 !== 'string' || typeof signatureB64 !== 'string')
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "servicetoken " + JSON.stringify(serviceTokenJO)).setEntity(masterToken).setEntity(userIdToken);
            var tokendata, signature;
            try {
                tokendata = base64$decode(tokendataB64);
            } catch (e) {
                throw new MslException(MslError.SERVICETOKEN_TOKENDATA_INVALID, "servicetoken " + JSON.stringify(serviceTokenJO), e).setEntity(masterToken).setEntity(userIdToken);
            }
            if (!tokendata || tokendata.length == 0)
                throw new MslEncodingException(MslError.SERVICETOKEN_TOKENDATA_MISSING, "servicetoken " + JSON.stringify(serviceTokenJO)).setEntity(masterToken).setEntity(userIdToken);
            try {
                signature = base64$decode(signatureB64);
            } catch (e) {
                throw new MslException(MslError.SERVICETOKEN_SIGNATURE_INVALID, "servicetoken " + JSON.stringify(serviceTokenJO), e).setEntity(masterToken).setEntity(userIdToken);
            }

            // Pull the token data.
            var name, mtSerialNumber, uitSerialNumber, encrypted, algoName, ciphertextB64;
            var tokenDataJson = textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET);
            try {
                var tokenDataJO = JSON.parse(tokenDataJson);
                name = tokenDataJO[KEY_NAME];
                mtSerialNumber = (tokenDataJO[KEY_MASTER_TOKEN_SERIAL_NUMBER])
                    ? parseInt(tokenDataJO[KEY_MASTER_TOKEN_SERIAL_NUMBER])
                    : -1;
                uitSerialNumber = (tokenDataJO[KEY_USER_ID_TOKEN_SERIAL_NUMBER])
                    ? parseInt(tokenDataJO[KEY_USER_ID_TOKEN_SERIAL_NUMBER])
                    : -1;
                // There has to be a master token serial number if there is a
                // user ID token serial number.
                encrypted = tokenDataJO[KEY_ENCRYPTED];
                algoName = tokenDataJO[KEY_COMPRESSION_ALGORITHM];
                ciphertextB64 = tokenDataJO[KEY_SERVICEDATA];
            } catch (e) {
                if (e instanceof SyntaxError)
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "servicetokendata " + tokenDataJson, e).setEntity(masterToken).setEntity(userIdToken);
                throw e;
            }

            // Verify token data.
            if (!name ||
                typeof mtSerialNumber !== 'number' || mtSerialNumber != mtSerialNumber ||
                typeof uitSerialNumber !== 'number' || uitSerialNumber != uitSerialNumber ||
                typeof encrypted !== 'boolean' ||
                (algoName && typeof algoName !== 'string') ||
                typeof ciphertextB64 !== 'string')
            {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "servicetokendata " + tokenDataJson).setEntity(masterToken).setEntity(userIdToken);
            }

            // Verify serial number values.
            if (tokenDataJO[KEY_MASTER_TOKEN_SERIAL_NUMBER] &&
                mtSerialNumber < 0 || mtSerialNumber > MslConstants$MAX_LONG_VALUE)
            {
                throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "servicetokendata " + tokenDataJson).setEntity(masterToken).setEntity(userIdToken);
            }
            if (tokenDataJO[KEY_USER_ID_TOKEN_SERIAL_NUMBER] &&
                uitSerialNumber < 0 || uitSerialNumber > MslConstants$MAX_LONG_VALUE)
            {
                throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "servicetokendata " + tokenDataJson).setEntity(masterToken).setEntity(userIdToken);
            }

            // Verify serial numbers match.
            if (mtSerialNumber != -1 && (!masterToken || mtSerialNumber != masterToken.serialNumber))
                throw new MslException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH, "st mtserialnumber " + mtSerialNumber + "; mt " + masterToken).setEntity(masterToken).setEntity(userIdToken);
            if (uitSerialNumber != -1 && (!userIdToken || uitSerialNumber != userIdToken.serialNumber))
                throw new MslException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH, "st uitserialnumber " + uitSerialNumber + "; uit " + userIdToken).setEntity(masterToken).setEntity(userIdToken);

            // Convert encrypted to the correct type.
            encrypted = (encrypted === true);

            // Verify compression algorithm.
            var compressionAlgo;
            if (algoName) {
                if (!MslConstants$CompressionAlgorithm[algoName])
                    throw new MslException(MslError.UNIDENTIFIED_COMPRESSION, algoName);
                compressionAlgo = algoName;
            } else {
                compressionAlgo = null;
            }

            if (cryptoContext) {
                cryptoContext.verify(tokendata, signature, {
                    result: function(verified) {
                        AsyncExecutor(callback, function() {
                            // If encrypted, and we were able to verify the data then we better
                            // be able to decrypt it. (An exception is thrown if decryption
                            // fails.)
                            if (verified) {
                                var ciphertext;
                                try {
                                    ciphertext = base64$decode(ciphertextB64);
                                } catch (e) {
                                    throw new MslException(MslError.SERVICETOKEN_SERVICEDATA_INVALID, "servicetokendata " + tokenDataJson, e).setEntity(masterToken).setEntity(userIdToken);
                                }
                                if (!ciphertext || (ciphertextB64.length != 0 && ciphertext.length == 0))
                                    throw new MslException(MslError.SERVICETOKEN_SERVICEDATA_INVALID, "servicetokendata " + tokenDataJson).setEntity(masterToken).setEntity(userIdToken);
                                if (encrypted && ciphertext.length > 0) {
                                    cryptoContext.decrypt(ciphertext, {
                                        result: function(compressedData) {
                                            AsyncExecutor(callback, function() {
                                                var servicedata = (compressionAlgo)
                                                    ? MslUtils$uncompress(compressionAlgo, compressedData)
                                                    : compressedData;

                                                // Return the new service token.
                                                var creationData = new CreationData(tokendata, signature, verified);
                                                new ServiceToken(ctx, name, servicedata, (mtSerialNumber != -1) ? masterToken : null, (uitSerialNumber != -1) ? userIdToken : null, encrypted, compressionAlgo, cryptoContext, creationData, callback);
                                            });
                                        },
                                        error: function(e) {
                                            AsyncExecutor(callback, function() {
                                                if (e instanceof MslException) {
                                                    e.setEntity(masterToken);
                                                    e.setUserIdToken(userIdToken);
                                                }
                                                throw e;
                                            });
                                        }
                                    });
                                } else {
                                    var compressedData = ciphertext;
                                    var servicedata = (compressionAlgo)
                                        ? MslUtils$uncompress(compressionAlgo, compressedData)
                                        : compressedData;

                                    // Return the new service token.
                                    var creationData = new CreationData(tokendata, signature, verified);
                                    new ServiceToken(ctx, name, servicedata, (mtSerialNumber != -1) ? masterToken : null, (uitSerialNumber != -1) ? userIdToken : null, encrypted, compressionAlgo, cryptoContext, creationData, callback);
                                }
                            } else {
                                var servicedata = (ciphertextB64 == "") ? new Uint8Array(0) : null;

                                // Return the new service token.
                                var creationData = new CreationData(tokendata, signature, verified);
                                new ServiceToken(ctx, name, servicedata, (mtSerialNumber != -1) ? masterToken : null, (uitSerialNumber != -1) ? userIdToken : null, encrypted, compressionAlgo, cryptoContext, creationData, callback);
                            }
                        });
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            if (e instanceof MslException) {
                                e.setEntity(masterToken);
                                e.setUserIdToken(userIdToken);
                            }
                            throw e;
                        });
                    }
                });
            } else {
                var verified = false;
                var servicedata = (ciphertextB64 == "") ? new Uint8Array(0) : null;

                // Return the new service token.
                var creationData = new CreationData(tokendata, signature, verified);
                new ServiceToken(ctx, name, servicedata, (mtSerialNumber != -1) ? masterToken : null, (uitSerialNumber != -1) ? userIdToken : null, encrypted, compressionAlgo, cryptoContext, creationData, callback);
            }
        });
    };
})();
