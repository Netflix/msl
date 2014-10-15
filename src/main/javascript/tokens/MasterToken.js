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

/**
 * <p>The master token provides proof of remote entity identity. A MSL-specific
 * crypto context is used to encrypt the master token data and generate the
 * master token verification data. The remote entity cannot decrypt the master
 * token data or generate the master token verification data.</p>
 *
 * <p>The master token session keys will be used for MSL message encryption and
 * integrity protection. The use of these session keys implies the MSL message
 * identity as specified in the master token.</p>
 *
 * <p>Master tokens also contain a sequence number identifying the issue number
 * of the token. This is a monotonically increasing number that is incremented
 * by one each time a master token is renewed.</p>
 *
 * <p>When in possession of multiple master tokens, the token with the highest
 * sequence number should be considered the newest token. Since the sequence
 * number space is signed 53-bit numbers, if a sequence number is smaller by
 * more than 45-bits (e.g. the new sequence number is <= 128 and the old
 * sequence number is 2^53), it is considered the newest token.</p>
 *
 * <p>The renewal window indicates the time after which the master token will
 * be renewed if requested by the entity. The expiration is the time after
 * which the master token will be renewed no matter what.</p>
 *
 * <p>Master tokens also contain a serial number against which all other tokens
 * are bound. Changing the serial number when the master token is renewed
 * invalidates all of those tokens.</p>
 *
 * <p>The issuer identity identifies the issuer of this master token, which may
 * be useful to services that accept the master token.</p>
 *
 * <p>While there can be multiple versions of a master token, this class should
 * encapsulate support for all of those versions.</p>
 *
 * <p>Master tokens are represented as
 * {@code
 * mastertoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the Base64-encoded master token data (mastertokendata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the master token data</li>
 * </ul></p>
 *
 * <p>The token data is represented as
 * {@code
 * mastertokendata = {
 *   "#mandatory" : [ "renewalwindow", "expiration", "sequencenumber", "serialnumber", "sessiondata" ],
 *   "renewalwindow" : "int64(0,-)",
 *   "expiration" : "int64(0,-)",
 *   "sequencenumber" : "int64(0,-)",
 *   "serialnumber" : "int64(0,-)",
 *   "sessiondata" : "base64"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code sequencenumber} is the master token sequence number</li>
 * <li>{@code serialnumber} is the master token serial number</li>
 * <li>{@code sessiondata} is the Base64-encoded encrypted session data (sessiondata)</li>
 * </ul></p>
 *
 * <p>The decrypted session data is represented as
 * {@code
 * sessiondata = {
 *   "#mandatory" : [ "identity", "encryptionkey", "hmackey" ],
 *   "issuerdata" : object,
 *   "identity" : "string",
 *   "encryptionkey" : "base64",
 *   "hmackey" : "base64"
 * }}
 * where:
 * <ul>
 * <li>{@code issuerdata} is the master token issuer data</li>
 * <li>{@code identity} is the identifier of the remote entity</li>
 * <li>{@code encryptionkey} is the Base64-encoded AES-128 encryption session key</li>
 * <li>{@code hmackey} is the Base64-encoded SHA-256 HMAC session key</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MasterToken;
var MasterToken$create;
var MasterToken$parse;

(function() {
    /**
     * Milliseconds per second.
     * @const
     * @type {number}
     */
    var MILLISECONDS_PER_SECOND = 1000;

    /**
     * JSON key token data.
     * @const
     * @type {string}
     */
    var KEY_TOKENDATA = "tokendata";
    /**
     * JSON key signature.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";

    // tokendata
    /**
     * JSON key renewal window timestamp.
     * @const
     * @type {string}
     */
    var KEY_RENEWAL_WINDOW = "renewalwindow";
    /**
     * JSON key expiration timestamp.
     * @const
     * @type {string}
     */
    var KEY_EXPIRATION = "expiration";
    /**
     * JSON key sequence number.
     * @const
     * @type {string}
     */
    var KEY_SEQUENCE_NUMBER = "sequencenumber";
    /**
     * JSON key serial number.
     * @const
     * @type {string}
     */
    var KEY_SERIAL_NUMBER = "serialnumber";
    /**
     * JSON key session data.
     * @const
     * @type {string}
     */
    var KEY_SESSIONDATA = "sessiondata";

    // sessiondata
    /**
     * JSON key issuer data.
     * @const
     * @type {string}
     */
    var KEY_ISSUER_DATA = "issuerdata";
    /**
     * JSON key identity.
     * @const
     * @type {string}
     */
    var KEY_IDENTITY = "identity";
    /**
     * JSON key symmetric encryption key.
     * @const
     * @type {string}
     */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /**
     * JSON key symmetric HMAC key.
     * @const
     * @type {string}
     */
    var KEY_HMAC_KEY = "hmackey";

    /**
     * Create a new session and token data container object.
     *
     * @param {Uint8Array} sessiondata raw session data. May be null.
     * @param {Uint8Array} tokendata raw token data.
     * @param {Uint8Array} signature raw signature.
     * @param {boolean} verified true if verified.
     * @constructor
     */
    function CreationData(sessiondata, tokendata, signature, verified) {
        this.sessiondata = sessiondata;
        this.tokendata = tokendata;
        this.signature = signature;
        this.verified = verified;
    };

    MasterToken = util.Class.create({
        /**
         * Create a new master token with the specified expiration, identity,
         * serial number, and encryption and HMAC keys.
         *
         * @param {MslContext} ctx MSL context.
         * @param {Date} renewalWindow the renewal window.
         * @param {Date} expiration the expiration.
         * @param {number} sequenceNumber the master token sequence number.
         * @param {number} serialNumber the master token serial number.
         * @param {Object} issuerData the issuer data. May be null.
         * @param {string} identity the singular identity this master token represents.
         * @param {CipherKey} encryptionKey the session encryption key.
         * @param {CipherKey} hmacKey the session HMAC key.
         * @param {?CreationData} creationData optional creation data.
         * @param {{result: function(MasterToken), error: function(Error)}}
         *        callback the callback functions that will receive the master token
         *        or any thrown exceptions.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @constructor
         */
        init: function init(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey, creationData, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // The expiration must appear after the renewal window.
                if (expiration.getTime() < renewalWindow.getTime())
                    throw new MslInternalException("Cannot construct a master token that expires before its renewal window opens.");
                // The sequence number and serial number must be within range.
                if (sequenceNumber < 0 || sequenceNumber > MslConstants$MAX_LONG_VALUE)
                    throw new MslInternalException("Sequence number " + sequenceNumber + " is outside the valid range.");
                if (serialNumber < 0 || serialNumber > MslConstants$MAX_LONG_VALUE)
                    throw new MslInternalException("Serial number " + serialNumber + " is outside the valid range.");

                // Renewal window and expiration are in seconds, not milliseconds.
                var renewalWindowSeconds = Math.floor(renewalWindow.getTime() / MILLISECONDS_PER_SECOND);
                var expirationSeconds = Math.floor(expiration.getTime() / MILLISECONDS_PER_SECOND);

                // Construct the session data.
                var sessiondata;
                if (!creationData) {
                    var sessionDataJO = {};
                    if (issuerData)
                        sessionDataJO[KEY_ISSUER_DATA] = issuerData;
                    sessionDataJO[KEY_IDENTITY] = identity;
                    sessionDataJO[KEY_ENCRYPTION_KEY] = base64$encode(encryptionKey.toByteArray());
                    sessionDataJO[KEY_HMAC_KEY] = base64$encode(hmacKey.toByteArray());
                    sessiondata = textEncoding$getBytes(JSON.stringify(sessionDataJO), MslConstants$DEFAULT_CHARSET);
                } else {
                    sessiondata = creationData.sessiondata;
                }

                // Construct the token data.
                if (!creationData) {
                    // Encrypt the session data.
                    var cryptoContext = ctx.getMslCryptoContext();
                    cryptoContext.encrypt(sessiondata, {
                        result: function(ciphertext) {
                            AsyncExecutor(callback, function() {
                                // Construct the token data.
                                var tokenDataJO = {};
                                tokenDataJO[KEY_RENEWAL_WINDOW] = renewalWindowSeconds;
                                tokenDataJO[KEY_EXPIRATION] = expirationSeconds;
                                tokenDataJO[KEY_SEQUENCE_NUMBER] = sequenceNumber;
                                tokenDataJO[KEY_SERIAL_NUMBER] = serialNumber;
                                tokenDataJO[KEY_SESSIONDATA] = base64$encode(ciphertext);
                                var tokendata = textEncoding$getBytes(JSON.stringify(tokenDataJO), MslConstants$DEFAULT_CHARSET);

                                // Sign the token data.
                                cryptoContext.sign(tokendata, {
                                    result: function(signature) {
                                        AsyncExecutor(callback, function() {
                                            var verified = true;

                                            // The properties.
                                            var props = {
                                                ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                                                renewalWindowSeconds: { value: renewalWindowSeconds, writable: false, enumerable: false, configurable: false },
                                                expirationSeconds: { value: expirationSeconds, writable: false, enumerable: false, configurable: false },
                                                sequenceNumber: { value: sequenceNumber, writable: false, enumerable: false, configurable: false },
                                                serialNumber: { value: serialNumber, writable: false, enumerable: false, configurable: false },
                                                issuerData: { value: issuerData, writable: false, configurable: false },
                                                identity: { value: identity, writable: false, configurable: false },
                                                encryptionKey: { value: encryptionKey, writable: false, configurable: false },
                                                hmacKey: { value: hmacKey, writable: false, configurable: false },
                                                sessiondata: { value: sessiondata, writable: false, enumerable: false, configurable: false },
                                                verified: { value: verified, writable: false, enumerable: false, configurable: false },
                                                tokendata: { value: tokendata, writable: false, enumerable: false, configurable: false },
                                                signature: { value: signature, writable: false, enumerable: false, configurable: false }
                                            };
                                            Object.defineProperties(this, props);
                                            return this;
                                        }, self);
                                    },
                                    error: function(err) { callback.error(err); },
                                });
                            }, self);
                        },
                        error: function(err) { callback.error(err); },
                    });
                } else {
                    var tokendata = creationData.tokendata;
                    var signature = creationData.signature;
                    var verified = creationData.verified;

                    // The properties.
                    var props = {
                        ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                        renewalWindowSeconds: { value: renewalWindowSeconds, writable: false, enumerable: false, configurable: false },
                        expirationSeconds: { value: expirationSeconds, writable: false, enumerable: false, configurable: false },
                        sequenceNumber: { value: sequenceNumber, writable: false, configurable: false },
                        serialNumber: { value: serialNumber, writable: false, configurable: false },
                        issuerData: { value: issuerData, writable: false, configurable: false },
                        identity: { value: identity, writable: false, configurable: false },
                        encryptionKey: { value: encryptionKey, writable: false, configurable: false },
                        hmacKey: { value: hmacKey, writable: false, configurable: false },
                        sessiondata: { value: sessiondata, writable: false, enumerable: false, configurable: false },
                        verified: { value: verified, writable: false, enumerable: false, configurable: false },
                        tokendata: { value: tokendata, writable: false, enumerable: false, configurable: false },
                        signature: { value: signature, writable: false, enumerable: false, configurable: false }
                    };
                    Object.defineProperties(this, props);
                    return this;
                }
            }, this);
        },

        /**
        * @return {Date} gets the renewal window.
        */
        get renewalWindow() {
            return new Date(this.renewalWindowSeconds * MILLISECONDS_PER_SECOND);
        },

        /**
        * @return {Date} gets the expiration.
        */
        get expiration() {
            return new Date(this.expirationSeconds * MILLISECONDS_PER_SECOND);
        },

        /**
         * @return {boolean} true if the decrypted content is available. (Implies verified.)
         */
        isDecrypted: function isDecrypted() {
            return (this.sessiondata) ? true : false;
        },

        /**
         * @return {boolean} true if the token has been verified.
         */
        isVerified: function isVerified() {
            return this.verified;
        },

        /**
         * <p>Returns true if the master token renewal window has been entered.</p>
         *
         * <ul>
         * <li>If a time is provided the renewal window value will be compared
         * against the provided time.</li>
         * <li>If the master token was issued by the local entity the renewal
         * window value will be compared against the local entity time. We assume
         * its clock at the time of issuance is in sync with the clock now.</li>
         * <li>Otherwise the master token is considered renewable under the
         * assumption that the local time is not synchronized with the master token
         * issuing entity time.</li>
         * </ul>
         *
         * @param {?Date} now the time to compare against.
         * @return {boolean} true if the renewal window has been entered.
         */
        isRenewable: function isRenewable(now) {
            if (now)
                return this.renewalWindow.getTime() <= now.getTime();
            if (this.isVerified())
                return this.renewalWindow.getTime() <= this.ctx.getTime();
            return true;
        },

        /**
         * <p>Returns true if the master token is expired.</p>
         *
         * <ul>
         * <li>If a time is provided the expiration value will be compared against
         * the provided time.</li>
         * <li>If the master token was issued by the local entity the expiration
         * value will be compared against the local entity time. We assume
         * its clock at the time of issuance is in sync with the clock now.</li>
         * <li>Otherwise the master token is considered not expired under the
         * assumption that the local time is not synchronized with the token-
         * issuing entity time.</li>
         * </ul>
         *
         * @param {?Date} now the time to compare against.
         * @return {boolean} true if expired.
         */
        isExpired: function isExpired(now) {
            if (now)
                return this.expiration.getTime() <= now.getTime();
            if (this.isVerified())
                return this.expiration.getTime() <= this.ctx.getTime();
            return false;
        },

        /**
         * <p>A master token is considered newer if its sequence number is greater
         * than another master token. If both the sequence numbers are equal, then
         * the master token with the later expiration date is considered newer.</p>
         * 
         * <p>Serial numbers are not taken into consideration when comparing which
         * master token is newer because serial numbers will change when new master
         * tokens are created as opposed to renewed. The caller of this function
         * should already be comparing master tokens that can be used
         * interchangeably (i.e. for the same MSL network).</p>
         *
         * @param {MasterToken} that the master token to compare with.
         * @return {boolean} true if this master token is newer than the provided one.
         */
        isNewerThan: function isNewerThan(that) {
            // If the sequence numbers are equal then compare the expiration dates.
            if (this.sequenceNumber == that.sequenceNumber)
                return this.expiration > that.expiration;

            // If this sequence number is bigger than that sequence number, make
            // sure that sequence number is not less than the cutoff.
            if (this.sequenceNumber > that.sequenceNumber) {
                var cutoff = this.sequenceNumber - MslConstants$MAX_LONG_VALUE + 127;
                return that.sequenceNumber >= cutoff;
            }

            // If this sequence number is smaller than that sequence number, make
            // sure this sequence number is less than the cutoff.
            var cutoff = that.sequenceNumber - MslConstants$MAX_LONG_VALUE + 127;
            return this.sequenceNumber < cutoff;
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
         * @return {boolean} true if the other object is a master token with the same
         *         serial number and sequence number.
         * @see #uniqueKey()
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof MasterToken)) return false;
            return this.serialNumber == that.serialNumber &&
                this.sequenceNumber == that.sequenceNumber &&
                this.expiration.getTime() == that.expiration.getTime();
        },

        /**
         * @return {string} a string that uniquely identifies this master token.
         * @see #equals(that)
         */
        uniqueKey: function uniqueKey() {
            return this.serialNumber + ':' + this.sequenceNumber + this.expiration.getTime();
        },
    });

    /**
     * Create a new master token with the specified expiration, identity,
     * serial number, and encryption and HMAC keys.
     *
     * @param {MslContext} ctx MSL context.
     * @param {Date} renewalWindow the renewal window.
     * @param {Date} expiration the expiration.
     * @param {number} sequenceNumber the master token sequence number.
     * @param {number} serialNumber the master token serial number.
     * @param {Object} issuerData the issuer data. May be null.
     * @param {string} identity the singular identity this master token represents.
     * @param {CipherKey} encryptionKey the session encryption key.
     * @param {CipherKey} hmacKey the session HMAC key.
     * @param {CreationData} creationData optional creation data.
     * @param {{result: function(MasterToken), error: function(Error)}}
     *        callback the callback functions that will receive the master token
     *        or any thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    MasterToken$create = function MasterToken$create(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey, callback) {
        new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey, null, callback);
    };

    /**
     * Create a new master token from the provided JSON.
     *
     * @param {MslContext} ctx MSL context.
     * @param {Object} masterTokenJO master token JSON object.
     * @param {{result: function(MasterToken), error: function(Error)}}
     *        callback the callback functions that will receive the master token
     *        or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error verifying the token data
     *         or extracting the session keys.
     * @throws MslException if the expiration timestamp occurs before the
     *         renewal window, or the sequence number is out of range, or the
     *         serial number is out of range, or the token data or signature is
     *         invalid.
     */
    MasterToken$parse = function MasterToken$parse(ctx, masterTokenJO, callback) {
        AsyncExecutor(callback, function() {
            // Grab the crypto context.
            var cryptoContext = ctx.getMslCryptoContext();

            // Verify the JSON representation.
            var tokendataB64 = masterTokenJO[KEY_TOKENDATA];
            var signatureB64 = masterTokenJO[KEY_SIGNATURE];
            if (typeof tokendataB64 !== 'string' || typeof signatureB64 !== 'string')
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "mastertoken " + JSON.stringify(masterTokenJO));
            var tokendata, signature;
            try {
                tokendata = base64$decode(tokendataB64);
            } catch (e) {
                throw new MslException(MslError.MASTERTOKEN_TOKENDATA_INVALID, "mastertoken " + JSON.stringify(masterTokenJO), e);
            }
            if (!tokendata || tokendata.length == 0)
                throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_MISSING, "mastertoken " + JSON.stringify(masterTokenJO));
            try {
                signature = base64$decode(signatureB64);
            } catch (e) {
                throw new MslException(MslError.MASTERTOKEN_SIGNATURE_INVALID, "mastertoken " + JSON.stringify(masterTokenJO), e);
            }
            cryptoContext.verify(tokendata, signature, {
                result: function(verified) {
                    AsyncExecutor(callback, function() {
                        // Pull the token data.
                        var renewalWindowSeconds, expirationSeconds, sequenceNumber, serialNumber, ciphertextB64;
                        var tokenDataJson = textEncoding$getString(tokendata, MslConstants$DEFAULT_CHARSET);
                        try {
                            var tokenDataJO = JSON.parse(tokenDataJson);
                            renewalWindowSeconds = parseInt(tokenDataJO[KEY_RENEWAL_WINDOW]);
                            expirationSeconds = parseInt(tokenDataJO[KEY_EXPIRATION]);
                            sequenceNumber = parseInt(tokenDataJO[KEY_SEQUENCE_NUMBER]);
                            serialNumber = parseInt(tokenDataJO[KEY_SERIAL_NUMBER]);
                            ciphertextB64 = tokenDataJO[KEY_SESSIONDATA];
                        } catch (e) {
                            if (e instanceof SyntaxError)
                                throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR, "mastertokendata " + tokenDataJson, e);
                            throw e;
                        }

                        // Verify token data.
                        if (!renewalWindowSeconds || renewalWindowSeconds != renewalWindowSeconds ||
                            !expirationSeconds || expirationSeconds != expirationSeconds ||
                            typeof sequenceNumber !== 'number' || sequenceNumber != sequenceNumber ||
                            typeof serialNumber !== 'number' || serialNumber != serialNumber ||
                            typeof ciphertextB64 !== 'string')
                        {
                            throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR, "mastertokendata " + tokenDataJson);
                        }
                        if (expirationSeconds < renewalWindowSeconds)
                            throw new MslException(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL, "mastertokendata " + tokenDataJson);

                        // Verify sequence number and serial number values.
                        if (sequenceNumber < 0 || sequenceNumber > MslConstants$MAX_LONG_VALUE)
                            throw new MslException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokenDataJson);
                        if (serialNumber < 0 || serialNumber > MslConstants$MAX_LONG_VALUE)
                            throw new MslException(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokenDataJson);

                        // Convert dates.
                        var renewalWindow = new Date(renewalWindowSeconds * MILLISECONDS_PER_SECOND);
                        var expiration = new Date(expirationSeconds * MILLISECONDS_PER_SECOND);

                        // Construct session data.
                        var ciphertext;
                        try {
                            ciphertext = base64$decode(ciphertextB64);
                        } catch (e) {
                            throw new MslException(MslError.MASTERTOKEN_SESSIONDATA_INVALID, ciphertextB64, e);
                        }
                        if (!ciphertext || ciphertext.length == 0)
                            throw new MslException(MslError.MASTERTOKEN_SESSIONDATA_MISSING, ciphertextB64);
                        if (verified) {
                            cryptoContext.decrypt(ciphertext, {
                                result: function(sessiondata) {
                                    AsyncExecutor(callback, function() {
                                        var issuerData, identity, encryptionKeyB64, hmacKeyB64;
                                        var sessionDataJson = textEncoding$getString(sessiondata, MslConstants$DEFAULT_CHARSET);
                                        try {
                                            var sessionDataJO = JSON.parse(sessionDataJson);
                                            issuerData = sessionDataJO[KEY_ISSUER_DATA];
                                            identity = sessionDataJO[KEY_IDENTITY];
                                            encryptionKeyB64 = sessionDataJO[KEY_ENCRYPTION_KEY];
                                            hmacKeyB64 = sessionDataJO[KEY_HMAC_KEY];
                                        } catch (e) {
                                            if (e instanceof SyntaxError)
                                                throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR, "sessiondata " + sessionDataJson, e);
                                            throw e;
                                        }

                                        // Verify session data.
                                        if (issuerData && typeof issuerData !== 'object' ||
                                            !identity ||
                                            typeof encryptionKeyB64 !== 'string' ||
                                            typeof hmacKeyB64 !== 'string')
                                        {
                                            throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR, "sessiondata " + sessionDataJson);
                                        }

                                        // Reconstruct cipher keys.
                                        CipherKey$import(encryptionKeyB64, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, {
                                            result: function(encryptionKey) {
                                                CipherKey$import(hmacKeyB64, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                                                    result: function(hmacKey) {
                                                        AsyncExecutor(callback, function() {
                                                            // Return the new master token.
                                                            var creationData = new CreationData(sessiondata, tokendata, signature, verified);
                                                            new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey, creationData, callback);
                                                        });
                                                    },
                                                    error: function(e) {
                                                        callback.error(new MslCryptoException(MslError.MASTERTOKEN_KEY_CREATION_ERROR, e));
                                                    }
                                                });
                                            },
                                            error: function(e) {
                                                callback.error(new MslCryptoException(MslError.MASTERTOKEN_KEY_CREATION_ERROR, e));
                                            }
                                        });
                                    });
                                },
                                error: function(err) { callback.error(err); },
                            });
                        } else {
                            var sessiondata = null;
                            var issuerData = null;
                            var identity = null;
                            var encryptionKey = null;
                            var hmacKey = null;

                            // Return the new master token.
                            var creationData = new CreationData(sessiondata, tokendata, signature, verified);
                            new MasterToken(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey, creationData, callback);
                        }
                    });
                },
                error: function(err) { callback.error(err); }
            });
        });
    };
})();
