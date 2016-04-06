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
 * <p>A payload chunk is a self-contained block of application data that is
 * encrypted, verified, and optionally compressed independent of other chunks.
 * A message payload may contain one or more chunks.</p>
 *
 * <p>Payload chunks are bound to a specific message by the message ID.</p>
 *
 * <p>Each payload chunk in a message is sequentially ordered by the chunk
 * sequence number. The sequence number starts at 1 and is incremented by 1 on
 * each sequential chunk.</p>
 *
 * <p>Payload chunks are represented as
 * {@code
 * payloadchunk = {
 *   "#mandatory" : [ "payload", "signature" ],
 *   "payload" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code payload} is the Base64-encoded encrypted payload (payload)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the payload</li>
 * </ul></p>
 *
 * <p>The payload is represented as
 * {@code
 * payload = {
 *   "#mandatory" : [ "sequencenumber", "messageid", "data" ],
 *   "sequencenumber" : "int64(1,2^53^)",
 *   "messageid" : "int64(0,2^53^)",
 *   "endofmsg" : "boolean",
 *   "compressionalgo" : "enum(GZIP\LZW)",
 *   "data" : "base64"
 * }} where:
 * <ul>
 * <li>{@code sequencenumber} is the chunk sequence number</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code endofmsg} indicates this is the last payload of the message</li>
 * <li>{@code compressionalgo} indicates the algorithm used to compress the data</li>
 * <li>{@code data} is the Base64-encoded optionally compressed application data</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var PayloadChunk;
var PayloadChunk$create;
var PayloadChunk$parse;

(function() {
    "use strict";
    /**
     * JSON key payload.
     * @const
     * @type {string}
     */
    var KEY_PAYLOAD = "payload";
    /**
     * JSON key signature.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";

    // payload
    /**
     * JSON key sequence number.
     * @const
     * @type {string}
     */
    var KEY_SEQUENCE_NUMBER = "sequencenumber";
    /**
     * JSON key message ID.
     * @const
     * @type {string}
     */
    var KEY_MESSAGE_ID = "messageid";
    /**
     * JSON key end of message.
     * @const
     * @type {string}
     */
    var KEY_END_OF_MESSAGE = "endofmsg";
    /**
     * JSON key compression algorithm.
     * @const
     * @type {string}
     */
    var KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /**
     * JSON key encrypted data.
     * @const
     * @type {string}
     */
    var KEY_DATA = "data";

    /**
     * Create a new payload container object.
     *
     * @param {Uint8Array} payload raw payload data.
     * @param {Uint8Array} signature raw signature.
     * @constructor
     */
    function CreationData(payload, signature) {
        this.payload = payload;
        this.signature = signature;
    }

    PayloadChunk = util.Class.create({
        /**
         * Construct a new payload chunk with the given message ID, data and
         * provided crypto context. If requested, the data will be compressed
         * before encrypting.
         *
         * @param {number} sequenceNumber sequence number.
         * @param {number} messageId the message ID.
         * @param {boolean} endofmsg true if this is the last payload chunk of the message.
         * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {Uint8Array} data the payload chunk application data.
         * @param {ICryptoContext} cryptoContext the crypto context.
         * @param {?CreationData} optional creation data.
         * @param {{result: function(PayloadChunk), error: function(Error)}}
         *        callback the callback that will receive the payload chunk or
         *        any thrown exceptions.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the payload chunk.
         * @throws MslException if there is an error compressing the data.
         */
        init: function init(sequenceNumber, messageId, endofmsg, compressionAlgo, data, cryptoContext, creationData, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Verify sequence number and message ID.
                if (sequenceNumber < 0 || sequenceNumber > MslConstants$MAX_LONG_VALUE)
                    throw new MslInternalException("Sequence number " + sequenceNumber + " is outside the valid range.");
                if (messageId < 0 || messageId > MslConstants$MAX_LONG_VALUE)
                    throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");

                // Construct the payload.
                if (!creationData) {
                    // Optionally compress the application data.
                    var payloadData;
                    if (compressionAlgo) {
                        var compressed = MslUtils$compress(compressionAlgo, data);

                        // Only use compression if the compressed data is smaller than the
                        // uncompressed data.
                        if (compressed) {
                            payloadData = compressed;
                        } else {
                            compressionAlgo = null;
                            payloadData = data;
                        }
                    } else {
                        compressionAlgo = null;
                        payloadData = data;
                    }

                    // Construct the payload.
                    var payloadJO = {};
                    payloadJO[KEY_SEQUENCE_NUMBER] = sequenceNumber;
                    payloadJO[KEY_MESSAGE_ID] = messageId;
                    if (endofmsg) payloadJO[KEY_END_OF_MESSAGE] = endofmsg;
                    if (compressionAlgo) payloadJO[KEY_COMPRESSION_ALGORITHM] = compressionAlgo;
                    payloadJO[KEY_DATA] = base64$encode(payloadData);
                    var plaintext = textEncoding$getBytes(JSON.stringify(payloadJO), MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(plaintext, {
                        result: function(payload) {
                            AsyncExecutor(callback, function() {
                                cryptoContext.sign(payload, {
                                    result: function(signature) {
                                        AsyncExecutor(callback, function() {
                                            // The properties.
                                            var props = {
                                                sequenceNumber: { value: sequenceNumber, writable: false, configurable: false },
                                                messageId: { value: messageId, writable: false, configurable: false },
                                                compressionAlgo: { value: compressionAlgo, writable: false, configurable: false },
                                                data: { value: data, writable: false, configurable: false },
                                                endofmsg: { value: endofmsg, writable: false, enumerable: false, configurable: false },
                                                payload: { value: payload, writable: false, enumerable: false, configurable: false },
                                                signature: { value: signature, writable: false, enumerable: false, configurable: false },
                                            };
                                            Object.defineProperties(this, props);
                                            return this;
                                        }, self);
                                    },
                                    error: function(e) { callback.error(e); }
                                });
                            }, self);
                        },
                        error: function(e) { callback.error(e); }
                    });
                } else {
                    var payload = creationData.payload;
                    var signature = creationData.signature;

                    // The properties.
                    var props = {
                        sequenceNumber: { value: sequenceNumber, writable: false, configurable: false },
                        messageId: { value: messageId, writable: false, configurable: false },
                        compressionAlgo: { value: compressionAlgo, writable: false, configurable: false },
                        data: { value: data, writable: false, configurable: false },
                        endofmsg: { value: endofmsg, writable: false, enumerable: false, configurable: false },
                        payload: { value: payload, writable: false, enumerable: false, configurable: false },
                        signature: { value: signature, writable: false, enumerable: false, configurable: false },
                    };
                    Object.defineProperties(this, props);
                    return this;
                }
            }, self);
        },

        /**
         * @return {boolean} true if this is the last payload chunk of the message.
         */
        isEndOfMessage: function isEndOfMessage() {
            return this.endofmsg;
        },

        /** @inheritDoc */
        toJSON: function toJSON() {
            var jsonObj = {};
            jsonObj[KEY_PAYLOAD] = base64$encode(this.payload);
            jsonObj[KEY_SIGNATURE] = base64$encode(this.signature);
            return jsonObj;
        },
    });

    /**
     * Construct a new payload chunk with the given message ID, data and
     * provided crypto context. If requested, the data will be compressed
     * before encrypting.
     *
     * @param {number} sequenceNumber sequence number.
     * @param {number} messageId the message ID.
     * @param {boolean} endofmsg true if this is the last payload chunk of the message.
     * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @param {Uint8Array} data the payload chunk application data.
     * @param {ICryptoContext} cryptoContext the crypto context.
     * @param {{result: function(PayloadChunk), error: function(Error)}}
     *        callback the callback that will receive the payload chunk or
     *        any thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the payload chunk.
     * @throws MslException if there is an error compressing the data.
     */
    PayloadChunk$create = function PayloadChunk$create(sequenceNumber, messageId, endofmsg, compressionAlgo, data, cryptoContext, callback) {
        new PayloadChunk(sequenceNumber, messageId, endofmsg, compressionAlgo, data, cryptoContext, null, callback);
    };

    /**
     * <p>Construct a new payload chunk from the provided JSON object.</p>
     *
     * <p>The provided crypto context will be used to decrypt and verify the
     * data signature.</p>
     *
     * @param {Object} payloadChunkJO the JSON object.
     * @param {ICryptoContext} cryptoContext the crypto context.
     * @param {{result: function(PayloadChunk), error: function(Error)}}
     *        callback the callback that will receive the payload chunk or
     *        any thrown exceptions.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the JSON.
     * @throws MslMessageException if the compression algorithm is not known,
     *         or the payload data is corrupt or missing.
     * @throws MslException if there is an error uncompressing the data.
     */
    PayloadChunk$parse = function PayloadChunk$parse(payloadChunkJO, cryptoContext, callback) {
        AsyncExecutor(callback, function() {
            // Pull the payload and signature.
            var payloadB64 = payloadChunkJO[KEY_PAYLOAD];
            var signatureB64 = payloadChunkJO[KEY_SIGNATURE];
            if (typeof payloadB64 !== 'string' ||
                typeof signatureB64 !== 'string')
            {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk " + JSON.stringify(payloadChunkJO));
            }

            // Verify the payload.
            var payload, signature;
            try {
                payload = base64$decode(payloadB64);
            } catch (e) {
                throw new MslMessageException(MslError.PAYLOAD_INVALID, "payload chunk " + JSON.stringify(payloadChunkJO), e);
            }
            try {
                signature = base64$decode(signatureB64);
            } catch (e) {
                throw new MslMessageException(MslError.PAYLOAD_SIGNATURE_INVALID, "payload chunk " + JSON.stringify(payloadChunkJO), e);
            }
            cryptoContext.verify(payload, signature, {
                result: function(verified) {
                    AsyncExecutor(callback, function() {
                        if (!verified)
                            throw new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED);

                        // Decrypt the payload.
                        cryptoContext.decrypt(payload, {
                            result: function(plaintext) {
                                AsyncExecutor(callback, function() {
                                    // Reconstruct the payload object.
                                    var payloadJson = textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET);
                                    var payloadJO;
                                    try {
                                        payloadJO = JSON.parse(payloadJson);
                                    } catch (e) {
                                        if (e instanceof SyntaxError)
                                            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk payload " + payloadJson, e);
                                        throw e;
                                    }

                                    // Pull payload information.
                                    var sequenceNumber = parseInt(payloadJO[KEY_SEQUENCE_NUMBER]);
                                    var messageId = parseInt(payloadJO[KEY_MESSAGE_ID]);
                                    var endofmsg = payloadJO[KEY_END_OF_MESSAGE];
                                    var compressionAlgo = payloadJO[KEY_COMPRESSION_ALGORITHM];
                                    var payloadData = payloadJO[KEY_DATA];

                                    // Verify payload information.
                                    if (!sequenceNumber || sequenceNumber != sequenceNumber ||
                                        !messageId || messageId != messageId ||
                                        (endofmsg && typeof endofmsg !== 'boolean') ||
                                        (compressionAlgo && typeof compressionAlgo !== 'string') ||
                                        typeof payloadData !== 'string')
                                    {
                                        throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk payload " + payloadJson);
                                    }

                                    // Verify sequence number and message ID values.
                                    if (sequenceNumber < 0 || sequenceNumber > MslConstants$MAX_LONG_VALUE)
                                        throw new MslException(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE, "payload chunk payload " + payloadJson);
                                    if (messageId < 0 || messageId > MslConstants$MAX_LONG_VALUE)
                                        throw new MslException(MslError.PAYLOAD_MESSAGE_ID_OUT_OF_RANGE, "payload chunk payload " + payloadJson);

                                    // Default end of message to false.
                                    if (!endofmsg) endofmsg = false;

                                    // Verify compression algorithm.
                                    if (compressionAlgo && !MslConstants$CompressionAlgorithm[compressionAlgo])
                                        throw new MslMessageException(MslError.UNIDENTIFIED_COMPRESSION, compressionAlgo);

                                    // Decompress the data if it is compressed.
                                    var data;
                                    var compressedData;
                                    try {
                                        compressedData = base64$decode(payloadData);
                                    } catch (e) {
                                        throw new MslMessageException(MslError.PAYLOAD_DATA_CORRUPT, payloadData, e);
                                    }
                                    if (!compressedData || compressedData.length == 0) {
                                        if (payloadData.length > 0)
                                            throw new MslMessageException(MslError.PAYLOAD_DATA_CORRUPT, payloadData);
                                        else if (!endofmsg)
                                            throw new MslMessageException(MslError.PAYLOAD_DATA_MISSING, payloadData);
                                        else
                                            data = new Uint8Array(0);
                                    } else {
                                        data = (compressionAlgo) ? MslUtils$uncompress(compressionAlgo, compressedData) : compressedData;
                                    }

                                    // Return the payload chunk.
                                    var creationData = new CreationData(payload, signature);
                                    new PayloadChunk(sequenceNumber, messageId, endofmsg, compressionAlgo, data, cryptoContext, creationData, callback);
                                });
                            },
                            error: function(e) { callback.error(e); }
                        });
                    });
                },
                error: function(e) { callback.error(e); }
            });
        });
    };
})();
