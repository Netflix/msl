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
 *   "payload" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code payload} is the encrypted payload (payload)</li>
 * <li>{@code signature} is the verification data of the payload</li>
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
 *   "data" : "binary"
 * }} where:
 * <ul>
 * <li>{@code sequencenumber} is the chunk sequence number</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code endofmsg} indicates this is the last payload of the message</li>
 * <li>{@code compressionalgo} indicates the algorithm used to compress the data</li>
 * <li>{@code data} is the optionally compressed application data</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var MslEncodable = require('../io/MslEncodable.js');
	var MslConstants = require('../MslConstants.js');
	var MslInternalException = require('../MslInternalException.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslError = require('../MslError.js');
	var MslMessageException = require('../MslMessageException.js');
	var MslException = require('../MslException.js');
	var Base64 = require('../util/Base64.js');
	var MslCompression = require('../util/MslCompression.js');
	
    /**
     * Key payload.
     * @const
     * @type {string}
     */
    var KEY_PAYLOAD = "payload";
    /**
     * Key signature.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = "signature";

    // payload
    /**
     * Key sequence number.
     * @const
     * @type {string}
     */
    var KEY_SEQUENCE_NUMBER = "sequencenumber";
    /**
     * Key message ID.
     * @const
     * @type {string}
     */
    var KEY_MESSAGE_ID = "messageid";
    /**
     * Key end of message.
     * @const
     * @type {string}
     */
    var KEY_END_OF_MESSAGE = "endofmsg";
    /**
     * Key compression algorithm.
     * @const
     * @type {string}
     */
    var KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /**
     * Key encrypted data.
     * @const
     * @type {string}
     */
    var KEY_DATA = "data";

    /**
     * Create a new payload container object.
     *
     * @param {MslObject} payload payload MSL object.
     * @constructor
     */
    function CreationData(payload, signature) {
        this.payload = payload;
    }

    var PayloadChunk = module.exports = MslEncodable.extend({
        /**
         * Construct a new payload chunk with the given message ID, data and
         * provided crypto context. If requested, the data will be compressed
         * before encrypting.
         *
         * @param {MslContext} ctx the MSL context.
         * @param {number} sequenceNumber sequence number.
         * @param {number} messageId the message ID.
         * @param {boolean} endofmsg true if this is the last payload chunk of the message.
         * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {Uint8Array} data the payload chunk application data.
         * @param {ICryptoContext} cryptoContext the crypto context.
         * @param {?CreationData} optional creation data.
         * @throws MslEncodingException if there is an error encoding the data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the payload chunk.
         * @throws MslException if there is an error compressing the data.
         */
        init: function init(ctx, sequenceNumber, messageId, endofmsg, compressionAlgo, data, cryptoContext, creationData) {
            // Verify sequence number and message ID.
            if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslInternalException("Sequence number " + sequenceNumber + " is outside the valid range.");
            if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
                throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");

            // Construct the payload.
            var payload;
            if (!creationData) {
                // Optionally compress the application data.
                var payloadData;
                if (compressionAlgo) {
                    var compressed = MslCompression.compress(compressionAlgo, data);

                    // Only use compression if the compressed data is smaller than the
                    // uncompressed data.
                    if (compressed && compressed.length < data.length) {
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
                var encoder = ctx.getMslEncoderFactory();
                payload = encoder.createObject();
                payload.put(KEY_SEQUENCE_NUMBER, sequenceNumber);
                payload.put(KEY_MESSAGE_ID, messageId);
                if (endofmsg) payload.put(KEY_END_OF_MESSAGE, endofmsg);
                if (compressionAlgo != null) payload.put(KEY_COMPRESSION_ALGORITHM, compressionAlgo);
                payload.put(KEY_DATA, payloadData);
            } else {
                payload = creationData.payload;
            }

            // The properties.
            var props = {
                /** @type {MslObject} */
                payload: { value: payload, writable: false, enumerable: false, configurable: false },
                /** @type {number} */
                sequenceNumber: { value: sequenceNumber, writable: false, configurable: false },
                /** @type {number} */
                messageId: { value: messageId, writable: false, configurable: false },
                /** @type {boolean} */
                endofmsg: { value: endofmsg, writable: false, enumerable: false, configurable: false },
                /** @type {MslConstants$CompressionAlgorithm} */
                compressionAlgo: { value: compressionAlgo, writable: false, configurable: false },
                /** @type {Uint8Array} */
                data: { value: data, writable: false, configurable: false },
                /** @type {ICryptoContext} */
                cryptoContext: { value: cryptoContext, writable: false, enumerable: false, configurable: false },
                /** @type {Object<MslEncoderFormat,Uint8Array>} */
                encodings: { value: {}, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {boolean} true if this is the last payload chunk of the message.
         */
        isEndOfMessage: function isEndOfMessage() {
            return this.endofmsg;
        },
        
        /** @inheritDoc */
        toMslEncoding: function toMslEncoding(encoder, format, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Return any cached encoding.
                if (this.encodings[format])
                    return this.encodings[format];
                
                // Encrypt the payload.
                encoder.encodeObject(this.payload, format, {
                	result: function(plaintext) {
                		AsyncExecutor(callback, function() {
                			this.cryptoContext.encrypt(plaintext, encoder, format, {
                				result: function(ciphertext) {
                					AsyncExecutor(callback, function() {
                						// Sign the payload.
                						this.cryptoContext.sign(ciphertext, encoder, format, {
                							result: function(signature) {
                								AsyncExecutor(callback, function() {
                									// Encode the payload chunk.
                									var mo = encoder.createObject();
                									mo.put(KEY_PAYLOAD, ciphertext);
                									mo.put(KEY_SIGNATURE, signature);
                									encoder.encodeObject(mo, format, {
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
                							},
                							error: function(e) {
                								AsyncExecutor(callback, function() {
                									if (e instanceof MslCryptoException)
                										throw new MslEncoderException("Error signing the payload.", e);
                									throw e;
                								}, self);
                							}
                						});
                					}, self);
                				},
                				error: function(e) {
                					AsyncExecutor(callback, function() {
                						if (e instanceof MslCryptoException)
                							throw new MslEncoderException("Error encrypting the payload.", e);
                						throw e;
                					}, self);
                				}
                			});
                		}, self);
                	},
                	error: callback.error,
                });
            }, self);
        },
    });

    /**
     * Construct a new payload chunk with the given message ID, data and
     * provided crypto context. If requested, the data will be compressed
     * before encrypting.
     *
     * @param {MslContext} ctx the MSL context.
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
    var PayloadChunk$create = function PayloadChunk$create(ctx, sequenceNumber, messageId, endofmsg, compressionAlgo, data, cryptoContext, callback) {
        AsyncExecutor(callback, function() {
            return new PayloadChunk(ctx, sequenceNumber, messageId, endofmsg, compressionAlgo, data, cryptoContext, null);
        });
    };

    /**
     * <p>Construct a new payload chunk from the provided MSL object.</p>
     *
     * <p>The provided crypto context will be used to decrypt and verify the
     * data signature.</p>
     *
     * @param {MslContext} ctx the MSL context.
     * @param {MslObject} payloadChunkMo the MSL object.
     * @param {ICryptoContext} cryptoContext the crypto context.
     * @param {{result: function(PayloadChunk), error: function(Error)}}
     *        callback the callback that will receive the payload chunk or
     *        any thrown exceptions.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslMessageException if the compression algorithm is not known,
     *         or the payload data is corrupt or missing.
     * @throws MslException if there is an error uncompressing the data.
     */
    var PayloadChunk$parse = function PayloadChunk$parse(ctx, payloadChunkMo, cryptoContext, callback) {
        AsyncExecutor(callback, function() {
            var encoder = ctx.getMslEncoderFactory();
            
            // Verify the data.
            var ciphertext, signature;
            try {
                ciphertext = payloadChunkMo.getBytes(KEY_PAYLOAD);
                signature = payloadChunkMo.getBytes(KEY_SIGNATURE);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "payload chunk " + payloadChunkMo, e);
                throw e;
            }
            cryptoContext.verify(ciphertext, signature, encoder, {
                result: function(verified) {
                    AsyncExecutor(callback, function() {
                        if (!verified)
                            throw new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED);
                        
                        // Pull the payload data.
                        cryptoContext.decrypt(ciphertext, encoder, {
                            result: function(plaintext) {
                                parsePayload(encoder, plaintext);
                            },
                            error: callback.error,
                        });
                    });
                },
                error: callback.error,
            });
        });
            
        function parsePayload(encoder, plaintext) {
            AsyncExecutor(callback, function() {
                try {
                    var payload = encoder.parseObject(plaintext);
                    var sequenceNumber = payload.getLong(KEY_SEQUENCE_NUMBER);
                    if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
                        throw new MslException(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE, "payload chunk payload " + payload);
                    var messageId = payload.getLong(KEY_MESSAGE_ID);
                    if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
                        throw new MslException(MslError.PAYLOAD_MESSAGE_ID_OUT_OF_RANGE, "payload chunk payload " + payload);
                    var endofmsg = (payload.has(KEY_END_OF_MESSAGE)) ? payload.getBoolean(KEY_END_OF_MESSAGE) : false;
                    var compressionAlgo;
                    if (payload.has(KEY_COMPRESSION_ALGORITHM)) {
                        compressionAlgo = payload.getString(KEY_COMPRESSION_ALGORITHM);
                        if (!MslConstants.CompressionAlgorithm[compressionAlgo])
                            throw new MslMessageException(MslError.UNIDENTIFIED_COMPRESSION, compressionAlgo);
                    } else {
                        compressionAlgo = null;
                    }
                    var data;
                    var compressedData = payload.getBytes(KEY_DATA);
                    if (compressedData.length == 0) {
                        if (!endofmsg)
                            throw new MslMessageException(MslError.PAYLOAD_DATA_MISSING);
                        data = new Uint8Array(0);
                    } else if (compressionAlgo == null) {
                        data = compressedData;
                    } else {
                        data = MslCompression.uncompress(compressionAlgo, compressedData);
                    }
                    
                    // Return the payload chunk.
                    var creationData = new CreationData(payload);
                    return new PayloadChunk(ctx, sequenceNumber, messageId, endofmsg, compressionAlgo, data, cryptoContext, creationData);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "payload chunk payload " + Base64.encode(plaintext), e);
                    throw e;
                }
            });
        }
    };
    
    // Exports.
    module.exports.create = PayloadChunk$create;
    module.exports.parse = PayloadChunk$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('PayloadChunk'));
