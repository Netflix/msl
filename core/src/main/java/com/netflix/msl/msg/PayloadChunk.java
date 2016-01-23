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
package com.netflix.msl.msg;

import javax.xml.bind.DatatypeConverter;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.util.MslUtils;

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
 *   "compressionalgo" : "enum(GZIP|LZW)",
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
@EqualsAndHashCode(exclude={"payload", "signature"})
public class PayloadChunk implements JSONString {
    /** JSON key payload. */
    private static final String KEY_PAYLOAD = "payload";

    /** JSON key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // payload
    /** JSON key sequence number. */
    private static final String KEY_SEQUENCE_NUMBER = "sequencenumber";

    /** JSON key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";

    /** JSON key end of message. */
    private static final String KEY_END_OF_MESSAGE = "endofmsg";

    /** JSON key compression algorithm. */
    private static final String KEY_COMPRESSION_ALGORITHM = "compressionalgo";

    /** JSON key encrypted data. */
    private static final String KEY_DATA = "data";

    /** Payload (ciphertext). */
    private final byte[] payload;

    /** Payload data signature. */
    private final byte[] signature;

    /** Sequence number. */
    @Getter
    private final long sequenceNumber;

    /** Message ID. */
    @Getter
    private final long messageId;

    /** End of message flag, i.e. last payload chunk of the message */
    @Getter
    private final boolean endOfMessage;

    /** Compression algorithm. May be {@code null} if not not compressed.*/
    @Getter
    private final CompressionAlgorithm compressionAlgorithm;

    /** The application data, if we were able to decrypt it. May be empty (zero-length). */
    @Getter
    private final byte[] data;

    /**
     * Construct a new payload chunk with the given message ID, data and
     * provided crypto context. If requested, the data will be compressed
     * before encrypting.
     * 
     * @param sequenceNumber sequence number.
     * @param messageId the message ID.
     * @param endOfMessage true if this is the last payload chunk of the message.
     * @param compressionAlgorithm the compression algorithm. May be {@code null}
     *        for no compression.
     * @param data the payload chunk application data.
     * @param cryptoContext the crypto context.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the payload chunk.
     * @throws MslException if there is an error compressing the data.
     */
    public PayloadChunk(final long sequenceNumber, final long messageId, final boolean endOfMessage, final CompressionAlgorithm compressionAlgorithm, final byte[] data, final ICryptoContext cryptoContext) throws MslEncodingException, MslCryptoException, MslException {
        // Verify sequence number and message ID.
        if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Sequence number " + sequenceNumber + " is outside the valid range.");
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");
        
        // Optionally compress the application data.
        final byte[] payloadData;
        if (compressionAlgorithm != null) {
            final byte[] compressed = MslUtils.compress(compressionAlgorithm, data);
            
            // Only use compression if the compressed data is smaller than the
            // uncompressed data.
            if (compressed.length < data.length) {
                this.compressionAlgorithm = compressionAlgorithm;
                payloadData = compressed;
            } else {
                this.compressionAlgorithm = null;
                payloadData = data;
            }
        } else {
            this.compressionAlgorithm = null;
            payloadData = data;
        }
        
        this.sequenceNumber = sequenceNumber;
        this.messageId = messageId;
        this.endOfMessage = endOfMessage;
        this.data = data;
        
        // Construct the payload.
        try {
            final JSONObject payloadJO = new JSONObject();
            payloadJO.put(KEY_SEQUENCE_NUMBER, this.sequenceNumber);
            payloadJO.put(KEY_MESSAGE_ID, this.messageId);
            if (this.endOfMessage) payloadJO.put(KEY_END_OF_MESSAGE, this.endOfMessage);
            if (this.compressionAlgorithm != null) payloadJO.put(KEY_COMPRESSION_ALGORITHM, this.compressionAlgorithm.name());
            payloadJO.put(KEY_DATA, DatatypeConverter.printBase64Binary(payloadData));
            final byte[] plaintext = payloadJO.toString().getBytes(MslConstants.DEFAULT_CHARSET);
            this.payload = cryptoContext.encrypt(plaintext);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "payloadchunk payload", e);
        }

        // Sign the payload chunk.
        this.signature = cryptoContext.sign(this.payload);
    }
    
    /**
     * <p>Construct a new payload chunk from the provided JSON object.</p>
     * 
     * <p>The provided crypto context will be used to decrypt and verify the
     * data signature.</p>
     * 
     * @param payloadChunkJO the JSON object.
     * @param cryptoContext the crypto context.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the JSON.
     * @throws MslMessageException if the compression algorithm is not known,
     *         or the payload data is corrupt or missing.
     * @throws MslException if there is an error uncompressing the data.
     */
    public PayloadChunk(final JSONObject payloadChunkJO, final ICryptoContext cryptoContext) throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        // Verify the JSON representation.
        try {
            try {
                payload = DatatypeConverter.parseBase64Binary(payloadChunkJO.getString(KEY_PAYLOAD));
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.PAYLOAD_INVALID, "payload chunk " + payloadChunkJO.toString(), e);
            }
            try {
                signature = DatatypeConverter.parseBase64Binary(payloadChunkJO.getString(KEY_SIGNATURE));
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.PAYLOAD_SIGNATURE_INVALID, "payload chunk " + payloadChunkJO.toString(), e);
            }
            if (!cryptoContext.verify(payload, signature))
                throw new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk " + payloadChunkJO.toString(), e);
        }
        
        // Pull the payload data.
        final byte[] plaintext = cryptoContext.decrypt(payload);
        final String payloadJson = new String(plaintext, MslConstants.DEFAULT_CHARSET);
        try {
            final JSONObject payloadJO = new JSONObject(payloadJson);
            sequenceNumber = payloadJO.getLong(KEY_SEQUENCE_NUMBER);
            if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE, "payload chunk payload " + payloadJson);
            messageId = payloadJO.getLong(KEY_MESSAGE_ID);
            if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.PAYLOAD_MESSAGE_ID_OUT_OF_RANGE, "payload chunk payload " + payloadJson);
            endOfMessage = (payloadJO.has(KEY_END_OF_MESSAGE)) ? payloadJO.getBoolean(KEY_END_OF_MESSAGE) : false;
            if (payloadJO.has(KEY_COMPRESSION_ALGORITHM)) {
                final String algoName = payloadJO.getString(KEY_COMPRESSION_ALGORITHM);
                try {
                    compressionAlgorithm = CompressionAlgorithm.valueOf(algoName);
                } catch (final IllegalArgumentException e) {
                    throw new MslMessageException(MslError.UNIDENTIFIED_COMPRESSION, algoName, e);
                }
            } else {
                compressionAlgorithm = null;
            }
            final String payloadData = payloadJO.getString(KEY_DATA);
            byte[] compressedData;
            try {
                compressedData = DatatypeConverter.parseBase64Binary(payloadData);
            } catch (final IllegalArgumentException e) {
                // Fall through to the error handling below.
                compressedData = null;
            }
            if (compressedData == null || compressedData.length == 0) {
                if (payloadData.length() > 0)
                    throw new MslMessageException(MslError.PAYLOAD_DATA_CORRUPT, payloadData);
                else if (!endOfMessage)
                    throw new MslMessageException(MslError.PAYLOAD_DATA_MISSING, payloadData);
                else
                    data = new byte[0];
            } else {
                if (compressionAlgorithm == null) {
                    data = compressedData;
                } else {
                    data = MslUtils.uncompress(compressionAlgorithm, compressedData);
                }
            }
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk payload " + payloadJson, e);
        }
    }

    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_PAYLOAD, DatatypeConverter.printBase64Binary(payload));
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }

}
