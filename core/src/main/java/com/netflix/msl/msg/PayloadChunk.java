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

import java.util.Arrays;

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
import com.netflix.msl.util.Base64;
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
    
    /**
     * Construct a new payload chunk with the given message ID, data and
     * provided crypto context. If requested, the data will be compressed
     * before encrypting.
     * 
     * @param sequenceNumber sequence number.
     * @param messageId the message ID.
     * @param endofmsg true if this is the last payload chunk of the message.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @param data the payload chunk application data.
     * @param cryptoContext the crypto context.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the payload chunk.
     * @throws MslException if there is an error compressing the data.
     */
    public PayloadChunk(final long sequenceNumber, final long messageId, final boolean endofmsg, final CompressionAlgorithm compressionAlgo, final byte[] data, final ICryptoContext cryptoContext) throws MslEncodingException, MslCryptoException, MslException {
        // Verify sequence number and message ID.
        if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Sequence number " + sequenceNumber + " is outside the valid range.");
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");
        
        // Optionally compress the application data.
        final byte[] payloadData;
        if (compressionAlgo != null) {
            final byte[] compressed = MslUtils.compress(compressionAlgo, data);
            
            // Only use compression if the compressed data is smaller than the
            // uncompressed data.
            if (compressed.length < data.length) {
                this.compressionAlgo = compressionAlgo;
                payloadData = compressed;
            } else {
                this.compressionAlgo = null;
                payloadData = data;
            }
        } else {
            this.compressionAlgo = null;
            payloadData = data;
        }
        
        this.sequenceNumber = sequenceNumber;
        this.messageId = messageId;
        this.endofmsg = endofmsg;
        this.data = data;
        
        // Construct the payload.
        try {
            final JSONObject payloadJO = new JSONObject();
            payloadJO.put(KEY_SEQUENCE_NUMBER, this.sequenceNumber);
            payloadJO.put(KEY_MESSAGE_ID, this.messageId);
            if (this.endofmsg) payloadJO.put(KEY_END_OF_MESSAGE, this.endofmsg);
            if (this.compressionAlgo != null) payloadJO.put(KEY_COMPRESSION_ALGORITHM, this.compressionAlgo.name());
            payloadJO.put(KEY_DATA, Base64.encode(payloadData));
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
                payload = Base64.decode(payloadChunkJO.getString(KEY_PAYLOAD));
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.PAYLOAD_INVALID, "payload chunk " + payloadChunkJO.toString(), e);
            }
            try {
                signature = Base64.decode(payloadChunkJO.getString(KEY_SIGNATURE));
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
            endofmsg = (payloadJO.has(KEY_END_OF_MESSAGE)) ? payloadJO.getBoolean(KEY_END_OF_MESSAGE) : false;
            if (payloadJO.has(KEY_COMPRESSION_ALGORITHM)) {
                final String algoName = payloadJO.getString(KEY_COMPRESSION_ALGORITHM);
                try {
                    compressionAlgo = CompressionAlgorithm.valueOf(algoName);
                } catch (final IllegalArgumentException e) {
                    throw new MslMessageException(MslError.UNIDENTIFIED_COMPRESSION, algoName, e);
                }
            } else {
                compressionAlgo = null;
            }
            final String payloadData = payloadJO.getString(KEY_DATA);
            byte[] compressedData;
            try {
                compressedData = Base64.decode(payloadData);
            } catch (final IllegalArgumentException e) {
                // Fall through to the error handling below.
                compressedData = null;
            }
            if (compressedData == null || compressedData.length == 0) {
                if (payloadData.length() > 0)
                    throw new MslMessageException(MslError.PAYLOAD_DATA_CORRUPT, payloadData);
                else if (!endofmsg)
                    throw new MslMessageException(MslError.PAYLOAD_DATA_MISSING, payloadData);
                else
                    data = new byte[0];
            } else {
                if (compressionAlgo == null) {
                    data = compressedData;
                } else {
                    data = MslUtils.uncompress(compressionAlgo, compressedData);
                }
            }
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "payload chunk payload " + payloadJson, e);
        }
    }
    
    /**
     * @return the sequence number.
     */
    public long getSequenceNumber() {
        return sequenceNumber;
    }
    
    /**
     * @return the message ID.
     */
    public long getMessageId() {
        return messageId;
    }
    
    /**
     * @return true if this is the last payload chunk of the message.
     */
    public boolean isEndOfMessage() {
        return endofmsg;
    }
    
    /**
     * @return the compression algorithm. May be {@code null} if not
     *         not compressed.
     */
    public CompressionAlgorithm getCompressionAlgo() {
        return compressionAlgo;
    }
    
    /**
     * Returns the application data if we were able to decrypt it.
     * 
     * @return the chunk application data. May be empty (zero-length).
     */
    public byte[] getData() {
        return data;
    }

    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_PAYLOAD, Base64.encode(payload));
            jsonObj.put(KEY_SIGNATURE, Base64.encode(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof PayloadChunk)) return false;
        final PayloadChunk that = (PayloadChunk)obj;
        return sequenceNumber == that.sequenceNumber &&
            messageId == that.messageId &&
            endofmsg == that.endofmsg &&
            compressionAlgo == that.compressionAlgo &&
            Arrays.equals(data, that.data);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return Long.valueOf(sequenceNumber).hashCode() ^
            Long.valueOf(messageId).hashCode() ^
            Boolean.valueOf(endofmsg).hashCode() ^
            ((compressionAlgo != null) ? compressionAlgo.hashCode() : 0) ^
            Arrays.hashCode(data);
    }

    /** Payload (ciphertext). */
    private final byte[] payload;
    /** Payload data signature. */
    private final byte[] signature;
    
    /** Sequence number. */
    private final long sequenceNumber;
    /** Message ID. */
    private final long messageId;
    /** End of message flag. */
    private final boolean endofmsg;
    /** Compression algorithm. */
    private final CompressionAlgorithm compressionAlgo;
    /** The application data. */
    private final byte[] data;
}
