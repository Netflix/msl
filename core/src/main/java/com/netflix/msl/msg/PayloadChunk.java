/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslCompression;
import com.netflix.msl.util.MslContext;

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
public class PayloadChunk implements MslEncodable {
    /** Key payload. */
    private static final String KEY_PAYLOAD = "payload";
    /** Key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // payload
    /** Key sequence number. */
    private static final String KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** Key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** Key end of message. */
    private static final String KEY_END_OF_MESSAGE = "endofmsg";
    /** Key compression algorithm. */
    private static final String KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** Key encrypted data. */
    private static final String KEY_DATA = "data";
    
    /**
     * Construct a new payload chunk with the given message ID, data and
     * provided crypto context. If requested, the data will be compressed
     * before encrypting.
     * 
     * @param ctx the MSL context.
     * @param sequenceNumber sequence number.
     * @param messageId the message ID.
     * @param endofmsg true if this is the last payload chunk of the message.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @param data the payload chunk application data.
     * @param cryptoContext the crypto context.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the payload chunk.
     * @throws MslException if there is an error compressing the data.
     */
    public PayloadChunk(final MslContext ctx, final long sequenceNumber, final long messageId, final boolean endofmsg, final CompressionAlgorithm compressionAlgo, final byte[] data, final ICryptoContext cryptoContext) throws MslEncodingException, MslCryptoException, MslException {
        // Verify sequence number and message ID.
        if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Sequence number " + sequenceNumber + " is outside the valid range.");
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");
        
        // Optionally compress the application data.
        final byte[] payloadData;
        if (compressionAlgo != null) {
            final byte[] compressed = MslCompression.compress(compressionAlgo, data);
            
            // Only use compression if the compressed data is smaller than the
            // uncompressed data.
            if (compressed != null && compressed.length < data.length) {
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
        
        // Set the payload properties.
        this.sequenceNumber = sequenceNumber;
        this.messageId = messageId;
        this.endofmsg = endofmsg;
        this.data = data;
        
        // Construct the payload.
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        this.payload = encoder.createObject();
        this.payload.put(KEY_SEQUENCE_NUMBER, this.sequenceNumber);
        this.payload.put(KEY_MESSAGE_ID, this.messageId);
        if (this.endofmsg) this.payload.put(KEY_END_OF_MESSAGE, this.endofmsg);
        if (this.compressionAlgo != null) this.payload.put(KEY_COMPRESSION_ALGORITHM, this.compressionAlgo.name());
        this.payload.put(KEY_DATA, payloadData);
        
        // Save the crypto context.
        this.cryptoContext = cryptoContext;
    }
    
    /**
     * <p>Construct a new payload chunk from the provided MSL object.</p>
     * 
     * <p>The provided crypto context will be used to decrypt and verify the
     * data signature.</p>
     * 
     * @param ctx the MSL context.
     * @param payloadChunkMo the MSL object.
     * @param cryptoContext the crypto context.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslMessageException if the compression algorithm is not known,
     *         or the payload data is corrupt or missing.
     * @throws MslException if there is an error uncompressing the data.
     */
    public PayloadChunk(final MslContext ctx, final MslObject payloadChunkMo, final ICryptoContext cryptoContext) throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        
        // Save the crypto context.
        this.cryptoContext = cryptoContext;
        
        // Verify the data.
        final byte[] ciphertext;
        try {
            ciphertext = payloadChunkMo.getBytes(KEY_PAYLOAD);
            final byte[] signature = payloadChunkMo.getBytes(KEY_SIGNATURE);
            if (!cryptoContext.verify(ciphertext, signature, encoder))
                throw new MslCryptoException(MslError.PAYLOAD_VERIFICATION_FAILED);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "payload chunk " + payloadChunkMo, e);
        }
        
        // Pull the payload data.
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        try {
            payload = encoder.parseObject(plaintext);
            sequenceNumber = payload.getLong(KEY_SEQUENCE_NUMBER);
            if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE, "payload chunk payload " + payload);
            messageId = payload.getLong(KEY_MESSAGE_ID);
            if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.PAYLOAD_MESSAGE_ID_OUT_OF_RANGE, "payload chunk payload " + payload);
            endofmsg = (payload.has(KEY_END_OF_MESSAGE)) ? payload.getBoolean(KEY_END_OF_MESSAGE) : false;
            if (payload.has(KEY_COMPRESSION_ALGORITHM)) {
                final String algoName = payload.getString(KEY_COMPRESSION_ALGORITHM);
                try {
                    compressionAlgo = CompressionAlgorithm.valueOf(algoName);
                } catch (final IllegalArgumentException e) {
                    throw new MslMessageException(MslError.UNIDENTIFIED_COMPRESSION, algoName, e);
                }
            } else {
                compressionAlgo = null;
            }
            final byte[] compressedData = payload.getBytes(KEY_DATA);
            if (compressedData.length == 0) {
                if (!endofmsg)
                    throw new MslMessageException(MslError.PAYLOAD_DATA_MISSING);
                data = new byte[0];
            } else if (compressionAlgo == null) {
                data = compressedData;
            } else {
                data = MslCompression.uncompress(compressionAlgo, compressedData);
            }
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "payload chunk payload " + Base64.encode(plaintext), e);
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
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        // Return any cached encoding.
        if (encodings.containsKey(format))
            return encodings.get(format);
        
        // Encrypt the payload.
        final byte[] plaintext = encoder.encodeObject(payload, format);
        final byte[] ciphertext;
        try{
            ciphertext = cryptoContext.encrypt(plaintext, encoder, format);
        } catch (final MslCryptoException e) {
            throw new MslEncoderException("Error encrypting the payload.", e);
        }

        // Sign the payload.
        final byte[] signature;
        try {
            signature = cryptoContext.sign(ciphertext, encoder, format);
        } catch (final MslCryptoException e) {
            throw new MslEncoderException("Error signing the payload.", e);
        }
        
        // Encode the payload chunk.
        final MslObject mo = encoder.createObject();
        mo.put(KEY_PAYLOAD, ciphertext);
        mo.put(KEY_SIGNATURE, signature);
        final byte[] encoding = encoder.encodeObject(mo, format);

        // Cache and return the encoding.
        encodings.put(format, encoding);
        return encoding;
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

    /** Payload. */
    private final MslObject payload;
    
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
    
    /** Payload crypto context. */
    protected final ICryptoContext cryptoContext;

    /** Cached encodings. */
    protected final Map<MslEncoderFormat,byte[]> encodings = new HashMap<MslEncoderFormat,byte[]>();
}
