/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_MSG_PAYLOADCHUNK_H_
#define SRC_MSG_PAYLOADCHUNK_H_

#include <MslConstants.h>
#include <io/MslEncodable.h>
#include <map>
#include <memory>

namespace netflix {
namespace msl {

typedef std::vector<uint8_t> ByteArray;

namespace crypto { class ICryptoContext; }
namespace io { class MslObject; }
namespace util { class MslContext; }
namespace msg {

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
class PayloadChunk : public io::MslEncodable
{
public:
	virtual ~PayloadChunk() {}

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
    PayloadChunk(std::shared_ptr<util::MslContext> ctx,
    		int64_t sequenceNumber, int64_t messageId, bool endofmsg,
			MslConstants::CompressionAlgorithm compressionAlgo, std::shared_ptr<ByteArray> data,
			std::shared_ptr<crypto::ICryptoContext> cryptoContext);

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
    PayloadChunk(std::shared_ptr<util::MslContext> ctx,
    		std::shared_ptr<io::MslObject> payloadChunkMo,
			std::shared_ptr<crypto::ICryptoContext> cryptoContext);

    /**
     * @return the sequence number.
     */
    int64_t getSequenceNumber() const { return sequenceNumber; }

    /**
     * @return the message ID.
     */
    int64_t getMessageId() const { return messageId; }

    /**
     * @return true if this is the last payload chunk of the message.
     */
    bool isEndOfMessage() const { return endofmsg; }

    /**
     * @return the compression algorithm. May be {@code null} if not
     *         not compressed.
     */
    MslConstants::CompressionAlgorithm getCompressionAlgo() const { return compressionAlgo; }

    /**
     * Returns the application data if we were able to decrypt it.
     *
     * @return the chunk application data. May be empty (zero-length).
     */
    std::shared_ptr<ByteArray> getData() const { return data; }

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    /** @inheritDoc */
    bool equals(std::shared_ptr<const PayloadChunk> other) const;

protected:
    /** Payload crypto context. */
    std::shared_ptr<crypto::ICryptoContext> cryptoContext;

    /** Cached encodings. */
    mutable std::map<io::MslEncoderFormat,std::shared_ptr<ByteArray>> encodings;

private:
    /** Payload. */
    std::shared_ptr<io::MslObject> payload;

    /** Sequence number. */
    int64_t sequenceNumber;
    /** Message ID. */
    int64_t messageId;
    /** End of message flag. */
    bool endofmsg;
    /** Compression algorithm. */
    MslConstants::CompressionAlgorithm compressionAlgo;
    /** The application data. */
    std::shared_ptr<ByteArray> data;
};

/*
* Non-member deep comparison operators
*/
bool operator==(const PayloadChunk& a, const PayloadChunk& b);
inline bool operator!=(const PayloadChunk& a, const PayloadChunk& b) { return !(a == b); }

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_PAYLOADCHUNK_H_ */
