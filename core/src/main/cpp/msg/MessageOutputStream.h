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

#ifndef SRC_MSG_MESSAGEOUTPUTSTREAM_H_
#define SRC_MSG_MESSAGEOUTPUTSTREAM_H_

#include <io/MslEncoderFormat.h>
#include <io/OutputStream.h>
#include <MslConstants.h>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace crypto { class ICryptoContext; }
namespace io { class ByteArrayOutputStream; }
namespace util { class MslContext; }
namespace msg {
class ErrorHeader;
class Header;
class MessageCapabilities;
class MessageHeader;
class PayloadChunk;

/**
 * <p>A MSL message consists of a single MSL header followed by one or more
 * payload chunks carrying application data. Each payload chunk is individually
 * packaged but sequentially ordered. The end of the message is indicated by a
 * payload with no data.</p>
 *
 * <p>No payload chunks may be included in an error message.</p>
 *
 * <p>Data is buffered until {@link #flush()} or {@link #close()} is called.
 * At that point a new payload chunk is created and written out. Closing a
 * {@code MessageOutputStream} does not close the destination output stream in
 * case additional MSL messages will be written.</p>
 *
 * <p>A copy of the payload chunks is kept in-memory and can be retrieved by a
 * a call to {@code getPayloads()} until {@code stopCaching()} is called. This
 * is used to facilitate automatic re-sending of messages.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageOutputStream : public io::OutputStream
{
public:
	virtual ~MessageOutputStream() { close(); }

    /**
     * Construct a new error message output stream. The header is output
     * immediately by calling {@code #flush()} on the destination output
     * stream.
     *
     * @param ctx the MSL context.
     * @param destination MSL output stream.
     * @param header error header.
     * @param format the MSL encoder format.
     * @throws IOException if there is an error writing the header.
     */
    MessageOutputStream(std::shared_ptr<util::MslContext> ctx,
    		std::shared_ptr<io::OutputStream> destination,
			std::shared_ptr<msg::ErrorHeader> header,
			const io::MslEncoderFormat& format);

    /**
     * <p>Construct a new message output stream. The header is output
     * immediately by calling {@code #flush()} on the destination output
     * stream.</p>
     *
     * <p>The most preferred compression algorithm and encoder format supported
     * by the message header will be used. If this is a response, the message
     * header capabilities will already consist of the intersection of the
     * local and remote entity capabiltities.</p>
     *
     * @param ctx the MSL context.
     * @param destination MSL output stream.
     * @param header message header.
     * @param cryptoContext payload data crypto context.
     * @throws IOException if there is an error writing the header.
     */
    MessageOutputStream(std::shared_ptr<util::MslContext> ctx,
    		std::shared_ptr<io::OutputStream> destination,
			std::shared_ptr<msg::MessageHeader> header,
			std::shared_ptr<crypto::ICryptoContext> cryptoContext);

    /**
     * Set the payload chunk compression algorithm that will be used for all
     * future payload chunks. This function will flush any buffered data iff
     * the compression algorithm is being changed.
     *
     * @param compressionAlgo payload chunk compression algorithm. Null for no
     *        compression.
     * @return true if the compression algorithm is supported by the message,
     *         false if it is not.
     * @throws IOException if buffered data could not be flushed. The
     *         compression algorithm will be unchanged.
     * @throws MslInternalException if writing an error message.
     * @see #flush()
     */
    virtual bool setCompressionAlgorithm(const MslConstants::CompressionAlgorithm& compressionAlgo);

    /**
     * @return the message header. Will be null for error messages.
     */
    virtual std::shared_ptr<MessageHeader> getMessageHeader();

    /**
     * @return the error header. Will be null except for error messages.
     */
    virtual std::shared_ptr<ErrorHeader> getErrorHeader();

    /**
     * Returns true if the payload application data is encrypted. This will be
     * true if the entity authentication scheme provides encryption or if
     * session keys were used. Returns false for error messages which do not
     * have any payload chunks.
     *
     * @return true if the payload application data is encrypted. Will be false
     *         for error messages.
     */
    virtual bool encryptsPayloads();

    /**
     * Returns true if the payload application data is integrity protected.
     * This will be true if the entity authentication scheme provides integrity
     * protection or if session keys were used. Returns false for error
     * messages which do not have any payload chunks.
     *
     * @return true if the payload application data is integrity protected.
     *         Will be false for error messages.
     */
    virtual bool protectsPayloadIntegrity();

    /**
     * Returns the payloads sent so far. Once payload caching is turned off
     * this list will always be empty.
     *
     * @return an immutable ordered list of the payloads sent so far.
     */
    virtual std::vector<std::shared_ptr<PayloadChunk>> getPayloads() { return payloads_; }

    /**
     * Turns off caching of any message data (e.g. payloads).
     */
    virtual void stopCaching();

    /**
     * By default the destination output stream is not closed when this message
     * output stream is closed. If it should be closed then this method can be
     * used to dictate the desired behavior.
     *
     * @param close true if the destination output stream should be closed,
     *        false if it should not.
     */
    virtual void closeDestination(bool close) { closeDestination_ = close; }

    /** @inheritDoc */
    virtual void abort();

    /** @inheritDoc */
    virtual bool close();

    /** @inheritDoc */
    virtual size_t write(const ByteArray& data, int timeout = -1) { return write(data, 0, data.size(), timeout); }

    /** @inheritDoc */
    virtual size_t write(const ByteArray& data, size_t off, size_t len, int timeout = -1);
    
    /** @inheritDoc */
    virtual bool flush(int timeout = -1);

protected:

    /**
     * <p>Create new payload chunk.</p>
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
    std::shared_ptr<msg::PayloadChunk> createPayloadChunk(std::shared_ptr<util::MslContext> ctx,
            int64_t sequenceNumber, int64_t messageId, bool endofmsg,
            MslConstants::CompressionAlgorithm compressionAlgo, std::shared_ptr<ByteArray> data,
            std::shared_ptr<crypto::ICryptoContext> cryptoContext);

private:
    /** MSL context. */
    std::shared_ptr<util::MslContext> ctx_;

    /** Destination output stream. */
    std::shared_ptr<io::OutputStream> destination_;
    /** MSL encoder format. */
    io::MslEncoderFormat encoderFormat_;
    /** Message output stream capabilities. */
    std::shared_ptr<MessageCapabilities> capabilities_;
    
    /** Header. */
    std::shared_ptr<Header> header_;
    /** Payload crypto context. */
    std::shared_ptr<crypto::ICryptoContext> cryptoContext_;
    
    /** Paload chunk compression algorithm. */
    MslConstants::CompressionAlgorithm compressionAlgo_;
    /** Current payload sequence number. */
    int64_t payloadSequenceNumber_ = 1;
    /** Current payload chunk data. */
    std::shared_ptr<io::ByteArrayOutputStream> currentPayload_;
    
    /** Stream is aborted. */
    bool aborted_ = false;
    /** Stream is timed out. */
    bool timedout_ = false;
    /** Stream is closed. */
    bool closed_ = false;
    /** True if the destination output stream should be closed. */
    bool closeDestination_ = false;
    
    /** True if caching data. */
    bool caching_ = true;
    /** Ordered list of sent payloads. */
    std::vector<std::shared_ptr<msg::PayloadChunk>> payloads_;
};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_MESSAGEOUTPUTSTREAM_H_ */
