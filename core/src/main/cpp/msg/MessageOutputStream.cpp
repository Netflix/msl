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

#include <msg/MessageOutputStream.h>
#include <IOException.h>
#include <Macros.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <crypto/ICryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <io/ByteArrayOutputStream.h>
#include <io/MslEncoderFactory.h>
#include <keyx/KeyResponseData.h>
#include <msg/ErrorHeader.h>
#include <msg/Header.h>
#include <msg/MessageCapabilities.h>
#include <msg/MessageHeader.h>
#include <msg/PayloadChunk.h>
#include <tokens/MasterToken.h>
#include <util/MslContext.h>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::keyx;
using namespace netflix::msl::msg;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;
using namespace netflix::msl::MslConstants;

namespace netflix {
namespace msl {
namespace msg {

MessageOutputStream::MessageOutputStream(shared_ptr<MslContext> ctx,
		shared_ptr<OutputStream> destination,
		shared_ptr<ErrorHeader> header,
		const MslEncoderFormat& format)
	: ctx_(ctx)
	, destination_(destination)
	, encoderFormat_(format)
	, capabilities_(ctx->getMessageCapabilities())
	, header_(header)
	, compressionAlgo_(CompressionAlgorithm::NOCOMPRESSION)
	, currentPayload_(make_shared<ByteArrayOutputStream>())
{
	// Encode the header.
	shared_ptr<ByteArray> encoding;
	try {
		shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
		encoding = header->toMslEncoding(encoder, format);
	} catch (const MslEncoderException& e) {
		throw IOException("Error encoding the error header.", e);
	}

	const size_t numWritten = destination_->write(*encoding);
	if (numWritten < encoding->size() && !aborted_) {
		timedout_ = true;
		return;
	}
	const bool flushed = destination_->flush();
	timedout_ = (!flushed && !aborted_);
}

MessageOutputStream::MessageOutputStream(shared_ptr<MslContext> ctx,
		shared_ptr<OutputStream> destination,
		shared_ptr<MessageHeader> header,
		shared_ptr<ICryptoContext> cryptoContext)
	: ctx_(ctx)
	, destination_(destination)
	, capabilities_(header->getMessageCapabilities())
	, header_(header)
	, cryptoContext_(cryptoContext)
	, currentPayload_(make_shared<ByteArrayOutputStream>())
{
	shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();

	// Identify the compression algorithm and encoder format.
	if (capabilities_) {
		set<CompressionAlgorithm> compressionAlgos = capabilities_->getCompressionAlgorithms();
		compressionAlgo_ = CompressionAlgorithm::getPreferredAlgorithm(compressionAlgos);
		set<MslEncoderFormat> encoderFormats = capabilities_->getEncoderFormats();
		encoderFormat_ = encoder->getPreferredFormat(encoderFormats);
	} else {
		compressionAlgo_ = CompressionAlgorithm::NOCOMPRESSION;
		encoderFormat_ = encoder->getPreferredFormat();
	}

	// Encode the header.
	shared_ptr<ByteArray> encoding;
	try {
		encoding = header->toMslEncoding(encoder, encoderFormat_);
	} catch (const MslEncoderException& e) {
		throw IOException("Error encoding the message header.", e);
	}

	size_t numWritten = destination_->write(*encoding);
	if (numWritten < encoding->size() && !aborted_) {
		timedout_ = true;
		return;
	}
	bool flushed = destination_->flush();
	timedout_ = (!flushed && !aborted_);
}


bool MessageOutputStream::setCompressionAlgorithm(const CompressionAlgorithm& compressionAlgo)
{
	// Make sure this is not an error message,
	shared_ptr<MessageHeader> messageHeader = getMessageHeader();
	if (!messageHeader)
		throw MslInternalException("Cannot write payload data for an error message.");

	// Make sure the message is capable of using the compression algorithm.
	if (compressionAlgo != CompressionAlgorithm::NOCOMPRESSION) {
		if (!capabilities_)
			return false;
		const set<CompressionAlgorithm> compressionAlgos = capabilities_->getCompressionAlgorithms();
		set<CompressionAlgorithm>::const_iterator found = compressionAlgos.find(compressionAlgo);
		if (found == compressionAlgos.end())
			return false;
	}

	if (compressionAlgo_ != compressionAlgo)
		flush();
	compressionAlgo_ = compressionAlgo;
	return true;
}

shared_ptr<MessageHeader> MessageOutputStream::getMessageHeader() {
	if (dynamic_pointer_cast<MessageHeader>(header_))
		return dynamic_pointer_cast<MessageHeader>(header_);
	return shared_ptr<MessageHeader>();
}

shared_ptr<ErrorHeader> MessageOutputStream::getErrorHeader() {
	if (dynamic_pointer_cast<ErrorHeader>(header_))
		return dynamic_pointer_cast<ErrorHeader>(header_);
	return shared_ptr<ErrorHeader>();
}

bool MessageOutputStream::encryptsPayloads()
{
    // Return false for error messages.
    shared_ptr<MessageHeader> messageHeader = getMessageHeader();
    if (!messageHeader)
        return false;

    // If the message uses entity authentication data for an entity
    // authentication scheme that provides encryption, return true.
    shared_ptr<EntityAuthenticationData> entityAuthData = messageHeader->getEntityAuthenticationData();
    if (entityAuthData && entityAuthData->getScheme().encrypts())
        return true;

    // If the message uses a master token, return true.
    shared_ptr<MasterToken> masterToken = messageHeader->getMasterToken();
    if (masterToken)
        return true;

    // If the message includes key response data, return true.
    shared_ptr<KeyResponseData> keyResponseData = messageHeader->getKeyResponseData();
    if (keyResponseData)
        return true;

    // Otherwise return false.
    return false;
}

bool MessageOutputStream::protectsPayloadIntegrity()
{
    // Return false for error messages.
    shared_ptr<MessageHeader> messageHeader = getMessageHeader();
    if (!messageHeader)
        return false;

    // If the message uses entity authentication data for an entity
    // authentication scheme that provides integrity protection, return
    // true.
    shared_ptr<EntityAuthenticationData> entityAuthData = messageHeader->getEntityAuthenticationData();
    if (entityAuthData && entityAuthData->getScheme().protectsIntegrity())
        return true;

    // If the message uses a master token, return true.
    shared_ptr<MasterToken> masterToken = messageHeader->getMasterToken();
    if (masterToken)
        return true;

    // If the message includes key response data, return true.
    shared_ptr<KeyResponseData> keyResponseData = messageHeader->getKeyResponseData();
    if (keyResponseData)
        return true;

    // Otherwise return false.
    return false;
}

void MessageOutputStream::stopCaching()
{
	caching_ = false;
	payloads_.clear();
}

void MessageOutputStream::abort()
{
	aborted_ = true;
	destination_->abort();
}

bool MessageOutputStream::close()
{
	// Check if already aborted or timed out.
	if (aborted_ || timedout_) return false;

	// If already closed return true.
	if (closed_) return true;

	// Send a final payload that can be used to identify the end of data.
	// This is done by setting closed equal to true while the current
	// payload not null.
	closed_ = true;
	flush();
	currentPayload_.reset();

	// Only close the destination if instructed to do so because we might
	// want to reuse the connection.
	if (closeDestination_)
		return destination_->close();
	return true;
}

bool MessageOutputStream::flush(int timeout)
{
	// Check if already aborted or timed out.
	if (aborted_ || timedout_) return false;

	// If the current payload is null, we are already closed.
	if (!currentPayload_) return true;

	// If we are not closed, and there is no data then we have nothing to
	// send.
	if (!closed_ && currentPayload_->size() == 0) return true;

	// This is a no-op for error messages and handshake messages.
	shared_ptr<MessageHeader> messageHeader = getMessageHeader();
	if (!messageHeader || messageHeader->isHandshake()) return true;

	// Otherwise we are closed and need to send any buffered data as the
	// last payload. If there is no buffered data, we still need to send a
	// payload with the end of message flag set.
	try {
		shared_ptr<ByteArray> data = currentPayload_->toByteArray();
		shared_ptr<PayloadChunk> chunk = createPayloadChunk(ctx_, payloadSequenceNumber_,
                        messageHeader->getMessageId(), closed_, compressionAlgo_, data, cryptoContext_);
		if (caching_) payloads_.push_back(chunk);
		shared_ptr<MslEncoderFactory> encoder = ctx_->getMslEncoderFactory();
		shared_ptr<ByteArray> encoding = chunk->toMslEncoding(encoder, encoderFormat_);
		size_t written = destination_->write(*encoding, timeout);
		if (written < encoding->size())
			return false;
		if (!destination_->flush())
			return false;
		++payloadSequenceNumber_;

		// If we are closed, get rid of the current payload. This prevents
		// us from sending any more payloads. Otherwise reset it for reuse.
		if (closed_)
			currentPayload_.reset();
		else
			currentPayload_->reset();
	} catch (const MslEncoderException& e) {
		stringstream ss;
		ss << "Error encoding payload chunk [sequence number " << payloadSequenceNumber_ << "].";
		throw IOException(ss.str(), e);
	} catch (const MslCryptoException& e) {
		stringstream ss;
		ss << "Error encrypting payload chunk [sequence number " << payloadSequenceNumber_ << "].";
		throw IOException(ss.str(), e);
	} catch (const MslException& e) {
		stringstream ss;
		ss << "Error compressing payload chunk [sequence number " << payloadSequenceNumber_ << "].";
		throw IOException(ss.str(), e);
	}

	// Success.
	return true;
}

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
std::shared_ptr<PayloadChunk> MessageOutputStream::createPayloadChunk(std::shared_ptr<util::MslContext> ctx,
			int64_t sequenceNumber, int64_t messageId, bool endofmsg,
			MslConstants::CompressionAlgorithm compressionAlgo, std::shared_ptr<ByteArray> data,
			std::shared_ptr<crypto::ICryptoContext> cryptoContext)
{
	return make_shared<PayloadChunk>(ctx, sequenceNumber, messageId, endofmsg, compressionAlgo, data, cryptoContext);
}

size_t MessageOutputStream::write(const ByteArray& data, size_t off, size_t len, int timeout)
{
	// Return immediately if already aborted or timed out.
	if (aborted_ || timedout_)
		return 0;

	// Fail if closed.
	if (closed_)
		throw IOException("Message output stream already closed.");

	// Make sure this is not an error message or handshake message.
	shared_ptr<MessageHeader> messageHeader = getMessageHeader();
	if (!messageHeader)
		throw MslInternalException("Cannot write payload data for an error message.");
	if (messageHeader->isHandshake())
		throw MslInternalException("Cannot write payload data for a handshake message.");

	// Append data.
	return currentPayload_->write(data, off, len, timeout);
}

}}} // namespace netflix::msl::msg
