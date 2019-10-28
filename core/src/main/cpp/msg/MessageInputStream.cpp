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

#include <msg/MessageInputStream.h>
#include <IOException.h>
#include <Macros.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <MslMessageException.h>
#include <MslUserAuthException.h>
#include <MslUserIdTokenException.h>
#include <crypto/ICryptoContext.h>
#include <crypto/SessionCryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <io/ByteArrayInputStream.h>
#include <io/MslEncoderFactory.h>
#include <io/MslTokenizer.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyExchangeScheme.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>
#include <msg/ErrorHeader.h>
#include <msg/MessageHeader.h>
#include <msg/MessageInputStream.h>
#include <msg/PayloadChunk.h>
#include <tokens/MasterToken.h>
#include <tokens/TokenFactory.h>
#include <userauth/UserAuthenticationData.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::keyx;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace msg {

namespace {
/**
 * <p>Return the crypto context resulting from key response data contained
 * in the provided header.</p>
 *
 * <p>The {@link MslException}s thrown by this method will not have the
 * entity or user set.</p>
 *
 * @param ctx MSL context.
 * @param header header.
 * @param keyRequestData key request data for key exchange.
 * @return the crypto context or null if the header does not contain key
 *         response data or is for an error message.
 * @throws MslKeyExchangeException if there is an error with the key
 *         request data or key response data or the key exchange scheme is
 *         not supported.
 * @throws MslCryptoException if the crypto context cannot be created.
 * @throws MslEncodingException if there is an error parsing the data.
 * @throws MslMasterTokenException if the master token is not trusted and
 *         needs to be.
 * @throws MslEntityAuthException if there is a problem with the master
 *         token identity.
 */
shared_ptr<ICryptoContext> getKeyxCryptoContext(shared_ptr<MslContext> ctx, shared_ptr<MessageHeader> header, set<shared_ptr<KeyRequestData>> keyRequestData)
{
	// Pull the header data.
	shared_ptr<MessageHeader> messageHeader = header;
	shared_ptr<MasterToken> masterToken = messageHeader->getMasterToken();
	shared_ptr<KeyResponseData> keyResponse = messageHeader->getKeyResponseData();

	// If there is no key response data then return null.
	if (!keyResponse)
		return shared_ptr<ICryptoContext>();

	// If the key response data master token is decrypted then use the
	// master token keys to create the crypto context.
	shared_ptr<MasterToken> keyxMasterToken = keyResponse->getMasterToken();
	if (keyxMasterToken->isDecrypted())
		return make_shared<SessionCryptoContext>(ctx, keyxMasterToken);

	// Perform the key exchange.
	KeyExchangeScheme responseScheme = keyResponse->getKeyExchangeScheme();
	shared_ptr<KeyExchangeFactory> factory = ctx->getKeyExchangeFactory(responseScheme);
	if (!factory)
		throw MslKeyExchangeException(MslError::KEYX_FACTORY_NOT_FOUND, responseScheme.name());

	// Attempt the key exchange but if it fails then try with the next
	// key request data before giving up.
	shared_ptr<IException> keyxException;
	set<shared_ptr<KeyRequestData>>::iterator keyRequests = keyRequestData.begin();
	while (keyRequests != keyRequestData.end()) {
		shared_ptr<KeyRequestData> keyRequest = *keyRequests++;
		KeyExchangeScheme requestScheme = keyRequest->getKeyExchangeScheme();

		// Skip incompatible key request data.
		if (responseScheme != requestScheme)
			continue;

		try {
			return factory->getCryptoContext(ctx, keyRequest, keyResponse, masterToken);
		} catch (const MslKeyExchangeException& e) {
			if (keyRequests == keyRequestData.end()) throw e;
			keyxException = e.clone();
		} catch (const MslEncodingException& e) {
			if (keyRequests == keyRequestData.end()) throw e;
			keyxException = e.clone();
		} catch (const MslMasterTokenException& e) {
			if (keyRequests == keyRequestData.end()) throw e;
			keyxException = e.clone();
		} catch (const MslEntityAuthException& e) {
			if (keyRequests == keyRequestData.end()) throw e;
			keyxException = e.clone();
		}
	}

	// We did not perform a successful key exchange. If we caught an
	// exception then throw that exception now.
	if (keyxException) {
		MslUtils::rethrow(keyxException);
		throw MslInternalException("Unexpected exception caught during key exchange.", *keyxException);
	}

	// If we did not perform a successful key exchange then the
	// payloads will not decrypt properly. Throw an exception.
	stringstream ss;
	ss << "[ ";
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequests = keyRequestData.begin();
		 keyRequests != keyRequestData.end();
		 ++keyRequests)
	{
		ss << *keyRequests << " ";
	}
	ss << "]";
	throw MslKeyExchangeException(MslError::KEYX_RESPONSE_REQUEST_MISMATCH, ss.str());
}
} // namespace anonymous

// Use a value that is unlikely to be a real entity identity.
const std::string UNKNOWN_IDENTITY = "sentinel_value:netflix::msl::msg::MessageInputStream::UNKNOWN_IDENTITY";

MessageInputStream::MessageInputStream(shared_ptr<MslContext> ctx,
    		shared_ptr<InputStream> source,
			set<shared_ptr<KeyRequestData>> keyRequestData,
			map<string,shared_ptr<ICryptoContext>> cryptoContexts)
	: ctx_(ctx)
	, source_(source)
{
	// Parse the header.
	shared_ptr<MslObject> mo;
	try {
		this->tokenizer_ = this->ctx_->getMslEncoderFactory()->createTokenizer(source);
		if (!this->tokenizer_->more())
			throw MslEncodingException(MslError::MESSAGE_DATA_MISSING);
		mo = this->tokenizer_->nextObject();
	} catch (const MslEncoderException& e) {
		throw MslEncodingException(MslError::MSL_PARSE_ERROR, "header", e);
	}
	this->header_ = Header::parseHeader(ctx, mo, cryptoContexts);

	try {
		// For error messages there are no key exchange or payload crypto
		// contexts.
		if (dynamic_pointer_cast<ErrorHeader>(this->header_))
			return;

		// Grab the key exchange crypto context, if any.
		shared_ptr<MessageHeader> messageHeader = dynamic_pointer_cast<MessageHeader>(this->header_);
		this->keyxCryptoContext_ = getKeyxCryptoContext(ctx, messageHeader, keyRequestData);

		// In peer-to-peer mode or in trusted network mode with no key
		// exchange the payload crypto context equals the header crypto
		// context.
		if (ctx->isPeerToPeer() || !this->keyxCryptoContext_)
			this->cryptoContext_ = messageHeader->getCryptoContext();

		// Otherwise the payload crypto context equals the key exchange
		// crypto context.
		else
			this->cryptoContext_ = this->keyxCryptoContext_;

		// If this is a handshake message but it is not renewable or does
		// not contain key request data then reject the message.
		if (messageHeader->isHandshake() &&
			(!messageHeader->isRenewable() || messageHeader->getKeyRequestData().empty()))
		{
			stringstream ss;
			ss << messageHeader;
			throw MslMessageException(MslError::HANDSHAKE_DATA_MISSING, ss.str());
		}

		// If I am in peer-to-peer mode or the master token is verified
		// (i.e. issued by the local entity which is therefore a trusted
		// network server) then perform the master token checks.
		shared_ptr<MasterToken> masterToken = messageHeader->getMasterToken();
		if (masterToken && (ctx->isPeerToPeer() || masterToken->isVerified())) {
			// If the master token has been revoked then reject the
			// message.
			shared_ptr<TokenFactory> factory = ctx->getTokenFactory();
			const MslError revoked = factory->isMasterTokenRevoked(ctx, masterToken);
			if (revoked != MslError::OK)
				throw MslMasterTokenException(revoked, masterToken);

			// If the user ID token has been revoked then reject the
			// message. We know the master token is not null and that it is
			// verified so we assume the user ID token is as well.
			shared_ptr<UserIdToken> userIdToken = messageHeader->getUserIdToken();
			if (userIdToken) {
				const MslError uitRevoked = factory->isUserIdTokenRevoked(ctx, masterToken, userIdToken);
				if (uitRevoked != MslError::OK)
					throw MslUserIdTokenException(uitRevoked, userIdToken);
			}

			// If the master token is expired...
			if (masterToken->isExpired(shared_ptr<Date>())) {
				// If the message is not renewable or does not contain key
				// request data then reject the message.
				if (!messageHeader->isRenewable()) {
					stringstream ss;
					ss << messageHeader;
					throw MslMessageException(MslError::MESSAGE_EXPIRED_NOT_RENEWABLE, ss.str());
				}
				else if (messageHeader->getKeyRequestData().empty()) {
					stringstream ss;
					ss << messageHeader;
					throw MslMessageException(MslError::MESSAGE_EXPIRED_NO_KEYREQUEST_DATA, ss.str());
				}

				// If the master token will not be renewed by the token
				// factory then reject the message.
				//
				// This throws an exception if the master token is not
				// renewable.
				const MslError notRenewable = factory->isMasterTokenRenewable(ctx, masterToken);
				if (notRenewable != MslError::OK)
					throw MslMessageException(notRenewable, "Master token is expired and not renewable.");
			}
		}

		// If the message is non-replayable (it is not from a trusted
		// network server).
		const int64_t nonReplayableId = messageHeader->getNonReplayableId();
		if (nonReplayableId != -1) {
			// ...and does not include a master token then reject the
			// message.
			if (!masterToken) {
				stringstream ss;
				ss << messageHeader;
				throw MslMessageException(MslError::INCOMPLETE_NONREPLAYABLE_MESSAGE, ss.str());
			}

			// If the non-replayable ID is not accepted then notify the
			// sender.
			shared_ptr<TokenFactory> factory = ctx->getTokenFactory();
			const MslError replayed = factory->acceptNonReplayableId(ctx, masterToken, nonReplayableId);
			if (replayed != MslError::OK) {
				stringstream ss;
				ss << messageHeader;
				throw MslMessageException(replayed, ss.str());
			}
		}
	} catch (MslException& e) {
		if (dynamic_pointer_cast<MessageHeader>(this->header_)) {
			shared_ptr<MessageHeader> messageHeader = dynamic_pointer_cast<MessageHeader>(this->header_);
			e.setMasterToken(messageHeader->getMasterToken());
			e.setEntityAuthenticationData(messageHeader->getEntityAuthenticationData());
			e.setUserIdToken(messageHeader->getUserIdToken());
			e.setUserAuthenticationData(messageHeader->getUserAuthenticationData());
			e.setMessageId(messageHeader->getMessageId());
		} else {
			shared_ptr<ErrorHeader> errorHeader = dynamic_pointer_cast<ErrorHeader>(this->header_);
			e.setEntityAuthenticationData(errorHeader->getEntityAuthenticationData());
			e.setMessageId(errorHeader->getMessageId());
		}
		MslUtils::rethrow(e);
	}
}

shared_ptr<MslObject> MessageInputStream::nextMslObject()
{
	// Make sure this message is allowed to have payload chunks.
	shared_ptr<MessageHeader> messageHeader = getMessageHeader();
	if (!messageHeader)
		throw MslInternalException("Read attempted with error message.");

	// If we previously reached the end of the message, don't try to read
	// more.
	if (eom_)
		return shared_ptr<MslObject>();

	// Otherwise read the next MSL object.
	try {
		if (!tokenizer_->more()) {
			eom_ = true;
			return shared_ptr<MslObject>();
		}
		return tokenizer_->nextObject();
	} catch (const MslEncoderException& e) {
		throw MslEncodingException(MslError::MSL_PARSE_ERROR, "payloadchunk", e);
	}
}

shared_ptr<ByteArrayInputStream> MessageInputStream::nextData()
{
	// Make sure this message is allowed to have payload chunks.
	shared_ptr<MessageHeader> messageHeader = getMessageHeader();
	if (!messageHeader)
		throw MslInternalException("Read attempted with error message.");

	// If reading buffered data return the next buffered payload data.
	if (payloadIterator_ != -1 && payloadIterator_ < static_cast<int>(payloads_.size()))
		return payloads_[static_cast<size_t>(payloadIterator_++)];

	// Otherwise read the next payload.
	shared_ptr<MslObject> mo = nextMslObject();
	if (!mo) return shared_ptr<ByteArrayInputStream>();
	shared_ptr<PayloadChunk> payload = make_shared<PayloadChunk>(ctx_, mo, cryptoContext_);

	// Make sure the payload belongs to this message and is the one we are
	// expecting.
	shared_ptr<MasterToken> masterToken = messageHeader->getMasterToken();
	shared_ptr<EntityAuthenticationData> entityAuthData = messageHeader->getEntityAuthenticationData();
	shared_ptr<UserIdToken> userIdToken = messageHeader->getUserIdToken();
	shared_ptr<UserAuthenticationData> userAuthData = messageHeader->getUserAuthenticationData();
	if (payload->getMessageId() != messageHeader->getMessageId()) {
		stringstream ss;
		ss << "payload mid " << payload->getMessageId() << " header mid " << messageHeader->getMessageId();
		MslMessageException e(MslError::PAYLOAD_MESSAGE_ID_MISMATCH, ss.str());
		e.setMasterToken(masterToken);
		e.setEntityAuthenticationData(entityAuthData);
		e.setUserIdToken(userIdToken);
		e.setUserAuthenticationData(userAuthData);
		throw e;
	}
	if (payload->getSequenceNumber() != payloadSequenceNumber_) {
		stringstream ss;
		ss << "payload seqno " << payload->getSequenceNumber() << " expected seqno " << payloadSequenceNumber_;
		MslMessageException e(MslError::PAYLOAD_SEQUENCE_NUMBER_MISMATCH, ss.str());
		e.setMasterToken(masterToken);
		e.setEntityAuthenticationData(entityAuthData);
		e.setUserIdToken(userIdToken);
		e.setUserAuthenticationData(userAuthData);
		throw e;
	}
	++payloadSequenceNumber_;

	// FIXME remove this logic once the old handshake inference logic
	// is no longer supported.
	// Check for a handshake if this is the first payload chunk.
	if (handshake_ == -1) {
		handshake_ = (messageHeader->isRenewable() && !messageHeader->getKeyRequestData().empty() &&
				payload->isEndOfMessage() && payload->getData()->size() == 0)
			? 1
			: 0;
	}

	// Check for end of message.
	if (payload->isEndOfMessage())
		eom_ = true;

	// Save the payload in the buffer and return it. We have to unset the
	// payload iterator since we're adding to the payloads list.
	shared_ptr<ByteArrayInputStream> data = make_shared<ByteArrayInputStream>(payload->getData());
	payloads_.push_back(data);
	payloadIterator_ = -1;
	return data;
}

shared_ptr<PayloadChunk> MessageInputStream::createPayloadChunk(
                shared_ptr<MslContext> ctx,
                shared_ptr<MslObject> mo,
                shared_ptr<ICryptoContext> cryptoContext)
{
	return make_shared<PayloadChunk>(ctx, mo, cryptoContext);
}

bool MessageInputStream::isHandshake()
{
	shared_ptr<MessageHeader> messageHeader = getMessageHeader();

	// Error messages are not handshake messages.
	if (!messageHeader) return false;

	// If the message header has its handshake flag set return true.
	if (messageHeader->isHandshake()) return true;

	// If we haven't read a payload we don't know if this is a handshake
	// message or not. This also implies the current payload is null.
	if (handshake_ == -1) {
		try {
			// nextData() will set the value of handshake if a payload is
			// found.
			currentPayload_ = nextData();
			if (!currentPayload_)
				handshake_ = 0;
		} catch (const MslException& e) {
			// Save the exception to be thrown next time read() is called.
			readException_ = make_shared<IOException>("Error reading the payload chunk.", e);
			throw e;
		}
	}

	// Return the current handshake status.
	return (handshake_ == 1) ? true : false;
}

shared_ptr<MessageHeader> MessageInputStream::getMessageHeader()
{
	if (dynamic_pointer_cast<MessageHeader>(header_))
		return dynamic_pointer_cast<MessageHeader>(header_);
	return shared_ptr<MessageHeader>();
}

shared_ptr<ErrorHeader> MessageInputStream::getErrorHeader()
{
	if (dynamic_pointer_cast<ErrorHeader>(header_))
		return dynamic_pointer_cast<ErrorHeader>(header_);
	return shared_ptr<ErrorHeader>();
}

string MessageInputStream::getIdentity()
{
	shared_ptr<MessageHeader> messageHeader = getMessageHeader();
	if (messageHeader) {
		shared_ptr<MasterToken> masterToken = messageHeader->getMasterToken();
		if (masterToken)
			return masterToken->getIdentity();
		return messageHeader->getEntityAuthenticationData()->getIdentity();
	}
	shared_ptr<ErrorHeader> errorHeader = getErrorHeader();
	return errorHeader->getEntityAuthenticationData()->getIdentity();
}

shared_ptr<MslUser> MessageInputStream::getUser()
{
	shared_ptr<MessageHeader> messageHeader = getMessageHeader();
	if (!messageHeader)
		return shared_ptr<MslUser>();
	return messageHeader->getUser();
}

bool MessageInputStream::encryptsPayloads()
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

bool MessageInputStream::protectsPayloadIntegrity()
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

void MessageInputStream::abort()
{
	aborted_ = true;
	source_->abort();
}

bool MessageInputStream::close(int timeout)
{
    // Close the tokenizer.
    try {
        tokenizer_->close();
    } catch (const MslEncoderException& e) {
        // Ignore exceptions.
    }

	// Only close the source if instructed to do so because we might want
	// to reuse the connection.
	if (closeSource_) {
		source_->close(timeout);
	}

	// Otherwise if this is not a handshake message or error message then
	// consume all payloads that may still be on the source input stream.
	else {
		try {
			if (!isHandshake() && getMessageHeader()) {
				while (true) {
					shared_ptr<ByteArrayInputStream> data = nextData();
					if (!data) break;
				}
			}
		} catch (const MslException& e) {
			// Ignore exceptions.
		}
	}

	// Success.
	return true;
}

void MessageInputStream::mark(size_t readlimit)
{
    // Remember the read limit, reset the read count.
    readlimit_ = readlimit;
    readcount_ = 0;

    // Start buffering.
    buffering_ = true;

	// If there is a current payload...
	if (currentPayload_) {
		// Remove all buffered data earlier than the current payload.
		size_t offset = 0;
		while (offset < payloads_.size() && payloads_[offset] != currentPayload_)
			++offset;
		payloads_.erase(payloads_.begin(), payloads_.begin() + static_cast<ptrdiff_t>(offset));

		// Add the current payload if it was not already buffered.
		if (payloads_.size() == 0)
		    payloads_.push_back(currentPayload_);

		// Reset the iterator to continue reading buffered data from the
		// current payload.
		payloadIterator_ = 0;
		currentPayload_ = payloads_[static_cast<size_t>(payloadIterator_++)];

		// Set the new mark point on the current payload.
		currentPayload_->mark(readlimit);
		return;
	}

	// Otherwise we've either read to the end or haven't read anything at
	// all yet. Discard all buffered data.
	payloadIterator_ = -1;
	payloads_.clear();
}

int MessageInputStream::read(ByteArray& out, size_t offset, size_t len, int timeout)
{
	// Check if aborted.
	if (aborted_)
		return 0;

	// Throw any cached read exception.
	if (readException_) {
		shared_ptr<IOException> e = readException_;
		readException_.reset();
		throw *e;
	}

	// Return end of stream immediately for handshake messages.
	try {
		if (isHandshake())
			return -1;
	} catch (const MslException& e) {
		// FIXME
		// Unset the read exception since we are going to throw it right
		// now. This logic can go away once the old handshake logic is
		// removed.
		readException_.reset();
		throw IOException("Error reading the payload chunk.", e);
	}

	// Read from payloads until we are done or cannot read anymore.
	size_t bytesRead = 0;
	while (bytesRead < len) {
		int read = (currentPayload_) ? currentPayload_->read(out, offset + bytesRead, len - bytesRead, timeout) : -1;

		// If we read some data continue.
		if (read != -1) {
			bytesRead += static_cast<size_t>(read);
			continue;
		}

		// Otherwise grab the next payload data.
		try {
			currentPayload_ = nextData();
			if (!currentPayload_)
				break;
		} catch (const MslException& e) {
			// If we already read some data return it and save the
			// exception to be thrown next time read() is called.
			shared_ptr<IOException> ioe = make_shared<IOException>("Error reading the payload chunk.", e);
			if (bytesRead > 0) {
				readException_ = ioe;
				return static_cast<int>(bytesRead);
			}

			// Otherwise throw the exception now.
			throw *ioe;
		}
	}

	// If nothing was read (but something was requested) return end of
	// stream.
	if (bytesRead == 0 && len > 0)
		return -1;

	// If buffering data increment the read count.
	if (buffering_) {
	    readcount_ += bytesRead;

	    // If the read count exceeds the read limit stop buffering payloads
	    // and reset the read count and limit, but retain the payload
	    // iterator as we need to continue reading from any buffered data.
	    if (readcount_ > readlimit_) {
	        buffering_ = false;
	        readcount_ = readlimit_ = 0;
	    }
	}

	// Return the number of bytes read.
	return static_cast<int>(bytesRead);
}

void MessageInputStream::reset()
{
    // Do nothing if we are not buffering.
    if (!buffering_)
        return;

    // Reset all payloads and initialize the payload iterator.
    //
    // We need to reset the payloads since we are going to re-read them and
    // want the correct value returned when queried for available bytes.
	for (size_t i = 0; i < payloads_.size(); ++i)
		payloads_[i]->reset();
	payloadIterator_ = 0;
	if (payloads_.size() > 0) {
		currentPayload_ = payloads_[static_cast<size_t>(payloadIterator_++)];
	} else {
		currentPayload_.reset();
	}

	// Reset the read count.
	readcount_ = 0;
}

}}} // namespace netflix::msl::msg
