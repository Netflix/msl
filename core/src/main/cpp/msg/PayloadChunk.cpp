/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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

#include <msg/PayloadChunk.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <MslMessageException.h>
#include <crypto/ICryptoContext.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <util/MslCompression.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <string>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;
using namespace netflix::msl::MslConstants;

namespace netflix {
namespace msl {
namespace msg {

namespace {
/** Key payload. */
const string KEY_PAYLOAD = "payload";
/** Key signature. */
const string KEY_SIGNATURE = "signature";

// payload
/** Key sequence number. */
const string KEY_SEQUENCE_NUMBER = "sequencenumber";
/** Key message ID. */
const string KEY_MESSAGE_ID = "messageid";
/** Key end of message. */
const string KEY_END_OF_MESSAGE = "endofmsg";
/** Key compression algorithm. */
const string KEY_COMPRESSION_ALGORITHM = "compressionalgo";
/** Key encrypted data. */
const string KEY_DATA = "data";
} // namespace anonymous

PayloadChunk::PayloadChunk(shared_ptr<MslContext> ctx,
		int64_t sequenceNumber, int64_t messageId, bool endofmsg,
		CompressionAlgorithm compressionAlgo, shared_ptr<ByteArray> data,
		shared_ptr<ICryptoContext> cryptoContext)
{
	// Verify sequence number and message ID.
	if (sequenceNumber < 0 || sequenceNumber > MslConstants::MAX_LONG_VALUE) {
		stringstream ss;
		ss << "Sequence number " << sequenceNumber << " is outside the valid range.";
		throw MslInternalException(ss.str());
	}
	if (messageId < 0 || messageId > MslConstants::MAX_LONG_VALUE) {
		stringstream ss;
		ss << "Message ID " << messageId << " is outside the valid range.";
		throw MslInternalException(ss.str());
	}

	// Optionally compress the application data.
	shared_ptr<ByteArray> payloadData;
	if (compressionAlgo != CompressionAlgorithm::NOCOMPRESSION) {
		shared_ptr<ByteArray> compressed = MslCompression::compress(compressionAlgo, *data);

		// Only use compression if the compressed data is smaller than the
		// uncompressed data.
		if (compressed && compressed->size() < data->size()) {
			this->compressionAlgo = compressionAlgo;
			payloadData = compressed;
		} else {
			this->compressionAlgo = CompressionAlgorithm::NOCOMPRESSION;
			payloadData = data;
		}
	} else {
		this->compressionAlgo = CompressionAlgorithm::NOCOMPRESSION;
		payloadData = data;
	}

	// Set the payload properties.
	this->sequenceNumber = sequenceNumber;
	this->messageId = messageId;
	this->endofmsg = endofmsg;
	this->data = data;

	// Construct the payload.
	const shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
	this->payload = encoder->createObject();
	this->payload->put(KEY_SEQUENCE_NUMBER, this->sequenceNumber);
	this->payload->put(KEY_MESSAGE_ID, this->messageId);
	if (this->endofmsg) this->payload->put(KEY_END_OF_MESSAGE, this->endofmsg);
	if (this->compressionAlgo != CompressionAlgorithm::NOCOMPRESSION) this->payload->put(KEY_COMPRESSION_ALGORITHM, this->compressionAlgo.name());
	this->payload->put(KEY_DATA, payloadData);

	// Save the crypto context.
	this->cryptoContext = cryptoContext;
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
PayloadChunk::PayloadChunk(shared_ptr<MslContext> ctx,
		shared_ptr<MslObject> payloadChunkMo,
		shared_ptr<ICryptoContext> cryptoContext)
{
	const shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();

	// Save the crypto context.
	this->cryptoContext = cryptoContext;

	// Verify the data.
	shared_ptr<ByteArray> ciphertext;
	try {
		ciphertext = payloadChunkMo->getBytes(KEY_PAYLOAD);
		shared_ptr<ByteArray> signature = payloadChunkMo->getBytes(KEY_SIGNATURE);
		if (!cryptoContext->verify(ciphertext, signature, encoder))
			throw MslCryptoException(MslError::PAYLOAD_VERIFICATION_FAILED);
	} catch (const MslEncoderException& e) {
		stringstream ss;
		ss << "payload chunk " << payloadChunkMo;
		throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
	}

	// Pull the payload data.
	shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
	try {
		this->payload = encoder->parseObject(plaintext);
		this->sequenceNumber = payload->getLong(KEY_SEQUENCE_NUMBER);
		if (this->sequenceNumber < 0 || this->sequenceNumber > MslConstants::MAX_LONG_VALUE) {
			stringstream ss;
			ss << "payload chunk payload " << payload;
			throw MslException(MslError::PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE, ss.str());
		}
		this->messageId = payload->getLong(KEY_MESSAGE_ID);
		if (this->messageId < 0 || this->messageId > MslConstants::MAX_LONG_VALUE) {
			stringstream ss;
			ss << "payload chunk payload " << payload;
			throw MslException(MslError::PAYLOAD_MESSAGE_ID_OUT_OF_RANGE, ss.str());
		}
		this->endofmsg = (payload->has(KEY_END_OF_MESSAGE)) ? payload->getBoolean(KEY_END_OF_MESSAGE) : false;
		if (payload->has(KEY_COMPRESSION_ALGORITHM)) {
			const string algoName = payload->getString(KEY_COMPRESSION_ALGORITHM);
			try {
				this->compressionAlgo = CompressionAlgorithm::fromString(algoName);
			} catch (const IllegalArgumentException& e) {
				throw MslMessageException(MslError::UNIDENTIFIED_COMPRESSION, algoName, e);
			}
		} else {
			this->compressionAlgo = CompressionAlgorithm::NOCOMPRESSION;
		}
		shared_ptr<ByteArray> compressedData = payload->getBytes(KEY_DATA);
		if (compressedData->size() == 0) {
			if (!this->endofmsg)
				throw MslMessageException(MslError::PAYLOAD_DATA_MISSING);
			this->data = make_shared<ByteArray>();
		} else if (this->compressionAlgo == CompressionAlgorithm::NOCOMPRESSION) {
			this->data = compressedData;
		} else {
			this->data = MslCompression::uncompress(compressionAlgo, *compressedData);
		}
	} catch (const MslEncoderException& e) {
		stringstream ss;
		ss << "payload chunk payload " + *Base64::encode(plaintext);
		throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
	}
}

/** @inheritDoc */
shared_ptr<ByteArray> PayloadChunk::toMslEncoding(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format) const
{
	// Return any cached encoding.
	map<MslEncoderFormat, shared_ptr<ByteArray>>::const_iterator it = encodings.find(format);
	if (it != encodings.end())
		return it->second;

	// Encrypt the payload.
	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payload, format);
	shared_ptr<ByteArray> ciphertext;
	try{
		ciphertext = cryptoContext->encrypt(plaintext, encoder, format);
	} catch (const MslCryptoException& e) {
		throw MslEncoderException("Error encrypting the payload.", e);
	}

	// Sign the payload.
	shared_ptr<ByteArray> signature;
	try {
		signature = cryptoContext->sign(ciphertext, encoder, format);
	} catch (const MslCryptoException& e) {
		throw MslEncoderException("Error signing the payload.", e);
	}

	// Encode the payload chunk.
	const shared_ptr<MslObject> mo = encoder->createObject();
	mo->put(KEY_PAYLOAD, ciphertext);
	mo->put(KEY_SIGNATURE, signature);
	shared_ptr<ByteArray> encoding = encoder->encodeObject(mo, format);

	// Cache and return the encoding.
	encodings.insert(make_pair(format, encoding));
	return encoding;
}

namespace {

// In this translation unit, make comparisons of shared_ptr defer to the
// underlying type's operator==. This is required to make comparisons work
// correctly with std::set containers that contain shared_ptr.
template <typename T>
bool operator==(const shared_ptr<T>& a, const shared_ptr<T>& b)
{
    if (!a && !b)
        return true;
    if ((!a && b) || (a && !b))
        return false;
    return *a == *b;
}

} // namespace anonymous

bool PayloadChunk::equals(shared_ptr<const PayloadChunk> that) const
{
	if (!that) return false;
	if (this == that.get()) return true;
	return sequenceNumber == that->sequenceNumber &&
			messageId == that->messageId &&
			endofmsg == that->endofmsg &&
			compressionAlgo == that->compressionAlgo &&
			*data == *that->data;
}

bool operator==(const PayloadChunk& a, const PayloadChunk& b)
{
	shared_ptr<const PayloadChunk> ap(&a, &MslUtils::nullDeleter<PayloadChunk>);
	shared_ptr<const PayloadChunk> bp(&b, &MslUtils::nullDeleter<PayloadChunk>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl::msg
