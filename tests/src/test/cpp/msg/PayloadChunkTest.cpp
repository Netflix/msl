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

#include <gtest/gtest.h>
#include <msg/PayloadChunk.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <MslMessageException.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/Key.h>
#include <crypto/Random.h>
#include <crypto/SymmetricCryptoContext.h>
#include <util/MslCompression.h>
#include <fstream>
#include <memory>
#include <sstream>

#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::msg;
using namespace netflix::msl::util;
using namespace netflix::msl::MslConstants;

namespace netflix {
namespace msl {
namespace msg {

namespace {
/** RAW data file. */
const string DATAFILE = "src/test/resources/pg1112.txt";

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

class PayloadChunkTest : public ::testing::Test
{
public:
	PayloadChunkTest()
		: ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
		, encoder(ctx->getMslEncoderFactory())
		, format(MslEncoderFormat::JSON)
	{
		shared_ptr<ByteArray> encryptionBytes = make_shared<ByteArray>(16);
		shared_ptr<ByteArray> hmacBytes = make_shared<ByteArray>(32);
		random.nextBytes(*encryptionBytes);
		random.nextBytes(*hmacBytes);
		ENCRYPTION_KEY = SecretKey(encryptionBytes, JcaAlgorithm::AES);
		HMAC_KEY = SecretKey(hmacBytes, JcaAlgorithm::HMAC_SHA256);
		SecretKey nullKey;
		CRYPTO_CONTEXT = make_shared<SymmetricCryptoContext>(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, HMAC_KEY, nullKey);

		DATA_STRING = "We have to use some data that is compressible, otherwise payloads will not always use the compression we request.";
		DATA = make_shared<ByteArray>(DATA_STRING.begin(), DATA_STRING.end());

		// Load the raw file.
		stringstream rawos;
		ifstream raw(DATAFILE.c_str(), ios::binary);
		if (raw) {
			raw.seekg(0, ios::end);
			streampos length = raw.tellg();
			raw.seekg(0, ios::beg);
			rawdata->resize(static_cast<size_t>(length));
			raw.read(reinterpret_cast<char*>(&(*rawdata)[0]), length);
			raw.close();
		} else {
			throw MslInternalException("Unable to read " + DATAFILE + ".");
		}
	}

protected:
    const string CRYPTO_CONTEXT_ID = "cryptoContextId";
    SecretKey ENCRYPTION_KEY;
    SecretKey HMAC_KEY;
    SecretKey NULL_KEY;

    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    /** MSL encoder format. */
    const MslEncoderFormat format;
    /** Random. */
    Random random;

    const int64_t SEQ_NO = 1;
    const int64_t MSG_ID = 42;
    const bool END_OF_MSG = false;
    string DATA_STRING;
    shared_ptr<ByteArray> DATA = make_shared<ByteArray>();
    shared_ptr<ICryptoContext> CRYPTO_CONTEXT;

    /** Raw data. */
    shared_ptr<ByteArray> rawdata = make_shared<ByteArray>();
};

TEST_F(PayloadChunkTest, ctors)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
	EXPECT_EQ(END_OF_MSG, chunk->isEndOfMessage());
	EXPECT_EQ(DATA, chunk->getData());
	EXPECT_EQ(CompressionAlgorithm::NOCOMPRESSION, chunk->getCompressionAlgo());
	EXPECT_EQ(MSG_ID, chunk->getMessageId());
	EXPECT_EQ(SEQ_NO, chunk->getSequenceNumber());
	shared_ptr<ByteArray> encode = chunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(encode->size() > 0);

	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, encoder->parseObject(encode), CRYPTO_CONTEXT);
	EXPECT_EQ(chunk->isEndOfMessage(), moChunk->isEndOfMessage());
	EXPECT_EQ(*chunk->getData(), *moChunk->getData());
	EXPECT_EQ(chunk->getMessageId(), moChunk->getMessageId());
	EXPECT_EQ(chunk->getSequenceNumber(), moChunk->getSequenceNumber());
	shared_ptr<ByteArray> moEncode = moChunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(moEncode->size() > 0);
	// The two payload chunk encodings will not be equal because the
	// ciphertext and signature will be generated on-demand.
}

TEST_F(PayloadChunkTest, negativeSequenceNumberCtor)
{
	try {
		const int64_t sequenceNumber = -1;
		make_shared<PayloadChunk>(ctx, sequenceNumber, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(PayloadChunkTest, tooLargeSequenceNumberCtor)
{
	try {
        const int64_t sequenceNumber = MslConstants::MAX_LONG_VALUE + 1;
        make_shared<PayloadChunk>(ctx, sequenceNumber, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslInternalException& e) {
    }
}

TEST_F(PayloadChunkTest, negativeMessageIdCtor)
{
	try {
		const int64_t messageId = -1;
		make_shared<PayloadChunk>(ctx, SEQ_NO, messageId, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(PayloadChunkTest, tooLargeMessageIdCtor)
{
	try {
		const int64_t messageId = MslConstants::MAX_LONG_VALUE + 1;
		make_shared<PayloadChunk>(ctx, SEQ_NO, messageId, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(PayloadChunkTest, mslObject)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
	shared_ptr<ByteArray> encode = chunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(encode->size() > 0);

	shared_ptr<MslObject> mo = encoder->parseObject(encode);
	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
	EXPECT_TRUE(CRYPTO_CONTEXT->verify(ciphertext, signature, encoder));
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);

	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);
	EXPECT_EQ(SEQ_NO, payloadMo->getLong(KEY_SEQUENCE_NUMBER));
	EXPECT_EQ(MSG_ID, payloadMo->getLong(KEY_MESSAGE_ID));
	EXPECT_EQ(END_OF_MSG, payloadMo->optBoolean(KEY_END_OF_MESSAGE));
	EXPECT_FALSE(payloadMo->has(KEY_COMPRESSION_ALGORITHM));
	EXPECT_EQ(*DATA, *payloadMo->getBytes(KEY_DATA));
}

TEST_F(PayloadChunkTest, gzipCtors)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	EXPECT_EQ(END_OF_MSG, chunk->isEndOfMessage());
	EXPECT_EQ(*DATA, *chunk->getData());
	EXPECT_EQ(CompressionAlgorithm::GZIP, chunk->getCompressionAlgo());
	EXPECT_EQ(MSG_ID, chunk->getMessageId());
	EXPECT_EQ(SEQ_NO, chunk->getSequenceNumber());
	shared_ptr<ByteArray> encode = chunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(encode->size() > 0);

	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, encoder->parseObject(encode), CRYPTO_CONTEXT);
	EXPECT_EQ(chunk->isEndOfMessage(), moChunk->isEndOfMessage());
	EXPECT_EQ(*chunk->getData(), *moChunk->getData());
	EXPECT_EQ(chunk->getMessageId(), moChunk->getMessageId());
	EXPECT_EQ(chunk->getSequenceNumber(), moChunk->getSequenceNumber());
	shared_ptr<ByteArray> moEncode = moChunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(moEncode->size() > 0);
	// The two payload chunk encodings will not be equal because the
	// ciphertext and signature will be generated on-demand.
}

TEST_F(PayloadChunkTest, gzipMslObject)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<ByteArray> encode = chunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(encode->size() > 0);

	shared_ptr<MslObject> mo = encoder->parseObject(encode);
	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
	EXPECT_TRUE(CRYPTO_CONTEXT->verify(ciphertext, signature, encoder));
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);

	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);
	EXPECT_EQ(SEQ_NO, payloadMo->getLong(KEY_SEQUENCE_NUMBER));
	EXPECT_EQ(MSG_ID, payloadMo->getLong(KEY_MESSAGE_ID));
	EXPECT_EQ(END_OF_MSG, payloadMo->optBoolean(KEY_END_OF_MESSAGE));
	EXPECT_EQ(CompressionAlgorithm::GZIP.toString(), payloadMo->getString(KEY_COMPRESSION_ALGORITHM));
	shared_ptr<ByteArray> gzipped = payloadMo->getBytes(KEY_DATA);
	shared_ptr<ByteArray> plaintext = MslCompression::uncompress(CompressionAlgorithm::GZIP, *gzipped);
	EXPECT_EQ(*DATA, *plaintext);
}
/* LZW not supported
TEST_F(PayloadChunkTest, lzwCtors)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::LZW, DATA, CRYPTO_CONTEXT);
	EXPECT_EQ(END_OF_MSG, chunk->isEndOfMessage());
	EXPECT_EQ(*DATA, *chunk->getData());
	EXPECT_EQ(CompressionAlgorithm::LZW, chunk->getCompressionAlgo());
	EXPECT_EQ(MSG_ID, chunk->getMessageId());
	EXPECT_EQ(SEQ_NO, chunk->getSequenceNumber());
	shared_ptr<ByteArray> encode = chunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(encode->size() > 0);

	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, encoder->parseObject(encode), CRYPTO_CONTEXT);
	EXPECT_EQ(chunk->isEndOfMessage(), moChunk->isEndOfMessage());
	EXPECT_EQ(chunk->getData(), moChunk->getData());
	EXPECT_EQ(chunk->getMessageId(), moChunk->getMessageId());
	EXPECT_EQ(chunk->getSequenceNumber(), moChunk->getSequenceNumber());
	shared_ptr<ByteArray> moEncode = moChunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(moEncode->size() > 0);
	// The two payload chunk encodings will not be equal because the
	// ciphertext and signature will be generated on-demand.
}

TEST_F(PayloadChunkTest, lzwMslObject)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::LZW, DATA, CRYPTO_CONTEXT);
	ByteArray encode = chunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(encode.size() > 0);

	shared_ptr<MslObject> mo = encoder->parseObject(encode);
	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
	EXPECT_TRUE(CRYPTO_CONTEXT->verify(ciphertext, signature, encoder));
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);

	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);
	EXPECT_EQ(SEQ_NO, payloadMo->getLong(KEY_SEQUENCE_NUMBER));
	EXPECT_EQ(MSG_ID, payloadMo->getLong(KEY_MESSAGE_ID));
	EXPECT_EQ(END_OF_MSG, payloadMo->optBoolean(KEY_END_OF_MESSAGE));
	EXPECT_EQ(CompressionAlgorithm::LZW.toString(), payloadMo->getString(KEY_COMPRESSION_ALGORITHM));
	shared_ptr<ByteArray> gzipped = payloadMo->getBytes(KEY_DATA);
	shared_ptr<ByteArray> plaintext = MslCompression::uncompress(CompressionAlgorithm::LZW, *gzipped);
	EXPECT_EQ(*DATA, *plaintext);
}
*/
TEST_F(PayloadChunkTest, mismatchedCryptoContextId)
{
	shared_ptr<ICryptoContext> cryptoContextA = make_shared<SymmetricCryptoContext>(ctx, CRYPTO_CONTEXT_ID + "A", ENCRYPTION_KEY, HMAC_KEY, NULL_KEY);
	shared_ptr<ICryptoContext> cryptoContextB = make_shared<SymmetricCryptoContext>(ctx, CRYPTO_CONTEXT_ID + "B", ENCRYPTION_KEY, HMAC_KEY, NULL_KEY);

	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, cryptoContextA);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, mo, cryptoContextB);
	EXPECT_EQ(chunk->isEndOfMessage(), moChunk->isEndOfMessage());
	EXPECT_EQ(*chunk->getData(), *moChunk->getData());
	EXPECT_EQ(chunk->getMessageId(), moChunk->getMessageId());
	EXPECT_EQ(chunk->getSequenceNumber(), moChunk->getSequenceNumber());
	shared_ptr<ByteArray> moEncode = moChunk->toMslEncoding(encoder, format);
	EXPECT_TRUE(moEncode->size() > 0);
	// The two payload chunk encodings will not be equal because the
	// ciphertext and signature will be generated on-demand.
}

TEST_F(PayloadChunkTest, mismatchedCryptoContextEncryptionKey)
{
	shared_ptr<ByteArray> encryptionBytesA = make_shared<ByteArray>(16);
	shared_ptr<ByteArray> encryptionBytesB = make_shared<ByteArray>(16);
	random.nextBytes(*encryptionBytesA);
	random.nextBytes(*encryptionBytesB);
	const SecretKey encryptionKeyA(encryptionBytesA, JcaAlgorithm::AES);
	const SecretKey encryptionKeyB(encryptionBytesB, JcaAlgorithm::AES);
	shared_ptr<ICryptoContext> cryptoContextA = make_shared<SymmetricCryptoContext>(ctx, CRYPTO_CONTEXT_ID, encryptionKeyA, HMAC_KEY, NULL_KEY);
	shared_ptr<ICryptoContext> cryptoContextB = make_shared<SymmetricCryptoContext>(ctx, CRYPTO_CONTEXT_ID, encryptionKeyB, HMAC_KEY, NULL_KEY);

	// Mismatched encryption keys will just result in the wrong data.
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, cryptoContextA);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);
	// Sometimes decryption will succeed so check for a crypto exception
	// or encoding exception. Both are OK.
	try {
		make_shared<PayloadChunk>(ctx, mo, cryptoContextB);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
	} catch (const MslCryptoException& e) {
	}
}

TEST_F(PayloadChunkTest, mismatchedCryptoContextSignKey)
{
	shared_ptr<ByteArray> hmacBytesA = make_shared<ByteArray>(32);
	shared_ptr<ByteArray> hmacBytesB = make_shared<ByteArray>(32);
	random.nextBytes(*hmacBytesA);
	random.nextBytes(*hmacBytesB);
	const SecretKey hmacKeyA(hmacBytesA, JcaAlgorithm::HMAC_SHA256);
	const SecretKey hmacKeyB(hmacBytesB, JcaAlgorithm::HMAC_SHA256);
	shared_ptr<ICryptoContext> cryptoContextA = make_shared<SymmetricCryptoContext>(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, hmacKeyA, NULL_KEY);
	shared_ptr<ICryptoContext> cryptoContextB = make_shared<SymmetricCryptoContext>(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, hmacKeyB, NULL_KEY);

	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, cryptoContextA);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);
	try {
		make_shared<PayloadChunk>(ctx, mo, cryptoContextB);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::PAYLOAD_VERIFICATION_FAILED, e.getError());
	}
}

TEST_F(PayloadChunkTest, incorrectSignature)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> signature = make_shared<ByteArray>(32);
	random.nextBytes(*signature);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::PAYLOAD_VERIFICATION_FAILED, e.getError());
	}
}

TEST_F(PayloadChunkTest, missingPayload)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	EXPECT_FALSE(mo->remove(KEY_PAYLOAD).isNull());

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(PayloadChunkTest, invalidPayload)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	mo->put(KEY_PAYLOAD, string("x"));

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(PayloadChunkTest, corruptPayload)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = make_shared<ByteArray>(32);
	random.nextBytes(*ciphertext);
	mo->put(KEY_PAYLOAD, ciphertext);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(ciphertext, encoder, format);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslCryptoException& e) {
	}
}

TEST_F(PayloadChunkTest, emptyPayloadEndOfMessage)
{
	shared_ptr<ByteArray> data = make_shared<ByteArray>();
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, data, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
	EXPECT_EQ(static_cast<size_t>(0), moChunk->getData()->size());
}

TEST_F(PayloadChunkTest, missingSequenceNumber)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	EXPECT_FALSE(payloadMo->remove(KEY_SEQUENCE_NUMBER).isNull());

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(PayloadChunkTest, invalidSequenceNumber)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	payloadMo->put(KEY_SEQUENCE_NUMBER, string("x"));

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(PayloadChunkTest, negativeSequenceNumber)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	payloadMo->put(KEY_SEQUENCE_NUMBER, -1);

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslException& e) {
		EXPECT_EQ(MslError::PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE, e.getError());
	}
}

TEST_F(PayloadChunkTest, tooLargeSequenceNumber)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	payloadMo->put(KEY_SEQUENCE_NUMBER, MslConstants::MAX_LONG_VALUE + 1);

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslException& e) {
		EXPECT_EQ(MslError::PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE, e.getError());
	}
}

TEST_F(PayloadChunkTest, missingMessageId)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	EXPECT_FALSE(payloadMo->remove(KEY_MESSAGE_ID).isNull());

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(PayloadChunkTest, invalidMessageId)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	payloadMo->put(KEY_MESSAGE_ID, string("x"));

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(PayloadChunkTest, invalidEndOfMessage)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	payloadMo->put(KEY_END_OF_MESSAGE, string("x"));

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(PayloadChunkTest, invalidCompressionAlgorithm)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	payloadMo->put(KEY_COMPRESSION_ALGORITHM, string("x"));

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::UNIDENTIFIED_COMPRESSION, e.getError());
	}
}

TEST_F(PayloadChunkTest, missingData)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	EXPECT_FALSE(payloadMo->remove(KEY_DATA).isNull());

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(PayloadChunkTest, emptyData)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	payloadMo->put(KEY_DATA, string(""));

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::PAYLOAD_DATA_MISSING, e.getError());
	}
}

TEST_F(PayloadChunkTest, invalidDataEndOfMessage)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);

	shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_PAYLOAD);
	shared_ptr<ByteArray> payload = CRYPTO_CONTEXT->decrypt(ciphertext, encoder);
	shared_ptr<MslObject> payloadMo = encoder->parseObject(payload);

	payloadMo->put(KEY_DATA, false);

	shared_ptr<ByteArray> plaintext = encoder->encodeObject(payloadMo, format);
	shared_ptr<ByteArray> newPayload = CRYPTO_CONTEXT->encrypt(plaintext, encoder, format);
	shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(newPayload, encoder, format);
	mo->put(KEY_PAYLOAD, newPayload);
	mo->put(KEY_SIGNATURE, signature);

	try {
		make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(PayloadChunkTest, largeData)
{
	shared_ptr<ByteArray> data = make_shared<ByteArray>(10 * 1024 * 1024);
	random.nextBytes(*data);
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::NOCOMPRESSION, data, CRYPTO_CONTEXT);
	EXPECT_EQ(data, chunk->getData());

	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);
	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
	EXPECT_EQ(*chunk->getData(), *moChunk->getData());
}

TEST_F(PayloadChunkTest, gzipLargeData)
{
	shared_ptr<ByteArray> data = make_shared<ByteArray>(10 * 1024 * 1024);
	random.nextBytes(*data);
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, data, CRYPTO_CONTEXT);
	EXPECT_EQ(data, chunk->getData());

	// Random data will not compress.
	EXPECT_EQ(CompressionAlgorithm::NOCOMPRESSION, chunk->getCompressionAlgo());

	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);
	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
	EXPECT_EQ(*chunk->getData(), *moChunk->getData());
	EXPECT_EQ(chunk->getCompressionAlgo(), moChunk->getCompressionAlgo());
}

TEST_F(PayloadChunkTest, gzipVerona)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, rawdata, CRYPTO_CONTEXT);
	EXPECT_EQ(rawdata, chunk->getData());

	// Romeo and Juliet will compress.
	EXPECT_EQ(CompressionAlgorithm::GZIP, chunk->getCompressionAlgo());

	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);
	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
	EXPECT_EQ(*chunk->getData(), *moChunk->getData());
	EXPECT_EQ(chunk->getCompressionAlgo(), moChunk->getCompressionAlgo());
}

/* LZW not supported
TEST_F(PayloadChunkTest, lzwRandomData)
{
	shared_ptr<ByteArray> data = make_shared<ByteArray>(10 * 1024 * 1024);
	random.nextBytes(*data);
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::LZW, data, CRYPTO_CONTEXT);
	EXPECT_EQ(data, chunk->getData());

	// Random data will not compress.
	EXPECT_EQ(CompressionAlgorithm::NOCOMPRESSION, chunk->getCompressionAlgo());

	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);
	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
	EXPECT_EQ(*chunk->getData(), *moChunk->getData());
	EXPECT_EQ(chunk->getCompressionAlgo(), moChunk->getCompressionAlgo());
}

TEST_F(PayloadChunkTest, lzwVerona)
{
	shared_ptr<PayloadChunk> chunk = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::LZW, rawdata, CRYPTO_CONTEXT);
	EXPECT_EQ(rawdata, chunk->getData());

	// Romeo and Juliet will compress.
	EXPECT_EQ(CompressionAlgorithm::LZW, chunk->getCompressionAlgo());

	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, chunk);
	shared_ptr<PayloadChunk> moChunk = make_shared<PayloadChunk>(ctx, mo, CRYPTO_CONTEXT);
	EXPECT_EQ(*chunk->getData(), *moChunk->getData());
	EXPECT_EQ(chunk->getCompressionAlgo(), moChunk->getCompressionAlgo());
}
*/
TEST_F(PayloadChunkTest, equalsSequenceNumber)
{
	const int64_t seqNoA = 1;
	const int64_t seqNoB = 2;
	shared_ptr<PayloadChunk> chunkA = make_shared<PayloadChunk>(ctx, seqNoA, MSG_ID, false, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkB = make_shared<PayloadChunk>(ctx, seqNoB, MSG_ID, false, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkA2 = make_shared<PayloadChunk>(ctx, MslTestUtils::toMslObject(encoder, chunkA), CRYPTO_CONTEXT);

	EXPECT_EQ(*chunkA, *chunkA);

	EXPECT_NE(*chunkA, *chunkB);
	EXPECT_NE(*chunkB, *chunkA);

	EXPECT_EQ(*chunkA, *chunkA2);
	EXPECT_EQ(*chunkA2, *chunkA);
}

TEST_F(PayloadChunkTest, equalsMessageId)
{
	const int64_t msgIdA = 1;
	const int64_t msgIdB = 2;
	shared_ptr<PayloadChunk> chunkA = make_shared<PayloadChunk>(ctx, SEQ_NO, msgIdA, false, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkB = make_shared<PayloadChunk>(ctx, SEQ_NO, msgIdB, false, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkA2 = make_shared<PayloadChunk>(ctx, MslTestUtils::toMslObject(encoder, chunkA), CRYPTO_CONTEXT);

	EXPECT_EQ(*chunkA, *chunkA);

	EXPECT_NE(*chunkA, *chunkB);
	EXPECT_NE(*chunkB, *chunkA);

	EXPECT_EQ(*chunkA, *chunkA2);
	EXPECT_EQ(*chunkA2, *chunkA);
}

TEST_F(PayloadChunkTest, equalsEndOfMessage)
{
	shared_ptr<PayloadChunk> chunkA = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkB = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, false, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkA2 = make_shared<PayloadChunk>(ctx, MslTestUtils::toMslObject(encoder, chunkA), CRYPTO_CONTEXT);

	EXPECT_EQ(*chunkA, *chunkA);

	EXPECT_NE(*chunkA, *chunkB);
	EXPECT_NE(*chunkB, *chunkA);

	EXPECT_EQ(*chunkA, *chunkA2);
	EXPECT_EQ(*chunkA2, *chunkA);
}

TEST_F(PayloadChunkTest, equalsCompressionAlgorithm)
{
	shared_ptr<PayloadChunk> chunkA = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, DATA, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkB = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::NOCOMPRESSION, DATA, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkA2 = make_shared<PayloadChunk>(ctx, MslTestUtils::toMslObject(encoder, chunkA), CRYPTO_CONTEXT);

	EXPECT_EQ(*chunkA, *chunkA);

	EXPECT_NE(*chunkA, *chunkB);
	EXPECT_NE(*chunkB, *chunkA);

	EXPECT_EQ(*chunkA, *chunkA2);
	EXPECT_EQ(*chunkA2, *chunkA);
}

TEST_F(PayloadChunkTest, equalsData)
{
	shared_ptr<ByteArray> dataA = make_shared<ByteArray>(32);
	random.nextBytes(*dataA);
	shared_ptr<ByteArray> dataB = make_shared<ByteArray>(32);
	random.nextBytes(*dataB);
	shared_ptr<ByteArray> dataC = make_shared<ByteArray>();
	shared_ptr<PayloadChunk> chunkA = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, dataA, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkB = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, dataB, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkC = make_shared<PayloadChunk>(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::GZIP, dataC, CRYPTO_CONTEXT);
	shared_ptr<PayloadChunk> chunkA2 = make_shared<PayloadChunk>(ctx, MslTestUtils::toMslObject(encoder, chunkA), CRYPTO_CONTEXT);

	EXPECT_EQ(*chunkA, *chunkA);

	EXPECT_NE(*chunkA, *chunkB);
	EXPECT_NE(*chunkB, *chunkA);

	EXPECT_NE(*chunkA, *chunkC);
	EXPECT_NE(*chunkC, *chunkA);

	EXPECT_EQ(*chunkA, *chunkA2);
	EXPECT_EQ(*chunkA2, *chunkA);
}

}}} // namespace netflix::msl::msg
