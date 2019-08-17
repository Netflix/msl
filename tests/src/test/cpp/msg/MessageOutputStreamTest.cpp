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

#include <IOException.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <MslMessageException.h>
#include <MslUserAuthException.h>
#include <crypto/ICryptoContext.h>
#include <crypto/Random.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <entityauth/PresharedAuthenticationData.h>
#include <entityauth/RsaAuthenticationData.h>
#include <entityauth/UnauthenticatedAuthenticationData.h>
#include <io/ByteArrayInputStream.h>
#include <io/ByteArrayOutputStream.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <io/MslTokenizer.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <msg/ErrorHeader.h>
#include <msg/MessageBuilder.h>
#include <msg/MessageFactory.h>
#include <msg/MessageHeader.h>
#include <msg/MessageOutputStream.h>
#include <msg/PayloadChunk.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <tokens/ServiceToken.h>
#include <userauth/UserAuthenticationData.h>
#include <util/GzipCompression.h>
#include <util/MslCompression.h>
#include <util/MslContext.h>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>


#include <gtest/gtest.h>
#include <util/MockMslContext.h>

#include "../entityauth/MockPresharedAuthenticationFactory.h"
#include "../entityauth/MockRsaAuthenticationFactory.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::keyx;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;
using namespace netflix::msl::MslConstants;
using HeaderData = netflix::msl::msg::MessageHeader::HeaderData;
using HeaderPeerData = netflix::msl::msg::MessageHeader::HeaderPeerData;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace msg {

namespace {

/** Maximum number of payload chunks to generate. */
const int MAX_PAYLOAD_CHUNKS = 10;
/** Maximum payload chunk data size in bytes. */
const int MAX_DATA_SIZE = 1024 * 1024;
/** Compressible data. */
const string COMPRESSIBLE_STRING =
		"Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me."
		"Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me."
		"Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me.";
const shared_ptr<ByteArray> COMPRESSIBLE_DATA = make_shared<ByteArray>(COMPRESSIBLE_STRING.begin(), COMPRESSIBLE_STRING.end());
/** I/O operation timeout in milliseconds. */
const int TIMEOUT = 20;

const int64_t REPLAYABLE_ID = -1;
const shared_ptr<MessageCapabilities> NULL_MSG_CAPS;
const set<shared_ptr<KeyRequestData>> EMPTY_KEYX_REQUESTS;
const shared_ptr<KeyResponseData> NULL_KEYX_RESPONSE;
const shared_ptr<EntityAuthenticationData> NULL_ENTITYAUTH_DATA;
const shared_ptr<UserAuthenticationData> NULL_USERAUTH_DATA;
const shared_ptr<MasterToken> NULL_MASTER_TOKEN;
const shared_ptr<UserIdToken> NULL_USER_ID_TOKEN;
const set<shared_ptr<ServiceToken>> EMPTY_SERVICE_TOKENS;
const shared_ptr<MslObject> NULL_ISSUER_DATA;
const vector<string> EMPTY_LANGUAGES;
const set<MslEncoderFormat> EMPTY_FORMATS;
const shared_ptr<MessageFactory> messageFactory = make_shared<MessageFactory>();

const string UNAUTHENTICATED_ESN = "MOCKUNAUTH-ESN";


} // namespace anonymous

/**
 * Message output stream unit tests.
 *
 * These tests assume the MessageOutputStream does not construct the header
 * data but delegates that to the Header. Likewise for PayloadChunks. So there
 * are no checks for proper encoding.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageOutputStreamTest : public ::testing::Test
{
public:
	virtual ~MessageOutputStreamTest() {}

	MessageOutputStreamTest()
		: format(MslEncoderFormat::JSON)
		, ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
		, encoder(ctx->getMslEncoderFactory())
	{
		shared_ptr<MslCompression::CompressionImpl> gzipImpl = make_shared<GzipCompression>();
		MslCompression::registerImpl(MslConstants::CompressionAlgorithm::GZIP, gzipImpl);

		shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
		shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
		ENTITY_AUTH_DATA = ctx->getEntityAuthenticationData();
		MESSAGE_HEADER = make_shared<MessageHeader>(ctx, ENTITY_AUTH_DATA, NULL_MASTER_TOKEN, headerData, peerData);
		PAYLOAD_CRYPTO_CONTEXT = MESSAGE_HEADER->getCryptoContext();

		ERROR_HEADER = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, 1, ResponseCode::FAIL, 3, "errormsg", "usermsg");

		shared_ptr<KeyRequestData> keyRequest = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
		KEY_REQUEST_DATA.insert(keyRequest);
		shared_ptr<KeyExchangeFactory> factory = ctx->getKeyExchangeFactory(keyRequest->getKeyExchangeScheme());
		shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(ctx, format, keyRequest, ENTITY_AUTH_DATA);
		KEY_RESPONSE_DATA = keyxData->keyResponseData;
		KEYX_CRYPTO_CONTEXT = keyxData->cryptoContext;
	}

protected:
	/** MSL encoder format. */
	const MslEncoderFormat format;

    /** Random. */
    Random random;
    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    /** Destination output stream. */
    shared_ptr<ByteArrayOutputStream> destination = make_shared<ByteArrayOutputStream>();
    /** Payload crypto context. */
    shared_ptr<ICryptoContext> PAYLOAD_CRYPTO_CONTEXT;
    /** Header service token crypto contexts. */
    map<string,shared_ptr<ICryptoContext>> cryptoContexts;

    shared_ptr<EntityAuthenticationData> ENTITY_AUTH_DATA;
    shared_ptr<MessageHeader> MESSAGE_HEADER;
    shared_ptr<ErrorHeader> ERROR_HEADER;
    set<shared_ptr<KeyRequestData>> KEY_REQUEST_DATA;
    shared_ptr<KeyResponseData> KEY_RESPONSE_DATA;
    shared_ptr<ICryptoContext> KEYX_CRYPTO_CONTEXT;
};

TEST_F(MessageOutputStreamTest, messageHeader)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
	mos->close();

	shared_ptr<InputStream> mslMessage = make_shared<ByteArrayInputStream>(destination->toByteArray());
	shared_ptr<MslTokenizer> tokenizer = encoder->createTokenizer(mslMessage);

	// There should be one header.
	EXPECT_TRUE(tokenizer->more(TIMEOUT));
	shared_ptr<MslObject> first = tokenizer->nextObject(TIMEOUT);
	EXPECT_TRUE(first);
	shared_ptr<MslObject> headerMo = first;

	// The reconstructed header should be equal to the original.
	shared_ptr<Header> header = Header::parseHeader(ctx, headerMo, cryptoContexts);
	EXPECT_TRUE(instanceof<MessageHeader>(header));
	shared_ptr<MessageHeader> messageHeader = dynamic_pointer_cast<MessageHeader>(header);
	EXPECT_EQ(*MESSAGE_HEADER, *messageHeader);

	// There should be one payload with no data indicating end of message.
	EXPECT_TRUE(tokenizer->more(TIMEOUT));
	shared_ptr<MslObject> second = tokenizer->nextObject(TIMEOUT);
	EXPECT_TRUE(second);
	shared_ptr<MslObject> payloadMo = second;

	// Verify the payload.
	shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
	EXPECT_TRUE(cryptoContext);
	shared_ptr<PayloadChunk> payload = make_shared<PayloadChunk>(ctx, payloadMo, cryptoContext);
	EXPECT_TRUE(payload->isEndOfMessage());
	EXPECT_EQ(1, payload->getSequenceNumber());
	EXPECT_EQ(MESSAGE_HEADER->getMessageId(), payload->getMessageId());
	EXPECT_EQ(static_cast<size_t>(0), payload->getData()->size());

	// There should be nothing else.
	EXPECT_FALSE(tokenizer->more(TIMEOUT));

	// Verify cached payloads.
	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(1), payloads.size());
	EXPECT_EQ(*payload, *payloads[0]);

	// Close tokenizer.
	tokenizer->close();
}

TEST_F(MessageOutputStreamTest, errorHeader)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, ERROR_HEADER, format);
	mos->close();

	shared_ptr<InputStream> mslMessage = make_shared<ByteArrayInputStream>(destination->toByteArray());
	shared_ptr<MslTokenizer> tokenizer = encoder->createTokenizer(mslMessage);

	// There should be one header.
	EXPECT_TRUE(tokenizer->more(TIMEOUT));
	shared_ptr<MslObject> first = tokenizer->nextObject(TIMEOUT);
	EXPECT_TRUE(first);
	shared_ptr<MslObject> headerMo = first;

	// The reconstructed header should be equal to the original.
	shared_ptr<Header> header = Header::parseHeader(ctx, headerMo, cryptoContexts);
	EXPECT_TRUE(instanceof<ErrorHeader>(header));
	EXPECT_EQ(*ERROR_HEADER, *header);

	// There should be no payloads.
	EXPECT_FALSE(tokenizer->more(TIMEOUT));

	// Verify cached payloads.
	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(0), payloads.size());

    // Close tokenizer.
    tokenizer->close();
}

TEST_F(MessageOutputStreamTest, entityAuthSchemeEncrypts)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, cryptoContext);
    EXPECT_TRUE(mos->encryptsPayloads());
    mos->close();
}

TEST_F(MessageOutputStreamTest, entityAuthSchemeDoesNotEncrypt)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, cryptoContext);
    EXPECT_FALSE(mos->encryptsPayloads());
    mos->close();
}

TEST_F(MessageOutputStreamTest, entityAuthSchemeIntegrityProtects)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, cryptoContext);
    EXPECT_TRUE(mos->protectsPayloadIntegrity());
    mos->close();
}

TEST_F(MessageOutputStreamTest, entityAuthSchemeDoesNotIntegrityProtect)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<UnauthenticatedAuthenticationData>(UNAUTHENTICATED_ESN);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, cryptoContext);
    EXPECT_FALSE(mos->protectsPayloadIntegrity());
    mos->close();
}

TEST_F(MessageOutputStreamTest, entityAuthSchemeKeyxEncrypts)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
    EXPECT_TRUE(mos->encryptsPayloads());
    mos->close();
}

TEST_F(MessageOutputStreamTest, entityAuthSchemeKeyxIntegrityProtects)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
    EXPECT_TRUE(mos->protectsPayloadIntegrity());
    mos->close();
}

TEST_F(MessageOutputStreamTest, entityAuthSchemeDoesNotKeyxEncrypts)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
    EXPECT_TRUE(mos->encryptsPayloads());
    mos->close();
}

TEST_F(MessageOutputStreamTest, entityAuthSchemeDoesNotKeyxIntegrityProtects)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<UnauthenticatedAuthenticationData>(UNAUTHENTICATED_ESN);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
    EXPECT_TRUE(mos->protectsPayloadIntegrity());
    mos->close();
}

TEST_F(MessageOutputStreamTest, masterTokenEncrypts)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

    shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, cryptoContext);
    EXPECT_TRUE(mos->encryptsPayloads());
    mos->close();
}

TEST_F(MessageOutputStreamTest, masterTokenIntegrityProtects)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

    shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, cryptoContext);
    EXPECT_TRUE(mos->protectsPayloadIntegrity());
    mos->close();
}

TEST_F(MessageOutputStreamTest, masterTokenKeyxEncrypts)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
    EXPECT_TRUE(mos->encryptsPayloads());
    mos->close();
}

TEST_F(MessageOutputStreamTest, masterTokenKeyxIntegrityProtects)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

    shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
    EXPECT_TRUE(mos->protectsPayloadIntegrity());
    mos->close();
}

TEST_F(MessageOutputStreamTest, writeOffsets)
{
	shared_ptr<ByteArray> data = make_shared<ByteArray>(32);
	random.nextBytes(*data);
	const int from = 8;
	const int length = 8;
	const int to = from + length; // exclusive
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
	mos->write(*data, from, length);
	mos->close();

	shared_ptr<InputStream> mslMessage = make_shared<ByteArrayInputStream>(destination->toByteArray());
	shared_ptr<MslTokenizer> tokenizer = encoder->createTokenizer(mslMessage);

	// There should be one header.
	EXPECT_TRUE(tokenizer->more(TIMEOUT));
	shared_ptr<MslObject> first = tokenizer->nextObject(TIMEOUT);
	EXPECT_TRUE(instanceof<MslObject>(first));
	shared_ptr<MslObject> headerMo = first;

	// We assume the reconstructed header is equal to the original.
	shared_ptr<Header> header = Header::parseHeader(ctx, headerMo, cryptoContexts);
	EXPECT_TRUE(instanceof<MessageHeader>(header));
	shared_ptr<MessageHeader> messageHeader = dynamic_pointer_cast<MessageHeader>(header);

	// There should be one payload.
	EXPECT_TRUE(tokenizer->more(TIMEOUT));
	shared_ptr<MslObject> second = tokenizer->nextObject(TIMEOUT);
	EXPECT_TRUE(instanceof<MslObject>(second));
	shared_ptr<MslObject> payloadMo = second;

	// Verify the payload.
	shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
	EXPECT_TRUE(cryptoContext);
	shared_ptr<PayloadChunk> payload = make_shared<PayloadChunk>(ctx, payloadMo, cryptoContext);
	EXPECT_TRUE(payload->isEndOfMessage());
	EXPECT_EQ(1, payload->getSequenceNumber());
	EXPECT_EQ(MESSAGE_HEADER->getMessageId(), payload->getMessageId());
	EXPECT_EQ(ByteArray(data->begin() + from, data->begin() + to), *payload->getData());

	// There should be nothing else.
	EXPECT_FALSE(tokenizer->more(TIMEOUT));

	// Verify cached payloads.
	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(1), payloads.size());
	EXPECT_EQ(*payload, *payloads[0]);

    // Close tokenizer.
    tokenizer->close();
}

TEST_F(MessageOutputStreamTest, writeBytes)
{
	shared_ptr<ByteArray> data = make_shared<ByteArray>(32);
	random.nextBytes(*data);
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
	mos->write(*data);
	mos->close();

	shared_ptr<InputStream> mslMessage = make_shared<ByteArrayInputStream>(destination->toByteArray());
	shared_ptr<MslTokenizer> tokenizer = encoder->createTokenizer(mslMessage);

	// There should be one header.
	EXPECT_TRUE(tokenizer->more(TIMEOUT));
	shared_ptr<MslObject> first = tokenizer->nextObject(TIMEOUT);
	EXPECT_TRUE(instanceof<MslObject>(first));
	shared_ptr<MslObject> headerMo = first;

	// We assume the reconstructed header is equal to the original.
	shared_ptr<Header> header = Header::parseHeader(ctx, headerMo, cryptoContexts);
	EXPECT_TRUE(instanceof<MessageHeader>(header));
	shared_ptr<MessageHeader> messageHeader = dynamic_pointer_cast<MessageHeader>(header);

	// There should be one payload.
	EXPECT_TRUE(tokenizer->more(TIMEOUT));
	shared_ptr<MslObject> second = tokenizer->nextObject(TIMEOUT);
	EXPECT_TRUE(instanceof<MslObject>(second));
	shared_ptr<MslObject> payloadMo = second;

	// Verify the payload.
	shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
	EXPECT_TRUE(cryptoContext);
	shared_ptr<PayloadChunk> payload = make_shared<PayloadChunk>(ctx, payloadMo, cryptoContext);
	EXPECT_TRUE(payload->isEndOfMessage());
	EXPECT_EQ(1, payload->getSequenceNumber());
	EXPECT_EQ(MESSAGE_HEADER->getMessageId(), payload->getMessageId());
	EXPECT_EQ(*data, *payload->getData());

	// There should be nothing else.
	EXPECT_FALSE(tokenizer->more(TIMEOUT));

	// Verify cached payloads.
	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(1), payloads.size());
	EXPECT_EQ(*payload, *payloads[0]);

    // Close tokenizer.
    tokenizer->close();
}

TEST_F(MessageOutputStreamTest, compressed)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);

	// Write the first payload.
	EXPECT_TRUE(mos->setCompressionAlgorithm(CompressionAlgorithm::NOCOMPRESSION));
	shared_ptr<ByteArray> first = make_shared<ByteArray>(COMPRESSIBLE_DATA->begin(), COMPRESSIBLE_DATA->end());
	random.nextBytes(*first);
	mos->write(*first);

	// Changing the compressed value should result in a new payload.
	EXPECT_TRUE(mos->setCompressionAlgorithm(CompressionAlgorithm::GZIP));
	shared_ptr<ByteArray> secondA = make_shared<ByteArray>(first->begin(), first->end());
	secondA->insert(secondA->end(), COMPRESSIBLE_DATA->begin(), COMPRESSIBLE_DATA->end());
	random.nextBytes(*secondA);
	mos->write(*secondA);

	// Setting the compressed value to the same should maintain the same
	// payload.
	EXPECT_TRUE(mos->setCompressionAlgorithm(CompressionAlgorithm::GZIP));
	shared_ptr<ByteArray> secondB = make_shared<ByteArray>(first->begin(), first->end());
	secondB->insert(secondB->end(), COMPRESSIBLE_DATA->begin(), COMPRESSIBLE_DATA->end());
	secondB->insert(secondB->end(), COMPRESSIBLE_DATA->begin(), COMPRESSIBLE_DATA->end());
	random.nextBytes(*secondB);
	mos->write(*secondB);

	// Changing the compressed value should flush the second payload.
	EXPECT_TRUE(mos->setCompressionAlgorithm(CompressionAlgorithm::NOCOMPRESSION));

	// Closing should create a final end-of-message payload.
	mos->close();

	// Grab the MSL objects.
	shared_ptr<InputStream> mslMessage = make_shared<ByteArrayInputStream>(destination->toByteArray());
	shared_ptr<MslTokenizer> tokenizer = encoder->createTokenizer(mslMessage);
	shared_ptr<MslObject> headerMo = tokenizer->nextObject(TIMEOUT);
	vector<shared_ptr<MslObject>> payloadMos;
	while (tokenizer->more(TIMEOUT))
		payloadMos.push_back(tokenizer->nextObject(TIMEOUT));
	tokenizer->close();

	// Verify the number and contents of the payloads.
	shared_ptr<MessageHeader> messageHeader = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(ctx, headerMo, cryptoContexts));
	shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
	EXPECT_EQ(static_cast<size_t>(3), payloadMos.size());
	shared_ptr<PayloadChunk> firstPayload = make_shared<PayloadChunk>(ctx, payloadMos[0], cryptoContext);
	EXPECT_EQ(*first, *firstPayload->getData());
	shared_ptr<PayloadChunk> secondPayload = make_shared<PayloadChunk>(ctx, payloadMos[1], cryptoContext);
	shared_ptr<ByteArray> secondData = secondPayload->getData();
	EXPECT_EQ(*secondA, ByteArray(secondData->begin(), secondData->begin() + static_cast<ptrdiff_t>(secondA->size())));
	EXPECT_EQ(*secondB, ByteArray(secondData->begin() + static_cast<ptrdiff_t>(secondA->size()), secondData->begin() + static_cast<ptrdiff_t>(secondA->size()) + static_cast<ptrdiff_t>(secondB->size())));
	shared_ptr<PayloadChunk> thirdPayload = make_shared<PayloadChunk>(ctx, payloadMos[2], cryptoContext);
	EXPECT_EQ(static_cast<size_t>(0), thirdPayload->getData()->size());
	EXPECT_TRUE(thirdPayload->isEndOfMessage());

	// Verify cached payloads.
	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(payloadMos.size(), payloads.size());
	EXPECT_EQ(*firstPayload, *payloads[0]);
	EXPECT_EQ(*secondPayload, *payloads[1]);
	EXPECT_EQ(*thirdPayload, *payloads[2]);
}

TEST_F(MessageOutputStreamTest, flush)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);

	// Write the first payload.
	shared_ptr<ByteArray> first = make_shared<ByteArray>(10);
	random.nextBytes(*first);
	mos->write(*first);

	// Flushing should result in a new payload.
	mos->flush();
	shared_ptr<ByteArray> secondA = make_shared<ByteArray>(20);
	random.nextBytes(*secondA);
	mos->write(*secondA);

	// Not flushing should maintain the same payload.
	shared_ptr<ByteArray> secondB = make_shared<ByteArray>(30);
	random.nextBytes(*secondB);
	mos->write(*secondB);

	// Flush the second payload.
	mos->flush();

	// Closing should create a final end-of-message payload.
	mos->close();

	// Grab the MSL objects.
	shared_ptr<InputStream> mslMessage = make_shared<ByteArrayInputStream>(destination->toByteArray());
	shared_ptr<MslTokenizer> tokenizer = encoder->createTokenizer(mslMessage);
	shared_ptr<MslObject> headerMo = tokenizer->nextObject(TIMEOUT);
	vector<shared_ptr<MslObject>> payloadMos;
	while (tokenizer->more(TIMEOUT))
		payloadMos.push_back(tokenizer->nextObject(TIMEOUT));
	tokenizer->close();

	// Verify the number and contents of the payloads.
	shared_ptr<MessageHeader> messageHeader = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(ctx, headerMo, cryptoContexts));
	shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
	EXPECT_EQ(static_cast<size_t>(3), payloadMos.size());
	shared_ptr<PayloadChunk> firstPayload = make_shared<PayloadChunk>(ctx, payloadMos[0], cryptoContext);
	EXPECT_EQ(*first, *firstPayload->getData());
	shared_ptr<PayloadChunk> secondPayload = make_shared<PayloadChunk>(ctx, payloadMos[1], cryptoContext);
	shared_ptr<ByteArray> secondData = secondPayload->getData();
	EXPECT_EQ(*secondA, ByteArray(secondData->begin(), secondData->begin() + static_cast<ptrdiff_t>(secondA->size())));
	EXPECT_EQ(*secondB, ByteArray(secondData->begin() + static_cast<ptrdiff_t>(secondA->size()), secondData->begin() + static_cast<ptrdiff_t>(secondA->size()) + static_cast<ptrdiff_t>(secondB->size())));
	shared_ptr<PayloadChunk> thirdPayload = make_shared<PayloadChunk>(ctx, payloadMos[2], cryptoContext);
	EXPECT_EQ(static_cast<size_t>(0), thirdPayload->getData()->size());
	EXPECT_TRUE(thirdPayload->isEndOfMessage());

	// Verify cached payloads.
	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(payloadMos.size(), payloads.size());
	EXPECT_EQ(*firstPayload, *payloads[0]);
	EXPECT_EQ(*secondPayload, *payloads[1]);
	EXPECT_EQ(*thirdPayload, *payloads[2]);
}

TEST_F(MessageOutputStreamTest, writeErrorHeader)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, ERROR_HEADER, format);
	try {
		mos->write(ByteArray());
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
	mos->close();
}

TEST_F(MessageOutputStreamTest, writeHandshakeMessage)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, true, ctx->getMessageCapabilities(), EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, ENTITY_AUTH_DATA, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, messageHeader->getCryptoContext());
	try {
		mos->write(ByteArray());
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
	mos->close();
}

TEST_F(MessageOutputStreamTest, closed)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
	mos->close();
	try {
		mos->write(ByteArray());
		ADD_FAILURE() << "Should have thrown";
	} catch (const IOException& e) {
	}
}

TEST_F(MessageOutputStreamTest, flushErrorHeader)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, ERROR_HEADER, format);
	// No data so this should be a no-op.
	mos->flush();
	mos->close();
}

TEST_F(MessageOutputStreamTest, stopCaching)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);

	// Write the first payload.
	shared_ptr<ByteArray> first = make_shared<ByteArray>(10);
	random.nextBytes(*first);
	mos->write(*first);
	mos->flush();

	// Verify one payload.
	vector<shared_ptr<PayloadChunk>> onePayload = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(1), onePayload.size());

	// Stop caching.
	mos->stopCaching();
	vector<shared_ptr<PayloadChunk>> zeroPayload = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(0), zeroPayload.size());

	// Write the second payload.
	shared_ptr<ByteArray> secondA = make_shared<ByteArray>(20);
	random.nextBytes(*secondA);
	mos->write(*secondA);

	// Verify zero payloads.
	vector<shared_ptr<PayloadChunk>> twoPayload = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(0), twoPayload.size());

	// Close
	mos->close();
}

TEST_F(MessageOutputStreamTest, multiClose)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
	mos->close();
	mos->close();

	shared_ptr<InputStream> mslMessage = make_shared<ByteArrayInputStream>(destination->toByteArray());
	shared_ptr<MslTokenizer> tokenizer = encoder->createTokenizer(mslMessage);

	// There should be one header.
	EXPECT_TRUE(tokenizer->more(TIMEOUT));
	shared_ptr<MslObject> first = tokenizer->nextObject(TIMEOUT);
	EXPECT_TRUE(instanceof<MslObject>(first));
	shared_ptr<MslObject> headerMo = first;

	// We assume the reconstructed header is equal to the original.
	shared_ptr<Header> header = Header::parseHeader(ctx, headerMo, cryptoContexts);
	EXPECT_TRUE(instanceof<MessageHeader>(header));
	shared_ptr<MessageHeader> messageHeader = dynamic_pointer_cast<MessageHeader>(header);

	// There should be one payload with no data indicating end of message.
	EXPECT_TRUE(tokenizer->more(TIMEOUT));
	shared_ptr<MslObject> second = tokenizer->nextObject(TIMEOUT);
	EXPECT_TRUE(instanceof<MslObject>(second));
	shared_ptr<MslObject> payloadMo = second;

	// Verify the payload.
	shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
	EXPECT_TRUE(cryptoContext);
	shared_ptr<PayloadChunk> payload = make_shared<PayloadChunk>(ctx, payloadMo, cryptoContext);
	EXPECT_TRUE(payload->isEndOfMessage());
	EXPECT_EQ(1, payload->getSequenceNumber());
	EXPECT_EQ(MESSAGE_HEADER->getMessageId(), payload->getMessageId());
	EXPECT_EQ(static_cast<size_t>(0), payload->getData()->size());

	// There should be nothing else.
	EXPECT_FALSE(tokenizer->more(TIMEOUT));

	// Verify cached payloads.
	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(1), payloads.size());
	EXPECT_EQ(*payload, *payloads[0]);

    // Close tokenizer.
    tokenizer->close();
}

TEST_F(MessageOutputStreamTest, stressWrite)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
	mos->setCompressionAlgorithm(CompressionAlgorithm::NOCOMPRESSION);

	// Generate some payload chunks, keeping track of what we're writing.
	shared_ptr<ByteArrayOutputStream> message = make_shared<ByteArrayOutputStream>();
	const int count = random.nextInt(MAX_PAYLOAD_CHUNKS) + 1;
	for (int i = 0; i < count; ++i) {
		// Randomly choose to set the compression algorithm and call flush.
		if (random.nextBoolean()) mos->flush();
		mos->setCompressionAlgorithm(random.nextBoolean() ? CompressionAlgorithm::GZIP : CompressionAlgorithm::NOCOMPRESSION);
		shared_ptr<ByteArray> data = make_shared<ByteArray>(random.nextInt(MAX_DATA_SIZE) + 1);
		random.nextBytes(*data);
		mos->write(*data);
		message->write(*data);
	}
	mos->close();

	// The destination should have received the message header followed by
	// one or more payload chunks.
	shared_ptr<InputStream> mslMessage = make_shared<ByteArrayInputStream>(destination->toByteArray());
	shared_ptr<MslTokenizer> tokenizer = encoder->createTokenizer(mslMessage);
	shared_ptr<MslObject> headerMo = tokenizer->nextObject(TIMEOUT);
	vector<shared_ptr<MslObject>> payloadMos;
	while (tokenizer->more(TIMEOUT))
		payloadMos.push_back(tokenizer->nextObject(TIMEOUT));
	tokenizer->close();

	shared_ptr<Header> header = Header::parseHeader(ctx, headerMo, cryptoContexts);
	EXPECT_TRUE(instanceof<MessageHeader>(header));
	shared_ptr<MessageHeader> messageHeader = dynamic_pointer_cast<MessageHeader>(header);

	// Verify payloads, cached payloads, and aggregate data.
	int sequenceNumber = 1;
	shared_ptr<ByteArrayOutputStream> data = make_shared<ByteArrayOutputStream>();
	shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(payloadMos.size(), payloads.size());
	for (size_t i = 0; i < payloadMos.size(); ++i) {
		shared_ptr<PayloadChunk> payload = make_shared<PayloadChunk>(ctx, payloadMos[i], cryptoContext);
		EXPECT_EQ(sequenceNumber++, payload->getSequenceNumber());
		EXPECT_EQ(messageHeader->getMessageId(), payload->getMessageId());
		EXPECT_EQ(i == payloadMos.size() - 1, payload->isEndOfMessage());
		data->write(*payload->getData());
		EXPECT_EQ(*payload, *payloads[i]);
	}
	EXPECT_EQ(*message->toByteArray(), *data->toByteArray());
}

TEST_F(MessageOutputStreamTest, noCtxCompressionAlgorithm)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	ctx->setMessageCapabilities(NULL_MSG_CAPS);

	// The intersection of compression algorithms is computed when a
	// response header is generated.
	shared_ptr<MessageHeader> responseHeader = messageFactory->createResponse(ctx, MESSAGE_HEADER)->getHeader();

	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, responseHeader, PAYLOAD_CRYPTO_CONTEXT);
	EXPECT_FALSE(mos->setCompressionAlgorithm(CompressionAlgorithm::GZIP));
	EXPECT_FALSE(mos->setCompressionAlgorithm(CompressionAlgorithm::LZW));
	mos->write(*COMPRESSIBLE_DATA);
	mos->close();

	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(1), payloads.size());
	EXPECT_EQ(CompressionAlgorithm::NOCOMPRESSION, payloads[0]->getCompressionAlgo());
}

TEST_F(MessageOutputStreamTest, noRequestCompressionAlgorithm)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, ENTITY_AUTH_DATA, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, PAYLOAD_CRYPTO_CONTEXT);
	EXPECT_FALSE(mos->setCompressionAlgorithm(CompressionAlgorithm::GZIP));
	EXPECT_FALSE(mos->setCompressionAlgorithm(CompressionAlgorithm::LZW));
	mos->write(*COMPRESSIBLE_DATA);
	mos->close();

	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(1), payloads.size());
	EXPECT_EQ(CompressionAlgorithm::NOCOMPRESSION, payloads[0]->getCompressionAlgo());
}

TEST_F(MessageOutputStreamTest, bestCompressionAlgorithm)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
	mos->write(*COMPRESSIBLE_DATA);
	mos->close();

	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(1), payloads.size());

	shared_ptr<MessageCapabilities> capabilities = ctx->getMessageCapabilities();
	set<CompressionAlgorithm> algos = capabilities->getCompressionAlgorithms();
	const CompressionAlgorithm bestAlgo = CompressionAlgorithm::getPreferredAlgorithm(algos);
	EXPECT_EQ(bestAlgo, payloads[0]->getCompressionAlgo());
}

TEST_F(MessageOutputStreamTest, setCompressionAlgorithm)
{
	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
	EXPECT_TRUE(mos->setCompressionAlgorithm(CompressionAlgorithm::GZIP));
	mos->write(*COMPRESSIBLE_DATA);
	EXPECT_TRUE(mos->setCompressionAlgorithm(CompressionAlgorithm::NOCOMPRESSION));
	mos->write(*COMPRESSIBLE_DATA);
	EXPECT_TRUE(mos->setCompressionAlgorithm(CompressionAlgorithm::GZIP));
	mos->write(*COMPRESSIBLE_DATA);
	mos->close();

	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(3), payloads.size());
	EXPECT_EQ(CompressionAlgorithm::GZIP, payloads[0]->getCompressionAlgo());
	EXPECT_EQ(CompressionAlgorithm::NOCOMPRESSION, payloads[1]->getCompressionAlgo());
	EXPECT_EQ(CompressionAlgorithm::GZIP, payloads[2]->getCompressionAlgo());
}

TEST_F(MessageOutputStreamTest, oneCompressionAlgorithm)
{
	set<CompressionAlgorithm> algos;
	algos.insert(CompressionAlgorithm::GZIP);
	shared_ptr<MessageCapabilities> capabilities = make_shared<MessageCapabilities>(algos, EMPTY_LANGUAGES, EMPTY_FORMATS);

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(1, REPLAYABLE_ID, false, false, capabilities, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, ENTITY_AUTH_DATA, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<MessageOutputStream> mos = make_shared<MessageOutputStream>(ctx, destination, messageHeader, PAYLOAD_CRYPTO_CONTEXT);
	EXPECT_FALSE(mos->setCompressionAlgorithm(CompressionAlgorithm::LZW));
	mos->write(*COMPRESSIBLE_DATA);
	mos->close();

	vector<shared_ptr<PayloadChunk>> payloads = mos->getPayloads();
	EXPECT_EQ(static_cast<size_t>(1), payloads.size());
	EXPECT_EQ(CompressionAlgorithm::GZIP, payloads[0]->getCompressionAlgo());
}

}}} // namespace netflix::msl::msg
