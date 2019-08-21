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

#include <gtest/gtest.h>
#include <msg/MessageInputStream.h>
#include <IOException.h>
#include <MslConstants.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <MslMessageException.h>
#include <MslUserIdTokenException.h>
#include <crypto/ICryptoContext.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/Key.h>
#include <crypto/NullCryptoContext.h>
#include <crypto/Random.h>
#include <crypto/SessionCryptoContext.h>
#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <entityauth/PresharedAuthenticationData.h>
#include <entityauth/PresharedAuthenticationFactory.h>
#include <entityauth/RsaAuthenticationData.h>
#include <entityauth/UnauthenticatedAuthenticationData.h>
#include <entityauth/UnauthenticatedAuthenticationFactory.h>
#include <io/ByteArrayInputStream.h>
#include <io/ByteArrayOutputStream.h>
#include <io/InputStream.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <msg/ErrorHeader.h>
#include <msg/Header.h>
#include <msg/MessageCapabilities.h>
#include <msg/MessageHeader.h>
#include <msg/PayloadChunk.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <tokens/ServiceToken.h>
#include <tokens/MslUser.h>
#include <userauth/UserAuthenticationData.h>
#include <util/MslContext.h>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../entityauth/MockPresharedAuthenticationFactory.h"
#include "../entityauth/MockRsaAuthenticationFactory.h"
#include "../tokens/MockTokenFactory.h"
#include "../userauth/MockEmailPasswordAuthenticationFactory.h"
#include "../util/MslTestUtils.h"
#include "../util/MockAuthenticationUtils.h"
#include "../util/MockMslContext.h"

using namespace std;
using namespace testing;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::keyx;
using namespace netflix::msl::msg;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;
using namespace netflix::msl::MslConstants;
using KeyExchangeData = netflix::msl::keyx::KeyExchangeFactory::KeyExchangeData;
using HeaderData = netflix::msl::msg::MessageHeader::HeaderData;
using HeaderPeerData = netflix::msl::msg::MessageHeader::HeaderPeerData;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace msg {

namespace {
/** Maximum number of payload chunks to generate. */
const int MAX_PAYLOAD_CHUNKS = 12;
/** Maximum payload chunk data size in bytes. */
const int MAX_DATA_SIZE = 100 * 1024;
/** Non-replayable ID acceptance window. */
const int64_t NON_REPLAYABLE_ID_WINDOW = 65536;

/**
 * A crypto context that always returns false for verify. The other crypto
 * operations are no-ops.
 */
class RejectingCryptoContext : public NullCryptoContext
{
	/** @inheritDoc */
    virtual bool verify(shared_ptr<ByteArray> /*data*/, shared_ptr<ByteArray> /*signature*/, shared_ptr<MslEncoderFactory> /*encoder*/) {
        return false;
    }
};

/**
 * Increments the provided non-replayable ID by 1, wrapping around to zero
 * if the provided value is equal to {@link MslConstants#MAX_LONG_VALUE}.
 *
 * @param id the non-replayable ID to increment.
 * @return the non-replayable ID + 1.
 * @throws MslInternalException if the provided non-replayable ID is out of
 *         range.
 */
int64_t incrementNonReplayableId(const int64_t id) {
    if (id < 0 || id > MslConstants::MAX_LONG_VALUE) {
    	stringstream ss;
    	ss << "Non-replayable ID " << id << " is outside the valid range.";
        throw MslInternalException(ss.str());
    }
    return (id == MslConstants::MAX_LONG_VALUE) ? 0 : id + 1;
}

const int64_t SEQ_NO = 1;
const int64_t MSG_ID = 42;
const bool END_OF_MSG = true;

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

const string UNAUTHENTICATED_ESN = "MOCKUNAUTH-ESN";

} // namespace anonymous

/**
 * Message input stream unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageInputStreamTest : public ::testing::Test
{
public:
	virtual ~MessageInputStreamTest() {}

	MessageInputStreamTest()
		: format(MslEncoderFormat::JSON)
		, trustedNetCtx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
		, p2pCtx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, true))
		, encoder(trustedNetCtx->getMslEncoderFactory())
		, buffer(MAX_PAYLOAD_CHUNKS * MAX_DATA_SIZE)
		, DATA(make_shared<ByteArray>(32))
	{
		random.nextBytes(*DATA);

		shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
		shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
		shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
		MESSAGE_HEADER = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

		ERROR_HEADER =  make_shared<ErrorHeader>(trustedNetCtx, entityAuthData, 1, ResponseCode::FAIL, 3, "errormsg", "usermsg");

		shared_ptr<KeyRequestData> keyRequest = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
		KEY_REQUEST_DATA.insert(keyRequest);
		shared_ptr<KeyExchangeFactory> factory = trustedNetCtx->getKeyExchangeFactory(keyRequest->getKeyExchangeScheme());
		shared_ptr<KeyExchangeData> keyxData = factory->generateResponse(trustedNetCtx, format, keyRequest, entityAuthData);
		KEY_RESPONSE_DATA = keyxData->keyResponseData;
		KEYX_CRYPTO_CONTEXT = keyxData->cryptoContext;

		shared_ptr<ByteArray> mke = make_shared<ByteArray>(16);
		shared_ptr<ByteArray> mkh = make_shared<ByteArray>(32);
		shared_ptr<ByteArray> mkw = make_shared<ByteArray>(16);
		random.nextBytes(*mke);
		random.nextBytes(*mkh);
		random.nextBytes(*mkw);
		SecretKey encryptionKey(mke, JcaAlgorithm::AES);
		SecretKey hmacKey(mkh, JcaAlgorithm::HMAC_SHA256);
		SecretKey wrappingKey(mkw, JcaAlgorithm::AESKW);
		ALT_MSL_CRYPTO_CONTEXT = make_shared<SymmetricCryptoContext>(trustedNetCtx, "clientMslCryptoContext", encryptionKey, hmacKey, wrappingKey);
	}

protected:
	/**
	 * Create a new input stream containing a MSL message constructed from the
	 * provided header and payloads.
	 *
	 * @param header message or error header.
	 * @param payloads zero or more payload chunks.
	 * @return an input stream containing the MSL message.
	 * @throws IOException if there is an error creating the input stream.
	 * @throws MslEncoderException if there is an error encoding the data.
	 */
	shared_ptr<InputStream> generateInputStream(shared_ptr<Header> header, vector<shared_ptr<PayloadChunk>> payloads) {
	    ByteArrayOutputStream baos;
	    shared_ptr<ByteArray> headerBytes = header->toMslEncoding(encoder, format);
	    baos.write(*headerBytes, 0, headerBytes->size());
	    for (size_t i = 0; i < payloads.size(); ++i) {
	    	shared_ptr<PayloadChunk> payload = payloads[i];
	    	shared_ptr<ByteArray> payloadBytes = payload->toMslEncoding(encoder, format);
	    	baos.write(*payloadBytes, 0, payloadBytes->size());
	    }
	    return make_shared<ByteArrayInputStream>(baos.toByteArray());
	}

	/** MSL encoder format. */
	const MslEncoderFormat format;

    /** Random. */
    Random random;
    /** Trusted network MSL context. */
    shared_ptr<MslContext> trustedNetCtx;
    /** Peer-to-peer MSL context. */
    shared_ptr<MslContext> p2pCtx;
    /** MSL encoder factory-> */
    shared_ptr<MslEncoderFactory> encoder;
    /** Header service token crypto contexts. */
    map<string,shared_ptr<ICryptoContext>> cryptoContexts;
    /** Message payloads (initially empty). */
    vector<shared_ptr<PayloadChunk>> payloads;
    /** Data read buffer. */
    ByteArray buffer;

    shared_ptr<MessageHeader> MESSAGE_HEADER;
    shared_ptr<ErrorHeader> ERROR_HEADER;
    set<shared_ptr<KeyRequestData>> KEY_REQUEST_DATA;
    shared_ptr<KeyResponseData> KEY_RESPONSE_DATA;
    shared_ptr<ICryptoContext> KEYX_CRYPTO_CONTEXT, ALT_MSL_CRYPTO_CONTEXT;

    shared_ptr<ByteArray> DATA;
};

TEST_F(MessageInputStreamTest, messageHeaderEmpty)
{
	// An end-of-message payload is expected.
	shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
	payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, make_shared<ByteArray>(), cryptoContext));
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_FALSE(mis->getErrorHeader());
	EXPECT_EQ(*MESSAGE_HEADER, *mis->getMessageHeader());
	EXPECT_TRUE(mis->markSupported());
	EXPECT_EQ(-1, mis->read(buffer));
	EXPECT_EQ(-1, mis->read(buffer, 0, 1));

	mis->mark(0);
	mis->reset();
	mis->close();
}

TEST_F(MessageInputStreamTest, messageHeaderData)
{
	// An end-of-message payload is expected.
	shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
	payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, cryptoContext));
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_EQ(static_cast<int>(DATA->size()), mis->read(buffer));
	EXPECT_EQ(*DATA, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(DATA->size())));

	mis->close();
}

TEST_F(MessageInputStreamTest, entityAuthDataIdentity)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_EQ(entityAuthData->getIdentity(), mis->getIdentity());

	mis->close();
}

TEST_F(MessageInputStreamTest, masterTokenIdentity)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(trustedNetCtx, 1, 1);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_EQ(masterToken->getIdentity(), mis->getIdentity());

	mis->close();
}

TEST_F(MessageInputStreamTest, errorHeaderIdentity)
{
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(trustedNetCtx, entityAuthData, 1, ResponseCode::FAIL, 3, "errormsg", "usermsg");

	shared_ptr<InputStream> is = generateInputStream(errorHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_EQ(entityAuthData->getIdentity(), mis->getIdentity());

	mis->close();
}

TEST_F(MessageInputStreamTest, revokedEntity)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::NONE, false);
	shared_ptr<MockAuthenticationUtils> authutils = make_shared<MockAuthenticationUtils>();
	shared_ptr<UnauthenticatedAuthenticationFactory> factory = make_shared<UnauthenticatedAuthenticationFactory>(authutils);
	ctx->addEntityAuthenticationFactory(factory);

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	authutils->revokeEntity(entityAuthData->getIdentity());
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEntityAuthException& e) {
		EXPECT_EQ(MslError::ENTITY_REVOKED, e.getError());
	}
}

TEST_F(MessageInputStreamTest, revokedMasterToken)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	shared_ptr<MockTokenFactory> factory = make_shared<MockTokenFactory>();
	ctx->setTokenFactory(factory);

	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	factory->setRevokedMasterToken(masterToken);
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMasterTokenException& e) {
		EXPECT_EQ(MslError::MASTERTOKEN_IDENTITY_REVOKED, e.getError());
	}
}

TEST_F(MessageInputStreamTest, nullUser)
{
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_FALSE(mis->getUser());

	mis->close();
}

TEST_F(MessageInputStreamTest, userIdTokenUser)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(trustedNetCtx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(trustedNetCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, userIdToken, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_EQ(*userIdToken->getUser(), *mis->getUser());

	mis->close();
}

TEST_F(MessageInputStreamTest, revokedUserIdToken)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	shared_ptr<MockTokenFactory> factory = make_shared<MockTokenFactory>();
	ctx->setTokenFactory(factory);

	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, userIdToken, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	factory->setRevokedUserIdToken(userIdToken);
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslUserIdTokenException& e) {
		EXPECT_EQ(MslError::USERIDTOKEN_REVOKED, e.getError());
	}
}

TEST_F(MessageInputStreamTest, untrustedUserIdToken)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	shared_ptr<MockTokenFactory> factory = make_shared<MockTokenFactory>();
	ctx->setTokenFactory(factory);

	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUntrustedUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, userIdToken, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	factory->setRevokedUserIdToken(userIdToken);
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslUserIdTokenException& e) {
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

// FIXME This can be removed once the old handshake logic is removed.
TEST_F(MessageInputStreamTest, explicitHandshake)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, true, true, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_TRUE(mis->isHandshake());

	mis->close();
}

// FIXME This can be removed once the old handshake logic is removed.
TEST_F(MessageInputStreamTest, inferredHandshake)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, make_shared<ByteArray>(), messageHeader->getCryptoContext()));
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_TRUE(mis->isHandshake());

	mis->close();
}

// FIXME This can be removed once the old handshake logic is removed.
TEST_F(MessageInputStreamTest, notHandshake)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, messageHeader->getCryptoContext()));
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_FALSE(mis->isHandshake());

	mis->close();
}

TEST_F(MessageInputStreamTest, keyExchange)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	// Encrypt the payload with the key exchange crypto context.
	payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, KEYX_CRYPTO_CONTEXT));
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_EQ(static_cast<int>(DATA->size()), mis->read(buffer));
	EXPECT_EQ(*DATA, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(DATA->size())));
	EXPECT_EQ(mis->getPayloadCryptoContext(), mis->getKeyExchangeCryptoContext());

	mis->close();
}

TEST_F(MessageInputStreamTest, peerKeyExchange)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	// Encrypt the payload with the key exchange crypto context.
	shared_ptr<ICryptoContext> cryptoContext = messageHeader->getCryptoContext();
	payloads.push_back(make_shared<PayloadChunk>(p2pCtx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm::NOCOMPRESSION, DATA, cryptoContext));
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_EQ(static_cast<int>(DATA->size()), mis->read(buffer));
	EXPECT_EQ(*DATA, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(DATA->size())));
	EXPECT_NE(mis->getPayloadCryptoContext(), mis->getKeyExchangeCryptoContext());

	mis->close();
}

TEST_F(MessageInputStreamTest, unsupportedKeyExchangeScheme)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	ctx->removeKeyExchangeFactories(KeyExchangeScheme::SYMMETRIC_WRAPPED);

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslKeyExchangeException& e) {
		EXPECT_EQ(MslError::KEYX_FACTORY_NOT_FOUND, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, missingKeyRequestData)
{
	// We need to replace the MSL crypto context before parsing the message
	// so create a local MSL context.
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, true);

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	ctx->setMslCryptoContext(make_shared<RejectingCryptoContext>());
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, EMPTY_KEYX_REQUESTS, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslKeyExchangeException& e) {
		EXPECT_EQ(MslError::KEYX_RESPONSE_REQUEST_MISMATCH, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, incompatibleKeyRequestData)
{
	// We need to replace the MSL crypto context before parsing the message
	// so create a local MSL context.
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, true);

	set<shared_ptr<KeyRequestData>> keyRequestData;
	keyRequestData.insert(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION));

	shared_ptr<KeyRequestData> keyRequest = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
	shared_ptr<KeyExchangeFactory> factory = ctx->getKeyExchangeFactory(keyRequest->getKeyExchangeScheme());
	shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData();
	shared_ptr<KeyExchangeData> keyExchangeData = factory->generateResponse(ctx, format, keyRequest, entityAuthData);
	shared_ptr<KeyResponseData> keyResponseData = keyExchangeData->keyResponseData;

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, keyResponseData, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	ctx->setMslCryptoContext(make_shared<RejectingCryptoContext>());
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, keyRequestData, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslKeyExchangeException& e) {
		EXPECT_EQ(MslError::KEYX_RESPONSE_REQUEST_MISMATCH, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, oneCompatibleKeyRequestData)
{
	// Populate the key request data such that the compatible data requires
	// iterating through one of the incompatible ones.
	set<shared_ptr<KeyRequestData>> keyRequestData;
	shared_ptr<KeyRequestData> keyRequest = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
	keyRequestData.insert(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION));
	keyRequestData.insert(keyRequest);
	keyRequestData.insert(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION));

	shared_ptr<KeyExchangeFactory> factory = trustedNetCtx->getKeyExchangeFactory(keyRequest->getKeyExchangeScheme());
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<KeyExchangeData> keyExchangeData = factory->generateResponse(trustedNetCtx, format, keyRequest, entityAuthData);
	shared_ptr<KeyResponseData> keyResponseData = keyExchangeData->keyResponseData;

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, keyResponseData, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, keyRequestData, cryptoContexts);
	mis->close();
}

TEST_F(MessageInputStreamTest, expiredRenewableClientMessage)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
	mis->close();
}

TEST_F(MessageInputStreamTest, expiredRenewablePeerMessage)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(p2pCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);
	mis->close();
}

TEST_F(MessageInputStreamTest, expiredNotRenewableClientMessage)
{
	// Expired messages received by a trusted network server should be
	// rejected.
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::MESSAGE_EXPIRED_NOT_RENEWABLE, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, expiredNoKeyRequestDataClientMessage)
{
	// Expired renewable messages received by a trusted network server
	// with no key request data should be rejected.
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::MESSAGE_EXPIRED_NO_KEYREQUEST_DATA, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, expiredNotRenewableServerMessage)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	// Expired messages received by a trusted network client should not be
	// rejected.
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	// The master token's crypto context must be cached, as if the client
	// constructed it after a previous message exchange.
	shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(ctx, masterToken);
	ctx->getMslStore()->setCryptoContext(masterToken, cryptoContext);

	// Generate the input stream. This will encode the message.
	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);

	// Change the MSL crypto context so the master token can no longer be
	// verified or decrypted.
	ctx->setMslCryptoContext(ALT_MSL_CRYPTO_CONTEXT);

	// Now "receive" the message with a master token that we cannot verify
	// or decrypt, but for which a cached crypto context exists.
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
	mis->close();
}

TEST_F(MessageInputStreamTest, expiredNoKeyRequestDataPeerMessage)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(p2pCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::MESSAGE_EXPIRED_NO_KEYREQUEST_DATA, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, expiredNotRenewablePeerMessage)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(p2pCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::MESSAGE_EXPIRED_NOT_RENEWABLE, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, handshakeNotRenewable)
{
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, 1L, false, true, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::HANDSHAKE_DATA_MISSING, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, handshakeMissingKeyRequestData)
{
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, 1L, true, true, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::HANDSHAKE_DATA_MISSING, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, nonReplayableNoMasterTokenClientMessage)
{

	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, 1L, true, true, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::INCOMPLETE_NONREPLAYABLE_MESSAGE, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, nonReplayableNoMasterTokenPeerMessage)
{
	shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData();
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, 1L, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::INCOMPLETE_NONREPLAYABLE_MESSAGE, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, nonReplayableIdEqual)
{
	const int64_t nonReplayableId = 1L;
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1L, 1L);
	shared_ptr<MockTokenFactory> factory = make_shared<MockTokenFactory>();
	factory->setLargestNonReplayableId(nonReplayableId);
	ctx->setTokenFactory(factory);

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, nonReplayableId, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::MESSAGE_REPLAYED, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, nonReplayableIdSmaller)
{
	const int64_t nonReplayableId = 2L;
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1L, 1L);
	shared_ptr<MockTokenFactory> factory = make_shared<MockTokenFactory>();
	factory->setLargestNonReplayableId(nonReplayableId);
	ctx->setTokenFactory(factory);

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, nonReplayableId - 1, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::MESSAGE_REPLAYED, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, nonReplayableIdOutsideWindow)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1L, 1L);
	shared_ptr<MockTokenFactory> factory = make_shared<MockTokenFactory>();
	ctx->setTokenFactory(factory);

	int64_t largestNonReplayableId = MslConstants::MAX_LONG_VALUE - NON_REPLAYABLE_ID_WINDOW - 1;
	int64_t nonReplayableId = MslConstants::MAX_LONG_VALUE;
	for (int i = 0; i < 2; ++i) {
		shared_ptr<MessageInputStream> mis;
		try {
			factory->setLargestNonReplayableId(largestNonReplayableId);

			shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, nonReplayableId, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
			shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
			shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

			shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
			mis = make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
			ADD_FAILURE() << i << ": Non-replayable ID " << nonReplayableId << " accepted with largest non-replayable ID " << largestNonReplayableId;
		} catch (const MslMessageException& e) {
			EXPECT_EQ(MslError::MESSAGE_REPLAYED_UNRECOVERABLE, e.getError());
			EXPECT_EQ(MSG_ID, e.getMessageId());
		}
		if (mis) mis->close();

		largestNonReplayableId = incrementNonReplayableId(largestNonReplayableId);
		nonReplayableId = incrementNonReplayableId(nonReplayableId);
	}
}

// FIXME this takes an unexpectedly long time to complete. It passes, but
// disable until the cause is identified.
/*
TEST_F(MessageInputStreamTest, nonReplayableIdInsideWindow)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1L, 1L);
	shared_ptr<MockTokenFactory> factory = make_shared<MockTokenFactory>();
	ctx->setTokenFactory(factory);

	int64_t largestNonReplayableId = MslConstants::MAX_LONG_VALUE - NON_REPLAYABLE_ID_WINDOW;
	int64_t nonReplayableId = MslConstants::MAX_LONG_VALUE;
	for (int i = 0; i < NON_REPLAYABLE_ID_WINDOW + 1; ++i) {
		shared_ptr<MessageInputStream> mis;
		try {
			factory->setLargestNonReplayableId(largestNonReplayableId);

			shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, nonReplayableId, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
			shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
			shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

			shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
			mis = make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		} catch (const MslMessageException& e) {
			ADD_FAILURE() << i << ": Non-replayable ID " << nonReplayableId << " rejected with largest non-replayable ID " << largestNonReplayableId;
		}
		if (mis) mis->close();

		largestNonReplayableId = incrementNonReplayableId(largestNonReplayableId);
		nonReplayableId = incrementNonReplayableId(nonReplayableId);
	}
}
*/

TEST_F(MessageInputStreamTest, replayedClientMessage)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1L, 1L);
	shared_ptr<MockTokenFactory> factory = make_shared<MockTokenFactory>();
	factory->setLargestNonReplayableId(1L);
	ctx->setTokenFactory(factory);

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, 1L, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::MESSAGE_REPLAYED, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, replayedPeerMessage)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, true);

	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1L, 1L);
	shared_ptr<MockTokenFactory> factory = make_shared<MockTokenFactory>();
	factory->setLargestNonReplayableId(1L);
	ctx->setTokenFactory(factory);

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, 1L, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	try {
		make_shared<MessageInputStream>(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::MESSAGE_REPLAYED, e.getError());
		EXPECT_EQ(MSG_ID, e.getMessageId());
	}
}

TEST_F(MessageInputStreamTest, errorHeader)
{
	shared_ptr<InputStream> is = generateInputStream(ERROR_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	EXPECT_EQ(*ERROR_HEADER, *mis->getErrorHeader());
	EXPECT_FALSE(mis->getMessageHeader());
	EXPECT_TRUE(mis->markSupported());

	mis->mark(0);
	mis->reset();
	mis->close();
}

TEST_F(MessageInputStreamTest, readFromError)
{
	shared_ptr<InputStream> is = generateInputStream(ERROR_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
	try {
		mis->read(buffer);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageInputStreamTest, readFromHandshakeMessage)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, true, true, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

	shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
	shared_ptr<ByteArray> b = make_shared<ByteArray>(1);
	int read = mis->read(*b);
	EXPECT_EQ(-1, read);
	mis->close();
}

TEST_F(MessageInputStreamTest, missingEndOfMessage)
{
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	// If there's nothing left we'll receive end of message anyway.
	EXPECT_EQ(-1, mis->read(buffer));

	mis->close();
}

TEST_F(MessageInputStreamTest, entityAuthSchemeEncrypts)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->encryptsPayloads());
    mis->close();
}

TEST_F(MessageInputStreamTest, entityAuthSchemeDoesNotEncrypt)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_FALSE(mis->encryptsPayloads());
    mis->close();
}

TEST_F(MessageInputStreamTest, entityAuthSchemeIntegrityProtects)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->protectsPayloadIntegrity());
    mis->close();
}

TEST_F(MessageInputStreamTest, entityAuthSchemeDoesNotIntegrityProtect)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<UnauthenticatedAuthenticationData>(UNAUTHENTICATED_ESN);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_FALSE(mis->protectsPayloadIntegrity());
    mis->close();
}

TEST_F(MessageInputStreamTest, entityAuthSchemeKeyxEncrypts)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->encryptsPayloads());
    mis->close();
}

TEST_F(MessageInputStreamTest, entityAuthSchemeKeyxIntegrityProtects)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->protectsPayloadIntegrity());
    mis->close();
}

TEST_F(MessageInputStreamTest, entitAuthSchemeDoesNotKeyxEncrypts)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->encryptsPayloads());
    mis->close();
}

TEST_F(MessageInputStreamTest, entityAuthSchemeDoesNotKeyxIntegrityProtects)
{
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<UnauthenticatedAuthenticationData>(UNAUTHENTICATED_ESN);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, NULL_MASTER_TOKEN, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->protectsPayloadIntegrity());
    mis->close();
}

TEST_F(MessageInputStreamTest, masterTokenEncrypts)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(trustedNetCtx, 1, 1);
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->encryptsPayloads());
    mis->close();
}

TEST_F(MessageInputStreamTest, masterTokenIntegrityProtects)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(trustedNetCtx, 1, 1);
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->protectsPayloadIntegrity());
    mis->close();
}

TEST_F(MessageInputStreamTest, masterTokenKeyxEncrypts)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(trustedNetCtx, 1, 1);
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->encryptsPayloads());
    mis->close();
}

TEST_F(MessageInputStreamTest, masterTokenKeyxIntegrityProtects)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(trustedNetCtx, 1, 1);
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MSG_ID, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, KEY_RESPONSE_DATA, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, masterToken, headerData, peerData);

    shared_ptr<InputStream> is = generateInputStream(messageHeader, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
    EXPECT_TRUE(mis->protectsPayloadIntegrity());
    mis->close();
}

TEST_F(MessageInputStreamTest, prematureEndOfMessage)
{
	// Payloads after an end of message are ignored.
	int extraPayloads = MAX_PAYLOAD_CHUNKS / 2;
	ByteArrayOutputStream baos;
	shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
	for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
		shared_ptr<ByteArray> data = make_shared<ByteArray>(random.nextInt(MAX_DATA_SIZE) + 1);
		random.nextBytes(*data);
		if (i < extraPayloads) {
			payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == extraPayloads - 1), CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
			baos.write(*data);
		} else {
			payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO + i, MSG_ID, false, CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
		}
	}
	shared_ptr<ByteArray> appdata = baos.toByteArray();
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	// Read everything. We shouldn't get any of the extra payloads.
	EXPECT_EQ(static_cast<int>(appdata->size()), mis->read(buffer, 0, appdata->size() * 2));
	EXPECT_EQ(*appdata, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(appdata->size())));

	mis->close();
}

TEST_F(MessageInputStreamTest, mismatchedMessageId)
{
	// Payloads with an incorrect message ID should be skipped.
	int badPayloads = 0;
	int64_t sequenceNumber = SEQ_NO;
	ByteArrayOutputStream baos;
	shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
	for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
		shared_ptr<ByteArray> data = make_shared<ByteArray>(random.nextInt(MAX_DATA_SIZE) + 1);
		random.nextBytes(*data);
		if (random.nextBoolean()) {
			payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, sequenceNumber++, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
			baos.write(*data);
		} else {
			payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, sequenceNumber, 2 * MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
			++badPayloads;
		}
	}
	shared_ptr<ByteArray> appdata = baos.toByteArray();
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	// Read everything. Each bad payload should throw an exception.
	int offset = 0;
	int caughtExceptions = 0;
	while (true) {
		try {
			const int bytesRead = mis->read(buffer, static_cast<size_t>(offset), buffer.size() - static_cast<size_t>(offset));
			if (bytesRead == -1) break;
			offset += bytesRead;
		} catch (const IOException& e) {
			++caughtExceptions;
		}
	}
	EXPECT_EQ(badPayloads, caughtExceptions);
	EXPECT_EQ(*appdata, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(appdata->size())));

	mis->close();
}

TEST_F(MessageInputStreamTest, incorrectSequenceNumber)
{
	// Payloads with an incorrect sequence number should be skipped.
	int badPayloads = 0;
	long sequenceNumber = SEQ_NO;
	ByteArrayOutputStream baos;
	shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
	for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
		shared_ptr<ByteArray> data = make_shared<ByteArray>(random.nextInt(MAX_DATA_SIZE) + 1);
		random.nextBytes(*data);
		if (random.nextBoolean()) {
			payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, sequenceNumber++, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
			baos.write(*data);
		} else {
			payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, 2 * sequenceNumber + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
			++badPayloads;
		}
	}
	shared_ptr<ByteArray> appdata = baos.toByteArray();
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	// Read everything. Each bad payload should throw an exception.
	int offset = 0;
	int caughtExceptions = 0;
	while (true) {
		try {
			const int bytesRead = mis->read(buffer, static_cast<size_t>(offset), buffer.size() - static_cast<size_t>(offset));
			if (bytesRead == -1) break;
			offset += bytesRead;
		} catch (const IOException& e) {
			++caughtExceptions;
		}
	}
	EXPECT_EQ(badPayloads, caughtExceptions);
	EXPECT_EQ(*appdata, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(appdata->size())));

	mis->close();
}

TEST_F(MessageInputStreamTest, markReset)
{
	ByteArrayOutputStream baos;
	shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
	for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
		shared_ptr<ByteArray> data = make_shared<ByteArray>(random.nextInt(MAX_DATA_SIZE) + 1);
		random.nextBytes(*data);
		payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
		baos.write(*data);
	}
	shared_ptr<ByteArray> appdata = baos.toByteArray();
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	// Mark and reset to the beginning.
	const size_t beginningOffset = 0;
	const size_t beginningLength = appdata->size() / 4;
	const size_t beginningTo = beginningOffset + beginningLength;
	ByteArray expectedBeginning(appdata->begin() + beginningOffset, appdata->begin() + static_cast<ptrdiff_t>(beginningTo));
	mis->mark(appdata->size());
	EXPECT_EQ(static_cast<int>(expectedBeginning.size()), mis->read(buffer, beginningOffset, beginningLength));
	EXPECT_EQ(expectedBeginning, ByteArray(buffer.begin() + beginningOffset, buffer.begin() + static_cast<ptrdiff_t>(beginningTo)));
	mis->reset();
	EXPECT_EQ(static_cast<int>(expectedBeginning.size()), mis->read(buffer, beginningOffset, beginningLength));
	EXPECT_EQ(expectedBeginning, ByteArray(buffer.begin() + beginningOffset, buffer.begin() + static_cast<ptrdiff_t>(beginningTo)));

	// Mark and reset from where we are.
	const size_t middleOffset = beginningTo;
	const size_t middleLength = appdata->size() / 4;
	const size_t middleTo = middleOffset + middleLength;
	ByteArray expectedMiddle(appdata->begin() + static_cast<ptrdiff_t>(middleOffset), appdata->begin() + static_cast<ptrdiff_t>(middleTo));
	mis->mark(appdata->size());
	EXPECT_EQ(static_cast<int>(expectedMiddle.size()), mis->read(buffer, middleOffset, middleLength));
	EXPECT_EQ(expectedMiddle, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(middleOffset), buffer.begin() + static_cast<ptrdiff_t>(middleTo)));
	mis->reset();
	EXPECT_EQ(static_cast<int>(expectedMiddle.size()), mis->read(buffer, middleOffset, middleLength));
	EXPECT_EQ(expectedMiddle, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(middleOffset), buffer.begin() + static_cast<ptrdiff_t>(middleTo)));

	// Mark and reset the remainder.
	const size_t endingOffset = middleTo;
	const size_t endingLength = appdata->size() - middleLength - beginningLength;
	const size_t endingTo = endingOffset + endingLength;
	ByteArray expectedEnding(appdata->begin() + static_cast<ptrdiff_t>(endingOffset), appdata->begin() + static_cast<ptrdiff_t>(endingTo));
	mis->mark(appdata->size());
	EXPECT_EQ(static_cast<int>(expectedEnding.size()), mis->read(buffer, endingOffset, endingLength));
	EXPECT_EQ(expectedEnding, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(endingOffset), buffer.begin() + static_cast<ptrdiff_t>(endingTo)));
	mis->reset();
	EXPECT_EQ(static_cast<int>(expectedEnding.size()), mis->read(buffer, endingOffset, endingLength));
	EXPECT_EQ(expectedEnding, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(endingOffset), buffer.begin() + static_cast<ptrdiff_t>(endingTo)));

	// Confirm equality.
	EXPECT_EQ(*appdata, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(appdata->size())));

	mis->close();
}

TEST_F(MessageInputStreamTest, markResetShortMark)
{
	ByteArrayOutputStream baos;
	shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
	for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
		shared_ptr<ByteArray> data = make_shared<ByteArray>(random.nextInt(MAX_DATA_SIZE) + 1);
		random.nextBytes(*data);
		payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
		baos.write(*data);
	}
	shared_ptr<ByteArray> appdata = baos.toByteArray();
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	// Mark and reset to the beginning.
	const size_t beginningOffset = 0;
	const size_t beginningLength = appdata->size() / 2;
	const size_t beginningTo = beginningOffset + beginningLength;
	ByteArray expectedBeginning(appdata->begin() + static_cast<ptrdiff_t>(beginningOffset), appdata->begin() + static_cast<ptrdiff_t>(beginningLength));
	mis->mark(appdata->size());
	EXPECT_EQ(static_cast<int>(expectedBeginning.size()), mis->read(buffer, beginningOffset, beginningLength));
	EXPECT_EQ(expectedBeginning, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(beginningOffset), buffer.begin() + static_cast<ptrdiff_t>(beginningTo)));
	mis->reset();

	// Read a little bit, and mark again so we drop one or more payloads
	// but are likely to have more than one payload remaining.
	ByteArray reread(appdata->size() / 4);
	EXPECT_EQ(static_cast<int>(reread.size()), mis->read(reread));
	mis->mark(appdata->size());

	// Read the remainder, reset, and re-read to confirm.
	const size_t endingOffset = reread.size();
	const size_t endingLength = appdata->size() - endingOffset;
	const size_t endingTo = endingOffset + endingLength;
	ByteArray expectedEnding(appdata->begin() + static_cast<ptrdiff_t>(endingOffset), appdata->begin() + static_cast<ptrdiff_t>(endingTo));
	EXPECT_EQ(static_cast<int>(expectedEnding.size()), mis->read(buffer, endingOffset, endingLength));
	EXPECT_EQ(expectedEnding, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(endingOffset), buffer.begin() + static_cast<ptrdiff_t>(endingTo)));
	mis->reset();
	EXPECT_EQ(static_cast<int>(expectedEnding.size()), mis->read(buffer, endingOffset, endingLength));
	EXPECT_EQ(expectedEnding, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(endingOffset), buffer.begin() + static_cast<ptrdiff_t>(endingTo)));

	// Confirm equality.
	EXPECT_EQ(*appdata, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(appdata->size())));

	mis->close();
}

TEST_F(MessageInputStreamTest, markOneReadLimit)
{
    ByteArrayOutputStream baos;
    shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
    for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
        shared_ptr<ByteArray> data = make_shared<ByteArray>(random.nextInt(MAX_DATA_SIZE) + 1);
        random.nextBytes(*data);
        payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
        baos.write(*data);
    }
    shared_ptr<ByteArray> appdata = baos.toByteArray();
    shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

    // Mark one byte and reset to the beginning.
    const uint8_t expectedOne = (*appdata)[0];
    mis->mark(1);
    EXPECT_EQ(1, mis->read(buffer, 0, 1));
    EXPECT_EQ(expectedOne, buffer[0]);
    mis->reset();

    // Read a little bit and reset (which should not work).
    const size_t beginningOffset = 0;
    const size_t beginningLength = appdata->size() / 2;
    const size_t beginningTo = beginningOffset + beginningLength;
    ByteArray expectedBeginning(appdata->begin() + static_cast<ptrdiff_t>(beginningOffset), appdata->begin() + static_cast<ptrdiff_t>(beginningLength));
    EXPECT_EQ(static_cast<int>(expectedBeginning.size()), mis->read(buffer, beginningOffset, beginningLength));
    EXPECT_EQ(expectedBeginning, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(beginningOffset), buffer.begin() + static_cast<ptrdiff_t>(beginningTo)));
    mis->reset();

    // Read the remainder.
    const size_t endingOffset = beginningLength;
    const size_t endingLength = appdata->size() - endingOffset;
    const size_t endingTo = endingOffset + endingLength;
    ByteArray expectedEnding(appdata->begin() + static_cast<ptrdiff_t>(endingOffset), appdata->begin() + static_cast<ptrdiff_t>(endingTo));
    EXPECT_EQ(static_cast<int>(expectedEnding.size()), mis->read(buffer, endingOffset, endingLength));
    EXPECT_EQ(expectedEnding, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(endingOffset), buffer.begin() + static_cast<ptrdiff_t>(endingTo)));

    // Confirm equality.
    EXPECT_EQ(*appdata, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(appdata->size())));

    // Confirm end-of-stream.
    EXPECT_EQ(-1, mis->read(buffer));

    mis->close();
}

TEST_F(MessageInputStreamTest, markReadLimit)
{
    ByteArrayOutputStream baos;
    shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
    for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
        shared_ptr<ByteArray> data = make_shared<ByteArray>(random.nextInt(MAX_DATA_SIZE) + 1);
        random.nextBytes(*data);
        payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
        baos.write(*data);
    }
    shared_ptr<ByteArray> appdata = baos.toByteArray();
    shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
    shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

    // Read a little bit and mark with a short read limit.
    const size_t beginningOffset = 0;
    const size_t beginningLength = appdata->size() / 4;
    const size_t beginningTo = beginningOffset + beginningLength;
    ByteArray expectedBeginning(appdata->begin() + static_cast<ptrdiff_t>(beginningOffset), appdata->begin() + static_cast<ptrdiff_t>(beginningLength));
    EXPECT_EQ(static_cast<int>(expectedBeginning.size()), mis->read(buffer, beginningOffset, beginningLength));
    EXPECT_EQ(expectedBeginning, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(beginningOffset), buffer.begin() + static_cast<ptrdiff_t>(beginningTo)));
    const size_t readlimit = appdata->size() / 8;
    mis->mark(readlimit);

    // Read up to the read limit.
    const size_t readOffset = beginningLength;
    const size_t readLength = readlimit;
    const size_t readTo = readOffset + readLength;
    ByteArray expectedRead(appdata->begin() + static_cast<ptrdiff_t>(readOffset), appdata->begin() + static_cast<ptrdiff_t>(readTo));
    EXPECT_EQ(static_cast<int>(expectedRead.size()), mis->read(buffer, readOffset, readLength));
    EXPECT_EQ(expectedRead, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(readOffset), buffer.begin() + static_cast<ptrdiff_t>(readTo)));

    // Reset and re-read.
    mis->reset();
    EXPECT_EQ(static_cast<int>(expectedRead.size()), mis->read(buffer, readOffset, readLength));
    EXPECT_EQ(expectedRead, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(readOffset), buffer.begin() + static_cast<ptrdiff_t>(readTo)));

    // Reset and re-read.
    mis->reset();
    EXPECT_EQ(static_cast<int>(expectedRead.size()), mis->read(buffer, readOffset, readLength));
    EXPECT_EQ(expectedRead, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(readOffset), buffer.begin() + static_cast<ptrdiff_t>(readTo)));

    // Reset and read past the read limit.
    mis->reset();
    const size_t readPastOffset = beginningLength;
    const size_t readPastLength = readlimit + 1;
    const size_t readPastTo = readPastOffset + readPastLength;
    ByteArray expectedReadPast(appdata->begin() + static_cast<ptrdiff_t>(readPastOffset), appdata->begin() + static_cast<ptrdiff_t>(readPastTo));
    EXPECT_EQ(static_cast<int>(expectedReadPast.size()), mis->read(buffer, readPastOffset, readPastLength));
    EXPECT_EQ(expectedReadPast, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(readPastOffset), buffer.begin() + static_cast<ptrdiff_t>(readPastTo)));

    // Reset and confirm it did not work.
    mis->reset();
    const size_t endingOffset = readPastTo;
    const size_t endingLength = appdata->size() - endingOffset;
    const size_t endingTo = appdata->size();
    ByteArray expectedEnding(appdata->begin() + static_cast<ptrdiff_t>(endingOffset), appdata->begin() + static_cast<ptrdiff_t>(endingTo));
    EXPECT_EQ(static_cast<int>(expectedEnding.size()), mis->read(buffer, endingOffset, endingLength));
    EXPECT_EQ(expectedEnding, ByteArray(buffer.begin() + static_cast<ptrdiff_t>(endingOffset), buffer.begin() + static_cast<ptrdiff_t>(endingTo)));

    // Confirm equality.
    EXPECT_EQ(*appdata, ByteArray(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(appdata->size())));

    // Confirm end-of-stream.
    EXPECT_EQ(-1, mis->read(buffer));

    mis->close();
}

TEST_F(MessageInputStreamTest, largePayload)
{
	shared_ptr<ICryptoContext> cryptoContext = MESSAGE_HEADER->getCryptoContext();
	shared_ptr<ByteArray> data = make_shared<ByteArray>(10 * 1024 * 1024);
	random.nextBytes(*data);
	payloads.push_back(make_shared<PayloadChunk>(trustedNetCtx, SEQ_NO, MSG_ID, true, CompressionAlgorithm::NOCOMPRESSION, data, cryptoContext));
	shared_ptr<InputStream> is = generateInputStream(MESSAGE_HEADER, payloads);
	shared_ptr<MessageInputStream> mis = make_shared<MessageInputStream>(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

	ByteArray copy(data->size());
	EXPECT_EQ(static_cast<int>(copy.size()), mis->read(copy));
	EXPECT_EQ(-1, mis->read(copy));
	EXPECT_EQ(*data, copy);

	mis->close();
}

}}} // namespace netflix::msl::msg
