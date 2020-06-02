/**
 * Copyright (c) 2016-2020 Netflix, Inc.  All rights reserved.
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

#include <msg/MessageBuilder.h>
#include <gtest/gtest.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <MslMessageException.h>
#include <MslUserAuthException.h>
#include <crypto/ICryptoContext.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/NullCryptoContext.h>
#include <crypto/OpenSslLib.h>
#include <crypto/Random.h>
#include <crypto/SessionCryptoContext.h>
#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <keyx/AsymmetricWrappedExchange.h>
#include <keyx/DiffieHellmanExchange.h>
#include <keyx/DiffieHellmanParameters.h>
#include <keyx/KeyExchangeScheme.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <msg/ErrorHeader.h>
#include <msg/MessageCapabilities.h>
#include <msg/MessageFactory.h>
#include <msg/MessageHeader.h>
#include <tokens/MasterToken.h>
#include <tokens/MslUser.h>
#include <tokens/ServiceToken.h>
#include <tokens/UserIdToken.h>
#include <userauth/EmailPasswordAuthenticationData.h>
#include <userauth/UserAuthenticationData.h>
#include <userauth/UserAuthenticationScheme.h>
#include <util/MslContext.h>
#include <util/MslStore.h>
#include <util/MslUtils.h>
#include <algorithm>
#include <memory>

#include "../entityauth/MockPresharedAuthenticationFactory.h"
#include "../keyx/MockDiffieHellmanParameters.h"
#include "../userauth/MockEmailPasswordAuthenticationFactory.h"
#include "../util/MockAuthenticationUtils.h"
#include "../util/MockMslContext.h"
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
namespace msg {

namespace {

const string SERVICE_TOKEN_NAME = "serviceTokenName";
const string USER_ID = "userid";
const string PEER_USER_ID = "peeruserid";
const string PARAMETERS_ID = MockDiffieHellmanParameters::DEFAULT_ID();

shared_ptr<MasterToken> NULL_MASTER_TOKEN;
shared_ptr<UserIdToken> NULL_USER_ID_TOKEN;
const vector<string> EMPTY_LANGUAGES;
const set<MslEncoderFormat> EMPTY_ENCODER_FORMATS;
shared_ptr<MessageCapabilities> NULL_MSG_CAPS;
shared_ptr<MslObject> NULL_ISSUER_DATA;
const shared_ptr<EntityAuthenticationData> NULL_ENTITYAUTH_DATA;
shared_ptr<UserAuthenticationData> NULL_USERAUTH_DATA;
const set<shared_ptr<KeyRequestData>> EMPTY_KEYX_REQUESTS;
const shared_ptr<KeyResponseData> NULL_KEYX_RESPONSE;
const set<shared_ptr<ServiceToken>> EMPTY_SERVICE_TOKENS;
const int64_t REPLAYABLE_ID = -1;

const shared_ptr<MessageFactory> messageFactory = make_shared<MessageFactory>();
} // namespace anonymous

/**
 * Message builder unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageBuilderSuite : public ::testing::Test
{
public:
	virtual ~MessageBuilderSuite() {}

	MessageBuilderSuite()
		: trustedNetCtx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
		, p2pCtx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, true))
		, encoder(trustedNetCtx->getMslEncoderFactory())
	{
		USER_AUTH_DATA = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD);

		MASTER_TOKEN = MslTestUtils::getMasterToken(trustedNetCtx, 1, 1);
		USER_ID_TOKEN = MslTestUtils::getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());
		CRYPTO_CONTEXT = make_shared<NullCryptoContext>();
		shared_ptr<DiffieHellmanParameters> params = MockDiffieHellmanParameters::getDefaultParameters();
		DHParameterSpec paramSpec = params->getParameterSpec(MockDiffieHellmanParameters::DEFAULT_ID());

		// FIXME: DH interface is clunky
		ByteArray pubKey, privKey;
		dhGenKeyPair(*paramSpec.getP(), *paramSpec.getG(), pubKey, privKey);
		shared_ptr<ByteArray> publicKey = make_shared<ByteArray>(pubKey);
		shared_ptr<PrivateKey> privateKey = make_shared<PrivateKey>(make_shared<ByteArray>(privKey), "DH");

		KEY_REQUEST_DATA.insert(make_shared<DiffieHellmanExchange::RequestData>(PARAMETERS_ID, publicKey, privateKey));
		KEY_REQUEST_DATA.insert(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION));
		KEY_REQUEST_DATA.insert(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK));

		PEER_MASTER_TOKEN = MslTestUtils::getMasterToken(p2pCtx, 1, 2);
		PEER_USER_ID_TOKEN = MslTestUtils::getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());

		shared_ptr<KeyRequestData> peerKeyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION);
		PEER_KEY_REQUEST_DATA.insert(peerKeyRequestData);
		PEER_KEY_REQUEST_DATA.insert(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK));

		shared_ptr<ByteArray> mke = make_shared<ByteArray>(16);
		shared_ptr<ByteArray> mkh = make_shared<ByteArray>(32);
		shared_ptr<ByteArray> mkw = make_shared<ByteArray>(16);
		random.nextBytes(*mke);
		random.nextBytes(*mkh);
		random.nextBytes(*mkw);
		const SecretKey encryptionKey(mke, JcaAlgorithm::AES);
		const SecretKey hmacKey(mkh, JcaAlgorithm::HMAC_SHA256);
		const SecretKey wrappingKey(mkw, JcaAlgorithm::AESKW);
		ALT_MSL_CRYPTO_CONTEXT = make_shared<SymmetricCryptoContext>(trustedNetCtx, "clientMslCryptoContext", encryptionKey, hmacKey, wrappingKey);
	}

protected:
	/** Random. */
	Random random;
	/** MSL trusted network context. */
	shared_ptr<MslContext> trustedNetCtx;
	/** MSL peer-to-peer context. */
	shared_ptr<MslContext> p2pCtx;
	/** MSL encoder factory. */
	shared_ptr<MslEncoderFactory> encoder;

	shared_ptr<MasterToken> MASTER_TOKEN, PEER_MASTER_TOKEN;
	shared_ptr<ICryptoContext> CRYPTO_CONTEXT, ALT_MSL_CRYPTO_CONTEXT;
	shared_ptr<UserIdToken> USER_ID_TOKEN, PEER_USER_ID_TOKEN;
	shared_ptr<UserAuthenticationData> USER_AUTH_DATA;
	set<shared_ptr<KeyRequestData>> KEY_REQUEST_DATA;
	set<shared_ptr<KeyRequestData>> PEER_KEY_REQUEST_DATA;
};

class MessageBuilderTest_Tests : public MessageBuilderSuite
{
public:
	virtual ~MessageBuilderTest_Tests() {}
};

/** Common tests. */
TEST_F(MessageBuilderTest_Tests, incrementMessageId)
{
	const int64_t one = MessageBuilder::incrementMessageId(0);
	EXPECT_EQ(1, one);

	const int64_t zero = MessageBuilder::incrementMessageId(MslConstants::MAX_LONG_VALUE);
	EXPECT_EQ(0, zero);

	for (int i = 0; i < 1000; ++i) {
		int64_t initial = random.nextLong(MslConstants::MAX_LONG_VALUE);
		const int64_t next = MessageBuilder::incrementMessageId(initial);
		EXPECT_EQ((initial != MslConstants::MAX_LONG_VALUE) ? initial + 1 : 0, next);
	}
}

TEST_F(MessageBuilderTest_Tests, incrementNegativeMessageId)
{
	try {
		MessageBuilder::incrementMessageId(-1);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_Tests, incrementTooLargeMessageId)
{
	try {
		MessageBuilder::incrementMessageId(MslConstants::MAX_LONG_VALUE + 1);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_Tests, decrementMessageId)
{
	const int64_t max = MessageBuilder::decrementMessageId(0);
	EXPECT_EQ(MslConstants::MAX_LONG_VALUE, max);

	const int64_t max_m1 = MessageBuilder::decrementMessageId(MslConstants::MAX_LONG_VALUE);
	EXPECT_EQ(MslConstants::MAX_LONG_VALUE - 1, max_m1);

	for (int i = 0; i < 1000; ++i) {
		int64_t initial = random.nextLong(MslConstants::MAX_LONG_VALUE);
		const int64_t next = MessageBuilder::decrementMessageId(initial);
		EXPECT_EQ((initial != 0) ? initial - 1 : MslConstants::MAX_LONG_VALUE, next);
	}
}

TEST_F(MessageBuilderTest_Tests, decrementNegativeMessageId)
{
	try {
		MessageBuilder::decrementMessageId(-1);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_Tests, decrementTooLargeMessageId) {
	try {
		MessageBuilder::decrementMessageId(MslConstants::MAX_LONG_VALUE + 1);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

class MessageBuilderTest_CreateRequest : public MessageBuilderSuite
{
public:
	virtual ~MessageBuilderTest_CreateRequest() {}
};

TEST_F(MessageBuilderTest_CreateRequest, createNullRequest)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(builder->willEncryptHeader());
	EXPECT_TRUE(builder->willEncryptPayloads());
	EXPECT_TRUE(builder->willIntegrityProtectHeader());
	EXPECT_TRUE(builder->willIntegrityProtectPayloads());
	shared_ptr<MessageHeader> header = builder->getHeader();
	EXPECT_TRUE(header);

	EXPECT_EQ(REPLAYABLE_ID, header->getNonReplayableId());
	EXPECT_FALSE(header->isRenewable());
	EXPECT_FALSE(header->isHandshake());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_EQ(*trustedNetCtx->getEntityAuthenticationData(), *header->getEntityAuthenticationData());
	EXPECT_TRUE(header->getKeyRequestData().empty());
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_FALSE(header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(header->getServiceTokens().empty());
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_FALSE(header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, createNullPeerRequest)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(builder->willEncryptHeader());
	EXPECT_TRUE(builder->willEncryptPayloads());
	EXPECT_TRUE(builder->willIntegrityProtectHeader());
	EXPECT_TRUE(builder->willIntegrityProtectPayloads());
	shared_ptr<MessageHeader> header = builder->getHeader();
	EXPECT_TRUE(header);

	EXPECT_EQ(REPLAYABLE_ID, header->getNonReplayableId());
	EXPECT_FALSE(header->isRenewable());
	EXPECT_FALSE(header->isHandshake());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_EQ(*p2pCtx->getEntityAuthenticationData(), *header->getEntityAuthenticationData());
	EXPECT_TRUE(header->getKeyRequestData().empty());
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_FALSE(header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*p2pCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(header->getServiceTokens().empty());
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_FALSE(header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, createRequest)
{
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		builder->addKeyRequestData(*keyRequestData);
	}
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		builder->addServiceToken(*serviceToken);
	}
	builder->setNonReplayable(true);
	builder->setRenewable(true);
	EXPECT_TRUE(builder->willEncryptHeader());
	EXPECT_TRUE(builder->willEncryptPayloads());
	EXPECT_TRUE(builder->willIntegrityProtectHeader());
	EXPECT_TRUE(builder->willIntegrityProtectPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());

	shared_ptr<MessageHeader> header = builder->getHeader();
	EXPECT_TRUE(header);

	EXPECT_TRUE(header->getNonReplayableId());
	EXPECT_TRUE(header->isRenewable());
	EXPECT_FALSE(header->isHandshake());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_FALSE(header->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(header->getKeyRequestData(), KEY_REQUEST_DATA));
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_TRUE(header->getNonReplayableId());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(header->getServiceTokens(), serviceTokens));;
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, createRequestWithMessageId)
{
	const int64_t messageId = 17;
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, messageId);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		builder->addKeyRequestData(*keyRequestData);
	}
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		builder->addServiceToken(*serviceToken);
	}
	builder->setNonReplayable(true);
	builder->setRenewable(true);
	EXPECT_TRUE(builder->willEncryptHeader());
	EXPECT_TRUE(builder->willEncryptPayloads());
	EXPECT_TRUE(builder->willIntegrityProtectHeader());
	EXPECT_TRUE(builder->willIntegrityProtectPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());

	shared_ptr<MessageHeader> header = builder->getHeader();
	EXPECT_TRUE(header);

	EXPECT_TRUE(header->isRenewable());
	EXPECT_FALSE(header->isHandshake());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_FALSE(header->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(header->getKeyRequestData(), KEY_REQUEST_DATA));
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *header->getMasterToken());
	EXPECT_EQ(messageId, header->getMessageId());
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_TRUE(header->getNonReplayableId());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(header->getServiceTokens(), serviceTokens));;
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, createPeerRequest)
{
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		builder->addKeyRequestData(*keyRequestData);
	}
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		builder->addServiceToken(*serviceToken);
	}
	builder->setNonReplayable(true);
	builder->setRenewable(true);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator peerServiceToken = peerServiceTokens.begin();
		 peerServiceToken != peerServiceTokens.end();
		 ++peerServiceToken)
	{
		builder->addPeerServiceToken(*peerServiceToken);
	}
	EXPECT_TRUE(builder->willEncryptHeader());
	EXPECT_TRUE(builder->willEncryptPayloads());
	EXPECT_TRUE(builder->willIntegrityProtectHeader());
	EXPECT_TRUE(builder->willIntegrityProtectPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(MslTestUtils::equal(peerServiceTokens, builder->getPeerServiceTokens()));

	shared_ptr<MessageHeader> header = builder->getHeader();
	EXPECT_TRUE(header);

	EXPECT_TRUE(header->isRenewable());
	EXPECT_FALSE(header->isHandshake());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_FALSE(header->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(header->getKeyRequestData(), KEY_REQUEST_DATA));
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*p2pCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_TRUE(header->getNonReplayableId());
	EXPECT_EQ(*PEER_MASTER_TOKEN, *header->getPeerMasterToken());
	EXPECT_TRUE(MslTestUtils::equal(header->getPeerServiceTokens(), peerServiceTokens));
	EXPECT_EQ(*PEER_USER_ID_TOKEN, *header->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(header->getServiceTokens(), serviceTokens));;
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, createHandshakeRequest)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setNonReplayable(true);
	builder->setRenewable(false);
	builder->setHandshake(true);
	EXPECT_FALSE(builder->isNonReplayable());
	EXPECT_TRUE(builder->isHandshake());
	EXPECT_TRUE(builder->isRenewable());
	shared_ptr<MessageHeader> header = builder->getHeader();
	EXPECT_TRUE(header);

	EXPECT_TRUE(header->isRenewable());
	EXPECT_TRUE(header->isHandshake());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_EQ(*trustedNetCtx->getEntityAuthenticationData(), *header->getEntityAuthenticationData());
	EXPECT_TRUE(header->getKeyRequestData().empty());
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_FALSE(header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_EQ(REPLAYABLE_ID, header->getNonReplayableId());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(header->getServiceTokens().empty());
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_FALSE(header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, createPeerHandshakeRequest)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setNonReplayable(true);
	builder->setRenewable(false);
	builder->setHandshake(true);
	EXPECT_FALSE(builder->isNonReplayable());
	EXPECT_TRUE(builder->isHandshake());
	EXPECT_TRUE(builder->isRenewable());
	shared_ptr<MessageHeader> header = builder->getHeader();
	EXPECT_TRUE(header);

	EXPECT_EQ(REPLAYABLE_ID, header->getNonReplayableId());
	EXPECT_TRUE(header->isRenewable());
	EXPECT_TRUE(header->isHandshake());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_EQ(*p2pCtx->getEntityAuthenticationData(), *header->getEntityAuthenticationData());
	EXPECT_TRUE(header->getKeyRequestData().empty());
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_FALSE(header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*p2pCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(header->getServiceTokens().empty());
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_FALSE(header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, willEncryptRsaEntityAuth)
{
	shared_ptr<MslContext> rsaCtx = make_shared<MockMslContext>(EntityAuthenticationScheme::RSA, false);
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(rsaCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_FALSE(builder->willEncryptHeader());
	EXPECT_FALSE(builder->willEncryptPayloads());
	EXPECT_TRUE(builder->willIntegrityProtectHeader());
	EXPECT_TRUE(builder->willIntegrityProtectPayloads());
}

TEST_F(MessageBuilderTest_CreateRequest, willIntegrityProtectNoneAuth)
{
	shared_ptr<MslContext> noneCtx = make_shared<MockMslContext>(EntityAuthenticationScheme::NONE, false);
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(noneCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_FALSE(builder->willEncryptHeader());
	EXPECT_FALSE(builder->willEncryptPayloads());
	EXPECT_FALSE(builder->willIntegrityProtectHeader());
	EXPECT_FALSE(builder->willIntegrityProtectPayloads());
}

TEST_F(MessageBuilderTest_CreateRequest, storedServiceTokens)
{
	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(USER_ID, USER_ID_TOKEN);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	// The message will include all unbound service tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(updatedServiceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> header = builder->getHeader();

	EXPECT_TRUE(MslTestUtils::equal(header->getServiceTokens(), updatedServiceTokens));
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
}

TEST_F(MessageBuilderTest_CreateRequest, storedPeerServiceTokens)
{
	shared_ptr<MslStore> store = p2pCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(USER_ID, USER_ID_TOKEN);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	// The non-peer service tokens will include all unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	// The peer service tokens will include all unbound service tokens.
	set<shared_ptr<ServiceToken>> updatedPeerServiceTokens(peerServiceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = serviceTokens.begin();
		 it != serviceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> serviceToken = *it;
		if (serviceToken->isUnbound())
			updatedPeerServiceTokens.insert(serviceToken);
	}

	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(updatedServiceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(MslTestUtils::equal(updatedPeerServiceTokens, builder->getPeerServiceTokens()));
	shared_ptr<MessageHeader> header = builder->getHeader();

	EXPECT_TRUE(MslTestUtils::equal(header->getServiceTokens(), updatedServiceTokens));
	EXPECT_TRUE(MslTestUtils::equal(header->getPeerServiceTokens(), updatedPeerServiceTokens));
}

TEST_F(MessageBuilderTest_CreateRequest, setUserAuthData)
{
	// Setting the user authentication data will replace the user ID token
	// and remove any user ID token bound service tokens.
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		builder->addKeyRequestData(*keyRequestData);
	}
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		builder->addServiceToken(*serviceToken);
	}
	builder->setNonReplayable(true);
	builder->setRenewable(true);
	builder->setUserAuthenticationData(USER_AUTH_DATA);

	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> header = builder->getHeader();

	EXPECT_TRUE(header->getNonReplayableId());
	EXPECT_TRUE(header->isRenewable());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_FALSE(header->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(header->getKeyRequestData(), KEY_REQUEST_DATA));
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(header->getServiceTokens(), serviceTokens));;
	EXPECT_EQ(*USER_AUTH_DATA, *header->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, setUserAuthDataNull)
{
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		builder->addKeyRequestData(*keyRequestData);
	}
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		builder->addServiceToken(*serviceToken);
	}
	builder->setNonReplayable(true);
	builder->setRenewable(true);
	builder->setUserAuthenticationData(NULL_USERAUTH_DATA);
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> header = builder->getHeader();

	EXPECT_TRUE(header->getNonReplayableId());
	EXPECT_TRUE(header->isRenewable());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_FALSE(header->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(header->getKeyRequestData(), KEY_REQUEST_DATA));
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(header->getServiceTokens(), serviceTokens));;
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, unsetUserAuthData)
{
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		builder->addKeyRequestData(*keyRequestData);
	}
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		builder->addServiceToken(*serviceToken);
	}
	builder->setNonReplayable(true);
	builder->setRenewable(true);
	builder->setUserAuthenticationData(USER_AUTH_DATA);
	builder->setUserAuthenticationData(NULL_USERAUTH_DATA);

	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> header = builder->getHeader();

	EXPECT_TRUE(header->getNonReplayableId());
	EXPECT_TRUE(header->isRenewable());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_FALSE(header->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(header->getKeyRequestData(), KEY_REQUEST_DATA));
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(header->getServiceTokens(), serviceTokens));;
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, overwriteKeyRequestData)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		builder->addKeyRequestData(*keyRequestData);
	}
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		builder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> header = builder->getHeader();

	EXPECT_EQ(REPLAYABLE_ID, header->getNonReplayableId());
	EXPECT_FALSE(header->isRenewable());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_EQ(*trustedNetCtx->getEntityAuthenticationData(), *header->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(header->getKeyRequestData(), KEY_REQUEST_DATA));
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_FALSE(header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(header->getServiceTokens().empty());
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_FALSE(header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, removeKeyRequestData)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		builder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<KeyRequestData> keyRequestData = *KEY_REQUEST_DATA.begin();
	set<shared_ptr<KeyRequestData>> updatedKeyRequestData(KEY_REQUEST_DATA);
	set<shared_ptr<KeyRequestData>>::iterator it = find_if(updatedKeyRequestData.begin(), updatedKeyRequestData.end(), MslUtils::sharedPtrEqual<set<shared_ptr<KeyRequestData>>>(keyRequestData));
	updatedKeyRequestData.erase(it);
	builder->removeKeyRequestData(keyRequestData);
	builder->removeKeyRequestData(keyRequestData);
	shared_ptr<MessageHeader> header = builder->getHeader();

	EXPECT_EQ(REPLAYABLE_ID, header->getNonReplayableId());
	EXPECT_FALSE(header->isRenewable());
	EXPECT_TRUE(header->getCryptoContext());
	EXPECT_EQ(*trustedNetCtx->getEntityAuthenticationData(), *header->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(header->getKeyRequestData(), updatedKeyRequestData));
	EXPECT_FALSE(header->getKeyResponseData());
	EXPECT_FALSE(header->getMasterToken());
	EXPECT_TRUE(header->getMessageId() >= 0);
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *header->getMessageCapabilities());
	EXPECT_FALSE(header->getPeerMasterToken());
	EXPECT_TRUE(header->getPeerServiceTokens().empty());
	EXPECT_FALSE(header->getPeerUserIdToken());
	EXPECT_TRUE(header->getServiceTokens().empty());
	EXPECT_FALSE(header->getUserAuthenticationData());
	EXPECT_FALSE(header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, nonReplayableMissingMasterToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setNonReplayable(true);
	try {
		builder->getHeader();
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN, e.getError());
	}
}

TEST_F(MessageBuilderTest_CreateRequest, mismatchedMasterTokenAddTokenServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
	random.nextBytes(*data);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		builder->addServiceToken(serviceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(MessageBuilderTest_CreateRequest, nullMasterTokenAddServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
	random.nextBytes(*data);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		builder->addServiceToken(serviceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(MessageBuilderTest_CreateRequest, mismatchedUserIdTokenAddServiceToken)
{
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(trustedNetCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, userIdTokenA);
	shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
	random.nextBytes(*data);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, userIdTokenB, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		builder->addServiceToken(serviceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(MessageBuilderTest_CreateRequest, nullUserIdTokenAddServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
	random.nextBytes(*data);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		builder->addServiceToken(serviceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(MessageBuilderTest_CreateRequest, addNamedServiceTokens)
{
    shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
    random.nextBytes(*data);

    shared_ptr<ServiceToken> unboundServiceTokenA = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addServiceToken(unboundServiceTokenA);
    EXPECT_EQ(static_cast<size_t>(1), builder->getServiceTokens().size());

    shared_ptr<ServiceToken> unboundServiceTokenB = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addServiceToken(unboundServiceTokenB);
    EXPECT_EQ(static_cast<size_t>(1), builder->getServiceTokens().size());

    shared_ptr<ServiceToken> masterBoundServiceTokenA = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addServiceToken(masterBoundServiceTokenA);
    EXPECT_EQ(static_cast<size_t>(2), builder->getServiceTokens().size());

    shared_ptr<ServiceToken> masterBoundServiceTokenB = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addServiceToken(masterBoundServiceTokenB);
    EXPECT_EQ(static_cast<size_t>(2), builder->getServiceTokens().size());

    shared_ptr<ServiceToken> userBoundServiceTokenA = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addServiceToken(userBoundServiceTokenA);
    EXPECT_EQ(static_cast<size_t>(3), builder->getServiceTokens().size());

    shared_ptr<ServiceToken> userBoundServiceTokenB = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addServiceToken(userBoundServiceTokenB);
    EXPECT_EQ(static_cast<size_t>(3), builder->getServiceTokens().size());
}

TEST_F(MessageBuilderTest_CreateRequest, excludeServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		builder->addServiceToken(*serviceToken);
	}

	set<shared_ptr<ServiceToken>>::iterator tokens = serviceTokens.begin();
	while (tokens != serviceTokens.end()) {
		shared_ptr<ServiceToken> token = *tokens;
		builder->excludeServiceToken(token->getName(), token->isMasterTokenBound(), token->isUserIdTokenBound());
		serviceTokens.erase(tokens++);
		shared_ptr<MessageHeader> messageHeader = builder->getHeader();
		EXPECT_TRUE(MslTestUtils::equal(messageHeader->getServiceTokens(), serviceTokens));
	}
}

TEST_F(MessageBuilderTest_CreateRequest, excludeServiceTokenAlternate)
{
    shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
         serviceToken != serviceTokens.end();
         ++serviceToken)
    {
        builder->addServiceToken(*serviceToken);
    }

    set<shared_ptr<ServiceToken>>::iterator tokens = serviceTokens.begin();
    while (tokens != serviceTokens.end()) {
        shared_ptr<ServiceToken> token = *tokens;
        builder->excludeServiceToken(token);
        serviceTokens.erase(tokens++);
        shared_ptr<MessageHeader> messageHeader = builder->getHeader();
        EXPECT_TRUE(MslTestUtils::equal(messageHeader->getServiceTokens(), serviceTokens));
    }
}

TEST_F(MessageBuilderTest_CreateRequest, deleteServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);

	// The service token must exist before it can be deleted.
	shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
	random.nextBytes(*data);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	builder->addServiceToken(serviceToken);

	// Delete the service token.
	builder->deleteServiceToken(SERVICE_TOKEN_NAME, true, true);
	shared_ptr<MessageHeader> messageHeader = builder->getHeader();
	set<shared_ptr<ServiceToken>> tokens = messageHeader->getServiceTokens();
	for (set<shared_ptr<ServiceToken>>::iterator it = tokens.begin();
		 it != tokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> token = *it;
		if (token->getName() == SERVICE_TOKEN_NAME) {
			EXPECT_EQ(static_cast<size_t>(0), token->getData()->size());
			return;
		}
	}
	ADD_FAILURE() << "Deleted service token not found";
}

TEST_F(MessageBuilderTest_CreateRequest, deleteServiceTokenAlternate)
{
    shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);

    // The service token must exist before it can be deleted.
    shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
    random.nextBytes(*data);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addServiceToken(serviceToken);

    // Delete the service token.
    builder->deleteServiceToken(serviceToken);
    shared_ptr<MessageHeader> messageHeader = builder->getHeader();
    set<shared_ptr<ServiceToken>> tokens = messageHeader->getServiceTokens();
    for (set<shared_ptr<ServiceToken>>::iterator it = tokens.begin();
         it != tokens.end();
         ++it)
    {
        shared_ptr<ServiceToken> token = *it;
        if (token->getName() == SERVICE_TOKEN_NAME) {
            EXPECT_EQ(static_cast<size_t>(0), token->getData()->size());
            return;
        }
    }
    ADD_FAILURE() << "Deleted service token not found";
}

TEST_F(MessageBuilderTest_CreateRequest, deleteUnknownServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	builder->deleteServiceToken(SERVICE_TOKEN_NAME, true, true);
	shared_ptr<MessageHeader> messageHeader = builder->getHeader();
	set<shared_ptr<ServiceToken>> tokens = messageHeader->getServiceTokens();
	for (set<shared_ptr<ServiceToken>>::iterator it = tokens.begin();
		 it != tokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> token = *it;
		if (token->getName() == SERVICE_TOKEN_NAME) {
		    EXPECT_EQ(static_cast<size_t>(0), token->getData()->size());
		    return;
		}
		ADD_FAILURE() << "Deleted unknown service token.";
	}
}

TEST_F(MessageBuilderTest_CreateRequest, notP2PCreatePeerRequest)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	try {
		builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, missingPeerMasterTokenCreatePeerRequest)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	try {
		builder->setPeerAuthTokens(NULL_MASTER_TOKEN, PEER_USER_ID_TOKEN);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, mismatchedPeerMasterTokenCreatePeerRequest)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	try {
		builder->setPeerAuthTokens(MASTER_TOKEN, PEER_USER_ID_TOKEN);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, notP2PAddPeerServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<ServiceToken> peerServiceToken = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, make_shared<ByteArray>(), NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		builder->addPeerServiceToken(peerServiceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, missingPeerMasterTokenAddPeerServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<ServiceToken> peerServiceToken = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, make_shared<ByteArray>(), PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		builder->addPeerServiceToken(peerServiceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(MessageBuilderTest_CreateRequest, mismatchedPeerMasterTokenAddPeerServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<ServiceToken> peerServiceToken = make_shared<ServiceToken>(trustedNetCtx, SERVICE_TOKEN_NAME, make_shared<ByteArray>(), MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		builder->addPeerServiceToken(peerServiceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(MessageBuilderTest_CreateRequest, missingPeerUserIdTokenAddPeerServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<ServiceToken> peerServiceToken = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, make_shared<ByteArray>(), PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		builder->addPeerServiceToken(peerServiceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(MessageBuilderTest_CreateRequest, mismatchedPeerUserIdTokenAddPeerServiceToken)
{
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, userIdTokenA);
	shared_ptr<ServiceToken> peerServiceToken = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, make_shared<ByteArray>(), PEER_MASTER_TOKEN, userIdTokenB, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		builder->addPeerServiceToken(peerServiceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMessageException& e) {
		EXPECT_EQ(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(MessageBuilderTest_CreateRequest, addNamedPeerServiceTokens)
{
    shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
    random.nextBytes(*data);

    shared_ptr<ServiceToken> unboundServiceTokenA = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, data, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addPeerServiceToken(unboundServiceTokenA);
    EXPECT_EQ(static_cast<size_t>(1), builder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> unboundServiceTokenB = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, data, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addPeerServiceToken(unboundServiceTokenB);
    EXPECT_EQ(static_cast<size_t>(1), builder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> masterBoundServiceTokenA = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addPeerServiceToken(masterBoundServiceTokenA);
    EXPECT_EQ(static_cast<size_t>(2), builder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> masterBoundServiceTokenB = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addPeerServiceToken(masterBoundServiceTokenB);
    EXPECT_EQ(static_cast<size_t>(2), builder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> userBoundServiceTokenA = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addPeerServiceToken(userBoundServiceTokenA);
    EXPECT_EQ(static_cast<size_t>(3), builder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> userBoundServiceTokenB = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addPeerServiceToken(userBoundServiceTokenB);
    EXPECT_EQ(static_cast<size_t>(3), builder->getPeerServiceTokens().size());
}

TEST_F(MessageBuilderTest_CreateRequest, excludePeerServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		builder->addPeerServiceToken(*serviceToken);
	}

	set<shared_ptr<ServiceToken>>::iterator tokens = serviceTokens.begin();
	while (tokens != serviceTokens.end()) {
		shared_ptr<ServiceToken> token = *tokens;
		builder->excludePeerServiceToken(token->getName(), token->isMasterTokenBound(), token->isUserIdTokenBound());
		serviceTokens.erase(tokens++);
		EXPECT_TRUE(MslTestUtils::equal(serviceTokens, builder->getPeerServiceTokens()));
		shared_ptr<MessageHeader> messageHeader = builder->getHeader();
		EXPECT_TRUE(MslTestUtils::equal(serviceTokens, messageHeader->getPeerServiceTokens()));
	}
}

TEST_F(MessageBuilderTest_CreateRequest, excludePeerServiceTokenAlternate)
{
    shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
         serviceToken != serviceTokens.end();
         ++serviceToken)
    {
        builder->addPeerServiceToken(*serviceToken);
    }

    set<shared_ptr<ServiceToken>>::iterator tokens = serviceTokens.begin();
    while (tokens != serviceTokens.end()) {
        shared_ptr<ServiceToken> token = *tokens;
        builder->excludePeerServiceToken(token);
        serviceTokens.erase(tokens++);
        EXPECT_TRUE(MslTestUtils::equal(serviceTokens, builder->getPeerServiceTokens()));
        shared_ptr<MessageHeader> messageHeader = builder->getHeader();
        EXPECT_TRUE(MslTestUtils::equal(serviceTokens, messageHeader->getPeerServiceTokens()));
    }
}

TEST_F(MessageBuilderTest_CreateRequest, deletePeerServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);

	// The service token must exist before it can be deleted.
	shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
	random.nextBytes(*data);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	builder->addPeerServiceToken(serviceToken);

	// Delete the service token.
	builder->deletePeerServiceToken(SERVICE_TOKEN_NAME, true, true);
	shared_ptr<MessageHeader> messageHeader = builder->getHeader();
	set<shared_ptr<ServiceToken>> tokens = messageHeader->getPeerServiceTokens();
	for (set<shared_ptr<ServiceToken>>::iterator it = tokens.begin();
		 it != tokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> token = *it;
		if (token->getName() == SERVICE_TOKEN_NAME) {
			EXPECT_EQ(static_cast<size_t>(0), token->getData()->size());
			return;
		}
	}
	ADD_FAILURE() << "Deleted peer service token not found";
}

TEST_F(MessageBuilderTest_CreateRequest, deletePeerServiceTokenAlternate)
{
    shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);

    // The service token must exist before it can be deleted.
    shared_ptr<ByteArray> data = make_shared<ByteArray>(1);
    random.nextBytes(*data);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    builder->addPeerServiceToken(serviceToken);

    // Delete the service token.
    builder->deletePeerServiceToken(serviceToken);
    shared_ptr<MessageHeader> messageHeader = builder->getHeader();
    set<shared_ptr<ServiceToken>> tokens = messageHeader->getPeerServiceTokens();
    for (set<shared_ptr<ServiceToken>>::iterator it = tokens.begin();
         it != tokens.end();
         ++it)
    {
        shared_ptr<ServiceToken> token = *it;
        if (token->getName() == SERVICE_TOKEN_NAME) {
            EXPECT_EQ(static_cast<size_t>(0), token->getData()->size());
            return;
        }
    }
    ADD_FAILURE() << "Deleted peer service token not found";
}

TEST_F(MessageBuilderTest_CreateRequest, deleteUnknownPeerServiceToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	builder->deletePeerServiceToken(SERVICE_TOKEN_NAME, true, true);
	shared_ptr<MessageHeader> messageHeader = builder->getHeader();
	set<shared_ptr<ServiceToken>> tokens = messageHeader->getPeerServiceTokens();
	for (set<shared_ptr<ServiceToken>>::iterator it = tokens.begin();
		 it != tokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> token = *it;
		if (token->getName() == SERVICE_TOKEN_NAME) {
		    EXPECT_EQ(static_cast<size_t>(0), token->getData()->size());
		    return;
		}
		ADD_FAILURE() << "Deleted unknown peer service token.";
	}
}

TEST_F(MessageBuilderTest_CreateRequest, setMasterToken)
{
	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setAuthTokens(MASTER_TOKEN, NULL_USER_ID_TOKEN);

	// The message service tokens will include all unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	EXPECT_TRUE(MslTestUtils::equal(updatedServiceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> messageHeader = builder->getHeader();
	EXPECT_EQ(updatedServiceTokens, messageHeader->getServiceTokens());
	EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
}

TEST_F(MessageBuilderTest_CreateRequest, setExistingMasterToken)
{
	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(USER_ID, USER_ID_TOKEN);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setAuthTokens(MASTER_TOKEN, NULL_USER_ID_TOKEN);

	// The message service tokens will include all unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	EXPECT_TRUE(MslTestUtils::equal(updatedServiceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> messageHeader = builder->getHeader();
	EXPECT_EQ(updatedServiceTokens, messageHeader->getServiceTokens());
	EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
}

TEST_F(MessageBuilderTest_CreateRequest, setAuthTokens)
{
	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(USER_ID, USER_ID_TOKEN);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);

	// The message service tokens will include all unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	EXPECT_TRUE(MslTestUtils::equal(updatedServiceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> messageHeader = builder->getHeader();
	EXPECT_EQ(updatedServiceTokens, messageHeader->getServiceTokens());
	EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
}

TEST_F(MessageBuilderTest_CreateRequest, setExistingAuthTokens)
{
	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(USER_ID, USER_ID_TOKEN);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);

	// The message service tokens will include all unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	EXPECT_TRUE(MslTestUtils::equal(updatedServiceTokens, builder->getServiceTokens()));
	EXPECT_TRUE(builder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> messageHeader = builder->getHeader();
	EXPECT_EQ(updatedServiceTokens, messageHeader->getServiceTokens());
	EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
}

TEST_F(MessageBuilderTest_CreateRequest, setNullMasterToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setAuthTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> header = builder->getHeader();
	EXPECT_TRUE(header);

	EXPECT_FALSE(header->getMasterToken());
	EXPECT_FALSE(header->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateRequest, setMismatchedAuthTokens)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	try {
		builder->setAuthTokens(MASTER_TOKEN, PEER_USER_ID_TOKEN);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, setUser)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setUser(USER_ID_TOKEN->getUser());
	shared_ptr<UserIdToken> userIdToken = builder->getUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*USER_ID_TOKEN->getUser(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateRequest, setUserNoMasterToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	try {
		builder->setUser(USER_ID_TOKEN->getUser());
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, setUserHasUserIdToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	try {
		builder->setUser(USER_ID_TOKEN->getUser());
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, setPeerUser)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setUser(PEER_USER_ID_TOKEN->getUser());
	shared_ptr<UserIdToken> userIdToken = builder->getPeerUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*PEER_USER_ID_TOKEN->getUser(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateRequest, setPeerUserNoPeerMasterToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	try {
		builder->setUser(PEER_USER_ID_TOKEN->getUser());
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, setPeerUserHasPeerUserIdToken)
{
	shared_ptr<MessageBuilder> builder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	builder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	try {
		builder->setUser(USER_ID_TOKEN->getUser());
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, negativeMessageId)
{
	try {
		messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, -1);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateRequest, tooLargeMessageId)
{
	try {
		messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, MslConstants::MAX_LONG_VALUE + 1);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

/** Create error unit tests. */
namespace {
const int64_t REQUEST_MESSAGE_ID = 17;
const MslError MSL_ERROR = MslError::MSL_PARSE_ERROR;
const string USER_MESSAGE = "user message";

const int64_t NULL_MSG_ID = -1;
const string NULL_USER_MESSAGE = "";
} // namespace anonymous

class MessageBuilderTest_CreateError : public MessageBuilderSuite
{
public:
	virtual ~MessageBuilderTest_CreateError() {}
};

TEST_F(MessageBuilderTest_CreateError, ctor)
{
	shared_ptr<ErrorHeader> errorHeader = messageFactory->createErrorResponse(trustedNetCtx, REQUEST_MESSAGE_ID, MSL_ERROR, USER_MESSAGE);
	EXPECT_TRUE(errorHeader);
	EXPECT_EQ(MSL_ERROR.getResponseCode(), errorHeader->getErrorCode());
	EXPECT_EQ(MSL_ERROR.getMessage(), errorHeader->getErrorMessage());
	EXPECT_EQ(USER_MESSAGE, errorHeader->getUserMessage());
	EXPECT_EQ(REQUEST_MESSAGE_ID + 1, errorHeader->getMessageId());
}

TEST_F(MessageBuilderTest_CreateError, maxMessageId)
{
	const int64_t messageId = MslConstants::MAX_LONG_VALUE;
	shared_ptr<ErrorHeader> errorHeader = messageFactory->createErrorResponse(trustedNetCtx, messageId, MSL_ERROR, USER_MESSAGE);
	EXPECT_TRUE(errorHeader);
	EXPECT_EQ(MSL_ERROR.getResponseCode(), errorHeader->getErrorCode());
	EXPECT_EQ(MSL_ERROR.getMessage(), errorHeader->getErrorMessage());
	EXPECT_EQ(USER_MESSAGE, errorHeader->getUserMessage());
	EXPECT_EQ(0, errorHeader->getMessageId());
}

TEST_F(MessageBuilderTest_CreateError, nullMessageId)
{
	shared_ptr<ErrorHeader> errorHeader = messageFactory->createErrorResponse(trustedNetCtx, NULL_MSG_ID, MSL_ERROR, USER_MESSAGE);
	EXPECT_TRUE(errorHeader);
	EXPECT_EQ(MSL_ERROR.getResponseCode(), errorHeader->getErrorCode());
	EXPECT_EQ(MSL_ERROR.getMessage(), errorHeader->getErrorMessage());
	EXPECT_EQ(USER_MESSAGE, errorHeader->getUserMessage());
	EXPECT_TRUE(errorHeader->getMessageId() > 0);
}

TEST_F(MessageBuilderTest_CreateError, negativeMessageId)
{
	const int64_t messageId = -12L;
	try {
		messageFactory->createErrorResponse(trustedNetCtx, messageId, MSL_ERROR, USER_MESSAGE);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateError, nullUserMessage)
{
	shared_ptr<ErrorHeader> errorHeader = messageFactory->createErrorResponse(trustedNetCtx, REQUEST_MESSAGE_ID, MSL_ERROR, NULL_USER_MESSAGE);
	EXPECT_TRUE(errorHeader);
	EXPECT_EQ(MSL_ERROR.getResponseCode(), errorHeader->getErrorCode());
	EXPECT_EQ(MSL_ERROR.getMessage(), errorHeader->getErrorMessage());
	EXPECT_EQ(NULL_USER_MESSAGE, errorHeader->getUserMessage());
	EXPECT_EQ(REQUEST_MESSAGE_ID + 1, errorHeader->getMessageId());
}

/** Create response unit tests. */
namespace {
const string KEY_PAIR_ID = "rsaKeyPairId";

/**
 * @param value the value to increment.
 * @return the value + 1, wrapped back to zero on overflow.
 */
int64_t incrementLong(int64_t value) {
	if (value == MslConstants::MAX_LONG_VALUE) return 0;
	return value + 1;
}

// This class ensures stuff shared between suites is only created once, since
// RSA stuff can be expensive to create.
class TestSingleton
{
public:
    static PublicKey getPublicKey() { return keyInstance().first; }
    static PrivateKey getPrivateKey() { return keyInstance().second; }

private:
    static pair<PublicKey,PrivateKey> keyInstance() {
        static pair<PublicKey,PrivateKey> theInstance;
        if (theInstance.first.isNull())
            theInstance = MslTestUtils::generateRsaKeys(JcaAlgorithm::SHA256withRSA, 2048); // Note 2048 keysize required to accomodate test data size
        return theInstance;
    }
};

} // namespace anonymous

class MessageBuilderTest_CreateResponse : public MessageBuilderSuite
{
public:
	virtual ~MessageBuilderTest_CreateResponse() {}

	MessageBuilderTest_CreateResponse()
	{
		RSA_PUBLIC_KEY = make_shared<PublicKey>(TestSingleton::getPublicKey());
		RSA_PRIVATE_KEY = make_shared<PrivateKey>(TestSingleton::getPrivateKey());
		string json = "{ \"issuerid\" : 17 }";
		ISSUER_DATA = encoder->parseObject(make_shared<ByteArray>(json.begin(), json.end()));
		USER = MockEmailPasswordAuthenticationFactory::USER();
	}

protected:
	shared_ptr<PublicKey> RSA_PUBLIC_KEY;
	shared_ptr<PrivateKey> RSA_PRIVATE_KEY;
	map<string,shared_ptr<ICryptoContext>> CRYPTO_CONTEXTS;
	shared_ptr<MslObject> ISSUER_DATA;
	shared_ptr<MslUser> USER;
};

TEST_F(MessageBuilderTest_CreateResponse, createNullResponse)
{
	// This will not exercise any of the complex logic, so no key
	// request data, entity auth data, or user auth data. Just tokens.
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		requestBuilder->addServiceToken(*serviceToken);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	EXPECT_TRUE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, responseBuilder->getServiceTokens()));
	EXPECT_TRUE(responseBuilder->getPeerServiceTokens().empty());

	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response);
	EXPECT_EQ(REPLAYABLE_ID, response->getNonReplayableId());
	EXPECT_FALSE(response->isRenewable());
	EXPECT_FALSE(response->isHandshake());
	EXPECT_TRUE(response->getCryptoContext());
	EXPECT_FALSE(response->getEntityAuthenticationData());
	EXPECT_TRUE(response->getKeyRequestData().empty());
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *response->getMasterToken());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *response->getMessageCapabilities());
	EXPECT_FALSE(response->getPeerMasterToken());
	EXPECT_TRUE(response->getPeerServiceTokens().empty());
	EXPECT_FALSE(response->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), serviceTokens));
	EXPECT_FALSE(response->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *response->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateResponse, createNullPeerResponse)
{
	// This will not exercise any of the complex logic, so no key
	// request data, entity auth data, or user auth data. Just tokens.
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	requestBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		requestBuilder->addServiceToken(*serviceToken);
	}
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator peerServiceToken = peerServiceTokens.begin();
		 peerServiceToken != peerServiceTokens.end();
		 ++peerServiceToken)
	{
		requestBuilder->addPeerServiceToken(*peerServiceToken);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	// The tokens should be swapped.
	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	EXPECT_TRUE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, responseBuilder->getPeerServiceTokens()));
	EXPECT_TRUE(MslTestUtils::equal(peerServiceTokens, responseBuilder->getServiceTokens()));
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response);
	EXPECT_EQ(REPLAYABLE_ID, response->getNonReplayableId());
	EXPECT_FALSE(response->isRenewable());
	EXPECT_FALSE(response->isHandshake());
	EXPECT_TRUE(response->getCryptoContext());
	EXPECT_FALSE(response->getEntityAuthenticationData());
	EXPECT_TRUE(response->getKeyRequestData().empty());
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_EQ(*PEER_MASTER_TOKEN, *response->getMasterToken());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
	EXPECT_EQ(*p2pCtx->getMessageCapabilities(), *response->getMessageCapabilities());
	EXPECT_EQ(*MASTER_TOKEN, *response->getPeerMasterToken());
	EXPECT_EQ(*USER_ID_TOKEN, *response->getPeerUserIdToken());
	EXPECT_FALSE(response->getUserAuthenticationData());
	EXPECT_EQ(*PEER_USER_ID_TOKEN, *response->getUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(response->getPeerServiceTokens(), serviceTokens));
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), peerServiceTokens));
}

TEST_F(MessageBuilderTest_CreateResponse, createEntityAuthResponse)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		requestBuilder->addServiceToken(*serviceToken);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	EXPECT_TRUE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, responseBuilder->getServiceTokens()));
	EXPECT_TRUE(responseBuilder->getPeerServiceTokens().empty());

	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response);
	EXPECT_EQ(REPLAYABLE_ID, response->getNonReplayableId());
	EXPECT_FALSE(response->isRenewable());
	EXPECT_FALSE(response->isHandshake());
	EXPECT_TRUE(response->getCryptoContext());
	shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData();
	EXPECT_EQ(*entityAuthData, *response->getEntityAuthenticationData());
	EXPECT_TRUE(response->getKeyRequestData().empty());
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_FALSE(response->getMasterToken());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *response->getMessageCapabilities());
	EXPECT_FALSE(response->getPeerMasterToken());
	EXPECT_TRUE(response->getPeerServiceTokens().empty());
	EXPECT_FALSE(response->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), serviceTokens));
	EXPECT_FALSE(response->getUserAuthenticationData());
	EXPECT_FALSE(response->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateResponse, createEntityAuthPeerResponse)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		requestBuilder->addServiceToken(*serviceToken);
	}
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator peerServiceToken = peerServiceTokens.begin();
		 peerServiceToken != peerServiceTokens.end();
		 ++peerServiceToken)
	{
		requestBuilder->addPeerServiceToken(*peerServiceToken);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	// The tokens should be swapped.
	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	EXPECT_TRUE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, responseBuilder->getPeerServiceTokens()));
	EXPECT_TRUE(MslTestUtils::equal(peerServiceTokens, responseBuilder->getServiceTokens()));
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response);
	EXPECT_EQ(REPLAYABLE_ID, response->getNonReplayableId());
	EXPECT_FALSE(response->isRenewable());
	EXPECT_FALSE(response->isHandshake());
	EXPECT_TRUE(response->getCryptoContext());
	EXPECT_FALSE(response->getEntityAuthenticationData());
	EXPECT_TRUE(response->getKeyRequestData().empty());
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_EQ(*PEER_MASTER_TOKEN, *response->getMasterToken());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
	EXPECT_EQ(*p2pCtx->getMessageCapabilities(), *response->getMessageCapabilities());
	EXPECT_FALSE(response->getPeerMasterToken());
	EXPECT_FALSE(response->getPeerUserIdToken());
	EXPECT_FALSE(response->getUserAuthenticationData());
	EXPECT_EQ(*PEER_USER_ID_TOKEN, *response->getUserIdToken());
	shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData();
	EXPECT_TRUE(MslTestUtils::equal(response->getPeerServiceTokens(), serviceTokens));
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), peerServiceTokens));
}

TEST_F(MessageBuilderTest_CreateResponse, createResponse)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	responseBuilder->setNonReplayable(true);
	responseBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		responseBuilder->addKeyRequestData(*keyRequestData);
	}
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		responseBuilder->addServiceToken(*serviceToken);
	}
	responseBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	EXPECT_TRUE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, responseBuilder->getServiceTokens()));
	EXPECT_TRUE(responseBuilder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response);
	EXPECT_TRUE(response->getNonReplayableId());
	EXPECT_TRUE(response->isRenewable());
	EXPECT_FALSE(response->isHandshake());
	EXPECT_TRUE(response->getCryptoContext());
	EXPECT_FALSE(response->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(response->getKeyRequestData(), KEY_REQUEST_DATA));
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *response->getMasterToken());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *response->getMessageCapabilities());
	EXPECT_FALSE(response->getPeerMasterToken());
	EXPECT_TRUE(response->getPeerServiceTokens().empty());
	EXPECT_FALSE(response->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), serviceTokens));
	EXPECT_EQ(*USER_AUTH_DATA, *response->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *response->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateResponse, createPeerResponse)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		responseBuilder->addServiceToken(*serviceToken);
	}
	responseBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator peerServiceToken = peerServiceTokens.begin();
		 peerServiceToken != peerServiceTokens.end();
		 ++peerServiceToken)
	{
		responseBuilder->addPeerServiceToken(*peerServiceToken);
	}
	EXPECT_TRUE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
	EXPECT_TRUE(MslTestUtils::equal(peerServiceTokens, responseBuilder->getPeerServiceTokens()));
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, responseBuilder->getServiceTokens()));
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response);
	EXPECT_EQ(REPLAYABLE_ID, response->getNonReplayableId());
	EXPECT_FALSE(response->isRenewable());
	EXPECT_FALSE(response->isHandshake());
	EXPECT_TRUE(response->getCryptoContext());
	EXPECT_EQ(*trustedNetCtx->getEntityAuthenticationData(), *response->getEntityAuthenticationData());
	EXPECT_TRUE(response->getKeyRequestData().empty());
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_FALSE(response->getMasterToken());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
	EXPECT_EQ(*p2pCtx->getMessageCapabilities(), *response->getMessageCapabilities());
	EXPECT_EQ(*PEER_MASTER_TOKEN, *response->getPeerMasterToken());
	EXPECT_EQ(*PEER_USER_ID_TOKEN, *response->getPeerUserIdToken());
	EXPECT_EQ(*USER_AUTH_DATA, *response->getUserAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(response->getPeerServiceTokens(), peerServiceTokens));
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), serviceTokens));
	EXPECT_FALSE(response->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateResponse, createHandshakeResponse)
{
	// This will not exercise any of the complex logic, so no key
	// request data, entity auth data, or user auth data. Just tokens.
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		requestBuilder->addServiceToken(*serviceToken);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	responseBuilder->setNonReplayable(true);
	responseBuilder->setRenewable(false);
	responseBuilder->setHandshake(true);
	EXPECT_TRUE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, responseBuilder->getServiceTokens()));
	EXPECT_TRUE(responseBuilder->getPeerServiceTokens().empty());

	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response);
	EXPECT_EQ(REPLAYABLE_ID, response->getNonReplayableId());
	EXPECT_TRUE(response->isRenewable());
	EXPECT_TRUE(response->isHandshake());
	EXPECT_TRUE(response->getCryptoContext());
	EXPECT_FALSE(response->getEntityAuthenticationData());
	EXPECT_TRUE(response->getKeyRequestData().empty());
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *response->getMasterToken());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *response->getMessageCapabilities());
	EXPECT_FALSE(response->getPeerMasterToken());
	EXPECT_TRUE(response->getPeerServiceTokens().empty());
	EXPECT_FALSE(response->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), serviceTokens));
	EXPECT_FALSE(response->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *response->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateResponse, createPeerHandshakeResponse)
{
	// This will not exercise any of the complex logic, so no key
	// request data, entity auth data, or user auth data. Just tokens.
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	requestBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		requestBuilder->addServiceToken(*serviceToken);
	}
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator peerServiceToken = peerServiceTokens.begin();
		 peerServiceToken != peerServiceTokens.end();
		 ++peerServiceToken)
	{
		requestBuilder->addPeerServiceToken(*peerServiceToken);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	// The tokens should be swapped.
	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	responseBuilder->setNonReplayable(true);
	responseBuilder->setRenewable(false);
	responseBuilder->setHandshake(true);
	EXPECT_TRUE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, responseBuilder->getPeerServiceTokens()));
	EXPECT_TRUE(MslTestUtils::equal(peerServiceTokens, responseBuilder->getServiceTokens()));

	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response);
	EXPECT_EQ(REPLAYABLE_ID, response->getNonReplayableId());
	EXPECT_TRUE(response->isRenewable());
	EXPECT_TRUE(response->isHandshake());
	EXPECT_TRUE(response->getCryptoContext());
	EXPECT_FALSE(response->getEntityAuthenticationData());
	EXPECT_TRUE(response->getKeyRequestData().empty());
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_EQ(*PEER_MASTER_TOKEN, *response->getMasterToken());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
	EXPECT_EQ(*p2pCtx->getMessageCapabilities(), *response->getMessageCapabilities());
	EXPECT_EQ(*MASTER_TOKEN, *response->getPeerMasterToken());
	EXPECT_EQ(*USER_ID_TOKEN, *response->getPeerUserIdToken());
	EXPECT_FALSE(response->getUserAuthenticationData());
	EXPECT_EQ(*PEER_USER_ID_TOKEN, *response->getUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(response->getPeerServiceTokens(), serviceTokens));
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), peerServiceTokens));
}

TEST_F(MessageBuilderTest_CreateResponse, willEncryptRsaEntityAuth)
{
	shared_ptr<MslContext> rsaCtx = make_shared<MockMslContext>(EntityAuthenticationScheme::RSA, false);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(rsaCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(rsaCtx, request);
	EXPECT_FALSE(responseBuilder->willEncryptHeader());
	EXPECT_FALSE(responseBuilder->willEncryptPayloads());
}

TEST_F(MessageBuilderTest_CreateResponse, willEncryptRsaEntityAuthKeyExchange)
{
	shared_ptr<MslContext> rsaCtx = make_shared<MockMslContext>(EntityAuthenticationScheme::RSA, false);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(rsaCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(rsaCtx, request);
	EXPECT_FALSE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
}

TEST_F(MessageBuilderTest_CreateResponse, storedServiceTokens)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();
	EXPECT_TRUE(request->getServiceTokens().empty());

	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(USER_ID, USER_ID_TOKEN);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);

	// The message will include all unbound service tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	EXPECT_EQ(updatedServiceTokens, responseBuilder->getServiceTokens());
	EXPECT_TRUE(responseBuilder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(updatedServiceTokens, response->getServiceTokens());
	EXPECT_TRUE(response->getPeerServiceTokens().empty());
}

TEST_F(MessageBuilderTest_CreateResponse, storedPeerServiceTokens)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();
	EXPECT_TRUE(request->getServiceTokens().empty());
	EXPECT_TRUE(request->getPeerServiceTokens().empty());

	shared_ptr<MslStore> store = p2pCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(USER_ID, USER_ID_TOKEN);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);

	// Update the set of expected peer service tokens with any unbound
	// service tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	// The service tokens will all be unbound.
	set<shared_ptr<ServiceToken>> responseServiceTokens = responseBuilder->getServiceTokens();
	for (set<shared_ptr<ServiceToken>>::iterator it = responseServiceTokens.begin();
		 it != responseServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> serviceToken = *it;
		EXPECT_TRUE(serviceToken->isUnbound());
		set<shared_ptr<ServiceToken>>::iterator serviceTokensContains = find_if(serviceTokens.begin(), serviceTokens.end(), MslUtils::sharedPtrEqual<set<shared_ptr<ServiceToken>>>(serviceToken));
		set<shared_ptr<ServiceToken>>::iterator peerServiceTokensContains = find_if(peerServiceTokens.begin(), peerServiceTokens.end(), MslUtils::sharedPtrEqual<set<shared_ptr<ServiceToken>>>(serviceToken));
		EXPECT_TRUE(serviceTokensContains != serviceTokens.end() || peerServiceTokensContains != peerServiceTokens.end());
	}
	EXPECT_TRUE(MslTestUtils::equal(updatedServiceTokens, responseBuilder->getPeerServiceTokens()));
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	// The service tokens will all be unbound.
	responseServiceTokens = responseBuilder->getServiceTokens();
	for (set<shared_ptr<ServiceToken>>::iterator it = responseServiceTokens.begin();
		 it != responseServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> serviceToken = *it;
		EXPECT_TRUE(serviceToken->isUnbound());
		set<shared_ptr<ServiceToken>>::iterator serviceTokensContains = find_if(serviceTokens.begin(), serviceTokens.end(), MslUtils::sharedPtrEqual<set<shared_ptr<ServiceToken>>>(serviceToken));
		set<shared_ptr<ServiceToken>>::iterator peerServiceTokensContains = find_if(peerServiceTokens.begin(), peerServiceTokens.end(), MslUtils::sharedPtrEqual<set<shared_ptr<ServiceToken>>>(serviceToken));
		EXPECT_TRUE(serviceTokensContains != serviceTokens.end() || peerServiceTokensContains != peerServiceTokens.end());
	}
	EXPECT_TRUE(MslTestUtils::equal(updatedServiceTokens, response->getPeerServiceTokens()));
}

TEST_F(MessageBuilderTest_CreateResponse, keyxAddServiceToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	EXPECT_FALSE(responseBuilder->getMasterToken());
	shared_ptr<UserIdToken> userIdToken = responseBuilder->getUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_TRUE(responseBuilder->getKeyExchangeData());
	shared_ptr<MasterToken> keyxMasterToken = responseBuilder->getKeyExchangeData()->keyResponseData->getMasterToken();
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, keyxMasterToken, userIdToken);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		responseBuilder->addServiceToken(*serviceToken);
	}
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();

	EXPECT_EQ(serviceTokens, response->getServiceTokens());
}

TEST_F(MessageBuilderTest_CreateResponse, nullKeyxAddServiceToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	EXPECT_FALSE(responseBuilder->getMasterToken());
	EXPECT_FALSE(responseBuilder->getKeyExchangeData());
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	bool thrown = false;
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		try {
			responseBuilder->addServiceToken(*serviceToken);
		} catch (const MslMessageException& e) {
			EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, e.getError());
			thrown = true;
		}
	}
	EXPECT_TRUE(thrown);
}

TEST_F(MessageBuilderTest_CreateResponse, keyxAddMismatchedServiceToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	EXPECT_FALSE(responseBuilder->getMasterToken());
	EXPECT_TRUE(responseBuilder->getKeyExchangeData());
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	bool thrown = false;
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		try {
			responseBuilder->addServiceToken(*serviceToken);
		} catch (const MslMessageException& e) {
			EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, e.getError());
			thrown = true;
		}
	}
	EXPECT_TRUE(thrown);
}

TEST_F(MessageBuilderTest_CreateResponse, peerKeyxAddMismatchedServiceToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	EXPECT_FALSE(responseBuilder->getMasterToken());
	EXPECT_FALSE(responseBuilder->getUserIdToken());
	EXPECT_TRUE(responseBuilder->getKeyExchangeData());
	shared_ptr<MasterToken> keyxMasterToken = responseBuilder->getKeyExchangeData()->keyResponseData->getMasterToken();
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, keyxMasterToken, NULL_USER_ID_TOKEN);
	bool thrown = false;
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		try {
			responseBuilder->addServiceToken(*serviceToken);
		} catch (const MslMessageException& e) {
			EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, e.getError());
			thrown = true;
		}
	}
	EXPECT_TRUE(thrown);
}

TEST_F(MessageBuilderTest_CreateResponse, maxRequestMessageId)
{
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(MslConstants::MAX_LONG_VALUE, REPLAYABLE_ID, false, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> request = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, MASTER_TOKEN, headerData, peerData);

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(0, response->getMessageId());
}

TEST_F(MessageBuilderTest_CreateResponse, renewMasterToken)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, requestMasterToken, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*requestMasterToken, *response->getMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(requestMasterToken->getIdentity(), keyxMasterToken->getIdentity());
	EXPECT_EQ(incrementLong(requestMasterToken->getSequenceNumber()), keyxMasterToken->getSequenceNumber());
	EXPECT_EQ(requestMasterToken->getSerialNumber(), keyxMasterToken->getSerialNumber());
}

TEST_F(MessageBuilderTest_CreateResponse, peerRenewMasterToken)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(p2pCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, requestMasterToken, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	EXPECT_EQ(*requestMasterToken, *response->getPeerMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(requestMasterToken->getIdentity(), keyxMasterToken->getIdentity());
	EXPECT_EQ(incrementLong(requestMasterToken->getSequenceNumber()), keyxMasterToken->getSequenceNumber());
	EXPECT_EQ(requestMasterToken->getSerialNumber(), keyxMasterToken->getSerialNumber());
}

TEST_F(MessageBuilderTest_CreateResponse, renewMasterTokenMaxSequenceNumber)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, MslConstants::MAX_LONG_VALUE, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, requestMasterToken, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	shared_ptr<MasterToken> responseMasterToken = response->getMasterToken();
	EXPECT_EQ(requestMasterToken->getIdentity(), responseMasterToken->getIdentity());
	EXPECT_EQ(requestMasterToken->getSequenceNumber(), responseMasterToken->getSequenceNumber());
	EXPECT_EQ(requestMasterToken->getSerialNumber(), responseMasterToken->getSerialNumber());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(requestMasterToken->getIdentity(), keyxMasterToken->getIdentity());
	EXPECT_EQ(incrementLong(requestMasterToken->getSequenceNumber()), keyxMasterToken->getSequenceNumber());
	EXPECT_EQ(requestMasterToken->getSerialNumber(), keyxMasterToken->getSerialNumber());
}

TEST_F(MessageBuilderTest_CreateResponse, renewMasterTokenFutureRenewalWindow)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 20000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, requestMasterToken, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	shared_ptr<MasterToken> responseMasterToken = response->getMasterToken();
	EXPECT_EQ(requestMasterToken->getIdentity(), responseMasterToken->getIdentity());
	EXPECT_EQ(requestMasterToken->getSequenceNumber(), responseMasterToken->getSequenceNumber());
	EXPECT_EQ(requestMasterToken->getSerialNumber(), responseMasterToken->getSerialNumber());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_FALSE(keyResponseData);
}

TEST_F(MessageBuilderTest_CreateResponse, expiredMasterToken)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, requestMasterToken, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*requestMasterToken, *response->getMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(requestMasterToken->getIdentity(), keyxMasterToken->getIdentity());
	EXPECT_EQ(incrementLong(requestMasterToken->getSequenceNumber()), keyxMasterToken->getSequenceNumber());
	EXPECT_EQ(requestMasterToken->getSerialNumber(), keyxMasterToken->getSerialNumber());
}

TEST_F(MessageBuilderTest_CreateResponse, nonReplayableRequest)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 20000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, MslConstants::MAX_LONG_VALUE, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, requestMasterToken, NULL_USER_ID_TOKEN);
	requestBuilder->setNonReplayable(true);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*requestMasterToken, *response->getMasterToken());
	EXPECT_FALSE(response->getKeyResponseData());
}

TEST_F(MessageBuilderTest_CreateResponse, unsupportedKeyExchangeRenewMasterToken)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	vector<KeyExchangeScheme> schemes = KeyExchangeScheme::values();
	for (vector<KeyExchangeScheme>::const_iterator scheme = schemes.begin();
		 scheme != schemes.end();
		 ++scheme)
	{
		ctx->removeKeyExchangeFactories(*scheme);
	}

	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(REQUEST_MESSAGE_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> request = make_shared<MessageHeader>(trustedNetCtx, NULL_ENTITYAUTH_DATA, requestMasterToken, headerData, peerData);

	try {
		messageFactory->createResponse(ctx, request);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslKeyExchangeException& e) {
		EXPECT_EQ(MslError::KEYX_FACTORY_NOT_FOUND, e.getError());
		EXPECT_EQ(REQUEST_MESSAGE_ID, e.getMessageId());
	}
}

TEST_F(MessageBuilderTest_CreateResponse, oneSupportedKeyExchangeRenewMasterToken)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	vector<KeyExchangeScheme> schemes = KeyExchangeScheme::values();
	for (vector<KeyExchangeScheme>::const_iterator scheme = schemes.begin();
		 scheme != schemes.end();
		 ++scheme)
	{
		ctx->removeKeyExchangeFactories(*scheme);
	}
	ctx->addKeyExchangeFactory(make_shared<SymmetricWrappedExchange>(make_shared<MockAuthenticationUtils>()));

	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, requestMasterToken, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	// This should place the supported key exchange scheme in the
	// middle, guaranteeing that we will have to skip one unsupported
	// scheme.
	requestBuilder->addKeyRequestData(make_shared<AsymmetricWrappedExchange::RequestData>(KEY_PAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
	requestBuilder->addKeyRequestData(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK));
	requestBuilder->addKeyRequestData(make_shared<AsymmetricWrappedExchange::RequestData>(KEY_PAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(ctx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*requestMasterToken, *response->getMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(requestMasterToken->getIdentity(), keyxMasterToken->getIdentity());
	EXPECT_EQ(incrementLong(requestMasterToken->getSequenceNumber()), keyxMasterToken->getSequenceNumber());
	EXPECT_EQ(requestMasterToken->getSerialNumber(), keyxMasterToken->getSerialNumber());
}

TEST_F(MessageBuilderTest_CreateResponse, untrustedMasterTokenRenewMasterToken)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(REQUEST_MESSAGE_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> request = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, requestMasterToken, headerData, peerData);

	// Encode the request. This will use the MSL crypto context to
	// encrypt and sign the master token.
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, request);

	// The master token's crypto context must be cached, so we can
	// rebuild the message.
	shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(ctx, requestMasterToken);
	ctx->getMslStore()->setCryptoContext(requestMasterToken, cryptoContext);

	// Change the MSL crypto context so the master token can no longer be
	// verified or decrypted.
	shared_ptr<ByteArray> mke = make_shared<ByteArray>(16);
	shared_ptr<ByteArray> mkh = make_shared<ByteArray>(32);
	shared_ptr<ByteArray> mkw = make_shared<ByteArray>(16);
	random.nextBytes(*mke);
	random.nextBytes(*mkh);
	random.nextBytes(*mkw);
	const SecretKey encryptionKey(mke, JcaAlgorithm::AES);
	const SecretKey hmacKey(mkh, JcaAlgorithm::HMAC_SHA256);
	const SecretKey wrappingKey(mkw, JcaAlgorithm::AESKW);
	ctx->setMslCryptoContext(make_shared<SymmetricCryptoContext>(ctx, "clientMslCryptoContext", encryptionKey, hmacKey, wrappingKey));

	// Reconstruct the request now that we no longer have the same
	// MSL crypto context.
	shared_ptr<MessageHeader> untrustedRequest = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(ctx, mo, CRYPTO_CONTEXTS));

	try {
		messageFactory->createResponse(ctx, untrustedRequest);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslMasterTokenException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateResponse, keyResponseData)
{
	shared_ptr<MessageBuilder> localRequestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	localRequestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		localRequestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> localRequest = localRequestBuilder->getHeader();

	shared_ptr<MessageBuilder> remoteResponseBuilder = messageFactory->createResponse(trustedNetCtx, localRequest);
	shared_ptr<MessageHeader> remoteResponse = remoteResponseBuilder->getHeader();
	shared_ptr<KeyResponseData> keyResponseData = remoteResponse->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);

	shared_ptr<MessageBuilder> localResponseBuilder = messageFactory->createResponse(trustedNetCtx, remoteResponse);
	shared_ptr<MessageHeader> localResponse = localResponseBuilder->getHeader();
	shared_ptr<MasterToken> localMasterToken = localResponse->getMasterToken();
	EXPECT_TRUE(localMasterToken);
	EXPECT_EQ(*keyResponseData->getMasterToken(), *localMasterToken);
}

TEST_F(MessageBuilderTest_CreateResponse, peerKeyResponseData)
{
	shared_ptr<MessageBuilder> localRequestBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	localRequestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		localRequestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> localRequest = localRequestBuilder->getHeader();

	shared_ptr<MessageBuilder> remoteResponseBuilder = messageFactory->createResponse(p2pCtx, localRequest);
	shared_ptr<MessageHeader> remoteResponse = remoteResponseBuilder->getHeader();
	EXPECT_FALSE(remoteResponse->getMasterToken());
	EXPECT_FALSE(remoteResponse->getPeerMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = remoteResponse->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);

	shared_ptr<MessageBuilder> localResponseBuilder = messageFactory->createResponse(p2pCtx, remoteResponse);
	shared_ptr<MessageHeader> localResponse = localResponseBuilder->getHeader();
	shared_ptr<MasterToken> localMasterToken = localResponse->getMasterToken();
	EXPECT_TRUE(localMasterToken);
	EXPECT_EQ(*keyResponseData->getMasterToken(), *localMasterToken);
	EXPECT_FALSE(localResponse->getPeerMasterToken());

	shared_ptr<MessageBuilder> remoteSecondResponseBuilder = messageFactory->createResponse(p2pCtx, localResponse);
	shared_ptr<MessageHeader> remoteSecondResponse = remoteSecondResponseBuilder->getHeader();
	EXPECT_FALSE(remoteResponse->getMasterToken());
	shared_ptr<MasterToken> remotePeerMasterToken = remoteSecondResponse->getPeerMasterToken();
	EXPECT_TRUE(remotePeerMasterToken);
	EXPECT_EQ(*localMasterToken, *remotePeerMasterToken);
}

TEST_F(MessageBuilderTest_CreateResponse, entityAuthDataNotRenewable)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	EXPECT_EQ(*trustedNetCtx->getEntityAuthenticationData(), *response->getEntityAuthenticationData());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
}

TEST_F(MessageBuilderTest_CreateResponse, entityAuthDataRenewable)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(trustedNetCtx->getEntityAuthenticationData()->getIdentity(), keyxMasterToken->getIdentity());
}

TEST_F(MessageBuilderTest_CreateResponse, peerEntityAuthDataRenewable)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	EXPECT_FALSE(response->getPeerMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_TRUE(keyxMasterToken);
	EXPECT_EQ(p2pCtx->getEntityAuthenticationData()->getIdentity(), keyxMasterToken->getIdentity());
}

TEST_F(MessageBuilderTest_CreateResponse, unsupportedKeyExchangeEntityAuthData)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	vector<KeyExchangeScheme> schemes = KeyExchangeScheme::values();
	for (vector<KeyExchangeScheme>::const_iterator scheme = schemes.begin();
		 scheme != schemes.end();
		 ++scheme)
	{
		ctx->removeKeyExchangeFactories(*scheme);
	}

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(REQUEST_MESSAGE_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, KEY_REQUEST_DATA, NULL_KEYX_RESPONSE, NULL_USERAUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> request = make_shared<MessageHeader>(ctx, ctx->getEntityAuthenticationData(), NULL_MASTER_TOKEN, headerData, peerData);

	try {
		messageFactory->createResponse(ctx, request);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslKeyExchangeException& e) {
		EXPECT_EQ(MslError::KEYX_FACTORY_NOT_FOUND, e.getError());
		EXPECT_EQ(REQUEST_MESSAGE_ID, e.getMessageId());
	}
}

TEST_F(MessageBuilderTest_CreateResponse, oneSupportedKeyExchangeEntityAuthData)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	vector<KeyExchangeScheme> schemes = KeyExchangeScheme::values();
	for (vector<KeyExchangeScheme>::const_iterator scheme = schemes.begin();
		 scheme != schemes.end();
		 ++scheme)
	{
		ctx->removeKeyExchangeFactories(*scheme);
	}
	ctx->addKeyExchangeFactory(make_shared<AsymmetricWrappedExchange>(make_shared<MockAuthenticationUtils>()));

	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	// This should place the supported key exchange scheme in the
	// middle, guaranteeing that we will have to skip one unsupported
	// scheme.
	requestBuilder->addKeyRequestData(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION));
	requestBuilder->addKeyRequestData(make_shared<AsymmetricWrappedExchange::RequestData>(KEY_PAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::JWK_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
	requestBuilder->addKeyRequestData(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK));
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(ctx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response->getKeyResponseData());
}

TEST_F(MessageBuilderTest_CreateResponse, renewUserIdToken)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<UserIdToken> requestUserIdToken = make_shared<UserIdToken>(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken);
	requestBuilder->setRenewable(true);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*MASTER_TOKEN, *response->getMasterToken());
	shared_ptr<UserIdToken> responseUserIdToken = response->getUserIdToken();
	EXPECT_TRUE(responseUserIdToken);
	EXPECT_EQ(*requestUserIdToken->getUser(), *responseUserIdToken->getUser());
	EXPECT_EQ(requestUserIdToken->getMasterTokenSerialNumber(), responseUserIdToken->getMasterTokenSerialNumber());
	EXPECT_EQ(requestUserIdToken->getSerialNumber(), responseUserIdToken->getSerialNumber());
	EXPECT_FALSE(responseUserIdToken->isRenewable());
}

TEST_F(MessageBuilderTest_CreateResponse, renewUserIdTokenNotRenewable)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<UserIdToken> requestUserIdToken = make_shared<UserIdToken>(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*MASTER_TOKEN, *response->getMasterToken());
	shared_ptr<UserIdToken> responseUserIdToken = response->getUserIdToken();
	EXPECT_TRUE(responseUserIdToken);
	EXPECT_EQ(*requestUserIdToken->getUser(), *responseUserIdToken->getUser());
	EXPECT_EQ(requestUserIdToken->getMasterTokenSerialNumber(), responseUserIdToken->getMasterTokenSerialNumber());
	EXPECT_EQ(requestUserIdToken->getSerialNumber(), responseUserIdToken->getSerialNumber());
	EXPECT_EQ(*requestUserIdToken->getRenewalWindow(), *responseUserIdToken->getRenewalWindow());
	EXPECT_EQ(*requestUserIdToken->getExpiration(), *responseUserIdToken->getExpiration());
}

TEST_F(MessageBuilderTest_CreateResponse, peerRenewUserIdToken)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<UserIdToken> requestUserIdToken = make_shared<UserIdToken>(p2pCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, requestUserIdToken);
	requestBuilder->setRenewable(true);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*MASTER_TOKEN, *response->getPeerMasterToken());
	EXPECT_FALSE(response->getUserIdToken());
	shared_ptr<UserIdToken> responseUserIdToken = response->getPeerUserIdToken();
	EXPECT_TRUE(responseUserIdToken);
	EXPECT_EQ(*requestUserIdToken->getUser(), *responseUserIdToken->getUser());
	EXPECT_EQ(requestUserIdToken->getMasterTokenSerialNumber(), responseUserIdToken->getMasterTokenSerialNumber());
	EXPECT_EQ(requestUserIdToken->getSerialNumber(), responseUserIdToken->getSerialNumber());
	EXPECT_FALSE(responseUserIdToken->isRenewable());
}

TEST_F(MessageBuilderTest_CreateResponse, expiredUserIdToken)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<UserIdToken> requestUserIdToken = make_shared<UserIdToken>(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken);
	requestBuilder->setRenewable(true);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*MASTER_TOKEN, *response->getMasterToken());
	shared_ptr<UserIdToken> responseUserIdToken = response->getUserIdToken();
	EXPECT_TRUE(responseUserIdToken);
	EXPECT_EQ(*requestUserIdToken->getUser(), *responseUserIdToken->getUser());
	EXPECT_EQ(requestUserIdToken->getMasterTokenSerialNumber(), responseUserIdToken->getMasterTokenSerialNumber());
	EXPECT_EQ(requestUserIdToken->getSerialNumber(), responseUserIdToken->getSerialNumber());
	EXPECT_FALSE(responseUserIdToken->isExpired());
}

TEST_F(MessageBuilderTest_CreateResponse, expiredUserIdTokenNotRenewable)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<UserIdToken> requestUserIdToken = make_shared<UserIdToken>(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*MASTER_TOKEN, *response->getMasterToken());
	shared_ptr<UserIdToken> responseUserIdToken = response->getUserIdToken();
	EXPECT_TRUE(responseUserIdToken);
	EXPECT_EQ(*requestUserIdToken->getUser(), *responseUserIdToken->getUser());
	EXPECT_EQ(requestUserIdToken->getMasterTokenSerialNumber(), responseUserIdToken->getMasterTokenSerialNumber());
	EXPECT_EQ(requestUserIdToken->getSerialNumber(), responseUserIdToken->getSerialNumber());
	EXPECT_FALSE(responseUserIdToken->isExpired());
}

TEST_F(MessageBuilderTest_CreateResponse, expiredUserIdTokenServerMessage)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 20000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<UserIdToken> requestUserIdToken = make_shared<UserIdToken>(ctx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);

	// Change the MSL crypto context so the master token and user ID
	// token are not issued by the local entity.
	ctx->setMslCryptoContext(ALT_MSL_CRYPTO_CONTEXT);

	// Now rebuild the user ID token and the build the request.
	shared_ptr<MslObject> userIdTokenMo = MslTestUtils::toMslObject(encoder, requestUserIdToken);
	shared_ptr<UserIdToken> unverifiedUserIdToken = make_shared<UserIdToken>(ctx, userIdTokenMo, MASTER_TOKEN);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, MASTER_TOKEN, unverifiedUserIdToken);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(ctx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*MASTER_TOKEN, *response->getMasterToken());
	shared_ptr<UserIdToken> responseUserIdToken = response->getUserIdToken();
	EXPECT_TRUE(responseUserIdToken);
	// Can't compare users because the unverified user ID token won't
	// have it.
	EXPECT_EQ(unverifiedUserIdToken->getMasterTokenSerialNumber(), responseUserIdToken->getMasterTokenSerialNumber());
	EXPECT_EQ(unverifiedUserIdToken->getSerialNumber(), responseUserIdToken->getSerialNumber());
	EXPECT_FALSE(responseUserIdToken->isExpired());
}

TEST_F(MessageBuilderTest_CreateResponse, renewMasterTokenAndRenewUserIdToken)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<UserIdToken> requestUserIdToken = make_shared<UserIdToken>(trustedNetCtx, renewalWindow, expiration, requestMasterToken, 1L, ISSUER_DATA, USER);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, requestMasterToken, requestUserIdToken);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*requestMasterToken, *response->getMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(requestMasterToken->getIdentity(), keyxMasterToken->getIdentity());
	EXPECT_EQ(incrementLong(requestMasterToken->getSequenceNumber()), keyxMasterToken->getSequenceNumber());
	EXPECT_EQ(requestMasterToken->getSerialNumber(), keyxMasterToken->getSerialNumber());
	shared_ptr<UserIdToken> responseUserIdToken = response->getUserIdToken();
	EXPECT_TRUE(responseUserIdToken);
	EXPECT_EQ(*requestUserIdToken->getUser(), *responseUserIdToken->getUser());
	EXPECT_EQ(requestUserIdToken->getMasterTokenSerialNumber(), responseUserIdToken->getMasterTokenSerialNumber());
	EXPECT_EQ(requestUserIdToken->getSerialNumber(), responseUserIdToken->getSerialNumber());
}

TEST_F(MessageBuilderTest_CreateResponse, renewTokensNoKeyRequestData)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<UserIdToken> requestUserIdToken = make_shared<UserIdToken>(trustedNetCtx, renewalWindow, expiration, requestMasterToken, 1L, ISSUER_DATA, USER);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, requestMasterToken, requestUserIdToken);
	requestBuilder->setRenewable(true);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	shared_ptr<MasterToken> responseMasterToken = response->getMasterToken();
	shared_ptr<UserIdToken> responseUserIdToken = response->getUserIdToken();
	EXPECT_EQ(requestMasterToken, responseMasterToken);
	EXPECT_EQ(*requestMasterToken->getRenewalWindow(), *responseMasterToken->getRenewalWindow());
	EXPECT_EQ(*requestMasterToken->getExpiration(), *responseMasterToken->getExpiration());
	EXPECT_EQ(*requestUserIdToken, *responseUserIdToken);
	EXPECT_NE(*requestUserIdToken->getRenewalWindow(), *responseUserIdToken->getRenewalWindow());
	EXPECT_NE(*requestUserIdToken->getExpiration(), *responseUserIdToken->getExpiration());
	EXPECT_FALSE(response->getKeyResponseData());
}

TEST_F(MessageBuilderTest_CreateResponse, peerRenewMasterTokenAndRenewUserIdToken)
{
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 10000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 10000);
	shared_ptr<MasterToken> requestMasterToken = make_shared<MasterToken>(p2pCtx, renewalWindow, expiration, 1L, 1L, NULL_ISSUER_DATA, MockPresharedAuthenticationFactory::PSK_ESN, MockPresharedAuthenticationFactory::KPE, MockPresharedAuthenticationFactory::KPH);
	shared_ptr<UserIdToken> requestUserIdToken = make_shared<UserIdToken>(p2pCtx, renewalWindow, expiration, requestMasterToken, 1L, ISSUER_DATA, USER);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, requestMasterToken, requestUserIdToken);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	EXPECT_EQ(*requestMasterToken, *response->getPeerMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(requestMasterToken->getIdentity(), keyxMasterToken->getIdentity());
	EXPECT_EQ(incrementLong(requestMasterToken->getSequenceNumber()), keyxMasterToken->getSequenceNumber());
	EXPECT_EQ(requestMasterToken->getSerialNumber(), keyxMasterToken->getSerialNumber());
	EXPECT_FALSE(response->getUserIdToken());
	shared_ptr<UserIdToken> responseUserIdToken = response->getPeerUserIdToken();
	EXPECT_TRUE(responseUserIdToken);
	EXPECT_EQ(*requestUserIdToken->getUser(), *responseUserIdToken->getUser());
	EXPECT_EQ(requestUserIdToken->getMasterTokenSerialNumber(), responseUserIdToken->getMasterTokenSerialNumber());
	EXPECT_EQ(requestUserIdToken->getSerialNumber(), responseUserIdToken->getSerialNumber());
}

TEST_F(MessageBuilderTest_CreateResponse, masterTokenUserAuthData)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	shared_ptr<UserIdToken> userIdToken = response->getUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*MockEmailPasswordAuthenticationFactory::USER(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateResponse, masterTokenUserAuthenticated)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MslObject> requestMo = MslTestUtils::toMslObject(encoder, request);
	shared_ptr<MessageHeader> moRequest = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(ctx, requestMo, CRYPTO_CONTEXTS));
	EXPECT_TRUE(moRequest->getUser());

	// Remove support for user authentication to prove the response
	// does not perform it.
	ctx->removeUserAuthenticationFactory(USER_AUTH_DATA->getScheme());

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(ctx, moRequest);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	shared_ptr<UserIdToken> userIdToken = response->getUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*MockEmailPasswordAuthenticationFactory::USER(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateResponse, peerMasterTokenUserAuthData)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getUserIdToken());
	shared_ptr<UserIdToken> userIdToken = response->getPeerUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*MockEmailPasswordAuthenticationFactory::USER(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateResponse, peerMasterTokenUserAuthenticated)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, true);

	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MslObject> requestMo = MslTestUtils::toMslObject(encoder, request);
	shared_ptr<MessageHeader> moRequest = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(ctx, requestMo, CRYPTO_CONTEXTS));
	EXPECT_TRUE(moRequest->getUser());

	// Remove support for user authentication to prove the response
	// does not perform it.
	ctx->removeUserAuthenticationFactory(USER_AUTH_DATA->getScheme());

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(ctx, moRequest);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	shared_ptr<UserIdToken> userIdToken = response->getPeerUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*MockEmailPasswordAuthenticationFactory::USER(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateResponse, entityAuthDataUserAuthData)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(trustedNetCtx->getEntityAuthenticationData()->getIdentity(), keyxMasterToken->getIdentity());
	shared_ptr<UserIdToken> userIdToken = response->getUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*MockEmailPasswordAuthenticationFactory::USER(), *userIdToken->getUser());
	EXPECT_TRUE(userIdToken->isBoundTo(keyxMasterToken));
}

TEST_F(MessageBuilderTest_CreateResponse, entityAuthDataUserAuthenticatedData)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);

	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MslObject> requestMo = MslTestUtils::toMslObject(encoder, request);
	shared_ptr<MessageHeader> moRequest = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(ctx, requestMo, CRYPTO_CONTEXTS));
	EXPECT_TRUE(moRequest->getUser());

	// Remove support for user authentication to prove the response
	// does not perform it.
	ctx->removeUserAuthenticationFactory(USER_AUTH_DATA->getScheme());

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(ctx, moRequest);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(trustedNetCtx->getEntityAuthenticationData()->getIdentity(), keyxMasterToken->getIdentity());
	shared_ptr<UserIdToken> userIdToken = response->getUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*MockEmailPasswordAuthenticationFactory::USER(), *userIdToken->getUser());
	EXPECT_TRUE(userIdToken->isBoundTo(keyxMasterToken));
}

TEST_F(MessageBuilderTest_CreateResponse, entityUserAuthNoKeyRequestData)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	EXPECT_FALSE(response->getUserIdToken());
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_EQ(*trustedNetCtx->getEntityAuthenticationData(), *response->getEntityAuthenticationData());
}

TEST_F(MessageBuilderTest_CreateResponse, peerEntityAuthDataUserAuthData)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(p2pCtx->getEntityAuthenticationData()->getIdentity(), keyxMasterToken->getIdentity());
	EXPECT_FALSE(response->getUserIdToken());
	shared_ptr<UserIdToken> userIdToken = response->getPeerUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*MockEmailPasswordAuthenticationFactory::USER(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateResponse, peerEntityAuthDataUserAuthenticatedData)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, true);

	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MslObject> requestMo = MslTestUtils::toMslObject(encoder, request);
	shared_ptr<MessageHeader> moRequest = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(ctx, requestMo, CRYPTO_CONTEXTS));
	EXPECT_TRUE(moRequest->getUser());

	// Remove support for user authentication to prove the response
	// does not perform it.
	ctx->removeUserAuthenticationFactory(USER_AUTH_DATA->getScheme());

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(ctx, moRequest);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMasterToken());
	shared_ptr<KeyResponseData> keyResponseData = response->getKeyResponseData();
	EXPECT_TRUE(keyResponseData);
	shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
	EXPECT_EQ(p2pCtx->getEntityAuthenticationData()->getIdentity(), keyxMasterToken->getIdentity());
	EXPECT_FALSE(response->getUserIdToken());
	shared_ptr<UserIdToken> userIdToken = response->getPeerUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*MockEmailPasswordAuthenticationFactory::USER(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateResponse, unsupportedUserAuthentication)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	vector<UserAuthenticationScheme> schemes = UserAuthenticationScheme::values();
	for (vector<UserAuthenticationScheme>::const_iterator scheme = schemes.begin();
		 scheme != schemes.end();
		 ++scheme)
	{
		ctx->removeUserAuthenticationFactory(*scheme);
	}

	shared_ptr<HeaderData> headerData = make_shared<HeaderData>(REQUEST_MESSAGE_ID, REPLAYABLE_ID, true, false, NULL_MSG_CAPS, EMPTY_KEYX_REQUESTS, NULL_KEYX_RESPONSE, USER_AUTH_DATA, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, EMPTY_SERVICE_TOKENS);
	shared_ptr<MessageHeader> request = make_shared<MessageHeader>(ctx, NULL_ENTITYAUTH_DATA, MASTER_TOKEN, headerData, peerData);

	try {
		messageFactory->createResponse(ctx, request);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslUserAuthException& e) {
		EXPECT_EQ(MslError::USERAUTH_FACTORY_NOT_FOUND, e.getError());
		EXPECT_EQ(REQUEST_MESSAGE_ID, e.getMessageId());
	}
}

TEST_F(MessageBuilderTest_CreateResponse, setMasterToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	responseBuilder->setAuthTokens(MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> messageHeader = responseBuilder->getHeader();

	// The message service tokens will include all unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	EXPECT_TRUE(MslTestUtils::equal(messageHeader->getServiceTokens(), updatedServiceTokens));
}

TEST_F(MessageBuilderTest_CreateResponse, setExistingMasterToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	responseBuilder->setAuthTokens(MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> messageHeader = responseBuilder->getHeader();

	// The message service tokens will include all unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	EXPECT_TRUE(MslTestUtils::equal(messageHeader->getServiceTokens(), updatedServiceTokens));
}

TEST_F(MessageBuilderTest_CreateResponse, setAuthTokens)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	responseBuilder->setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageHeader> messageHeader = responseBuilder->getHeader();

	// The message service tokens will include all unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	EXPECT_TRUE(MslTestUtils::equal(messageHeader->getServiceTokens(), updatedServiceTokens));
}

TEST_F(MessageBuilderTest_CreateResponse, setExistingAuthTokens)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MslStore> store = trustedNetCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	responseBuilder->setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageHeader> messageHeader = responseBuilder->getHeader();

	// The message service tokens will include all unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> updatedServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator it = peerServiceTokens.begin();
		 it != peerServiceTokens.end();
		 ++it)
	{
		shared_ptr<ServiceToken> peerServiceToken = *it;
		if (peerServiceToken->isUnbound())
			updatedServiceTokens.insert(peerServiceToken);
	}

	EXPECT_TRUE(MslTestUtils::equal(messageHeader->getServiceTokens(), updatedServiceTokens));
}

TEST_F(MessageBuilderTest_CreateResponse, setNullMasterToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	responseBuilder->setAuthTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();

	EXPECT_FALSE(response->getMasterToken());
	EXPECT_FALSE(response->getUserIdToken());
}

TEST_F(MessageBuilderTest_CreateResponse, setMismatchedAuthTokens)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	try {
		responseBuilder->setAuthTokens(MASTER_TOKEN, PEER_USER_ID_TOKEN);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateResponse, setMasterTokenHasKeyExchangeData)
{
	// The master token must be renewable to force a key exchange to
	// happen.
	shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 1000);
	shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 2000);
	const string identity = MockPresharedAuthenticationFactory::PSK_ESN;
	const SecretKey encryptionKey = MockPresharedAuthenticationFactory::KPE;
	const SecretKey hmacKey = MockPresharedAuthenticationFactory::KPH;
	shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(trustedNetCtx, renewalWindow, expiration, 1, 1, NULL_ISSUER_DATA, identity, encryptionKey, hmacKey);

	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, masterToken, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	try {
		responseBuilder->setAuthTokens(MASTER_TOKEN, NULL_USER_ID_TOKEN);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateResponse, setMasterTokenHasPeerKeyExchangeData)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
	     keyRequestData != KEY_REQUEST_DATA.end();
	     ++keyRequestData)
	{
		requestBuilder->addKeyRequestData(*keyRequestData);
	}
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MslStore> store = p2pCtx->getMslStore();
	store->setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(USER_ID, USER_ID_TOKEN);
	store->setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
	store->addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	store->addServiceTokens(serviceTokens);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	store->addServiceTokens(peerServiceTokens);

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	responseBuilder->setAuthTokens(PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();

	// Build the set of expected service tokens.
	set<shared_ptr<ServiceToken>> expectedServiceTokens;
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		if ((*serviceToken)->isUnbound())
			expectedServiceTokens.insert(*serviceToken);
	}
	for (set<shared_ptr<ServiceToken>>::iterator peerServiceToken = peerServiceTokens.begin();
		 peerServiceToken != peerServiceTokens.end();
		 ++peerServiceToken)
	{
		if (!(*peerServiceToken)->isUserIdTokenBound())
			expectedServiceTokens.insert(*peerServiceToken);
	}
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), expectedServiceTokens));

	// Build the set of expected peer service tokens.
	set<shared_ptr<ServiceToken>> expectedPeerServiceTokens(serviceTokens);
	for (set<shared_ptr<ServiceToken>>::iterator peerServiceToken = peerServiceTokens.begin();
		 peerServiceToken != peerServiceTokens.end();
		 ++peerServiceToken)
	{
		if ((*peerServiceToken)->isUnbound())
			expectedPeerServiceTokens.insert(*peerServiceToken);
	}
	EXPECT_TRUE(MslTestUtils::equal(response->getPeerServiceTokens(), expectedPeerServiceTokens));
}

TEST_F(MessageBuilderTest_CreateResponse, setUser)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	responseBuilder->setUser(USER_ID_TOKEN->getUser());
	shared_ptr<UserIdToken> userIdToken = responseBuilder->getUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*USER_ID_TOKEN->getUser(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateResponse, setUserNoMasterToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	try {
		responseBuilder->setUser(USER_ID_TOKEN->getUser());
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateResponse, setUserHasUserIdToken)
		{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	try {
		responseBuilder->setUser(USER_ID_TOKEN->getUser());
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateResponse, setPeerUser)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	responseBuilder->setUser(USER_ID_TOKEN->getUser());
	shared_ptr<UserIdToken> userIdToken = responseBuilder->getPeerUserIdToken();
	EXPECT_TRUE(userIdToken);
	EXPECT_EQ(*USER_ID_TOKEN->getUser(), *userIdToken->getUser());
}

TEST_F(MessageBuilderTest_CreateResponse, setPeerUserNoPeerMasterToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	try {
		responseBuilder->setUser(USER_ID_TOKEN->getUser());
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateResponse, setPeerUserHasPeerUserIdToken)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(p2pCtx, request);
	try {
		responseBuilder->setUser(USER_ID_TOKEN->getUser());
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageBuilderTest_CreateResponse, oneRequestCapabilities)
{
	set<CompressionAlgorithm> algos;;
	algos.insert(CompressionAlgorithm::GZIP);
	algos.insert(CompressionAlgorithm::LZW);
	set<CompressionAlgorithm> gzipOnly;
	gzipOnly.insert(CompressionAlgorithm::GZIP);

	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	shared_ptr<MessageCapabilities> caps = make_shared<MessageCapabilities>(gzipOnly, EMPTY_LANGUAGES, EMPTY_ENCODER_FORMATS);
	ctx->setMessageCapabilities(caps);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();
	EXPECT_EQ(*caps, *request->getMessageCapabilities());

	ctx->setMessageCapabilities(make_shared<MessageCapabilities>(algos, EMPTY_LANGUAGES, EMPTY_ENCODER_FORMATS));
	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(ctx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_EQ(*caps, *response->getMessageCapabilities());
}

TEST_F(MessageBuilderTest_CreateResponse, nullRequestCapabilities)
{
	set<CompressionAlgorithm> algos;;
	algos.insert(CompressionAlgorithm::GZIP);
	algos.insert(CompressionAlgorithm::LZW);

	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	ctx->setMessageCapabilities(NULL_MSG_CAPS);
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();
	EXPECT_FALSE(request->getMessageCapabilities());

	ctx->setMessageCapabilities(make_shared<MessageCapabilities>(algos, EMPTY_LANGUAGES, EMPTY_ENCODER_FORMATS));
	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(ctx, request);
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_FALSE(response->getMessageCapabilities());
}

TEST_F(MessageBuilderTest_CreateResponse, createIdempotentResponse)
{
	shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder> responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	responseBuilder->setNonReplayable(true);
	responseBuilder->setRenewable(true);
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequestData = KEY_REQUEST_DATA.begin();
		 keyRequestData != KEY_REQUEST_DATA.end();
		 ++keyRequestData)
	{
		responseBuilder->addKeyRequestData(*keyRequestData);
	}
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		responseBuilder->addServiceToken(*serviceToken);
	}
	responseBuilder->setUserAuthenticationData(USER_AUTH_DATA);
	EXPECT_TRUE(responseBuilder->willEncryptHeader());
	EXPECT_TRUE(responseBuilder->willEncryptPayloads());
	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, responseBuilder->getServiceTokens()));
	EXPECT_TRUE(responseBuilder->getPeerServiceTokens().empty());
	shared_ptr<MessageHeader> response = responseBuilder->getHeader();
	EXPECT_TRUE(response);
	EXPECT_TRUE(response->getNonReplayableId());
	EXPECT_TRUE(response->isRenewable());
	EXPECT_FALSE(response->isHandshake());
	EXPECT_TRUE(response->getCryptoContext());
	EXPECT_FALSE(response->getEntityAuthenticationData());
	EXPECT_TRUE(MslTestUtils::equal(response->getKeyRequestData(), KEY_REQUEST_DATA));
	EXPECT_FALSE(response->getKeyResponseData());
	EXPECT_EQ(*MASTER_TOKEN, *response->getMasterToken());
	EXPECT_EQ(incrementLong(request->getMessageId()), response->getMessageId());
	EXPECT_EQ(*trustedNetCtx->getMessageCapabilities(), *response->getMessageCapabilities());
	EXPECT_FALSE(response->getPeerMasterToken());
	EXPECT_TRUE(response->getPeerServiceTokens().empty());
	EXPECT_FALSE(response->getPeerUserIdToken());
	EXPECT_TRUE(MslTestUtils::equal(response->getServiceTokens(), serviceTokens));
	EXPECT_EQ(*USER_AUTH_DATA, *response->getUserAuthenticationData());
	EXPECT_EQ(*USER_ID_TOKEN, *response->getUserIdToken());
}

}}} // namespace netflix::msl::msg
