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

#include <gtest/gtest.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMessageException.h>
#include <crypto/NullCryptoContext.h>
#include <crypto/Random.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <keyx/AsymmetricWrappedExchange.h>
#include <keyx/KeyRequestData.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <msg/MessageBuilder.h>
#include <msg/MessageFactory.h>
#include <msg/MessageServiceTokenBuilder.h>
#include <tokens/MasterToken.h>
#include <tokens/ServiceToken.h>
#include <tokens/UserIdToken.h>
#include <userauth/UserAuthenticationScheme.h>
#include <util/MslContext.h>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../msg/MockMessageContext.h"
#include "../userauth/MockEmailPasswordAuthenticationFactory.h"
#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::keyx;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;
using namespace netflix::msl::MslConstants;
using Mechanism = netflix::msl::keyx::AsymmetricWrappedExchange::RequestData::Mechanism;

namespace netflix {
namespace msl {
namespace msg {

namespace {
const string KEY_PAIR_ID = "keyPairId";
const string USER_ID = "userid";
const string TOKEN_NAME = "tokenName";
const string EMPTY_TOKEN_NAME = "";
const bool ENCRYPT = true;
const CompressionAlgorithm COMPRESSION_ALGO = CompressionAlgorithm::NOCOMPRESSION;

const shared_ptr<MasterToken> NULL_MASTER_TOKEN;
const shared_ptr<UserIdToken> NULL_USER_ID_TOKEN;
const shared_ptr<MessageFactory> messageFactory = make_shared<MessageFactory>();

} // namespace anonymous

/**
 * Message service token builder unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageServiceTokenBuilderTest : public ::testing::Test
{
public:
	virtual ~MessageServiceTokenBuilderTest() {}

	MessageServiceTokenBuilderTest()
	{
		trustedNetCtx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
		trustedNetMsgCtx = make_shared<MockMessageContext>(trustedNetCtx, USER_ID, UserAuthenticationScheme::EMAIL_PASSWORD);
		p2pCtx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, true);
		p2pMsgCtx = make_shared<MockMessageContext>(p2pCtx, USER_ID, UserAuthenticationScheme::EMAIL_PASSWORD);

		MASTER_TOKEN = MslTestUtils::getMasterToken(p2pCtx, 1, 1);
		USER_ID_TOKEN = MslTestUtils::getUserIdToken(p2pCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());

		PEER_MASTER_TOKEN = MslTestUtils::getMasterToken(p2pCtx, 1, 2);
		PEER_USER_ID_TOKEN = MslTestUtils::getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());

		/* FIXME Needs AsymmetricWrapped keyx
		pair<PublicKey,PrivateKey> rsaKeyPair = MslTestUtils::generateRsaKeys("RSA", 512);
		PublicKey publicKey = rsaKeyPair.first;
		PrivateKey privateKey = rsaKeyPair.second;
		KEY_REQUEST_DATA = make_shared<AsymmetricWrappedExchange::RequestData>(KEY_PAIR_ID, Mechanism::JWEJS_RSA, publicKey, privateKey);
		*/
		KEY_REQUEST_DATA = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);

		DATA = make_shared<ByteArray>(128);
		random.nextBytes(*DATA);
	}

protected:
	shared_ptr<ByteArray> DATA;

	shared_ptr<MasterToken> MASTER_TOKEN, PEER_MASTER_TOKEN;
	shared_ptr<UserIdToken> USER_ID_TOKEN, PEER_USER_ID_TOKEN;
	shared_ptr<KeyRequestData> KEY_REQUEST_DATA;

	Random random;
	shared_ptr<MslContext> trustedNetCtx;
	shared_ptr<MockMessageContext> trustedNetMsgCtx;
	shared_ptr<MslContext> p2pCtx;
	shared_ptr<MockMessageContext> p2pMsgCtx;
};

TEST_F(MessageServiceTokenBuilderTest, primaryMasterToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_TRUE(tokenBuilder->isPrimaryMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPrimaryUserIdTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPeerMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPeerUserIdTokenAvailable());
}

TEST_F(MessageServiceTokenBuilderTest, primaryMasterTokenKeyx)
{
	shared_ptr<MessageBuilder>requestBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->addKeyRequestData(KEY_REQUEST_DATA);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder>responseBuilder = messageFactory->createResponse(trustedNetCtx, request);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(trustedNetCtx, trustedNetMsgCtx, responseBuilder);
	EXPECT_FALSE(responseBuilder->getMasterToken());
	EXPECT_TRUE(responseBuilder->getKeyExchangeData());

	EXPECT_TRUE(tokenBuilder->isPrimaryMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPrimaryUserIdTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPeerMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPeerUserIdTokenAvailable());
}

TEST_F(MessageServiceTokenBuilderTest, primaryUserIdToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_TRUE(tokenBuilder->isPrimaryMasterTokenAvailable());
	EXPECT_TRUE(tokenBuilder->isPrimaryUserIdTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPeerMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPeerUserIdTokenAvailable());
}

TEST_F(MessageServiceTokenBuilderTest, peerMasterToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->isPrimaryMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPrimaryUserIdTokenAvailable());
	EXPECT_TRUE(tokenBuilder->isPeerMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPeerUserIdTokenAvailable());
}

TEST_F(MessageServiceTokenBuilderTest, peerMasterTokenKeyx)
{
	shared_ptr<MessageBuilder>requestBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	requestBuilder->setRenewable(true);
	requestBuilder->addKeyRequestData(KEY_REQUEST_DATA);
	shared_ptr<MessageHeader> request = requestBuilder->getHeader();

	shared_ptr<MessageBuilder>responseBuilder = messageFactory->createResponse(p2pCtx, request);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, responseBuilder);

	EXPECT_FALSE(tokenBuilder->isPrimaryMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPrimaryUserIdTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPeerMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPeerUserIdTokenAvailable());
}

TEST_F(MessageServiceTokenBuilderTest, peerUserIdToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->isPrimaryMasterTokenAvailable());
	EXPECT_FALSE(tokenBuilder->isPrimaryUserIdTokenAvailable());
	EXPECT_TRUE(tokenBuilder->isPeerMasterTokenAvailable());
	EXPECT_TRUE(tokenBuilder->isPeerUserIdTokenAvailable());
}

TEST_F(MessageServiceTokenBuilderTest, getPrimaryServiceTokens)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::const_iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		msgBuilder->addServiceToken(*serviceToken);
	}
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, tokenBuilder->getPrimaryServiceTokens()));
	EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, getPeerServiceTokens)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::const_iterator peerServiceToken = peerServiceTokens.begin();
		 peerServiceToken != peerServiceTokens.end();
		 ++peerServiceToken)
	{
		msgBuilder->addPeerServiceToken(*peerServiceToken);
	}
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_TRUE(MslTestUtils::equal(peerServiceTokens, tokenBuilder->getPeerServiceTokens()));
	EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, getBothServiceTokens)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::const_iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		msgBuilder->addServiceToken(*serviceToken);
	}
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	for (set<shared_ptr<ServiceToken>>::const_iterator peerServiceToken = peerServiceTokens.begin();
		 peerServiceToken != peerServiceTokens.end();
		 ++peerServiceToken)
	{
		msgBuilder->addPeerServiceToken(*peerServiceToken);
	}
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, tokenBuilder->getPrimaryServiceTokens()));
	EXPECT_TRUE(MslTestUtils::equal(peerServiceTokens, tokenBuilder->getPeerServiceTokens()));
}

TEST_F(MessageServiceTokenBuilderTest, addPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());

	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(serviceToken));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), serviceTokens.size());
	shared_ptr<ServiceToken> builderServiceToken = *serviceTokens.begin();
	EXPECT_EQ(serviceToken, builderServiceToken);
}

TEST_F(MessageServiceTokenBuilderTest, addNamedPrimaryServiceTokens)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());

    shared_ptr<ServiceToken> unboundServiceTokenA = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(unboundServiceTokenA));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());

    shared_ptr<ServiceToken> unboundServiceTokenB = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(unboundServiceTokenB));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());

    shared_ptr<ServiceToken> masterBoundServiceTokenA = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(masterBoundServiceTokenA));
    EXPECT_EQ(static_cast<size_t>(2), tokenBuilder->getPrimaryServiceTokens().size());

    shared_ptr<ServiceToken> masterBoundServiceTokenB = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(masterBoundServiceTokenB));
    EXPECT_EQ(static_cast<size_t>(2), tokenBuilder->getPrimaryServiceTokens().size());

    shared_ptr<ServiceToken> userBoundServiceTokenA = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(userBoundServiceTokenA));
    EXPECT_EQ(static_cast<size_t>(3), tokenBuilder->getPrimaryServiceTokens().size());

    shared_ptr<ServiceToken> userBoundServiceTokenB = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(userBoundServiceTokenB));
    EXPECT_EQ(static_cast<size_t>(3), tokenBuilder->getPrimaryServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, mismatchedMasterTokenAddPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	EXPECT_FALSE(tokenBuilder->addPrimaryServiceToken(serviceToken));
	EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, mismatchedUserIdTokenAddPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(p2pCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, userIdToken, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	EXPECT_FALSE(tokenBuilder->addPrimaryServiceToken(serviceToken));
	EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, noMasterTokenAddPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	EXPECT_FALSE(tokenBuilder->addPrimaryServiceToken(serviceToken));
	EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, noUserIdTokenAddPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	EXPECT_FALSE(tokenBuilder->addPrimaryServiceToken(serviceToken));
	EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, addPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());

	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	tokenBuilder->addPeerServiceToken(serviceToken);

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), serviceTokens.size());
	shared_ptr<ServiceToken> builderServiceToken = *serviceTokens.begin();
	EXPECT_EQ(serviceToken, builderServiceToken);
}

TEST_F(MessageServiceTokenBuilderTest, addNamedPeerServiceTokens)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());

    shared_ptr<ServiceToken> unboundServiceTokenA = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(unboundServiceTokenA));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> unboundServiceTokenB = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(unboundServiceTokenB));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> masterBoundServiceTokenA = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(masterBoundServiceTokenA));
    EXPECT_EQ(static_cast<size_t>(2), tokenBuilder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> masterBoundServiceTokenB = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(masterBoundServiceTokenB));
    EXPECT_EQ(static_cast<size_t>(2), tokenBuilder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> userBoundServiceTokenA = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(userBoundServiceTokenA));
    EXPECT_EQ(static_cast<size_t>(3), tokenBuilder->getPeerServiceTokens().size());

    shared_ptr<ServiceToken> userBoundServiceTokenB = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(userBoundServiceTokenB));
    EXPECT_EQ(static_cast<size_t>(3), tokenBuilder->getPeerServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, mismatchedMasterTokenAddPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	EXPECT_FALSE(tokenBuilder->addPeerServiceToken(serviceToken));
	EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, mismatchedUserIdTokenAddPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, userIdToken, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	EXPECT_FALSE(tokenBuilder->addPeerServiceToken(serviceToken));
	EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, noMasterTokenAddPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	EXPECT_FALSE(tokenBuilder->addPeerServiceToken(serviceToken));
	EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, noUserIdTokenAddPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	EXPECT_FALSE(tokenBuilder->addPeerServiceToken(serviceToken));
	EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());
}

TEST_F(MessageServiceTokenBuilderTest, trustedNetAddPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(trustedNetCtx, TOKEN_NAME, DATA, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
	try {
		tokenBuilder->addPeerServiceToken(serviceToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageServiceTokenBuilderTest, addUnboundPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());

	EXPECT_TRUE(tokenBuilder->addUnboundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), serviceTokens.size());
	shared_ptr<ServiceToken> serviceToken = *serviceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, serviceToken->getName());
	EXPECT_EQ(*DATA, *serviceToken->getData());
	EXPECT_EQ(ENCRYPT, serviceToken->isEncrypted());
	EXPECT_TRUE(serviceToken->isUnbound());

	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, msgBuilder->getServiceTokens()));
}

TEST_F(MessageServiceTokenBuilderTest, noCryptoContextAddUnboundPrimaryServiceToken)
{
	p2pMsgCtx->removeCryptoContext(TOKEN_NAME);
	p2pMsgCtx->removeCryptoContext(EMPTY_TOKEN_NAME);

	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addUnboundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, addMasterBoundPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());

	EXPECT_TRUE(tokenBuilder->addMasterBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), serviceTokens.size());
	shared_ptr<ServiceToken> serviceToken = *serviceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, serviceToken->getName());
	EXPECT_EQ(*DATA, *serviceToken->getData());
	EXPECT_EQ(ENCRYPT, serviceToken->isEncrypted());
	EXPECT_TRUE(serviceToken->isBoundTo(MASTER_TOKEN));

	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, msgBuilder->getServiceTokens()));
}

TEST_F(MessageServiceTokenBuilderTest, noMasterTokenAddMasterBoundPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addMasterBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, noCryptoContextAddMasterBoundPrimaryServiceToken)
{
	p2pMsgCtx->removeCryptoContext(TOKEN_NAME);
	p2pMsgCtx->removeCryptoContext(EMPTY_TOKEN_NAME);

	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addMasterBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, addUserBoundPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_TRUE(tokenBuilder->getPrimaryServiceTokens().empty());

	EXPECT_TRUE(tokenBuilder->addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), serviceTokens.size());
	shared_ptr<ServiceToken> serviceToken = *serviceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, serviceToken->getName());
	EXPECT_EQ(*DATA, *serviceToken->getData());
	EXPECT_EQ(ENCRYPT, serviceToken->isEncrypted());
	EXPECT_TRUE(serviceToken->isBoundTo(USER_ID_TOKEN));

	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, msgBuilder->getServiceTokens()));
}

TEST_F(MessageServiceTokenBuilderTest, noMasterTokenAddUserBoundPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, noUserIdTokenAddUserBoundPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, noCryptoContextAddUserBoundPrimaryServiceToken)
{
	p2pMsgCtx->removeCryptoContext(TOKEN_NAME);
	p2pMsgCtx->removeCryptoContext(EMPTY_TOKEN_NAME);

	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, excludeUnboundPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
	msgBuilder->addServiceToken(serviceToken);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
	EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

	EXPECT_FALSE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, true, false));
	EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, true, true));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, false, false));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePrimaryServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, excludeMasterBoundPrimaryServiceToken)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, NULL_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
    msgBuilder->addServiceToken(serviceToken);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, false, false));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, true, true));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, true, false));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePrimaryServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());


}

TEST_F(MessageServiceTokenBuilderTest, excludeUserBoundPrimaryServiceToken)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
    msgBuilder->addServiceToken(serviceToken);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, false, false));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, true, false));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, true, true));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePrimaryServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, excludeUnknownPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

    EXPECT_FALSE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, false, false));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, true, false));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePrimaryServiceToken(TOKEN_NAME, true, true));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, deleteUnboundPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
	msgBuilder->addServiceToken(serviceToken);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());

	EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, false));
    EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, true));
    EXPECT_TRUE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, false, false));
	set<shared_ptr<ServiceToken>> builderServiceTokens = tokenBuilder->getPrimaryServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), builderServiceTokens.size());
	shared_ptr<ServiceToken> builderServiceToken = *builderServiceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, builderServiceToken->getName());
	EXPECT_EQ(static_cast<size_t>(0), builderServiceToken->getData()->size());
	EXPECT_FALSE(builderServiceToken->isEncrypted());
	EXPECT_FALSE(builderServiceToken->isMasterTokenBound());
	EXPECT_FALSE(builderServiceToken->isUserIdTokenBound());

	set<shared_ptr<ServiceToken>> msgServiceTokens = msgBuilder->getServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), msgServiceTokens.size());
	shared_ptr<ServiceToken> msgServiceToken = *msgServiceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, msgServiceToken->getName());
	EXPECT_EQ(static_cast<size_t>(0), msgServiceToken->getData()->size());
	EXPECT_FALSE(msgServiceToken->isEncrypted());
	EXPECT_FALSE(msgServiceToken->isMasterTokenBound());
	EXPECT_FALSE(msgServiceToken->isUserIdTokenBound());

    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(serviceToken));
    EXPECT_TRUE(tokenBuilder->deletePrimaryServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, deleteMasterBoundPrimaryServiceToken)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, NULL_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
    msgBuilder->addServiceToken(serviceToken);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, false, false));
    EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, true));
    EXPECT_TRUE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, false));
    set<shared_ptr<ServiceToken>> builderServiceTokens = tokenBuilder->getPrimaryServiceTokens();
    EXPECT_EQ(static_cast<size_t>(1), builderServiceTokens.size());
    shared_ptr<ServiceToken> builderServiceToken = *builderServiceTokens.begin();
    EXPECT_EQ(TOKEN_NAME, builderServiceToken->getName());
    EXPECT_EQ(static_cast<size_t>(0), builderServiceToken->getData()->size());
    EXPECT_FALSE(builderServiceToken->isEncrypted());
    EXPECT_TRUE(builderServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_FALSE(builderServiceToken->isUserIdTokenBound());

    set<shared_ptr<ServiceToken>> msgServiceTokens = msgBuilder->getServiceTokens();
    EXPECT_EQ(static_cast<size_t>(1), msgServiceTokens.size());
    shared_ptr<ServiceToken> msgServiceToken = *msgServiceTokens.begin();
    EXPECT_EQ(TOKEN_NAME, msgServiceToken->getName());
    EXPECT_EQ(static_cast<size_t>(0), msgServiceToken->getData()->size());
    EXPECT_FALSE(msgServiceToken->isEncrypted());
    EXPECT_TRUE(msgServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_FALSE(msgServiceToken->isUserIdTokenBound());

    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(serviceToken));
    EXPECT_TRUE(tokenBuilder->deletePrimaryServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, deleteUserBoundPrimaryServiceToken)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
    msgBuilder->addServiceToken(serviceToken);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, false, false));
    EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, false));
    EXPECT_TRUE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, true));
    set<shared_ptr<ServiceToken>> builderServiceTokens = tokenBuilder->getPrimaryServiceTokens();
    EXPECT_EQ(static_cast<size_t>(1), builderServiceTokens.size());
    shared_ptr<ServiceToken> builderServiceToken = *builderServiceTokens.begin();
    EXPECT_EQ(TOKEN_NAME, builderServiceToken->getName());
    EXPECT_EQ(static_cast<size_t>(0), builderServiceToken->getData()->size());
    EXPECT_FALSE(builderServiceToken->isEncrypted());
    EXPECT_TRUE(builderServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_TRUE(builderServiceToken->isBoundTo(USER_ID_TOKEN));

    set<shared_ptr<ServiceToken>> msgServiceTokens = msgBuilder->getServiceTokens();
    EXPECT_EQ(static_cast<size_t>(1), msgServiceTokens.size());
    shared_ptr<ServiceToken> msgServiceToken = *msgServiceTokens.begin();
    EXPECT_EQ(TOKEN_NAME, msgServiceToken->getName());
    EXPECT_EQ(static_cast<size_t>(0), msgServiceToken->getData()->size());
    EXPECT_FALSE(msgServiceToken->isEncrypted());
    EXPECT_TRUE(msgServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_TRUE(msgServiceToken->isBoundTo(USER_ID_TOKEN));

    EXPECT_TRUE(tokenBuilder->addPrimaryServiceToken(serviceToken));
    EXPECT_TRUE(tokenBuilder->deletePrimaryServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPrimaryServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, deleteUnknownPrimaryServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, false, false));
	EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, false));
	EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, true));
}

TEST_F(MessageServiceTokenBuilderTest, addUnboundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());

	EXPECT_TRUE(tokenBuilder->addUnboundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), serviceTokens.size());
	shared_ptr<ServiceToken> serviceToken = *serviceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, serviceToken->getName());
	EXPECT_EQ(*DATA, *serviceToken->getData());
	EXPECT_EQ(ENCRYPT, serviceToken->isEncrypted());
	EXPECT_TRUE(serviceToken->isUnbound());

	EXPECT_EQ(serviceTokens, msgBuilder->getPeerServiceTokens());
}

TEST_F(MessageServiceTokenBuilderTest, trustedNetAddUnboundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(trustedNetCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(trustedNetCtx, trustedNetMsgCtx, msgBuilder);

	try {
		tokenBuilder->addUnboundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslInternalException& e) {
	}
}

TEST_F(MessageServiceTokenBuilderTest, noCryptoContextAddUnboundPeerServiceToken)
{
	p2pMsgCtx->removeCryptoContext(TOKEN_NAME);
	p2pMsgCtx->removeCryptoContext(EMPTY_TOKEN_NAME);

	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addUnboundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, addMasterBoundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());

	EXPECT_TRUE(tokenBuilder->addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), serviceTokens.size());
	shared_ptr<ServiceToken> serviceToken = *serviceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, serviceToken->getName());
	EXPECT_EQ(*DATA, *serviceToken->getData());
	EXPECT_EQ(ENCRYPT, serviceToken->isEncrypted());
	EXPECT_TRUE(serviceToken->isBoundTo(PEER_MASTER_TOKEN));

	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, msgBuilder->getPeerServiceTokens()));
}

TEST_F(MessageServiceTokenBuilderTest, noMasterTokenAddMasterBoundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, noCryptoContextAddMasterBoundPeerServiceToken)
{
	p2pMsgCtx->removeCryptoContext(TOKEN_NAME);
	p2pMsgCtx->removeCryptoContext(EMPTY_TOKEN_NAME);

	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, trustedNetAddMasterBoundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(trustedNetCtx, trustedNetMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
}

TEST_F(MessageServiceTokenBuilderTest, addUserBoundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_TRUE(tokenBuilder->getPeerServiceTokens().empty());

	EXPECT_TRUE(tokenBuilder->addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), serviceTokens.size());
	shared_ptr<ServiceToken> serviceToken = *serviceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, serviceToken->getName());
	EXPECT_EQ(*DATA, *serviceToken->getData());
	EXPECT_EQ(ENCRYPT, serviceToken->isEncrypted());
	EXPECT_TRUE(serviceToken->isBoundTo(USER_ID_TOKEN));

	EXPECT_TRUE(MslTestUtils::equal(serviceTokens, msgBuilder->getPeerServiceTokens()));
}

TEST_F(MessageServiceTokenBuilderTest, noMasterTokenAddUserBoundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, noUserIdTokenAddUserBoundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, NULL_USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, noCryptoContextAddUserBoundPeerServiceToken)
{
	p2pMsgCtx->removeCryptoContext(TOKEN_NAME);
	p2pMsgCtx->removeCryptoContext(EMPTY_TOKEN_NAME);

	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));

	set<shared_ptr<ServiceToken>> serviceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(0), serviceTokens.size());
	EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, trustedNetAddUserBoundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(trustedNetCtx, trustedNetMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
}

TEST_F(MessageServiceTokenBuilderTest, excludeUnboundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
	msgBuilder->addPeerServiceToken(serviceToken);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
	EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

	EXPECT_FALSE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, true, false));
	EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, true, true));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, false, false));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getPeerServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePeerServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getPeerServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, excludeMasterBoundPeerServiceToken)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
    msgBuilder->addPeerServiceToken(serviceToken);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, false, false));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, true, true));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, true, false));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getPeerServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePeerServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getPeerServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, excludeUserBoundPeerServiceToken)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
    msgBuilder->addPeerServiceToken(serviceToken);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, false, false));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, true, false));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, true, true));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getPeerServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());

    EXPECT_TRUE(tokenBuilder->excludePeerServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getPeerServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, excludeUnknownPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, false, false));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getPeerServiceTokens().size());

	EXPECT_FALSE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, true, false));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getPeerServiceTokens().size());

	EXPECT_FALSE(tokenBuilder->excludePeerServiceToken(TOKEN_NAME, true, true));
    EXPECT_EQ(static_cast<size_t>(0), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(0), msgBuilder->getPeerServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, deleteUnboundPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
	msgBuilder->addPeerServiceToken(serviceToken);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
	EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());

	EXPECT_FALSE(tokenBuilder->deletePeerServiceToken(TOKEN_NAME, true, false));
	EXPECT_FALSE(tokenBuilder->deletePeerServiceToken(TOKEN_NAME, true, true));
	EXPECT_TRUE(tokenBuilder->deletePeerServiceToken(TOKEN_NAME, false, false));
	set<shared_ptr<ServiceToken>> builderServiceTokens = tokenBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), builderServiceTokens.size());
	shared_ptr<ServiceToken> builderServiceToken = *builderServiceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, builderServiceToken->getName());
	EXPECT_EQ(static_cast<size_t>(0), builderServiceToken->getData()->size());
	EXPECT_FALSE(builderServiceToken->isEncrypted());
	EXPECT_FALSE(builderServiceToken->isMasterTokenBound());
	EXPECT_FALSE(builderServiceToken->isUserIdTokenBound());

	set<shared_ptr<ServiceToken>> msgServiceTokens = msgBuilder->getPeerServiceTokens();
	EXPECT_EQ(static_cast<size_t>(1), msgServiceTokens.size());
	shared_ptr<ServiceToken> msgServiceToken = *msgServiceTokens.begin();
	EXPECT_EQ(TOKEN_NAME, msgServiceToken->getName());
	EXPECT_EQ(static_cast<size_t>(0), msgServiceToken->getData()->size());
	EXPECT_FALSE(msgServiceToken->isEncrypted());
	EXPECT_FALSE(msgServiceToken->isMasterTokenBound());
	EXPECT_FALSE(msgServiceToken->isUserIdTokenBound());

	EXPECT_TRUE(tokenBuilder->addPeerServiceToken(serviceToken));
	EXPECT_TRUE(tokenBuilder->deletePeerServiceToken(serviceToken));
	EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
	EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, deleteMasterBoundPeerServiceToken)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, NULL_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
    msgBuilder->addPeerServiceToken(serviceToken);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->deletePeerServiceToken(TOKEN_NAME, false, false));
    EXPECT_FALSE(tokenBuilder->deletePeerServiceToken(TOKEN_NAME, true, true));
    EXPECT_TRUE(tokenBuilder->deletePeerServiceToken(TOKEN_NAME, true, false));
    set<shared_ptr<ServiceToken>> builderServiceTokens = tokenBuilder->getPeerServiceTokens();
    EXPECT_EQ(static_cast<size_t>(1), builderServiceTokens.size());
    shared_ptr<ServiceToken> builderServiceToken = *builderServiceTokens.begin();
    EXPECT_EQ(TOKEN_NAME, builderServiceToken->getName());
    EXPECT_EQ(static_cast<size_t>(0), builderServiceToken->getData()->size());
    EXPECT_FALSE(builderServiceToken->isEncrypted());
    EXPECT_TRUE(builderServiceToken->isBoundTo(PEER_MASTER_TOKEN));
    EXPECT_FALSE(builderServiceToken->isUserIdTokenBound());

    set<shared_ptr<ServiceToken>> msgServiceTokens = msgBuilder->getPeerServiceTokens();
    EXPECT_EQ(static_cast<size_t>(1), msgServiceTokens.size());
    shared_ptr<ServiceToken> msgServiceToken = *msgServiceTokens.begin();
    EXPECT_EQ(TOKEN_NAME, msgServiceToken->getName());
    EXPECT_EQ(static_cast<size_t>(0), msgServiceToken->getData()->size());
    EXPECT_FALSE(msgServiceToken->isEncrypted());
    EXPECT_TRUE(msgServiceToken->isBoundTo(PEER_MASTER_TOKEN));
    EXPECT_FALSE(msgServiceToken->isUserIdTokenBound());

    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(serviceToken));
    EXPECT_TRUE(tokenBuilder->deletePeerServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, deleteUserBoundPeerServiceToken)
{
    shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, make_shared<NullCryptoContext>());
    msgBuilder->addPeerServiceToken(serviceToken);
    shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());

    EXPECT_FALSE(tokenBuilder->deletePeerServiceToken(TOKEN_NAME, false, false));
    EXPECT_FALSE(tokenBuilder->deletePeerServiceToken(TOKEN_NAME, true, false));
    EXPECT_TRUE(tokenBuilder->deletePeerServiceToken(TOKEN_NAME, true, true));
    set<shared_ptr<ServiceToken>> builderServiceTokens = tokenBuilder->getPeerServiceTokens();
    EXPECT_EQ(static_cast<size_t>(1), builderServiceTokens.size());
    shared_ptr<ServiceToken> builderServiceToken = *builderServiceTokens.begin();
    EXPECT_EQ(TOKEN_NAME, builderServiceToken->getName());
    EXPECT_EQ(static_cast<size_t>(0), builderServiceToken->getData()->size());
    EXPECT_FALSE(builderServiceToken->isEncrypted());
    EXPECT_TRUE(builderServiceToken->isBoundTo(PEER_MASTER_TOKEN));
    EXPECT_TRUE(builderServiceToken->isBoundTo(PEER_USER_ID_TOKEN));

    set<shared_ptr<ServiceToken>> msgServiceTokens = msgBuilder->getPeerServiceTokens();
    EXPECT_EQ(static_cast<size_t>(1), msgServiceTokens.size());
    shared_ptr<ServiceToken> msgServiceToken = *msgServiceTokens.begin();
    EXPECT_EQ(TOKEN_NAME, msgServiceToken->getName());
    EXPECT_EQ(static_cast<size_t>(0), msgServiceToken->getData()->size());
    EXPECT_FALSE(msgServiceToken->isEncrypted());
    EXPECT_TRUE(msgServiceToken->isBoundTo(PEER_MASTER_TOKEN));
    EXPECT_TRUE(msgServiceToken->isBoundTo(PEER_USER_ID_TOKEN));

    EXPECT_TRUE(tokenBuilder->addPeerServiceToken(serviceToken));
    EXPECT_TRUE(tokenBuilder->deletePeerServiceToken(serviceToken));
    EXPECT_EQ(static_cast<size_t>(1), tokenBuilder->getPeerServiceTokens().size());
    EXPECT_EQ(static_cast<size_t>(1), msgBuilder->getPeerServiceTokens().size());
}

TEST_F(MessageServiceTokenBuilderTest, deleteUnknownPeerServiceToken)
{
	shared_ptr<MessageBuilder> msgBuilder = messageFactory->createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
	msgBuilder->setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
	shared_ptr<MessageServiceTokenBuilder> tokenBuilder = make_shared<MessageServiceTokenBuilder>(p2pCtx, p2pMsgCtx, msgBuilder);

	EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, false, false));
	EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, false));
	EXPECT_FALSE(tokenBuilder->deletePrimaryServiceToken(TOKEN_NAME, true, true));
}

}}} // namespace netflix::msl::msg
