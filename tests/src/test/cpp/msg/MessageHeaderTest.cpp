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

#include <crypto/ICryptoContext.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/Key.h>
#include <crypto/NullCryptoContext.h>
#include <crypto/SessionCryptoContext.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <msg/MessageHeader.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <Date.h>
#include <entityauth/PresharedAuthenticationData.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderUtils.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <msg/MessageCapabilities.h>
#include <Macros.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <MslMasterTokenException.h>
#include <MslMessageException.h>
#include <MslUserAuthException.h>
#include <stdint.h>
#include <StaticAssert.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <tokens/ServiceToken.h>
#include <tokens/MslUser.h>
#include <unistd.h>
#include <userauth/EmailPasswordAuthenticationData.h>
#include <userauth/UserAuthenticationData.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../entityauth/MockPresharedAuthenticationFactory.h"
#include "../userauth/MockEmailPasswordAuthenticationFactory.h"
#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::keyx;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;
using namespace netflix::msl::userauth;

namespace testing {

MATCHER_P(DeRefEqual, x, "")
{
    return *arg == *x;
}

} // namespace testing

namespace netflix {
namespace msl {
namespace msg {

namespace {

/** Milliseconds per second. */
const int64_t MILLISECONDS_PER_SECOND = 1000;

/** Key entity authentication data. */
const string KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
/** Key master token. */
const string KEY_MASTER_TOKEN = "mastertoken";
/** Key header data. */
const string KEY_HEADERDATA = "headerdata";
/** Key error data signature. */
const string KEY_SIGNATURE = "signature";

// Message header data.
/** Key timestamp. */
const string KEY_TIMESTAMP = "timestamp";
/** Key message ID. */
const string KEY_MESSAGE_ID = "messageid";
/** Key non-replayable ID. */
const string KEY_NON_REPLAYABLE_ID = "nonreplayableid";
/** Key renewable flag. */
const string KEY_RENEWABLE = "renewable";
/** Key handshake flag */
const string KEY_HANDSHAKE = "handshake";
/** Key capabilities. */
const string KEY_CAPABILITIES = "capabilities";
/** Key key negotiation request. */
const string KEY_KEY_REQUEST_DATA = "keyrequestdata";
/** Key key negotiation response. */
const string KEY_KEY_RESPONSE_DATA = "keyresponsedata";
/** Key user authentication data. */
const string KEY_USER_AUTHENTICATION_DATA = "userauthdata";
/** Key user ID token. */
const string KEY_USER_ID_TOKEN = "useridtoken";
/** Key service tokens. */
const string KEY_SERVICE_TOKENS = "servicetokens";

// Message header peer data.
/** Key peer master token. */
const string KEY_PEER_MASTER_TOKEN = "peermastertoken";
/** Key peer user ID token. */
const string KEY_PEER_USER_ID_TOKEN = "peeruseridtoken";
/** Key peer service tokens. */
const string KEY_PEER_SERVICE_TOKENS = "peerservicetokens";

const int64_t MESSAGE_ID = 1;
const int64_t NON_REPLAYABLE_ID = 1L;   // java Long wants null allowed
const bool RENEWABLE = true;
const bool HANDSHAKE = false;

/**
 * Checks if the given timestamp is close to "now".
 *
 * @param timestamp the timestamp to compare.
 * @return true if the timestamp is about now.
 */
bool isAboutNow(shared_ptr<Date> timestamp)
{
    const int64_t now = Date::now()->getTime();
    const int64_t time = timestamp->getTime();
    return (now - 2000 <= time && time <= now + 2000);
}

/**
 * Checks if the given timestamp is close to "now".
 *
 * @param seconds the timestamp to compare in seconds since the epoch.
 * @return true if the timestamp is about now.
 */
bool isAboutNowSeconds(int64_t seconds)
{
    const int64_t now = Date::now()->getTime() / MILLISECONDS_PER_SECOND;
    const int64_t time = seconds;
    return (now - 1 <= time && time <= now + 1);
}

// Create a new MslArray out of a set of shared_ptr's, each of which point to an
// instance of type T. T must be derived from MslEncodable.
template <typename T>
shared_ptr<MslArray> createArray(shared_ptr<MslContext> ctx, const MslEncoderFormat& format, const set<shared_ptr<T>>& s)
{
    vector<Variant> result;
    for (typename set<shared_ptr<T>>::const_iterator it = s.begin(); it != s.end(); ++it)
    {
        shared_ptr<MslEncodable> mslEncodable = dynamic_pointer_cast<MslEncodable>(*it);
        assert(mslEncodable);
        Variant variant = VariantFactory::create(mslEncodable);
        result.push_back(variant);
    }
    return MslEncoderUtils::createArray(ctx, format, result);
}

// Compare two sets of shared_ptrs of type T. T must support equals(). Since
// the sets are effectively unsorted (they are sorted by pointer value), and the
// elements must be dereferenced before comparison. We are effectively forced
// to use O(n^2) search.
template <typename T>
bool sharedPtrSetEq(const set<shared_ptr<T>>& s1, const set<shared_ptr<T>>& s2)
{
    if (s1.size() != s2.size())
        return false;
    // std::sets do not have duplicates, so if we find that one set contains all
    // the elements of the other, the sets can be viewed as matching.
    size_t matchCount = 0;
    typename set<shared_ptr<T>>::const_iterator it, jt;
    for (it = s1.begin(); it != s1.end(); ++it) {
        for (jt = s2.begin(); jt != s2.end(); ++jt) {
            if ((*it)->equals(*jt)) ++matchCount;
        }
    }
    return matchCount == s1.size();
}

} // namespace anonymous

/**
 * Message header unit tests.
 */
class MessageHeaderTest : public ::testing::Test
{
public:
    MessageHeaderTest()
    : trustedNetCtx(getTrustedNetCtx())
    , p2pCtx(getP2pCtx())
    , encoder(trustedNetCtx->getMslEncoderFactory())
    {
        LANGUAGES.insert(LANGUAGES.begin(), string("en-US"));

        ALGOS.insert(MslConstants::CompressionAlgorithm::GZIP);
        ALGOS.insert(MslConstants::CompressionAlgorithm::LZW);
        FORMATS.insert(MslEncoderFormat::JSON);
        CAPABILITIES = make_shared<MessageCapabilities>(ALGOS, LANGUAGES, FORMATS);
        format = encoder->getPreferredFormat(CAPABILITIES->getEncoderFormats());

        MASTER_TOKEN = MslTestUtils::getMasterToken(trustedNetCtx, 1, 1);

        shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
        shared_ptr<KeyExchangeFactory> factory = trustedNetCtx->getKeyExchangeFactory(keyRequestData->getKeyExchangeScheme());
        shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(trustedNetCtx, format, keyRequestData, MASTER_TOKEN);
        KEY_REQUEST_DATA.insert(keyRequestData);
        KEY_RESPONSE_DATA = keyxData->keyResponseData;

        USER_AUTH_DATA = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD);
        USER_ID_TOKEN = MslTestUtils::getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());

        PEER_MASTER_TOKEN = MslTestUtils::getMasterToken(p2pCtx, 1, 2);
        PEER_USER_ID_TOKEN = MslTestUtils::getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());

        shared_ptr<KeyRequestData> peerKeyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
        shared_ptr<KeyExchangeFactory> peerFactory = p2pCtx->getKeyExchangeFactory(peerKeyRequestData->getKeyExchangeScheme());
        shared_ptr<KeyExchangeFactory::KeyExchangeData> peerKeyxData = peerFactory->generateResponse(p2pCtx, format, peerKeyRequestData, PEER_MASTER_TOKEN);
        PEER_KEY_REQUEST_DATA.insert(peerKeyRequestData);
        PEER_KEY_RESPONSE_DATA = peerKeyxData->keyResponseData;
    }
    ~MessageHeaderTest()
    {
        // Must clear out static members to release shared_ptr's
        format = MslEncoderFormat::INVALID;
        CAPABILITIES.reset();
        KEY_REQUEST_DATA.clear();
        KEY_RESPONSE_DATA.reset();
        USER_AUTH_DATA.reset();
        PEER_KEY_REQUEST_DATA.clear();
        PEER_KEY_RESPONSE_DATA.reset();
        SetUp();
    }

    // This probably is not required, since a new instance of MessageHeaderTest
    // is built before each test invocation.
    virtual void SetUp()
    {
        trustedNetCtx->getMslStore()->clearCryptoContexts();
        trustedNetCtx->getMslStore()->clearServiceTokens();
        p2pCtx->getMslStore()->clearCryptoContexts();
        p2pCtx->getMslStore()->clearServiceTokens();
    }

    /**
     * A helper class for building message header data.
     */
    class HeaderDataBuilder
    {
    public:
        /**
          * Create a new header data builder with the default constant values
          * and a random set of service tokens that may be bound to the provided
          * master token and user ID token.
          *
          * @param ctx MSL context.
          * @param masterToken message header master token. May be null.
          * @param userIdToken message header user ID token. May be null.
          * @param serviceTokens true to create service tokens. Otherwise the
          *        service token value will be set to null.
          * @throws MslEncodingException if there is an error encoding the JSON
          *         data.
          * @throws MslCryptoException if there is an error encrypting or signing
          *         the token data.
          * @throws MslException if there is an error compressing the data.
          */
        HeaderDataBuilder(shared_ptr<MockMslContext> ctx, shared_ptr<MasterToken> masterToken,
                shared_ptr<UserIdToken> userIdToken, bool createSrvcTokens)
        : messageId(MESSAGE_ID)
        , nonReplayableId(NON_REPLAYABLE_ID)
        , renewable(RENEWABLE)
        , handshake(HANDSHAKE)
        , capabilities(CAPABILITIES)
        , keyRequestData((!ctx->isPeerToPeer()) ? KEY_REQUEST_DATA : PEER_KEY_REQUEST_DATA)
        , keyResponseData((!ctx->isPeerToPeer()) ? KEY_RESPONSE_DATA : PEER_KEY_RESPONSE_DATA)
        , userAuthData(USER_AUTH_DATA)
        , userIdToken(userIdToken)
        {
            if (createSrvcTokens)
                serviceTokens = MslTestUtils::getServiceTokens(ctx, masterToken, userIdToken);
        }

        /**
        * Create a new header data builder with the default constant values
        * and the provided set of service tokens.
        *
        * @param ctx MSL context.
        * @param userIdToken message header user ID token. May be null.
        * @param serviceTokens message header service tokens. May be null.
        */
       HeaderDataBuilder(shared_ptr<MockMslContext> ctx, shared_ptr<UserIdToken> userIdToken,
               set<shared_ptr<ServiceToken>> serviceTokens)
       : messageId(MESSAGE_ID)
       , nonReplayableId(NON_REPLAYABLE_ID)
       , renewable(RENEWABLE)
       , handshake(HANDSHAKE)
       , capabilities(CAPABILITIES)
       , keyRequestData((!ctx->isPeerToPeer()) ? KEY_REQUEST_DATA : PEER_KEY_REQUEST_DATA)
       , keyResponseData((!ctx->isPeerToPeer()) ? KEY_RESPONSE_DATA : PEER_KEY_RESPONSE_DATA)
       , userAuthData(USER_AUTH_DATA)
       , userIdToken(userIdToken)
       , serviceTokens(serviceTokens)
       {
       }

       HeaderDataBuilder& setNull(const string& key)
       {
           if (key == KEY_CAPABILITIES) {
               capabilities.reset();
           } else if (key == KEY_KEY_REQUEST_DATA) {
               keyRequestData.clear();
           } else if (key == KEY_KEY_RESPONSE_DATA) {
               keyResponseData.reset();
           } else if (key == KEY_NON_REPLAYABLE_ID) {
               nonReplayableId = -1;
           } else if (key == KEY_USER_AUTHENTICATION_DATA) {
               userAuthData.reset();
           } else if (key == KEY_USER_ID_TOKEN) {
               userIdToken.reset();
           } else {
               // add other key handling as needed
               assert(false);
           }
           return *this;
       }

       /**
        * @return the current set of service tokens.
        */
       set<shared_ptr<ServiceToken>> getServiceTokens() { return serviceTokens; }

       /**
        * Set the value for the specified message data field.
        *
        * @param value message header field value.
        * @return the builder.
        */
       HeaderDataBuilder& setKEY_CAPABILITIES(const shared_ptr<MessageCapabilities> & value) { capabilities = value; return *this; }
       HeaderDataBuilder& setKEY_HANDSHAKE(const bool & value) { handshake = value; return *this; }
       HeaderDataBuilder& setKEY_KEY_REQUEST_DATA(const set<shared_ptr<KeyRequestData>> & value) { keyRequestData = value; return *this; }
       HeaderDataBuilder& setKEY_KEY_RESPONSE_DATA(const shared_ptr<KeyResponseData> & value) { keyResponseData = value; return *this; }
       HeaderDataBuilder& setKEY_MESSAGE_ID(const int64_t & value) { messageId = value; return *this; }
       HeaderDataBuilder& setKEY_NON_REPLAYABLE_ID(const int64_t & value) { nonReplayableId = value; return *this; }
       HeaderDataBuilder& setKEY_RENEWABLE(const bool & value) { renewable = value; return *this; }
       HeaderDataBuilder& setKEY_SERVICE_TOKENS(const set<shared_ptr<ServiceToken>> & value) { serviceTokens = value; return *this; }
       HeaderDataBuilder& setKEY_USER_AUTHENTICATION_DATA(const shared_ptr<UserAuthenticationData> & value) { userAuthData = value; return *this; }
       HeaderDataBuilder& setKEY_USER_ID_TOKEN(const shared_ptr<UserIdToken> & value) { userIdToken = value; return *this; }

       /**
        * Builds a new header data container with the currently set values.
        *
        * @return the header data.
        */
       shared_ptr<MessageHeader::HeaderData> build()
       {
           return make_shared<MessageHeader::HeaderData>(messageId,
                   nonReplayableId, renewable, handshake, capabilities, keyRequestData,
                   keyResponseData, userAuthData, userIdToken, serviceTokens);
       }

    private:
        /** Header data values. */
        int64_t messageId;
        int64_t nonReplayableId;
        bool renewable;
        bool handshake;
        shared_ptr<MessageCapabilities> capabilities;
        set<shared_ptr<KeyRequestData>> keyRequestData;
        shared_ptr<KeyResponseData> keyResponseData;
        shared_ptr<UserAuthenticationData> userAuthData;
        shared_ptr<UserIdToken> userIdToken;
        set<shared_ptr<ServiceToken>> serviceTokens;
    };

protected:
    /** MSL trusted network context. */
    shared_ptr<MockMslContext> trustedNetCtx;
    /** MSL peer-to-peer context. */
    shared_ptr<MockMslContext> p2pCtx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    /** MSL encoder format. */
    MslEncoderFormat format;

    set<MslConstants::CompressionAlgorithm> ALGOS;
    vector<string> LANGUAGES;
    set<MslEncoderFormat> FORMATS;

    shared_ptr<MasterToken> MASTER_TOKEN;
    shared_ptr<UserIdToken> USER_ID_TOKEN;
    shared_ptr<MasterToken> PEER_MASTER_TOKEN;
    shared_ptr<UserIdToken> PEER_USER_ID_TOKEN;
    map<string, shared_ptr<ICryptoContext>> CRYPTO_CONTEXTS;

    static shared_ptr<MessageCapabilities> CAPABILITIES;
    static set<shared_ptr<KeyRequestData>> KEY_REQUEST_DATA;
    static shared_ptr<KeyResponseData> KEY_RESPONSE_DATA;
    static shared_ptr<UserAuthenticationData> USER_AUTH_DATA;
    static set<shared_ptr<KeyRequestData>> PEER_KEY_REQUEST_DATA;
    static shared_ptr<KeyResponseData> PEER_KEY_RESPONSE_DATA;

private:
    // Factory methods for MockMslConext singletons; only need one each for all
    // tests, and it is expensive
    shared_ptr<MockMslContext> getTrustedNetCtx()
    {
        static shared_ptr<MockMslContext> theInstance;
        if (!theInstance)
            theInstance = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
        return theInstance;
    }
    shared_ptr<MockMslContext> getP2pCtx()
    {
        static shared_ptr<MockMslContext> theInstance;
        if (!theInstance)
            theInstance = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, true);
        return theInstance;
    }
};

// static member defs
shared_ptr<MessageCapabilities> MessageHeaderTest::CAPABILITIES;
set<shared_ptr<KeyRequestData>> MessageHeaderTest::KEY_REQUEST_DATA;
shared_ptr<KeyResponseData> MessageHeaderTest::KEY_RESPONSE_DATA;
shared_ptr<UserAuthenticationData> MessageHeaderTest::USER_AUTH_DATA;
set<shared_ptr<KeyRequestData>> MessageHeaderTest::PEER_KEY_REQUEST_DATA;
shared_ptr<KeyResponseData> MessageHeaderTest::PEER_KEY_RESPONSE_DATA;

TEST_F(MessageHeaderTest, entityAuthDataCtors)
{
    // Service tokens may be created with the key response data tokens. The
    // key response data master token has the same serial number as the
    // original master token so we can use the same user ID token.
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    MessageHeader messageHeader(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    EXPECT_TRUE(messageHeader.isEncrypting());
    EXPECT_EQ(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader.isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader.isHandshake());
    EXPECT_EQ(*CAPABILITIES, *messageHeader.getMessageCapabilities());
    EXPECT_TRUE(messageHeader.getCryptoContext());
    EXPECT_EQ(*entityAuthData, *messageHeader.getEntityAuthenticationData());
    EXPECT_EQ(KEY_REQUEST_DATA, messageHeader.getKeyRequestData());
    EXPECT_EQ(*KEY_RESPONSE_DATA, *messageHeader.getKeyResponseData());
    EXPECT_FALSE(messageHeader.getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader.getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader.getMessageId());
    EXPECT_FALSE(messageHeader.getPeerMasterToken());
    EXPECT_TRUE(messageHeader.getPeerServiceTokens().empty());
    EXPECT_FALSE(messageHeader.getPeerUserIdToken());
    EXPECT_EQ(messageHeader.getServiceTokens(), builder.getServiceTokens());
    EXPECT_EQ(*USER_AUTH_DATA, *messageHeader.getUserAuthenticationData());
    EXPECT_EQ(*USER_ID_TOKEN, *messageHeader.getUserIdToken());
    EXPECT_EQ(*USER_ID_TOKEN->getUser(), *messageHeader.getUser());
}

TEST_F(MessageHeaderTest, entityAuthDataReplayable)
{
    // Service tokens may be created with the key response data tokens. The
    // key response data master token has the same serial number as the
    // original master token so we can use the same user ID token.
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_NON_REPLAYABLE_ID);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    MessageHeader messageHeader(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    EXPECT_TRUE(messageHeader.isEncrypting());
    EXPECT_EQ(-1L, messageHeader.getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader.isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader.isHandshake());
    EXPECT_EQ(*CAPABILITIES, *messageHeader.getMessageCapabilities());
    EXPECT_TRUE(messageHeader.getCryptoContext());
    EXPECT_EQ(entityAuthData, messageHeader.getEntityAuthenticationData());
    EXPECT_EQ(KEY_REQUEST_DATA, messageHeader.getKeyRequestData());
    EXPECT_EQ(*KEY_RESPONSE_DATA, *messageHeader.getKeyResponseData());
    EXPECT_FALSE(messageHeader.getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader.getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader.getMessageId());
    EXPECT_FALSE(messageHeader.getPeerMasterToken());
    EXPECT_TRUE(messageHeader.getPeerServiceTokens().empty());
    EXPECT_FALSE(messageHeader.getPeerUserIdToken());
    EXPECT_EQ(messageHeader.getServiceTokens(), builder.getServiceTokens());
    EXPECT_EQ(*USER_AUTH_DATA, *messageHeader.getUserAuthenticationData());
    EXPECT_EQ(*USER_ID_TOKEN, *messageHeader.getUserIdToken());
    EXPECT_EQ(*USER_ID_TOKEN->getUser(), *messageHeader.getUser());
}

TEST_F(MessageHeaderTest, entityAuthDataMslObject)
{
    // Service tokens may be created with the key response data tokens. The
    // key response data master token has the same serial number as the
    // original master token so we can use the same user ID token.
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    const EntityAuthenticationScheme scheme = entityAuthData->getScheme();
    shared_ptr<EntityAuthenticationFactory> factory = trustedNetCtx->getEntityAuthenticationFactory(scheme);
    shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(trustedNetCtx, entityAuthData);

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<MslObject> entityAuthDataMo = mo->getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, entityAuthData), entityAuthDataMo);
    EXPECT_FALSE(mo->has(KEY_MASTER_TOKEN));
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_EQ(NON_REPLAYABLE_ID, headerdata->getLong(KEY_NON_REPLAYABLE_ID));
    EXPECT_EQ(RENEWABLE, headerdata->getBoolean(KEY_RENEWABLE));
    EXPECT_EQ(HANDSHAKE, headerdata->getBoolean(KEY_HANDSHAKE));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, CAPABILITIES), headerdata->getMslObject(KEY_CAPABILITIES, encoder));
    EXPECT_EQ(createArray(trustedNetCtx, format, KEY_REQUEST_DATA), headerdata->getMslArray(KEY_KEY_REQUEST_DATA));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, KEY_RESPONSE_DATA), headerdata->getMslObject(KEY_KEY_RESPONSE_DATA, encoder));
    EXPECT_TRUE(isAboutNowSeconds(headerdata->getLong(KEY_TIMESTAMP)));
    EXPECT_EQ(MESSAGE_ID, headerdata->getLong(KEY_MESSAGE_ID));
    EXPECT_FALSE(headerdata->has(KEY_PEER_MASTER_TOKEN));
    EXPECT_FALSE(headerdata->has(KEY_PEER_SERVICE_TOKENS));
    EXPECT_FALSE(headerdata->has(KEY_PEER_USER_ID_TOKEN));
    EXPECT_EQ(createArray(trustedNetCtx, format, builder.getServiceTokens()), headerdata->getMslArray(KEY_SERVICE_TOKENS));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_AUTH_DATA), headerdata->getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_ID_TOKEN), headerdata->getMslObject(KEY_USER_ID_TOKEN, encoder));
}

TEST_F(MessageHeaderTest, entityAuthDataReplayableMslObject)
{
    // Service tokens may be created with the key response data tokens. The
    // key response data master token has the same serial number as the
    // original master token so we can use the same user ID token.
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_NON_REPLAYABLE_ID);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    const EntityAuthenticationScheme scheme = entityAuthData->getScheme();
    shared_ptr<EntityAuthenticationFactory> factory = trustedNetCtx->getEntityAuthenticationFactory(scheme);
    shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(trustedNetCtx, entityAuthData);

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<MslObject> entityAuthDataMo = mo->getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, entityAuthData), entityAuthDataMo);
    EXPECT_FALSE(mo->has(KEY_MASTER_TOKEN));
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_FALSE(headerdata->has(KEY_NON_REPLAYABLE_ID));
    EXPECT_EQ(RENEWABLE, headerdata->getBoolean(KEY_RENEWABLE));
    EXPECT_EQ(HANDSHAKE, headerdata->getBoolean(KEY_HANDSHAKE));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, CAPABILITIES), headerdata->getMslObject(KEY_CAPABILITIES, encoder));
    EXPECT_EQ(createArray(trustedNetCtx, format, KEY_REQUEST_DATA), headerdata->getMslArray(KEY_KEY_REQUEST_DATA));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, KEY_RESPONSE_DATA), headerdata->getMslObject(KEY_KEY_RESPONSE_DATA, encoder));
    EXPECT_TRUE(isAboutNowSeconds(headerdata->getLong(KEY_TIMESTAMP)));
    EXPECT_EQ(MESSAGE_ID, headerdata->getLong(KEY_MESSAGE_ID));
    EXPECT_FALSE(headerdata->has(KEY_PEER_MASTER_TOKEN));
    EXPECT_FALSE(headerdata->has(KEY_PEER_SERVICE_TOKENS));
    EXPECT_FALSE(headerdata->has(KEY_PEER_USER_ID_TOKEN));
    EXPECT_EQ(createArray(trustedNetCtx, format, builder.getServiceTokens()), headerdata->getMslArray(KEY_SERVICE_TOKENS));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_AUTH_DATA), headerdata->getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_ID_TOKEN), headerdata->getMslObject(KEY_USER_ID_TOKEN, encoder));
}

TEST_F(MessageHeaderTest, entityAuthDataPeerCtors)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    // Peer service tokens may be created with the key response data master
    // token. The peer key response data master token has the same serial
    // number as the original peer master token so we can use the same peer
    // user ID token.
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    EXPECT_TRUE(messageHeader->isEncrypting());
    EXPECT_EQ(NON_REPLAYABLE_ID, messageHeader->getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader->isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader->isHandshake());
    EXPECT_EQ(*CAPABILITIES, *messageHeader->getMessageCapabilities());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(entityAuthData, messageHeader->getEntityAuthenticationData());
    EXPECT_EQ(PEER_KEY_REQUEST_DATA, messageHeader->getKeyRequestData());
    EXPECT_EQ(PEER_KEY_RESPONSE_DATA, messageHeader->getKeyResponseData());
    EXPECT_FALSE(messageHeader->getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader->getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader->getMessageId());
    EXPECT_EQ(PEER_MASTER_TOKEN, messageHeader->getPeerMasterToken());
    EXPECT_EQ(messageHeader->getPeerServiceTokens(), peerServiceTokens);
    EXPECT_EQ(PEER_USER_ID_TOKEN, messageHeader->getPeerUserIdToken());
    EXPECT_EQ(messageHeader->getServiceTokens(), builder.getServiceTokens());
    EXPECT_EQ(*USER_AUTH_DATA, *messageHeader->getUserAuthenticationData());
    EXPECT_FALSE(messageHeader->getUserIdToken());
    EXPECT_FALSE(messageHeader->getUser());
}

TEST_F(MessageHeaderTest, entityAuthDataReplayablePeerCtors)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), true);
    builder.setNull(KEY_NON_REPLAYABLE_ID);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    // Peer service tokens may be created with the key response data master
    // token. The peer key response data master token has the same serial
    // number as the original peer master token so we can use the same peer
    // user ID token.
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    EXPECT_TRUE(messageHeader->isEncrypting());
    EXPECT_EQ(messageHeader->getNonReplayableId(), -1L);
    EXPECT_EQ(RENEWABLE, messageHeader->isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader->isHandshake());
    EXPECT_EQ(*CAPABILITIES, *messageHeader->getMessageCapabilities());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(entityAuthData, messageHeader->getEntityAuthenticationData());
    EXPECT_EQ(messageHeader->getKeyRequestData(), PEER_KEY_REQUEST_DATA);
    EXPECT_EQ(PEER_KEY_RESPONSE_DATA, messageHeader->getKeyResponseData());
    EXPECT_FALSE(messageHeader->getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader->getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader->getMessageId());
    EXPECT_EQ(PEER_MASTER_TOKEN, messageHeader->getPeerMasterToken());
    EXPECT_EQ(messageHeader->getPeerServiceTokens(), peerServiceTokens);
    EXPECT_EQ(PEER_USER_ID_TOKEN, messageHeader->getPeerUserIdToken());
    EXPECT_EQ(messageHeader->getServiceTokens(), builder.getServiceTokens());
    EXPECT_EQ(*USER_AUTH_DATA, *messageHeader->getUserAuthenticationData());
    EXPECT_FALSE(messageHeader->getUserIdToken());
    EXPECT_FALSE(messageHeader->getUser());
}

TEST_F(MessageHeaderTest, entityAuthDataPeerMslObject)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    // Peer service tokens may be created with the key response data master
    // token. The peer key response data master token has the same serial
    // number as the original peer master token so we can use the same peer
    // user ID token.
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    const EntityAuthenticationScheme scheme = entityAuthData->getScheme();
    shared_ptr<EntityAuthenticationFactory> factory = p2pCtx->getEntityAuthenticationFactory(scheme);
    shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(p2pCtx, entityAuthData);

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<MslObject> entityAuthDataMo = mo->getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, entityAuthData), entityAuthDataMo);
    EXPECT_FALSE(mo->has(KEY_MASTER_TOKEN));
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_EQ(NON_REPLAYABLE_ID, headerdata->getLong(KEY_NON_REPLAYABLE_ID));
    EXPECT_EQ(RENEWABLE, headerdata->getBoolean(KEY_RENEWABLE));
    EXPECT_EQ(HANDSHAKE, headerdata->getBoolean(KEY_HANDSHAKE));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, CAPABILITIES), headerdata->getMslObject(KEY_CAPABILITIES, encoder));
    EXPECT_EQ(createArray(p2pCtx, format, PEER_KEY_REQUEST_DATA), headerdata->getMslArray(KEY_KEY_REQUEST_DATA));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, PEER_KEY_RESPONSE_DATA), headerdata->getMslObject(KEY_KEY_RESPONSE_DATA, encoder));
    EXPECT_TRUE(isAboutNowSeconds(headerdata->getLong(KEY_TIMESTAMP)));
    EXPECT_EQ(MESSAGE_ID, headerdata->getLong(KEY_MESSAGE_ID));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, PEER_MASTER_TOKEN), headerdata->getMslObject(KEY_PEER_MASTER_TOKEN, encoder));
    EXPECT_EQ(createArray(p2pCtx, format, peerServiceTokens), headerdata->getMslArray(KEY_PEER_SERVICE_TOKENS));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, PEER_USER_ID_TOKEN), headerdata->getMslObject(KEY_PEER_USER_ID_TOKEN, encoder));
    EXPECT_EQ(createArray(p2pCtx, format, builder.getServiceTokens()), headerdata->getMslArray(KEY_SERVICE_TOKENS));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_AUTH_DATA), headerdata->getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder));
    EXPECT_FALSE(headerdata->has(KEY_USER_ID_TOKEN));
}

TEST_F(MessageHeaderTest, entityAuthDataReplayablePeerMslObject)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), true);
    builder.setNull(KEY_NON_REPLAYABLE_ID);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    // Peer service tokens may be created with the key response data master
    // token. The peer key response data master token has the same serial
    // number as the original peer master token so we can use the same peer
    // user ID token.
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    const EntityAuthenticationScheme scheme = entityAuthData->getScheme();
    shared_ptr<EntityAuthenticationFactory> factory = p2pCtx->getEntityAuthenticationFactory(scheme);
    shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(p2pCtx, entityAuthData);

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<MslObject> entityAuthDataMo = mo->getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, entityAuthData), entityAuthDataMo);
    EXPECT_FALSE(mo->has(KEY_MASTER_TOKEN));
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_FALSE(headerdata->has(KEY_NON_REPLAYABLE_ID));
    EXPECT_EQ(RENEWABLE, headerdata->getBoolean(KEY_RENEWABLE));
    EXPECT_EQ(HANDSHAKE, headerdata->getBoolean(KEY_HANDSHAKE));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, CAPABILITIES), headerdata->getMslObject(KEY_CAPABILITIES, encoder));
    EXPECT_EQ(createArray(p2pCtx, format, PEER_KEY_REQUEST_DATA), headerdata->getMslArray(KEY_KEY_REQUEST_DATA));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, PEER_KEY_RESPONSE_DATA), headerdata->getMslObject(KEY_KEY_RESPONSE_DATA, encoder));
    EXPECT_TRUE(isAboutNowSeconds(headerdata->getLong(KEY_TIMESTAMP)));
    EXPECT_EQ(MESSAGE_ID, headerdata->getLong(KEY_MESSAGE_ID));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, PEER_MASTER_TOKEN), headerdata->getMslObject(KEY_PEER_MASTER_TOKEN, encoder));
    EXPECT_EQ(createArray(p2pCtx, format, peerServiceTokens), headerdata->getMslArray(KEY_PEER_SERVICE_TOKENS));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, PEER_USER_ID_TOKEN), headerdata->getMslObject(KEY_PEER_USER_ID_TOKEN, encoder));
    EXPECT_EQ(createArray(p2pCtx, format, builder.getServiceTokens()), headerdata->getMslArray(KEY_SERVICE_TOKENS));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_AUTH_DATA), headerdata->getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder));
    EXPECT_FALSE(headerdata->has(KEY_USER_ID_TOKEN));
}

TEST_F(MessageHeaderTest, masterTokenCtors)
{
    // Service tokens may be created with the key response data tokens. The
    // key response data master token has the same serial number as the
    // original master token so we can use the same user ID token.
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);

    EXPECT_TRUE(messageHeader->isEncrypting());
    EXPECT_EQ(NON_REPLAYABLE_ID, messageHeader->getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader->isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader->isHandshake());
    EXPECT_EQ(*CAPABILITIES, *messageHeader->getMessageCapabilities());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_FALSE(messageHeader->getEntityAuthenticationData());
    EXPECT_EQ(KEY_REQUEST_DATA, messageHeader->getKeyRequestData());
    EXPECT_EQ(*KEY_RESPONSE_DATA, *messageHeader->getKeyResponseData());
    EXPECT_EQ(MASTER_TOKEN, messageHeader->getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader->getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader->getMessageId());
    EXPECT_FALSE(messageHeader->getPeerMasterToken());
    EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getPeerUserIdToken());
    EXPECT_EQ(messageHeader->getServiceTokens(), builder.getServiceTokens());
    EXPECT_EQ(*USER_AUTH_DATA, *messageHeader->getUserAuthenticationData());
    EXPECT_EQ(*USER_ID_TOKEN, *messageHeader->getUserIdToken());
    EXPECT_EQ(*USER_ID_TOKEN->getUser(), *messageHeader->getUser());
}

TEST_F(MessageHeaderTest, masterTokenMslObject)
{
    // Service tokens may be created with the key response data tokens. The
    // key response data master token has the same serial number as the
    // original master token so we can use the same user ID token.
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);

    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(trustedNetCtx, MASTER_TOKEN);

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, messageHeader);
    EXPECT_FALSE(mo->has(KEY_ENTITY_AUTHENTICATION_DATA));
    shared_ptr<MslObject> masterToken = mo->getMslObject(KEY_MASTER_TOKEN, encoder);
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, MASTER_TOKEN), masterToken);
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_EQ(NON_REPLAYABLE_ID, headerdata->getLong(KEY_NON_REPLAYABLE_ID));
    EXPECT_EQ(RENEWABLE, headerdata->getBoolean(KEY_RENEWABLE));
    EXPECT_EQ(HANDSHAKE, headerdata->getBoolean(KEY_HANDSHAKE));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, CAPABILITIES), headerdata->getMslObject(KEY_CAPABILITIES, encoder));
    EXPECT_EQ(createArray(trustedNetCtx, format, KEY_REQUEST_DATA), headerdata->getMslArray(KEY_KEY_REQUEST_DATA));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, KEY_RESPONSE_DATA), headerdata->getMslObject(KEY_KEY_RESPONSE_DATA, encoder));
    EXPECT_TRUE(isAboutNowSeconds(headerdata->getLong(KEY_TIMESTAMP)));
    EXPECT_EQ(MESSAGE_ID, headerdata->getLong(KEY_MESSAGE_ID));
    EXPECT_FALSE(headerdata->has(KEY_PEER_MASTER_TOKEN));
    EXPECT_FALSE(headerdata->has(KEY_PEER_SERVICE_TOKENS));
    EXPECT_FALSE(headerdata->has(KEY_PEER_USER_ID_TOKEN));
    EXPECT_EQ(createArray(trustedNetCtx, format, builder.getServiceTokens()), headerdata->getMslArray(KEY_SERVICE_TOKENS));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_AUTH_DATA), headerdata->getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_ID_TOKEN), headerdata->getMslObject(KEY_USER_ID_TOKEN, encoder));
}

TEST_F(MessageHeaderTest, masterTokenPeerCtors)
{
    // The key response data master token has the same serial number as
    // the original master token so we can use the same service tokens and
    // user ID token.
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    // Peer service tokens may be created with the key response data master
    // token. The peer key response data master token has the same serial
    // number as the original peer master token so we can use the same peer
    // user ID token.
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);

    EXPECT_TRUE(messageHeader->isEncrypting());
    EXPECT_EQ(NON_REPLAYABLE_ID, messageHeader->getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader->isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader->isHandshake());
    EXPECT_EQ(*CAPABILITIES, *messageHeader->getMessageCapabilities());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_FALSE(messageHeader->getEntityAuthenticationData());
    EXPECT_EQ(messageHeader->getKeyRequestData(), PEER_KEY_REQUEST_DATA);
    EXPECT_EQ(PEER_KEY_RESPONSE_DATA, messageHeader->getKeyResponseData());
    EXPECT_EQ(MASTER_TOKEN, messageHeader->getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader->getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader->getMessageId());
    EXPECT_EQ(PEER_MASTER_TOKEN, messageHeader->getPeerMasterToken());
    EXPECT_EQ(messageHeader->getPeerServiceTokens(), peerServiceTokens);
    EXPECT_EQ(PEER_USER_ID_TOKEN, messageHeader->getPeerUserIdToken());
    EXPECT_EQ(messageHeader->getServiceTokens(), builder.getServiceTokens());
    EXPECT_EQ(*USER_AUTH_DATA, *messageHeader->getUserAuthenticationData());
    EXPECT_EQ(*USER_ID_TOKEN, *messageHeader->getUserIdToken());
    EXPECT_EQ(*USER_ID_TOKEN->getUser(), *messageHeader->getUser());
}

TEST_F(MessageHeaderTest, masterTokenPeerMslObject)
{
    // The key response data master token has the same serial number as
    // the original master token so we can use the same service tokens and
    // user ID token.
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    // Peer service tokens may be created with the key response data master
    // token. The peer key response data master token has the same serial
    // number as the original peer master token so we can use the same peer
    // user ID token.
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);

    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(trustedNetCtx, MASTER_TOKEN);

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, messageHeader);
    EXPECT_FALSE(mo->has(KEY_ENTITY_AUTHENTICATION_DATA));
    shared_ptr<MslObject> masterToken = mo->getMslObject(KEY_MASTER_TOKEN, encoder);
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, MASTER_TOKEN), masterToken);
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_EQ(NON_REPLAYABLE_ID, headerdata->getLong(KEY_NON_REPLAYABLE_ID));
    EXPECT_EQ(RENEWABLE, headerdata->getBoolean(KEY_RENEWABLE));
    EXPECT_EQ(HANDSHAKE, headerdata->getBoolean(KEY_HANDSHAKE));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, CAPABILITIES), headerdata->getMslObject(KEY_CAPABILITIES, encoder));
    EXPECT_EQ(createArray(p2pCtx, format, PEER_KEY_REQUEST_DATA), headerdata->getMslArray(KEY_KEY_REQUEST_DATA));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, PEER_KEY_RESPONSE_DATA), headerdata->getMslObject(KEY_KEY_RESPONSE_DATA, encoder));
    EXPECT_TRUE(isAboutNowSeconds(headerdata->getLong(KEY_TIMESTAMP)));
    EXPECT_EQ(MESSAGE_ID, headerdata->getLong(KEY_MESSAGE_ID));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, PEER_MASTER_TOKEN), headerdata->getMslObject(KEY_PEER_MASTER_TOKEN, encoder));
    EXPECT_EQ(createArray(p2pCtx, format, peerServiceTokens), headerdata->getMslArray(KEY_PEER_SERVICE_TOKENS));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, PEER_USER_ID_TOKEN), headerdata->getMslObject(KEY_PEER_USER_ID_TOKEN, encoder));
    EXPECT_EQ(createArray(p2pCtx, format, builder.getServiceTokens()), headerdata->getMslArray(KEY_SERVICE_TOKENS));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_AUTH_DATA), headerdata->getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder));
    EXPECT_EQ(MslTestUtils::toMslObject(encoder, USER_ID_TOKEN), headerdata->getMslObject(KEY_USER_ID_TOKEN, encoder));
}

TEST_F(MessageHeaderTest, nullArgumentsEntityAuthCtor)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_CAPABILITIES);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    EXPECT_TRUE(messageHeader->isEncrypting());
    EXPECT_EQ(NON_REPLAYABLE_ID, messageHeader->getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader->isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader->isHandshake());
    EXPECT_FALSE(messageHeader->getMessageCapabilities());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(entityAuthData, messageHeader->getEntityAuthenticationData());
    EXPECT_TRUE(messageHeader->getKeyRequestData().empty());
    EXPECT_FALSE(messageHeader->getKeyResponseData());
    EXPECT_FALSE(messageHeader->getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader->getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader->getMessageId());
    EXPECT_FALSE(messageHeader->getPeerMasterToken());
    EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getPeerUserIdToken());
    EXPECT_TRUE(messageHeader->getServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getUserAuthenticationData());
    EXPECT_FALSE(messageHeader->getUserIdToken());
    EXPECT_FALSE(messageHeader->getUser());
}

TEST_F(MessageHeaderTest, emptyArgumentsEntityAuthCtor)
{
    set<shared_ptr<KeyRequestData>> keyRequestData;
    set<shared_ptr<ServiceToken>> serviceTokens;
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_CAPABILITIES);
    builder.setKEY_KEY_REQUEST_DATA(keyRequestData);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    builder.setKEY_SERVICE_TOKENS(serviceTokens);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens;
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    EXPECT_TRUE(messageHeader->isEncrypting());
    EXPECT_EQ(NON_REPLAYABLE_ID, messageHeader->getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader->isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader->isHandshake());
    EXPECT_FALSE(messageHeader->getMessageCapabilities());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(entityAuthData, messageHeader->getEntityAuthenticationData());
    EXPECT_TRUE(messageHeader->getKeyRequestData().empty());
    EXPECT_FALSE(messageHeader->getKeyResponseData());
    EXPECT_FALSE(messageHeader->getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader->getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader->getMessageId());
    EXPECT_FALSE(messageHeader->getPeerMasterToken());
    EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getPeerUserIdToken());
    EXPECT_TRUE(messageHeader->getServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getUserAuthenticationData());
    EXPECT_FALSE(messageHeader->getUserIdToken());
    EXPECT_FALSE(messageHeader->getUser());
}

TEST_F(MessageHeaderTest, nullArgumentsMasterTokenCtor)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_CAPABILITIES);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);

    EXPECT_TRUE(messageHeader->isEncrypting());
    EXPECT_EQ(NON_REPLAYABLE_ID, messageHeader->getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader->isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader->isHandshake());
    EXPECT_FALSE(messageHeader->getMessageCapabilities());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_FALSE(messageHeader->getEntityAuthenticationData());
    EXPECT_TRUE(messageHeader->getKeyRequestData().empty());
    EXPECT_FALSE(messageHeader->getKeyResponseData());
    EXPECT_EQ(MASTER_TOKEN, messageHeader->getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader->getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader->getMessageId());
    EXPECT_FALSE(messageHeader->getPeerMasterToken());
    EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getPeerUserIdToken());
    EXPECT_TRUE(messageHeader->getServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getUserAuthenticationData());
    EXPECT_FALSE(messageHeader->getUserIdToken());
    EXPECT_FALSE(messageHeader->getUser());
}

TEST_F(MessageHeaderTest, emptyArgumentsMasterTokenCtor)
{
    set<shared_ptr<KeyRequestData>> keyRequestData;
    set<shared_ptr<ServiceToken>> serviceTokens;
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_CAPABILITIES);
    builder.setKEY_KEY_REQUEST_DATA(keyRequestData);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    builder.setKEY_SERVICE_TOKENS(serviceTokens);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens;
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);

    EXPECT_TRUE(messageHeader->isEncrypting());
    EXPECT_EQ(NON_REPLAYABLE_ID, messageHeader->getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader->isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader->isHandshake());
    EXPECT_FALSE(messageHeader->getMessageCapabilities());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_FALSE(messageHeader->getEntityAuthenticationData());
    EXPECT_TRUE(messageHeader->getKeyRequestData().empty());
    EXPECT_FALSE(messageHeader->getKeyResponseData());
    EXPECT_EQ(MASTER_TOKEN, messageHeader->getMasterToken());
    EXPECT_TRUE(isAboutNow(messageHeader->getTimestamp()));
    EXPECT_EQ(MESSAGE_ID, messageHeader->getMessageId());
    EXPECT_FALSE(messageHeader->getPeerMasterToken());
    EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getPeerUserIdToken());
    EXPECT_TRUE(messageHeader->getServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getUserAuthenticationData());
    EXPECT_FALSE(messageHeader->getUserIdToken());
    EXPECT_FALSE(messageHeader->getUser());
}

// FIXME: X509 is not supported yet
#if 0
TEST_F(MessageHeaderTest, x509isEncrypting)
{
    shared_ptr<MslContext> x509Ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::X509, false);

    HeaderDataBuilder builder(x509Ctx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = x509Ctx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(x509Ctx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    EXPECT_FALSE(messageHeader->isEncrypting());
}
#endif

TEST_F(MessageHeaderTest, missingBothAuthDataCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    EXPECT_THROW(MessageHeader(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, userIdTokenNullMasterTokenCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    EXPECT_THROW(MessageHeader(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, userIdTokenMismatchedMasterTokenCtor)
{
//(expected = MslInternalException.class)
    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(trustedNetCtx, PEER_MASTER_TOKEN, 1ll, MockEmailPasswordAuthenticationFactory::USER());
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, userIdToken, false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    EXPECT_THROW(MessageHeader(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, serviceTokenNullMasterTokenCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    EXPECT_THROW(MessageHeader(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, serviceTokenMismatchedMasterTokenCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(trustedNetCtx, PEER_MASTER_TOKEN, shared_ptr<UserIdToken>(), true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setKEY_USER_ID_TOKEN(USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    EXPECT_THROW(MessageHeader(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, serviceTokenNullUserIdTokenCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    EXPECT_THROW(MessageHeader(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, serviceTokenMismatchedUserIdTokenCtor)
{
//(expected = MslInternalException.class)
    // Technically the implementation does not hit this check because it
    // will bail out earlier, but in case the implementation changes the
    // order of checks (which it should not) this test will catch it.
    //
    // We cannot construct inconsistent service tokens via the ServiceToken
    // ctor, so pass in a mismatched user ID token.
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setKEY_USER_ID_TOKEN(PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    EXPECT_THROW(MessageHeader(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, peerUserIdTokenNullPeerMasterTokenCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    EXPECT_THROW(MessageHeader(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, peerUserIdTokenMismatchedPeerMasterTokenCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<UserIdToken> peerUserIdToken = MslTestUtils::getUserIdToken(p2pCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, peerUserIdToken, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    EXPECT_THROW(MessageHeader(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, peerServiceTokenNullMasterTokenCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, shared_ptr<UserIdToken>());
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    EXPECT_THROW(MessageHeader(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, peerServiceTokenMismatchedMasterTokenCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, shared_ptr<UserIdToken>());
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, shared_ptr<UserIdToken>(), peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    EXPECT_THROW(MessageHeader(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, peerServiceTokenNullUserIdTokenCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, shared_ptr<UserIdToken>(), peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    EXPECT_THROW(MessageHeader(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, peerServiceTokenMismatchedUserIdTokenCtor)
{
//(expected = MslInternalException.class)
    // Technically the implementation does not hit this check because it
    // will bail out earlier, but in case the implementation changes the
    // order of checks (which it should not) this test will catch it.
    //
    // We cannot construct inconsistent service tokens via the ServiceToken
    // ctor, so pass in a mismatched user ID token.
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    EXPECT_THROW(MessageHeader(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, untrustedMasterTokenCtor)
{
//    thrown.expect(MslMasterTokenException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<MasterToken> masterToken = MslTestUtils::getUntrustedMasterToken(p2pCtx);
    try {
        MessageHeader(p2pCtx, shared_ptr<EntityAuthenticationData>(), masterToken, headerData, peerData);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMasterTokenException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_UNTRUSTED, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, unsupportedEntityAuthSchemeCtor)
{
//    thrown.expect(MslEntityAuthException.class);
//    thrown.expectMslError(MslError.ENTITYAUTH_FACTORY_NOT_FOUND);
//    thrown.expectMessageId(MESSAGE_ID);

    shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
    shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    ctx->removeEntityAuthenticationFactory(entityAuthData->getScheme());
    HeaderDataBuilder builder(ctx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    try {
        MessageHeader(ctx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEntityAuthException& e) {
        EXPECT_EQ(MslError::ENTITYAUTH_FACTORY_NOT_FOUND, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, cachedCryptoContextMasterTokenCtor)
{
    // We should be okay with an untrusted master token if a crypto context
    // is associated with it.
    shared_ptr<MasterToken> masterToken = MslTestUtils::getUntrustedMasterToken(p2pCtx);
    shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
    p2pCtx->getMslStore()->setCryptoContext(masterToken, cryptoContext);

    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(p2pCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
    HeaderDataBuilder builder(p2pCtx, masterToken, shared_ptr<UserIdToken>(), true);
    builder.setKEY_USER_ID_TOKEN(userIdToken);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), masterToken, headerData, peerData);

    EXPECT_EQ(NON_REPLAYABLE_ID, messageHeader->getNonReplayableId());
    EXPECT_EQ(RENEWABLE, messageHeader->isRenewable());
    EXPECT_EQ(HANDSHAKE, messageHeader->isHandshake());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_FALSE(messageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    EXPECT_EQ(keyRequestData, PEER_KEY_REQUEST_DATA);
    EXPECT_EQ(PEER_KEY_RESPONSE_DATA, messageHeader->getKeyResponseData());
    EXPECT_EQ(masterToken, messageHeader->getMasterToken());
    EXPECT_EQ(MESSAGE_ID, messageHeader->getMessageId());
    EXPECT_EQ(PEER_MASTER_TOKEN, messageHeader->getPeerMasterToken());
    EXPECT_EQ(messageHeader->getPeerServiceTokens(), peerServiceTokens);
    EXPECT_EQ(PEER_USER_ID_TOKEN, messageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = builder.getServiceTokens();
    EXPECT_EQ(messageHeader->getServiceTokens(), serviceTokens);
    EXPECT_EQ(*USER_AUTH_DATA, *messageHeader->getUserAuthenticationData());
    EXPECT_EQ(userIdToken, messageHeader->getUserIdToken());
    EXPECT_EQ(userIdToken->getUser(), messageHeader->getUser());
}

TEST_F(MessageHeaderTest, entityAuthDataParseHeader)
{
    // Service tokens may be created with the key response data tokens. The
    // key response data master token has the same serial number as the
    // original master token so we can use the same user ID token.
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<Header> header = Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(*messageHeader->getEntityAuthenticationData(), *moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(*messageHeader->getKeyResponseData(), *moMessageHeader->getKeyResponseData());
    EXPECT_EQ(messageHeader->getMasterToken(), moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_FALSE(messageHeader->getPeerMasterToken());
    EXPECT_TRUE(messageHeader->getPeerServiceTokens().empty());
    EXPECT_FALSE(messageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(*messageHeader->getUserAuthenticationData(), *moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(*messageHeader->getUserIdToken(), *moMessageHeader->getUserIdToken());
    EXPECT_EQ(messageHeader->getUser(), moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, entityAuthDataPeerParseHeader)
{
    // Service tokens may be created with the key response data tokens. The
    // key response data master token has the same serial number as the
    // original master token so we can use the same user ID token.
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<Header> header = Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(*messageHeader->getEntityAuthenticationData(), *moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(*messageHeader->getKeyResponseData(), *moMessageHeader->getKeyResponseData());
    EXPECT_EQ(messageHeader->getMasterToken(), moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_EQ(*messageHeader->getPeerMasterToken(), *moMessageHeader->getPeerMasterToken());
    set<shared_ptr<ServiceToken>> moPeerServiceTokens = moMessageHeader->getPeerServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(peerServiceTokens, moPeerServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moPeerServiceTokens, peerServiceTokens));
    EXPECT_EQ(*messageHeader->getPeerUserIdToken(), *moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(*messageHeader->getUserAuthenticationData(), *moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(messageHeader->getUserIdToken(), moMessageHeader->getUserIdToken());
    EXPECT_TRUE(moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, masterTokenParseHeader)
{
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx,PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<Header> header = Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(messageHeader->getEntityAuthenticationData(), moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(*messageHeader->getKeyResponseData(), *moMessageHeader->getKeyResponseData());
    EXPECT_EQ(*messageHeader->getMasterToken(), *moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_FALSE(moMessageHeader->getPeerMasterToken());
    EXPECT_TRUE(moMessageHeader->getPeerServiceTokens().empty());
    EXPECT_FALSE(moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(*messageHeader->getUserAuthenticationData(), *moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(*messageHeader->getUserIdToken(), *moMessageHeader->getUserIdToken());
    EXPECT_EQ(messageHeader->getUser(), moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, masterTokenPeerParseHeader)
{
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<Header> header = Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(messageHeader->getEntityAuthenticationData(), moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(*messageHeader->getKeyResponseData(), *moMessageHeader->getKeyResponseData());
    EXPECT_EQ(*messageHeader->getMasterToken(), *moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_EQ(*messageHeader->getPeerMasterToken(), *moMessageHeader->getPeerMasterToken());
    set<shared_ptr<ServiceToken>> moPeerServiceTokens = moMessageHeader->getPeerServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(peerServiceTokens, moPeerServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moPeerServiceTokens, peerServiceTokens));
    EXPECT_EQ(*messageHeader->getPeerUserIdToken(), *moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(*messageHeader->getUserAuthenticationData(), *moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(*messageHeader->getUserIdToken(), *moMessageHeader->getUserIdToken());
    EXPECT_EQ(messageHeader->getUser(), moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, userAuthDataParseHeader)
{
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, shared_ptr<UserIdToken>(), true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(trustedNetCtx,PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<Header> header = Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(messageHeader->getEntityAuthenticationData(), moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(*messageHeader->getKeyResponseData(), *moMessageHeader->getKeyResponseData());
    EXPECT_EQ(*messageHeader->getMasterToken(), *moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_FALSE(moMessageHeader->getPeerMasterToken());
    EXPECT_TRUE(moMessageHeader->getPeerServiceTokens().empty());
    EXPECT_FALSE(moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(*messageHeader->getUserAuthenticationData(), *moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(messageHeader->getUserIdToken(), moMessageHeader->getUserIdToken());
    EXPECT_TRUE(moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, userAuthDataPeerParseHeader)
{
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, shared_ptr<UserIdToken>(), true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<Header> header = Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(messageHeader->getEntityAuthenticationData(), moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(*messageHeader->getKeyResponseData(), *moMessageHeader->getKeyResponseData());
    EXPECT_EQ(*messageHeader->getMasterToken(), *moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_EQ(*messageHeader->getPeerMasterToken(), *moMessageHeader->getPeerMasterToken());
    set<shared_ptr<ServiceToken>> moPeerServiceTokens = moMessageHeader->getPeerServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(peerServiceTokens, moPeerServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moPeerServiceTokens, peerServiceTokens));
    EXPECT_EQ(*messageHeader->getPeerUserIdToken(), *moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(*messageHeader->getUserAuthenticationData(), *moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(messageHeader->getUserIdToken(), moMessageHeader->getUserIdToken());
    EXPECT_TRUE(moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, untrustedMasterTokenParseHeader)
{
//    thrown.expect(MslMasterTokenException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);

    // We can first create a message header with an untrusted master token
    // by having a cached crypto context.
    shared_ptr<MasterToken> masterToken = MslTestUtils::getUntrustedMasterToken(p2pCtx);
    shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
    p2pCtx->getMslStore()->setCryptoContext(masterToken, cryptoContext);

    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(p2pCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
    HeaderDataBuilder builder(p2pCtx, masterToken, shared_ptr<UserIdToken>(), true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setKEY_USER_ID_TOKEN(userIdToken);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), masterToken, headerData, peerData);

    // Removing the cached crypto context means the master token must now
    // be trusted when parsing a message header.
    p2pCtx->getMslStore()->clearCryptoContexts();

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMasterTokenException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_UNTRUSTED, e.getError());
    }
}

TEST_F(MessageHeaderTest, unsupportedEntityAuthSchemeParseHeader)
{
//    thrown.expect(MslEntityAuthException.class);
//    thrown.expectMslError(MslError.ENTITYAUTH_FACTORY_NOT_FOUND);

    // We can first create a message header when the entity authentication
    // scheme is supported.
    shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
    HeaderDataBuilder builder(ctx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    // Removing support for the entity authentication scheme will now fail
    // parsing of message headers.
    ctx->removeEntityAuthenticationFactory(entityAuthData->getScheme());

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    try {
        Header::parseHeader(ctx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEntityAuthException& e) {
        EXPECT_EQ(MslError::ENTITYAUTH_FACTORY_NOT_FOUND, e.getError());
    }
}

TEST_F(MessageHeaderTest, unsupportedUserAuthSchemeParseHeader)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError.USERAUTH_FACTORY_NOT_FOUND);
//    thrown.expectMessageId(MESSAGE_ID);

    // We can first create a message header when the user authentication
    // scheme is supported.
    shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
    HeaderDataBuilder builder(ctx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(ctx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);

    // Remove support for the user authentication scheme will now fail
    // user authentication.
    ctx->removeUserAuthenticationFactory(USER_AUTH_DATA->getScheme());

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    try {
        Header::parseHeader(ctx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERAUTH_FACTORY_NOT_FOUND, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, cachedCryptoContextMasterTokenParseHeader)
{
    // We should be okay with an untrusted master token if a crypto context
    // is associated with it.
    shared_ptr<MasterToken> masterToken = MslTestUtils::getUntrustedMasterToken(p2pCtx);
    shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
    p2pCtx->getMslStore()->setCryptoContext(masterToken, cryptoContext);

    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(p2pCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
    HeaderDataBuilder builder(p2pCtx, masterToken, shared_ptr<UserIdToken>(), true);
    builder.setKEY_USER_ID_TOKEN(userIdToken);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), masterToken, headerData, peerData);

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<Header> header = Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(messageHeader->getEntityAuthenticationData(), moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(*messageHeader->getKeyResponseData(), *moMessageHeader->getKeyResponseData());
    // The reconstructed untrusted service token won't pass tests for
    // equality.
    EXPECT_TRUE(moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_EQ(*messageHeader->getPeerMasterToken(), *moMessageHeader->getPeerMasterToken());
    set<shared_ptr<ServiceToken>> moPeerServiceTokens = moMessageHeader->getPeerServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(peerServiceTokens, moPeerServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moPeerServiceTokens, peerServiceTokens));
    EXPECT_EQ(*messageHeader->getPeerUserIdToken(), *moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(*messageHeader->getUserAuthenticationData(), *moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(*messageHeader->getUserIdToken(), *moMessageHeader->getUserIdToken());
    EXPECT_EQ(messageHeader->getUser(), moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, invalidEntityAuthDataParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    HeaderDataBuilder builder(trustedNetCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(),false);
    builder.setKEY_USER_ID_TOKEN(USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    messageHeaderMo->put<string>(KEY_ENTITY_AUTHENTICATION_DATA, "x");

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MessageHeaderTest, missingBothAuthDataParseHeader)
{
//    thrown.expect(MslMessageException.class);
//    thrown.expectMslError(MslError.MESSAGE_ENTITY_NOT_FOUND);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    messageHeaderMo->remove(KEY_ENTITY_AUTHENTICATION_DATA);
    messageHeaderMo->remove(KEY_MASTER_TOKEN);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::MESSAGE_ENTITY_NOT_FOUND, e.getError());
    }
}

TEST_F(MessageHeaderTest, invalidMasterTokenParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    messageHeaderMo->put<string>(KEY_MASTER_TOKEN, "x");

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MessageHeaderTest, missingSignatureParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    messageHeaderMo->remove(KEY_SIGNATURE);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MessageHeaderTest, invalidSignatureParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    messageHeaderMo->put<string>(KEY_SIGNATURE, "x");

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MessageHeaderTest, incorrectSignatureParseHeader)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError.MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED);

    HeaderDataBuilder builder(trustedNetCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(),false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    messageHeaderMo->put(KEY_SIGNATURE, Base64::decode("AAA="));

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED, e.getError());
    }
}

TEST_F(MessageHeaderTest, missingHeaderdataParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    messageHeaderMo->remove(KEY_HEADERDATA);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MessageHeaderTest, invalidHeaderDataParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    messageHeaderMo->put<string>(KEY_HEADERDATA, "x");

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MessageHeaderTest, corruptHeaderDataParseHeader)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError.MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    ++(*ciphertext)[0];
    messageHeaderMo->put(KEY_HEADERDATA, ciphertext);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED, e.getError());
    }
}

TEST_F(MessageHeaderTest, missingPairsEntityAuthParseHeader)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<Header> header = Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(*messageHeader->getEntityAuthenticationData(), *moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(messageHeader->getKeyResponseData(), moMessageHeader->getKeyResponseData());
    EXPECT_EQ(messageHeader->getMasterToken(), moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_EQ(messageHeader->getPeerMasterToken(), moMessageHeader->getPeerMasterToken());
    set<shared_ptr<ServiceToken>> peerServiceTokens = messageHeader->getPeerServiceTokens();
    set<shared_ptr<ServiceToken>> moPeerServiceTokens = moMessageHeader->getPeerServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(peerServiceTokens, moPeerServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moPeerServiceTokens, peerServiceTokens));
    EXPECT_EQ(messageHeader->getPeerUserIdToken(), moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(messageHeader->getUserAuthenticationData(), moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(messageHeader->getUserIdToken(), moMessageHeader->getUserIdToken());
    EXPECT_EQ(messageHeader->getUser(), moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, emptyArraysEntityAuthParseHeader)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = p2pCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    const EntityAuthenticationScheme scheme = entityAuthData->getScheme();
    shared_ptr<EntityAuthenticationFactory> factory = p2pCtx->getEntityAuthenticationFactory(scheme);
    shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(p2pCtx, entityAuthData);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put(KEY_KEY_REQUEST_DATA, encoder->createArray());
    headerdataMo->put(KEY_SERVICE_TOKENS, encoder->createArray());
    headerdataMo->put(KEY_PEER_SERVICE_TOKENS, encoder->createArray());
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    shared_ptr<Header> header = Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(*messageHeader->getEntityAuthenticationData(), *moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(messageHeader->getKeyResponseData(), moMessageHeader->getKeyResponseData());
    EXPECT_EQ(messageHeader->getMasterToken(), moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_EQ(messageHeader->getPeerMasterToken(), moMessageHeader->getPeerMasterToken());
    set<shared_ptr<ServiceToken>> peerServiceTokens = messageHeader->getPeerServiceTokens();
    set<shared_ptr<ServiceToken>> moPeerServiceTokens = moMessageHeader->getPeerServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(peerServiceTokens, moPeerServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moPeerServiceTokens, peerServiceTokens));
    EXPECT_EQ(messageHeader->getPeerUserIdToken(), moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(messageHeader->getUserAuthenticationData(), moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(messageHeader->getUserIdToken(), moMessageHeader->getUserIdToken());
    EXPECT_EQ(messageHeader->getUser(), moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, missingPairsMasterTokenParseHeader)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);

    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);
    shared_ptr<Header> header = Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(messageHeader->getEntityAuthenticationData(), moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(messageHeader->getKeyResponseData(), moMessageHeader->getKeyResponseData());
    EXPECT_EQ(*messageHeader->getMasterToken(), *moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_EQ(messageHeader->getPeerMasterToken(), moMessageHeader->getPeerMasterToken());
    set<shared_ptr<ServiceToken>> peerServiceTokens = messageHeader->getPeerServiceTokens();
    set<shared_ptr<ServiceToken>> moPeerServiceTokens = moMessageHeader->getPeerServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(peerServiceTokens, moPeerServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moPeerServiceTokens, peerServiceTokens));
    EXPECT_EQ(messageHeader->getPeerUserIdToken(), moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(messageHeader->getUserAuthenticationData(), moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(messageHeader->getUserIdToken(), moMessageHeader->getUserIdToken());
    EXPECT_EQ(messageHeader->getUser(), moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, emptyArraysMasterTokenParseHeader)
{
    HeaderDataBuilder builder(p2pCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put(KEY_KEY_REQUEST_DATA, encoder->createArray());
    headerdataMo->put(KEY_SERVICE_TOKENS, encoder->createArray());
    headerdataMo->put(KEY_PEER_SERVICE_TOKENS, encoder->createArray());
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    shared_ptr<Header> header = Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);

    EXPECT_EQ(messageHeader->getNonReplayableId(), moMessageHeader->getNonReplayableId());
    EXPECT_EQ(messageHeader->isRenewable(), moMessageHeader->isRenewable());
    EXPECT_TRUE(messageHeader->getCryptoContext());
    EXPECT_EQ(messageHeader->getEntityAuthenticationData(), moMessageHeader->getEntityAuthenticationData());
    set<shared_ptr<KeyRequestData>> keyRequestData = messageHeader->getKeyRequestData();
    set<shared_ptr<KeyRequestData>> moKeyRequestData = moMessageHeader->getKeyRequestData();
    EXPECT_TRUE(sharedPtrSetEq(keyRequestData, moKeyRequestData));
    EXPECT_TRUE(sharedPtrSetEq(moKeyRequestData, keyRequestData));
    EXPECT_EQ(messageHeader->getKeyResponseData(), moMessageHeader->getKeyResponseData());
    EXPECT_EQ(*messageHeader->getMasterToken(), *moMessageHeader->getMasterToken());
    EXPECT_EQ(messageHeader->getMessageId(), moMessageHeader->getMessageId());
    EXPECT_EQ(messageHeader->getPeerMasterToken(), moMessageHeader->getPeerMasterToken());
    set<shared_ptr<ServiceToken>> peerServiceTokens = messageHeader->getPeerServiceTokens();
    set<shared_ptr<ServiceToken>> moPeerServiceTokens = moMessageHeader->getPeerServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(peerServiceTokens, moPeerServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moPeerServiceTokens, peerServiceTokens));
    EXPECT_EQ(messageHeader->getPeerUserIdToken(), moMessageHeader->getPeerUserIdToken());
    set<shared_ptr<ServiceToken>> serviceTokens = messageHeader->getServiceTokens();
    set<shared_ptr<ServiceToken>> moServiceTokens = moMessageHeader->getServiceTokens();
    EXPECT_TRUE(sharedPtrSetEq(serviceTokens, moServiceTokens));
    EXPECT_TRUE(sharedPtrSetEq(moServiceTokens, serviceTokens));
    EXPECT_EQ(messageHeader->getUserAuthenticationData(), moMessageHeader->getUserAuthenticationData());
    EXPECT_EQ(messageHeader->getUserIdToken(), moMessageHeader->getUserIdToken());
    EXPECT_EQ(messageHeader->getUser(), moMessageHeader->getUser());
}

TEST_F(MessageHeaderTest, userIdTokenNullMasterTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    // Since removing the master token will prevent the header data from
    // getting parsed, and removing the master token from the key exchange
    // data will also prevent the header data from getting parsed, the only
    // way to simulate this is to use entity authentication data and insert
    // a user ID token.
    HeaderDataBuilder builder(trustedNetCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    const EntityAuthenticationScheme scheme = entityAuthData->getScheme();
    shared_ptr<EntityAuthenticationFactory> factory = trustedNetCtx->getEntityAuthenticationFactory(scheme);
    shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(trustedNetCtx, entityAuthData);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    shared_ptr<MslEncodable> userIdToken = MslTestUtils::getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());
    headerdataMo->put(KEY_USER_ID_TOKEN, userIdToken);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, userIdTokenMismatchedMasterTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(trustedNetCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    shared_ptr<MslEncodable> userIdToken = MslTestUtils::getUserIdToken(trustedNetCtx, PEER_MASTER_TOKEN, 1ll, MockEmailPasswordAuthenticationFactory::USER());
    headerdataMo->put(KEY_USER_ID_TOKEN, userIdToken);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, userIdTokenMismatchedUserAuthDataParseHeader)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(trustedNetCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    shared_ptr<MslEncodable> userAuthData = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL_2, MockEmailPasswordAuthenticationFactory::PASSWORD_2);
    headerdataMo->put(KEY_USER_AUTHENTICATION_DATA, userAuthData);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_USERAUTH_DATA_MISMATCH, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, peerUserIdTokenMissingPeerMasterTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->remove(KEY_PEER_MASTER_TOKEN);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, peerUserIdTokenMismatchedPeerMasterTokenParseHeader)
{
//(expected = MslException.class)
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put(KEY_PEER_MASTER_TOKEN, dynamic_pointer_cast<MslEncodable>(MASTER_TOKEN));
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    EXPECT_THROW(Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS), MslException);
}

TEST_F(MessageHeaderTest, serviceTokenMismatchedMasterTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(trustedNetCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    set<shared_ptr<ServiceToken>> serviceTokens = builder.getServiceTokens();
    set<shared_ptr<ServiceToken>> st = MslTestUtils::getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, shared_ptr<UserIdToken>());
    serviceTokens.insert(st.begin(), st.end());
    headerdataMo->put(KEY_SERVICE_TOKENS, createArray(trustedNetCtx, format, serviceTokens));
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, serviceTokenMismatchedUserIdTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(trustedNetCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    set<shared_ptr<ServiceToken>> serviceTokens = builder.getServiceTokens();
    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(trustedNetCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory::USER());
    set<shared_ptr<ServiceToken>> st = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, userIdToken);
    serviceTokens.insert(st.begin(), st.end());
    headerdataMo->put(KEY_SERVICE_TOKENS, createArray(trustedNetCtx, format, serviceTokens));
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, peerServiceTokenMissingPeerMasterTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, shared_ptr<UserIdToken>());
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, shared_ptr<UserIdToken>(), peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->remove(KEY_PEER_MASTER_TOKEN);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, peerServiceTokenMismatchedPeerMasterTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, shared_ptr<UserIdToken>());
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, shared_ptr<UserIdToken>(), peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put(KEY_PEER_MASTER_TOKEN, dynamic_pointer_cast<MslEncodable>(MASTER_TOKEN));
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, peerServiceTokenMismatchedPeerUserIdTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    shared_ptr<MslEncodable> userIdToken = MslTestUtils::getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory::USER());
    headerdataMo->put(KEY_PEER_USER_ID_TOKEN, userIdToken);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, missingTimestamp)
{
    HeaderDataBuilder builder(trustedNetCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(),false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(trustedNetCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    EXPECT_FALSE(headerdataMo->remove(KEY_TIMESTAMP).isNull());
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    // FIXME: Is this test supposed to throw or something?
    EXPECT_NO_THROW(Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS));
}

TEST_F(MessageHeaderTest, invalidTimestamp)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    HeaderDataBuilder builder(trustedNetCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(),false);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(trustedNetCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_TIMESTAMP, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MessageHeaderTest, missingMessageIdParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    EXPECT_FALSE(headerdataMo->remove(KEY_MESSAGE_ID).isNull());
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MessageHeaderTest, invalidMessageIdParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_MESSAGE_ID, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MessageHeaderTest, negativeMessageIdCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setKEY_MESSAGE_ID(-1L);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    EXPECT_THROW(MessageHeader(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, tooLargeMessageIdCtor)
{
//(expected = MslInternalException.class)
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    builder.setKEY_MESSAGE_ID(MslConstants::MAX_LONG_VALUE + 1);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    EXPECT_THROW(MessageHeader(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, negativeMessageIdParseHeader)
{
//    thrown.expect(MslMessageException.class);
//    thrown.expectMslError(MslError.MESSAGE_ID_OUT_OF_RANGE);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put(KEY_MESSAGE_ID, -1);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::MESSAGE_ID_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(MessageHeaderTest, tooLargeMessageIdParseHeader)
{
//    thrown.expect(MslMessageException.class);
//    thrown.expectMslError(MslError.MESSAGE_ID_OUT_OF_RANGE);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put(KEY_MESSAGE_ID, MslConstants::MAX_LONG_VALUE + 1);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::MESSAGE_ID_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(MessageHeaderTest, invalidNonReplayableParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_NON_REPLAYABLE_ID, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, missingRenewableParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    EXPECT_FALSE(headerdataMo->remove(KEY_RENEWABLE).isNull());
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidRenewableParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_RENEWABLE, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, missingHandshakeParseHeader)
{
    // FIXME It is okay for the handshake flag to be missing for now.
//    //    thrown.expect(MslEncodingException.class);
//    //    thrown.expectMslError(MslError.MSL_PARSE_ERROR);
//    //    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    EXPECT_FALSE(headerdataMo->remove(KEY_HANDSHAKE).isNull());
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    // FIXME For now a missing handshake flag will result in a false value.
    shared_ptr<Header> header = Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(instanceof<MessageHeader>(header.get()));
    shared_ptr<MessageHeader> moMessageHeader = dynamic_pointer_cast<MessageHeader>(header);
    EXPECT_FALSE(moMessageHeader->isHandshake());
}

TEST_F(MessageHeaderTest, invalidHandshakeParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_HANDSHAKE, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidCapabilities)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_CAPABILITIES, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidKeyRequestDataArrayParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_KEY_REQUEST_DATA, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidKeyRequestDataParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    shared_ptr<MslArray> a = encoder->createArray();
    a->put<string>(-1, "x");
    headerdataMo->put(KEY_PEER_SERVICE_TOKENS, a);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidServiceTokensArrayParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_SERVICE_TOKENS, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidServiceTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    shared_ptr<MslArray> a = encoder->createArray();
    a->put<string>(-1, "x");
    headerdataMo->put(KEY_SERVICE_TOKENS, a);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidPeerServiceTokensArrayParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_PEER_SERVICE_TOKENS, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidPeerServiceTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    shared_ptr<MslArray> a = encoder->createArray();
    a->put<string>(-1, "x");
    headerdataMo->put(KEY_PEER_SERVICE_TOKENS, a);
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidPeerMasterTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_PEER_MASTER_TOKEN, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidPeerUserIdTokenParseHeader)
{
//    thrown.expect(MslException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_PEER_USER_ID_TOKEN, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, invalidUserAuthParseHeader)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, shared_ptr<UserIdToken>(), true);
    builder.setNull(KEY_KEY_REQUEST_DATA);
    builder.setNull(KEY_KEY_RESPONSE_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // Before modifying the header data we need to decrypt it.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(p2pCtx, MASTER_TOKEN);
    shared_ptr<ByteArray> ciphertext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);

    // After modifying the header data we need to encrypt it.
    headerdataMo->put<string>(KEY_USER_AUTHENTICATION_DATA, "x");
    shared_ptr<ByteArray> headerdata = cryptoContext->encrypt(encoder->encodeObject(headerdataMo, format), encoder, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(MessageHeaderTest, unencryptedUserAuthDataCtor)
{
    shared_ptr<MockMslContext> rsaCtx = make_shared<MockMslContext>(EntityAuthenticationScheme::RSA, false);

    HeaderDataBuilder builder(rsaCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = rsaCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    EXPECT_THROW(MessageHeader(rsaCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData), MslInternalException);
}

TEST_F(MessageHeaderTest, unencryptedUserAuthDataParseHeader)
{
//    thrown.expect(MslMessageException.class);
//    thrown.expectMessageId(MESSAGE_ID);

    shared_ptr<MockMslContext> rsaCtx = make_shared<MockMslContext>(EntityAuthenticationScheme::RSA, false);

    HeaderDataBuilder builder(rsaCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    builder.setNull(KEY_USER_AUTHENTICATION_DATA);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<EntityAuthenticationData> entityAuthData = rsaCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(rsaCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);
    shared_ptr<MslObject> messageHeaderMo = MslTestUtils::toMslObject(encoder, messageHeader);

    // The header data is not encrypted.
    shared_ptr<ByteArray> plaintext = messageHeaderMo->getBytes(KEY_HEADERDATA);
    shared_ptr<MslObject> headerdataMo = encoder->parseObject(plaintext);
    headerdataMo->put(KEY_USER_AUTHENTICATION_DATA, dynamic_pointer_cast<MslEncodable>(USER_AUTH_DATA));
    shared_ptr<ByteArray> headerdata = encoder->encodeObject(headerdataMo, format);
    messageHeaderMo->put(KEY_HEADERDATA, headerdata);

    // The header data must be signed or it will not be processed.
    shared_ptr<EntityAuthenticationFactory> factory = rsaCtx->getEntityAuthenticationFactory(entityAuthData->getScheme());
    shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(rsaCtx, entityAuthData);
    shared_ptr<ByteArray> signature = cryptoContext->sign(headerdata, encoder, format);
    messageHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(rsaCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::UNENCRYPTED_MESSAGE_WITH_USERAUTHDATA, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

#if 0 // FIXME: It's not clear these immutable* tests will ever work in C++
TEST_F(MessageHeaderTest, immutableKeyRequestData)
{
//(expected = UnsupportedOperationException.class)
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);

    EXPECT_THROW(messageHeader->getKeyRequestData()->clear(), UnsupportedOperationException);
}

TEST_F(MessageHeaderTest, immutableServiceTokens)
{
//(expected = UnsupportedOperationException.class)
    HeaderDataBuilder builder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<std::shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);

    EXPECT_THROW(messageHeader->getServiceTokens().clear(), UnsupportedOperationException);
}

TEST_F(MessageHeaderTest, immutablePeerServiceTokens)
{
//(expected = UnsupportedOperationException.class)
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokens = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
    shared_ptr<MessageHeader> messageHeader = make_shared<MessageHeader>(p2pCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);

    EXPECT_THROW(messageHeader->getPeerServiceTokens().clear(), UnsupportedOperationException);
}
#endif

TEST_F(MessageHeaderTest, equalsMasterToken)
{
    HeaderDataBuilder builder(trustedNetCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(),false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(trustedNetCtx, 1, 1);
    shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(trustedNetCtx, 1, 2);
    EXPECT_NE(*masterTokenA, *masterTokenB);
    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), masterTokenA, headerData, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), masterTokenB, headerData, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsEntityAuthData)
{
    HeaderDataBuilder builder(trustedNetCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(),false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<EntityAuthenticationData> entityAuthDataA = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    shared_ptr<EntityAuthenticationData> entityAuthDataB = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN2);
    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, entityAuthDataA, shared_ptr<MasterToken>(), headerData, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, entityAuthDataB, shared_ptr<MasterToken>(), headerData, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsMasterTokenEntityAuthData)
{
    HeaderDataBuilder builder(trustedNetCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<EntityAuthenticationData> entityAuthData = trustedNetCtx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, entityAuthData, shared_ptr<MasterToken>(), headerData, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsTimestamp)
{
    HeaderDataBuilder builder(trustedNetCtx, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(),false);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    sleep(1);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsMessageId)
{
    set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_MESSAGE_ID(1L).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_MESSAGE_ID(2L).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsNonReplayable)
{
    set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_NON_REPLAYABLE_ID(1L).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_NON_REPLAYABLE_ID(2L).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsRenewable)
{
    set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_RENEWABLE(true).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_RENEWABLE(false).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsHandshake)
{
    set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_HANDSHAKE(true).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_HANDSHAKE(false).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsCapabilities)
{
    shared_ptr<MessageCapabilities> capsA = make_shared<MessageCapabilities>(ALGOS, LANGUAGES, FORMATS);
    shared_ptr<MessageCapabilities> capsB = make_shared<MessageCapabilities>(set<MslConstants::CompressionAlgorithm>(), vector<string>(), set<MslEncoderFormat>());
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, set<shared_ptr<ServiceToken>>()).setKEY_CAPABILITIES(capsA).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, set<shared_ptr<ServiceToken>>()).setKEY_CAPABILITIES(capsB).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsKeyRequestData)
{
    set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    set<shared_ptr<KeyRequestData>> keyRequestDataA;
    keyRequestDataA.insert(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION));
    set<shared_ptr<KeyRequestData>> keyRequestDataB;
    keyRequestDataB.insert(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK));
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_KEY_REQUEST_DATA(keyRequestDataA).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_KEY_REQUEST_DATA(keyRequestDataB).build();
    shared_ptr<MessageHeader::HeaderData> headerDataC = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setNull(KEY_KEY_REQUEST_DATA).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderC = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataC, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderC));
    EXPECT_FALSE(messageHeaderC->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsKeyResponseData)
{
    set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<KeyRequestData> keyRequestData = *KEY_REQUEST_DATA.begin();
    shared_ptr<keyx::KeyExchangeFactory> factory = trustedNetCtx->getKeyExchangeFactory(keyRequestData->getKeyExchangeScheme());
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxDataA = factory->generateResponse(trustedNetCtx, format, keyRequestData, MASTER_TOKEN);
    shared_ptr<KeyResponseData> keyResponseDataA = keyxDataA->keyResponseData;
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxDataB = factory->generateResponse(trustedNetCtx, format, keyRequestData, MASTER_TOKEN);
    shared_ptr<KeyResponseData> keyResponseDataB = keyxDataB->keyResponseData;
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_KEY_RESPONSE_DATA(keyResponseDataA).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setKEY_KEY_RESPONSE_DATA(keyResponseDataB).build();
    shared_ptr<MessageHeader::HeaderData> headerDataC = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).setNull(KEY_KEY_RESPONSE_DATA).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderC = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataC, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderC));
    EXPECT_FALSE(messageHeaderC->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsUserAuthData)
{
    set<shared_ptr<ServiceToken>> serviceTokens = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, shared_ptr<UserIdToken>());
    shared_ptr<UserAuthenticationData> userAuthDataA = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL + "A", MockEmailPasswordAuthenticationFactory::PASSWORD);
    shared_ptr<UserAuthenticationData> userAuthDataB = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL + "B", MockEmailPasswordAuthenticationFactory::PASSWORD);
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, shared_ptr<UserIdToken>(), serviceTokens).setKEY_USER_AUTHENTICATION_DATA(userAuthDataA).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, shared_ptr<UserIdToken>(), serviceTokens).setKEY_USER_AUTHENTICATION_DATA(userAuthDataB).build();
    shared_ptr<MessageHeader::HeaderData> headerDataC = HeaderDataBuilder(trustedNetCtx, shared_ptr<UserIdToken>(), serviceTokens).setNull(KEY_USER_AUTHENTICATION_DATA).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderC = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataC, peerData);

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderC));
    EXPECT_FALSE(messageHeaderC->equals(messageHeaderA));

    // This test does not include a parsed header to avoid requiring user
    // authentication to succeed.
}

TEST_F(MessageHeaderTest, equalsUserIdToken)
{
    shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());
    shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(trustedNetCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory::USER());
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, userIdTokenA, set<shared_ptr<ServiceToken>>()).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, userIdTokenB, set<shared_ptr<ServiceToken>>()).build();
    shared_ptr<MessageHeader::HeaderData> headerDataC = HeaderDataBuilder(trustedNetCtx, shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>()).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderC = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataC, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderC));
    EXPECT_FALSE(messageHeaderC->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsServiceTokens)
{
    set<shared_ptr<ServiceToken>> serviceTokensA = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    set<shared_ptr<ServiceToken>> serviceTokensB = MslTestUtils::getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderData> headerDataA = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokensA).build();
    shared_ptr<MessageHeader::HeaderData> headerDataB = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokensB).build();
    shared_ptr<MessageHeader::HeaderData> headerDataC = HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, set<shared_ptr<ServiceToken>>()).build();
    shared_ptr<MessageHeader::HeaderPeerData> peerData = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataA, peerData);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataB, peerData);
    shared_ptr<MessageHeader> messageHeaderC = make_shared<MessageHeader>(trustedNetCtx, shared_ptr<EntityAuthenticationData>(), MASTER_TOKEN, headerDataC, peerData);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(trustedNetCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderC));
    EXPECT_FALSE(messageHeaderC->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsPeerMasterToken)
{
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<MasterToken> peerMasterTokenA = MslTestUtils::getMasterToken(p2pCtx, 1, 1);
    shared_ptr<MasterToken> peerMasterTokenB = MslTestUtils::getMasterToken(p2pCtx, 1, 2);
    shared_ptr<MessageHeader::HeaderPeerData> peerDataA = make_shared<MessageHeader::HeaderPeerData>(peerMasterTokenA, shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader::HeaderPeerData> peerDataB = make_shared<MessageHeader::HeaderPeerData>(peerMasterTokenB, shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader::HeaderPeerData> peerDataC = make_shared<MessageHeader::HeaderPeerData>(shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerDataA);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerDataB);
    shared_ptr<MessageHeader> messageHeaderC = make_shared<MessageHeader>(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerDataC);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(p2pCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderC));
    EXPECT_FALSE(messageHeaderC->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsPeerUserIdToken)
{
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    shared_ptr<UserIdToken> peerUserIdTokenA = MslTestUtils::getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory::USER());
    shared_ptr<UserIdToken> peerUserIdTokenB = MslTestUtils::getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory::USER());
    shared_ptr<MessageHeader::HeaderPeerData> peerDataA = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, peerUserIdTokenA, set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader::HeaderPeerData> peerDataB = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, peerUserIdTokenB, set<shared_ptr<ServiceToken>>());
    shared_ptr<MessageHeader::HeaderPeerData> peerDataC = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerDataA);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerDataB);
    shared_ptr<MessageHeader> messageHeaderC = make_shared<MessageHeader>(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerDataC);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(p2pCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderC));
    EXPECT_FALSE(messageHeaderC->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

TEST_F(MessageHeaderTest, equalsPeerServiceTokens)
{
    HeaderDataBuilder builder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
    shared_ptr<MessageHeader::HeaderData> headerData = builder.build();
    set<shared_ptr<ServiceToken>> peerServiceTokensA = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    set<shared_ptr<ServiceToken>> peerServiceTokensB = MslTestUtils::getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
    shared_ptr<MessageHeader::HeaderPeerData> peerDataA = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokensA);
    shared_ptr<MessageHeader::HeaderPeerData> peerDataB = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokensB);
    shared_ptr<MessageHeader::HeaderPeerData> peerDataC = make_shared<MessageHeader::HeaderPeerData>(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, set<shared_ptr<ServiceToken>>());

    shared_ptr<MessageHeader> messageHeaderA = make_shared<MessageHeader>(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerDataA);
    shared_ptr<MessageHeader> messageHeaderB = make_shared<MessageHeader>(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerDataB);
    shared_ptr<MessageHeader> messageHeaderC = make_shared<MessageHeader>(p2pCtx, shared_ptr<entityauth::EntityAuthenticationData>(), MASTER_TOKEN, headerData, peerDataC);
    shared_ptr<MessageHeader> messageHeaderA2 = dynamic_pointer_cast<MessageHeader>(Header::parseHeader(p2pCtx, MslTestUtils::toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderB));
    EXPECT_FALSE(messageHeaderB->equals(messageHeaderA));

    EXPECT_FALSE(messageHeaderA->equals(messageHeaderC));
    EXPECT_FALSE(messageHeaderC->equals(messageHeaderA));

    EXPECT_TRUE(messageHeaderA->equals(messageHeaderA2));
    EXPECT_TRUE(messageHeaderA2->equals(messageHeaderA));
}

}}} // namespace netflix::msl::msg
