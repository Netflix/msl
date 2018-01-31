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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <userauth/UserIdTokenAuthenticationData.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncoderFormat.h>
#include <Macros.h>
#include <MslEncodingException.h>
#include <MslUserAuthException.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <string>

#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"
#include "../tokens/MockMslUser.h"

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::entityauth;
//using namespace netflix::msl::keyx;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace userauth {

namespace {
/** Key user authentication scheme. */
const string KEY_SCHEME = "scheme";
/** Key user authentication data-> */
const string KEY_AUTHDATA = "authdata";
/** Key master token. */
const string KEY_MASTER_TOKEN = "mastertoken";
/** Key user ID token. */
const string KEY_USER_ID_TOKEN = "useridtoken";
const int64_t USER_ID = 999ll;
} // namespace anonymous

/**
 * User ID token user authentication data unit tests.
 */
class UserIdTokenAuthenticationDataTest : public ::testing::Test
{
public:
    UserIdTokenAuthenticationDataTest()
    : ENCODER_FORMAT(MslEncoderFormat::JSON)
    , ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , encoder(ctx->getMslEncoderFactory())
    , MASTER_TOKEN(MslTestUtils::getMasterToken(ctx, 1L, 1L))
    , USER_ID_TOKEN(MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, 1L, make_shared<NiceMock<MockMslUser>>(USER_ID)))
    {}
protected:
    /** MSL encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;
    /** MSL context. */
    shared_ptr<MockMslContext> ctx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    /** Master token. */
    shared_ptr<MasterToken> MASTER_TOKEN;
    /** User ID token. */
    shared_ptr<UserIdToken> USER_ID_TOKEN;
};

TEST_F(UserIdTokenAuthenticationDataTest, ctors)
{
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    EXPECT_EQ(UserAuthenticationScheme::USER_ID_TOKEN, data->getScheme());
    EXPECT_EQ(*MASTER_TOKEN, *data->getMasterToken());
    EXPECT_EQ(*USER_ID_TOKEN, *data->getUserIdToken());
    shared_ptr<MslObject> authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(authdata);
    shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    shared_ptr<UserIdTokenAuthenticationData> moData = make_shared<UserIdTokenAuthenticationData>(ctx, authdata);
    EXPECT_EQ(data->getScheme(), moData->getScheme());
    EXPECT_EQ(*data->getMasterToken(), *moData->getMasterToken());
    EXPECT_EQ(*data->getUserIdToken(), *moData->getUserIdToken());
    shared_ptr<MslObject> moAuthdata = moData->getAuthData(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moAuthdata);
    shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*moEncode, *encode);
}

TEST_F(UserIdTokenAuthenticationDataTest, mslObject)
{
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslObject>mo = MslTestUtils::toMslObject(encoder, data);
    EXPECT_EQ(UserAuthenticationScheme::USER_ID_TOKEN.name(), mo->getString(KEY_SCHEME));
    shared_ptr<MslObject>authdata = mo->getMslObject(KEY_AUTHDATA, encoder);
    shared_ptr<MslObject>masterTokenJo = authdata->getMslObject(KEY_MASTER_TOKEN, encoder);
    EXPECT_EQ(*MslTestUtils::toMslObject(encoder, MASTER_TOKEN), *masterTokenJo);
    shared_ptr<MslObject>userIdTokenJo = authdata->getMslObject(KEY_USER_ID_TOKEN, encoder);
    EXPECT_EQ(*MslTestUtils::toMslObject(encoder, USER_ID_TOKEN), *userIdTokenJo);
}

TEST_F(UserIdTokenAuthenticationDataTest, create)
{
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);
    shared_ptr<MasterToken> nullMasterToken;
    shared_ptr<UserAuthenticationData> userdata = UserAuthenticationData::create(ctx, nullMasterToken, mo);
    EXPECT_TRUE(userdata);
    EXPECT_TRUE(instanceof<UserIdTokenAuthenticationData>(userdata.get()));

    shared_ptr<UserIdTokenAuthenticationData> moData = dynamic_pointer_cast<UserIdTokenAuthenticationData>(userdata);
    EXPECT_EQ(data->getScheme(), moData->getScheme());
    EXPECT_EQ(*data->getMasterToken(), *moData->getMasterToken());
    EXPECT_EQ(*data->getUserIdToken(), *moData->getUserIdToken());
    shared_ptr<MslObject>moAuthdata = moData->getAuthData(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moAuthdata);
    shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*moEncode, *encode);
}

TEST_F(UserIdTokenAuthenticationDataTest, missingMasterToken)
{
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslObject>authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    authdata->remove(KEY_MASTER_TOKEN);
    try {
        shared_ptr<UserIdTokenAuthenticationData> uitad = make_shared<UserIdTokenAuthenticationData>(ctx, authdata);
        ADD_FAILURE() << "Should have thrown.";
    } catch(const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationDataTest, invalidMasterToken)
{
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslObject>authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    authdata->put(KEY_MASTER_TOKEN, make_shared<MslObject>());
    try {
        shared_ptr<UserIdTokenAuthenticationData> uitad = make_shared<UserIdTokenAuthenticationData>(ctx, authdata);
        ADD_FAILURE() << "Should have thrown.";
    } catch(const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERAUTH_MASTERTOKEN_INVALID, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationDataTest, missingUserIdToken)
{
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslObject>authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    authdata->remove(KEY_USER_ID_TOKEN);
    try {
        shared_ptr<UserIdTokenAuthenticationData> uitad = make_shared<UserIdTokenAuthenticationData>(ctx, authdata);
        ADD_FAILURE() << "Should have thrown.";
    } catch(const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationDataTest, invalidUserIdToken)
{
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslObject>authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    authdata->put(KEY_USER_ID_TOKEN, make_shared<MslObject>());
    try {
        shared_ptr<UserIdTokenAuthenticationData> uitad = make_shared<UserIdTokenAuthenticationData>(ctx, authdata);
        ADD_FAILURE() << "Should have thrown.";
    } catch(const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERAUTH_USERIDTOKEN_INVALID, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationDataTest, mismatchedTokens)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, MASTER_TOKEN->getSequenceNumber(), MASTER_TOKEN->getSerialNumber() + 1);

    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslObject>authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    authdata->put(KEY_MASTER_TOKEN, MslTestUtils::toMslObject(encoder, masterToken));
    try {
        shared_ptr<UserIdTokenAuthenticationData> uitad = make_shared<UserIdTokenAuthenticationData>(ctx, authdata);
        ADD_FAILURE() << "Should have thrown.";
    } catch(const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERAUTH_USERIDTOKEN_INVALID, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationDataTest, equalsMasterToken)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, MASTER_TOKEN->getSequenceNumber() + 1, MASTER_TOKEN->getSerialNumber());

    shared_ptr<UserIdTokenAuthenticationData> dataA = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<UserIdTokenAuthenticationData> dataB = make_shared<UserIdTokenAuthenticationData>(masterToken, USER_ID_TOKEN);
    shared_ptr<UserIdTokenAuthenticationData> dataA2 = make_shared<UserIdTokenAuthenticationData>(ctx, dataA->getAuthData(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(UserIdTokenAuthenticationDataTest, equalsUserIdToken)
{
    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, USER_ID_TOKEN->getSerialNumber() + 1, USER_ID_TOKEN->getUser());

    shared_ptr<UserIdTokenAuthenticationData> dataA = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<UserIdTokenAuthenticationData> dataB = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, userIdToken);
    shared_ptr<UserIdTokenAuthenticationData> dataA2 = make_shared<UserIdTokenAuthenticationData>(ctx, dataA->getAuthData(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

}}} // namespace netflix::msl::userauth
