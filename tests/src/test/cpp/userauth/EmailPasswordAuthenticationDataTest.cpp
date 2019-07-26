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
#include <gmock/gmock.h>
#include <userauth/EmailPasswordAuthenticationData.h>
#include <Macros.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <keyx/KeyExchangeScheme.h>
#include <MslEncodingException.h>
#include <tokens/MasterToken.h>
#include <userauth/EmailPasswordAuthenticationFactory.h>
#include <userauth/EmailPasswordStore.h>
#include <util/AuthenticationUtils.h>
#include <memory>

#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::keyx;
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
/** Key email. */
const string KEY_EMAIL = "email";
/** Key password. */
const string KEY_PASSWORD = "password";

/** Email. */
const string EMAIL = "email1@domain.com";
/** Password. */
const string PASSWORD = "password";

// FIXME: duplicated in UserAuthenticationData_test
class MockEmailPasswordStore : public EmailPasswordStore
{
    MOCK_METHOD2(isUser, shared_ptr<MslUser>(const string& email, const string& password));
};

// FIXME: duplicated in UserAuthenticationData_test
class MockAuthenticationUtils : public AuthenticationUtils
{
    MOCK_METHOD1(isEntityRevoked, bool(const string& identity));
    MOCK_METHOD2(isSchemePermitted, bool(const string& identity, const EntityAuthenticationScheme& scheme));
    MOCK_METHOD2(isSchemePermitted, bool(const string& identity, const UserAuthenticationScheme& scheme));
    MOCK_METHOD3(isSchemePermitted, bool(const string& identity, shared_ptr<MslUser> user, const UserAuthenticationScheme& scheme));
    MOCK_METHOD2(isSchemePermitted, bool(const string& identity, const KeyExchangeScheme& scheme));
};

} // namespace anonymous

/**
 * Email/password user authentication data unit tests.
 */
class EmailPasswordAuthenticationDataTest : public ::testing::Test
{
public:
    EmailPasswordAuthenticationDataTest()
    : ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , encoder(ctx->getMslEncoderFactory())
    , ENCODER_FORMAT(MslEncoderFormat::JSON)
    {}
protected:
    /** MSL context. */
    shared_ptr<MockMslContext> ctx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    /** MSL encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;
};

TEST_F(EmailPasswordAuthenticationDataTest, ctors)
{
    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(EMAIL, PASSWORD);
    EXPECT_EQ(UserAuthenticationScheme::EMAIL_PASSWORD, data->getScheme());
    EXPECT_EQ(EMAIL, data->getEmail());
    EXPECT_EQ(PASSWORD, data->getPassword());
    shared_ptr<MslObject> authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(authdata);
    shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    shared_ptr<EmailPasswordAuthenticationData> moData = make_shared<EmailPasswordAuthenticationData>(authdata);
    EXPECT_EQ(data->getScheme(), moData->getScheme());
    EXPECT_EQ(data->getEmail(), moData->getEmail());
    EXPECT_EQ(data->getPassword(), moData->getPassword());
    shared_ptr<MslObject> moAuthdata = moData->getAuthData(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moAuthdata);
    EXPECT_EQ(*authdata, *moAuthdata);
    shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_F(EmailPasswordAuthenticationDataTest, mslObject)
{
    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(EMAIL, PASSWORD);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
    EXPECT_EQ(UserAuthenticationScheme::EMAIL_PASSWORD.toString(), mo->getString(KEY_SCHEME));
    shared_ptr<MslObject> authdata = mo->getMslObject(KEY_AUTHDATA, encoder);
    EXPECT_EQ(EMAIL, authdata->getString(KEY_EMAIL));
    EXPECT_EQ(PASSWORD, authdata->getString(KEY_PASSWORD));
}

TEST_F(EmailPasswordAuthenticationDataTest, create)
{
    shared_ptr<EmailPasswordStore> meps(make_shared<NiceMock<MockEmailPasswordStore>>());
    shared_ptr<AuthenticationUtils> mau(make_shared<NiceMock<MockAuthenticationUtils>>());

    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(EMAIL, PASSWORD);
    shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);
    shared_ptr<MasterToken> nullMasterToken;
    shared_ptr<UserAuthenticationData> userdata = UserAuthenticationData::create(ctx, nullMasterToken, mo);
    EXPECT_TRUE(userdata);
    EXPECT_TRUE(instanceof<EmailPasswordAuthenticationData>(userdata.get()));

    shared_ptr<EmailPasswordAuthenticationData> moData = dynamic_pointer_cast<EmailPasswordAuthenticationData>(userdata);
    EXPECT_EQ(data->getScheme(), moData->getScheme());
    EXPECT_EQ(data->getEmail(), moData->getEmail());
    EXPECT_EQ(data->getPassword(), moData->getPassword());
    shared_ptr<MslObject> moAuthdata = moData->getAuthData(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moAuthdata);
    EXPECT_EQ(*data->getAuthData(encoder, ENCODER_FORMAT), *moAuthdata);
    shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_F(EmailPasswordAuthenticationDataTest, missingEmail)
{
    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(EMAIL, PASSWORD);
    shared_ptr<MslObject> authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    authdata->remove(KEY_EMAIL);
    try {
        EmailPasswordAuthenticationData epad(authdata);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(EmailPasswordAuthenticationDataTest, missingPassword)
{
    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(EMAIL, PASSWORD);
    shared_ptr<MslObject> authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    authdata->remove(KEY_PASSWORD);
    try {
        EmailPasswordAuthenticationData epad(authdata);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(EmailPasswordAuthenticationDataTest, equalsEmail)
{
    shared_ptr<EmailPasswordAuthenticationData> dataA = make_shared<EmailPasswordAuthenticationData>(EMAIL + "A", PASSWORD);
    shared_ptr<EmailPasswordAuthenticationData> dataB = make_shared<EmailPasswordAuthenticationData>(EMAIL + "B", PASSWORD);
    shared_ptr<EmailPasswordAuthenticationData> dataA2 = make_shared<EmailPasswordAuthenticationData>(dataA->getAuthData(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(EmailPasswordAuthenticationDataTest, equalsPassword)
{
    shared_ptr<EmailPasswordAuthenticationData> dataA = make_shared<EmailPasswordAuthenticationData>(EMAIL, PASSWORD + "A");
    shared_ptr<EmailPasswordAuthenticationData> dataB = make_shared<EmailPasswordAuthenticationData>(EMAIL, PASSWORD + "B");
    shared_ptr<EmailPasswordAuthenticationData> dataA2 = make_shared<EmailPasswordAuthenticationData>(dataA->getAuthData(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

}}} // namespace netflix::msl::userauth
