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
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <keyx/KeyExchangeScheme.h>
#include <Macros.h>
#include <MslEncodingException.h>
#include <MslUserAuthException.h>
#include <userauth/EmailPasswordAuthenticationData.h>
#include <userauth/EmailPasswordAuthenticationFactory.h>
#include <userauth/UserAuthenticationFactory.h>
#include <util/AuthenticationUtils.h>

#include <util/MockMslContext.h>
#include <util/MslTestUtils.h>
#include <util/MockAuthenticationUtils.h>
#include <userauth/MockEmailPasswordAuthenticationFactory.h>
#include <userauth/MockEmailPasswordStore.h>

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

/** Key email. */
const string KEY_EMAIL = "email";

/** Empty string. */
const string EMPTY_STRING = "";

} // namespace anonymous

/**
 * Email/password user authentication factory unit tests.
 */
class EmailPasswordAuthenticationFactoryTest : public ::testing::Test
{
public:
    EmailPasswordAuthenticationFactoryTest()
    : ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , encoder(ctx->getMslEncoderFactory())
    , ENCODER_FORMAT(MslEncoderFormat::JSON)
    {
        shared_ptr<MockEmailPasswordStore> store = make_shared<MockEmailPasswordStore>();
        store->addUser(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD, MockEmailPasswordAuthenticationFactory::USER());
        shared_ptr<AuthenticationUtils> authutils = make_shared<MockAuthenticationUtils>();
        factory = make_shared<EmailPasswordAuthenticationFactory>(store, authutils);
        ctx->addUserAuthenticationFactory(factory);
    }
protected:
    /** MSL context. */
     shared_ptr<MockMslContext> ctx;
     /** MSL encoder factory-> */
     shared_ptr<MslEncoderFactory> encoder;
     /** User authentication factory-> */
     shared_ptr<UserAuthenticationFactory> factory;
     /** MSL encoder format. */
     const MslEncoderFormat ENCODER_FORMAT;
};

TEST_F(EmailPasswordAuthenticationFactoryTest, createData)
{
    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD);
    shared_ptr<MslObject> userAuthMo = data->getAuthData(encoder, ENCODER_FORMAT);

    shared_ptr<UserAuthenticationData> authdata = factory->createData(ctx, shared_ptr<MasterToken>(), userAuthMo);
    EXPECT_TRUE(authdata);
    EXPECT_TRUE(instanceof<EmailPasswordAuthenticationData>(authdata.get()));

    shared_ptr<MslObject> dataMo = MslTestUtils::toMslObject(encoder, data);
    shared_ptr<MslObject> authdataMo = MslTestUtils::toMslObject(encoder, authdata);
    EXPECT_EQ(*dataMo, *authdataMo);
}

TEST_F(EmailPasswordAuthenticationFactoryTest, encodeException)
{
    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD);
    shared_ptr<MslObject> userAuthMo = data->getAuthData(encoder, ENCODER_FORMAT);
    userAuthMo->remove(KEY_EMAIL);
    try {
        factory->createData(ctx, shared_ptr<MasterToken>(), userAuthMo);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(EmailPasswordAuthenticationFactoryTest, authenticate)
{
    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD);
    shared_ptr<MslUser> user = factory->authenticate(ctx, string(), data, shared_ptr<UserIdToken>());
    EXPECT_TRUE(user);
    EXPECT_EQ(MockEmailPasswordAuthenticationFactory::USER(), user);
}

TEST_F(EmailPasswordAuthenticationFactoryTest, authenticateUserIdToken)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<MslUser> user = MockEmailPasswordAuthenticationFactory::USER();
    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, user);
    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD);
    shared_ptr<MslUser> u = factory->authenticate(ctx, string(), data, userIdToken);
    EXPECT_EQ(user, u);
}

TEST_F(EmailPasswordAuthenticationFactoryTest, authenticateMismatchedUserIdToken)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError::USERIDTOKEN_USERAUTH_DATA_MISMATCH);

    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<MslUser> user = MockEmailPasswordAuthenticationFactory::USER_2();
    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, user);
    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD);
    try {
        factory->authenticate(ctx, string(), data, userIdToken);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_USERAUTH_DATA_MISMATCH, e.getError());
    }
}

TEST_F(EmailPasswordAuthenticationFactoryTest, emailBlank)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError::EMAILPASSWORD_BLANK);

    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(EMPTY_STRING, MockEmailPasswordAuthenticationFactory::PASSWORD);
    try {
        factory->authenticate(ctx, string(), data, shared_ptr<UserIdToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::EMAILPASSWORD_BLANK, e.getError());
    }
}

TEST_F(EmailPasswordAuthenticationFactoryTest, passwordBlank)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError::EMAILPASSWORD_BLANK);

    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, EMPTY_STRING);
    try {
        factory->authenticate(ctx, string(), data, shared_ptr<UserIdToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::EMAILPASSWORD_BLANK, e.getError());
    }
}

TEST_F(EmailPasswordAuthenticationFactoryTest, badLogin)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError::EMAILPASSWORD_INCORRECT);

    shared_ptr<EmailPasswordAuthenticationData> data = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD + "x");
    try {
        factory->authenticate(ctx, string(), data, shared_ptr<UserIdToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::EMAILPASSWORD_INCORRECT, e.getError());
    }
}

}}} // namespace netflix::msl::userauth
