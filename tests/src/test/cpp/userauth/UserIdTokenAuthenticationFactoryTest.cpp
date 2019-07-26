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
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <keyx/KeyExchangeScheme.h>
#include <MslEncodingException.h>
#include <MslUserAuthException.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <userauth/EmailPasswordAuthenticationFactory.h>
#include <userauth/UserAuthenticationFactory.h>
#include <userauth/UserIdTokenAuthenticationData.h>
#include <userauth/UserIdTokenAuthenticationFactory.h>
#include <memory>
#include <string>

#include "../util/MockAuthenticationUtils.h"
#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"
#include "../tokens/MockMslUser.h"
#include "../tokens/MockTokenFactory.h"

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

/** Key master token. */
const string KEY_MASTER_TOKEN = "mastertoken";

} // namespace anonymous

/**
 * User ID token user authentication factory unit tests.
 */
class UserIdTokenAuthenticationFactoryTest : public ::testing::Test
{
public:
    UserIdTokenAuthenticationFactoryTest()
    : ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , encoder(ctx->getMslEncoderFactory())
    , authutils(make_shared<MockAuthenticationUtils>())
    , factory(make_shared<UserIdTokenAuthenticationFactory>(authutils))
    , tokenFactory(make_shared<MockTokenFactory>())
    , ENCODER_FORMAT(MslEncoderFormat::JSON)
    , MASTER_TOKEN(MslTestUtils::getMasterToken(ctx, 1L, 1L))
    {
        ctx->addUserAuthenticationFactory(factory);
        ctx->setTokenFactory(tokenFactory);
        shared_ptr<MslUser> user = make_shared<MockMslUser>(1);
        USER_ID_TOKEN = MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, 1L, user);
    }
    ~UserIdTokenAuthenticationFactoryTest()
    {
        authutils->reset();
        tokenFactory->reset();
    }
protected:
    /** MSL context. */
    shared_ptr<MockMslContext> ctx;
    /** MSL encoder factory-> */
    shared_ptr<MslEncoderFactory> encoder;
    /** Authentication utilities. */
    shared_ptr<MockAuthenticationUtils> authutils;
    /** User authentication factory-> */
    shared_ptr<UserAuthenticationFactory> factory;
    /** Token factory. */
    shared_ptr<MockTokenFactory> tokenFactory;
    /** MSL encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;
    /** Master token. */
    shared_ptr<MasterToken> MASTER_TOKEN;
    /** User ID token. */
    shared_ptr<UserIdToken> USER_ID_TOKEN;
};

TEST_F(UserIdTokenAuthenticationFactoryTest, createData)
{
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslObject> userAuthMo = data->getAuthData(encoder, ENCODER_FORMAT);

    shared_ptr<UserAuthenticationData> authdata = factory->createData(ctx, shared_ptr<MasterToken>(), userAuthMo);
    EXPECT_TRUE(authdata);
    EXPECT_TRUE(instanceof<UserIdTokenAuthenticationData>(authdata.get()));
    EXPECT_EQ(*data, *authdata);
}

TEST_F(UserIdTokenAuthenticationFactoryTest, encodeException)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);

    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslObject> userAuthMo = data->getAuthData(encoder, ENCODER_FORMAT);
    userAuthMo->remove(KEY_MASTER_TOKEN);
    try {
        factory->createData(ctx, shared_ptr<MasterToken>(), userAuthMo);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationFactoryTest, authenticate)
{
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslUser> user = factory->authenticate(ctx, MASTER_TOKEN->getIdentity(), data, shared_ptr<UserIdToken>());
    EXPECT_TRUE(user);
    EXPECT_EQ(USER_ID_TOKEN->getUser(), user);
}

TEST_F(UserIdTokenAuthenticationFactoryTest, authenticateUserIdToken)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, MASTER_TOKEN->getSequenceNumber() + 1, MASTER_TOKEN->getSerialNumber() + 1);
    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, USER_ID_TOKEN->getSerialNumber() + 1, USER_ID_TOKEN->getUser());
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    shared_ptr<MslUser> u = factory->authenticate(ctx, MASTER_TOKEN->getIdentity(), data, userIdToken);
    EXPECT_EQ(USER_ID_TOKEN->getUser(), u);
}

TEST_F(UserIdTokenAuthenticationFactoryTest, authenticateMismatchedUserIdToken)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError::USERIDTOKEN_USERAUTH_DATA_MISMATCH);

    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<MslUser> user = make_shared<MockMslUser>(2);
    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, user);
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    try {
        factory->authenticate(ctx, MASTER_TOKEN->getIdentity(), data, userIdToken);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_USERAUTH_DATA_MISMATCH, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationFactoryTest, untrustedMasterToken)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError::USERAUTH_MASTERTOKEN_NOT_DECRYPTED);

    shared_ptr<MasterToken> untrustedMasterToken = MslTestUtils::getUntrustedMasterToken(ctx);
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(untrustedMasterToken, USER_ID_TOKEN);
    try {
        factory->authenticate(ctx, MASTER_TOKEN->getIdentity(), data, shared_ptr<UserIdToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERAUTH_MASTERTOKEN_NOT_DECRYPTED, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationFactoryTest, mismatchedMasterTokenIdentity)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError::USERAUTH_ENTITY_MISMATCH);

    shared_ptr<MslContext> mismatchedCtx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK_PROFILE, false);
    shared_ptr<MasterToken> mismatchedMasterToken = MslTestUtils::getMasterToken(mismatchedCtx, 1, 1);
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(mismatchedMasterToken, USER_ID_TOKEN);
    try {
        factory->authenticate(ctx, MASTER_TOKEN->getIdentity(), data, shared_ptr<UserIdToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERAUTH_ENTITY_MISMATCH, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationFactoryTest, untrustedUserIdToken)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError::USERAUTH_USERIDTOKEN_NOT_DECRYPTED);

    shared_ptr<UserIdToken> untrustedUserIdToken = MslTestUtils::getUntrustedUserIdToken(ctx, MASTER_TOKEN, USER_ID_TOKEN->getSerialNumber(), USER_ID_TOKEN->getUser());
    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, untrustedUserIdToken);
    try {
        factory->authenticate(ctx, MASTER_TOKEN->getIdentity(), data, shared_ptr<UserIdToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERAUTH_USERIDTOKEN_NOT_DECRYPTED, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationFactoryTest, userNotPermitted)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError::USERAUTH_ENTITYUSER_INCORRECT_DATA);

    authutils->disallowScheme(MASTER_TOKEN->getIdentity(), USER_ID_TOKEN->getUser(), UserAuthenticationScheme::USER_ID_TOKEN);

    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    try {
        factory->authenticate(ctx, MASTER_TOKEN->getIdentity(), data, shared_ptr<UserIdToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERAUTH_ENTITYUSER_INCORRECT_DATA, e.getError());
    }
}

TEST_F(UserIdTokenAuthenticationFactoryTest, tokenRevoked)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError.USERIDTOKEN_REVOKED);

    tokenFactory->setRevokedUserIdToken(USER_ID_TOKEN);

    shared_ptr<UserIdTokenAuthenticationData> data = make_shared<UserIdTokenAuthenticationData>(MASTER_TOKEN, USER_ID_TOKEN);
    try {
        factory->authenticate(ctx, MASTER_TOKEN->getIdentity(), data, USER_ID_TOKEN);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_REVOKED, e.getError());
    }
}

}}} // namespace netflix::msl::userauth

