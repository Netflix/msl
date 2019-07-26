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
#include <userauth/UserAuthenticationData.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <keyx/KeyExchangeScheme.h>
#include <userauth/EmailPasswordAuthenticationFactory.h>
#include <userauth/EmailPasswordStore.h>
#include <util/AuthenticationUtils.h>
#include <MslEncodingException.h>
#include <MslUserAuthException.h>
#include <userauth/UserAuthenticationFactory.h>
#include <memory>
#include <string>

#include "../util/MockMslContext.h"

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace userauth {

namespace {

/** Key user authentication scheme. */
const string KEY_SCHEME = "scheme";
/** Key user authentication data. */
const string KEY_AUTHDATA = "authdata";

class MockUserAuthenticationFactory : public UserAuthenticationFactory
{
    MockUserAuthenticationFactory() : UserAuthenticationFactory(UserAuthenticationScheme::EMAIL_PASSWORD) {}

    MOCK_METHOD3(createData, std::shared_ptr<UserAuthenticationData>(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<io::MslObject> userAuthMo));

    MOCK_METHOD4(authenticate, std::shared_ptr<tokens::MslUser>(std::shared_ptr<util::MslContext> ctx,
            const std::string& identity, std::shared_ptr<UserAuthenticationData> data,
            std::shared_ptr<tokens::UserIdToken> userIdToken));
};

// FIXME: duplicated in EmailPasswordAuthenticationData_test
class MockEmailPasswordStore : public EmailPasswordStore
{
    MOCK_METHOD2(isUser, std::shared_ptr<tokens::MslUser>(const std::string& email, const std::string& password));
};

// FIXME: duplicated in EmailPasswordAuthenticationData_test
class MockAuthenticationUtils : public AuthenticationUtils
{
    MOCK_METHOD1(isEntityRevoked, bool(const std::string& identity));
    MOCK_METHOD2(isSchemePermitted, bool(const std::string& identity, const entityauth::EntityAuthenticationScheme& scheme));
    MOCK_METHOD2(isSchemePermitted, bool(const std::string& identity, const userauth::UserAuthenticationScheme& scheme));
    MOCK_METHOD3(isSchemePermitted, bool(const std::string& identity, shared_ptr<tokens::MslUser> user, const userauth::UserAuthenticationScheme& scheme));
    MOCK_METHOD2(isSchemePermitted, bool(const std::string& identity, const keyx::KeyExchangeScheme& scheme));
};

}  // namespace anonymous

/**
 * User authentication data unit tests.
 *
 * Successful calls to
 * {@link UserAuthenticationData#create(com.netflix.msl.util.MslContext, org.json.MslObject)}
 * covered in the individual user authentication data unit tests.
 */
class UserAuthenticationDataTest : public ::testing::Test
{
public:
    UserAuthenticationDataTest()
    : ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , encoder(ctx->getMslEncoderFactory())
    {}
protected:
    shared_ptr<MockMslContext> ctx;
    shared_ptr<MslEncoderFactory> encoder;
};

TEST_F(UserAuthenticationDataTest, noScheme)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME + "x", UserAuthenticationScheme::EMAIL_PASSWORD.name());
    mo->put(KEY_AUTHDATA, encoder->createObject());
    try {
        UserAuthenticationData::create(ctx, shared_ptr<MasterToken>(), mo);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserAuthenticationDataTest, noAuthdata)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME, UserAuthenticationScheme::EMAIL_PASSWORD.name());
    mo->put(KEY_AUTHDATA + "x", encoder->createObject());
    try {
        UserAuthenticationData::create(ctx, shared_ptr<MasterToken>(), mo);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserAuthenticationDataTest, unidentifiedScheme)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError.UNIDENTIFIED_USERAUTH_SCHEME);

    shared_ptr<MslObject> mo = encoder->createObject();
    const string invalidSchemeName = "foobar";
    mo->put<string>(KEY_SCHEME, invalidSchemeName);
    mo->put(KEY_AUTHDATA, encoder->createObject());
    try {
        UserAuthenticationData::create(ctx, shared_ptr<MasterToken>(), mo);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_USERAUTH_SCHEME, e.getError());
    }
}

TEST_F(UserAuthenticationDataTest, authFactoryNotFound)
{
//    thrown.expect(MslUserAuthException.class);
//    thrown.expectMslError(MslError.USERAUTH_FACTORY_NOT_FOUND);

	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	ctx->removeUserAuthenticationFactory(UserAuthenticationScheme::EMAIL_PASSWORD);

    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME, UserAuthenticationScheme::EMAIL_PASSWORD.name());
    mo->put(KEY_AUTHDATA, encoder->createObject());
    try {
        UserAuthenticationData::create(ctx, shared_ptr<MasterToken>(), mo);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslUserAuthException& e) {
        EXPECT_EQ(MslError::USERAUTH_FACTORY_NOT_FOUND, e.getError());
    }
}

}}} // namespace netflix::msl::userauth
