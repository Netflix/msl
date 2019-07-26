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

#include <crypto/Key.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationFactory.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>

#include <gtest/gtest.h>
#include <util/MockMslContext.h>

using netflix::msl::io::MslObject;
using netflix::msl::util::MockMslContext;

using namespace std;
using namespace testing;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {
/** Key entity authentication scheme. */
const string KEY_SCHEME = "scheme";
/** Key entity authentication data. */
const string KEY_AUTHDATA = "authdata";
} // namespace anonymous

class EntityAuthenticationDataTest : public ::testing::Test
{
public:
	virtual ~EntityAuthenticationDataTest() {}

    EntityAuthenticationDataTest()
    	: ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
		, encoder(ctx->getMslEncoderFactory())
	{}

protected:
    shared_ptr<MslContext> ctx;
    shared_ptr<MslEncoderFactory> encoder;
};

TEST_F(EntityAuthenticationDataTest, noScheme)
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME + "x", EntityAuthenticationScheme::NONE.name());
    mo->put(KEY_AUTHDATA, make_shared<MslObject>());
    try {
        EntityAuthenticationData::create(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(EntityAuthenticationDataTest, noAuthdata)
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME, EntityAuthenticationScheme::NONE.name());
    mo->put(KEY_AUTHDATA + "x", make_shared<MslObject>());
    try {
        EntityAuthenticationData::create(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(EntityAuthenticationDataTest, unidentifiedScheme)
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME, string("x"));
    mo->put(KEY_AUTHDATA, make_shared<MslObject>());
    try {
        EntityAuthenticationData::create(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslEntityAuthException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_ENTITYAUTH_SCHEME, e.getError());
    }
}

TEST_F(EntityAuthenticationDataTest, authFactoryNotFound)
{
	shared_ptr<MockMslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
	ctx->removeEntityAuthenticationFactory(EntityAuthenticationScheme::NONE);
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME, EntityAuthenticationScheme::NONE.name());
    mo->put(KEY_AUTHDATA, make_shared<MslObject>());
    try {
        EntityAuthenticationData::create(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslEntityAuthException& e) {
        EXPECT_EQ(MslError::ENTITYAUTH_FACTORY_NOT_FOUND, e.getError());
    }
}

}}} // namespace netflix::msl::entityauth
