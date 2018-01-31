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

#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/MockPresharedProfileAuthenticationFactory.h>
#include <entityauth/PresharedProfileAuthenticationData.h>
#include <gtest/gtest.h>
#include <MslEncodingException.h>

#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {

 /** Key entity authentication scheme. */
 const string KEY_SCHEME = "scheme";
 /** Key entity authentication data-> */
 const string KEY_AUTHDATA = "authdata";
 /** Key entity preshared keys identity. */
 const string KEY_PSKID = "pskid";
 /** Key entity profile. */
 const string KEY_PROFILE = "profile";

 /** Identity concatenation character. */
 const string CONCAT_CHAR = "-";

} // namespace anonymous

/**
 * Preshared keys profile entity authentication data unit tests.
 */
class PresharedProfileAuthenticationDataTest : public ::testing::Test
{
public:
    PresharedProfileAuthenticationDataTest()
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

TEST_F(PresharedProfileAuthenticationDataTest, ctors)
{
    shared_ptr<PresharedProfileAuthenticationData> data = make_shared<PresharedProfileAuthenticationData>(MockPresharedProfileAuthenticationFactory::PSK_ESN, MockPresharedProfileAuthenticationFactory::PROFILE);
    EXPECT_EQ(MockPresharedProfileAuthenticationFactory::PSK_ESN + CONCAT_CHAR + MockPresharedProfileAuthenticationFactory::PROFILE, data->getIdentity());
    EXPECT_EQ(MockPresharedProfileAuthenticationFactory::PSK_ESN, data->getPresharedKeysId());
    EXPECT_EQ(MockPresharedProfileAuthenticationFactory::PROFILE, data->getProfile());
    EXPECT_EQ(EntityAuthenticationScheme::PSK_PROFILE, data->getScheme());
    shared_ptr<MslObject> authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(authdata);
    shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    shared_ptr<PresharedProfileAuthenticationData> moData = make_shared<PresharedProfileAuthenticationData>(authdata);
    EXPECT_EQ(data->getIdentity(), moData->getIdentity());
    EXPECT_EQ(data->getPresharedKeysId(), moData->getPresharedKeysId());
    EXPECT_EQ(data->getProfile(), moData->getProfile());
    EXPECT_EQ(data->getScheme(), moData->getScheme());
    shared_ptr<MslObject> moAuthdata = moData->getAuthData(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moAuthdata);
    EXPECT_EQ(authdata, moAuthdata);
    shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_F(PresharedProfileAuthenticationDataTest, encode)
{
    shared_ptr<PresharedProfileAuthenticationData> data = make_shared<PresharedProfileAuthenticationData>(MockPresharedProfileAuthenticationFactory::PSK_ESN, MockPresharedProfileAuthenticationFactory::PROFILE);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
    EXPECT_EQ(EntityAuthenticationScheme::PSK_PROFILE.toString(), mo->getString(KEY_SCHEME));
    shared_ptr<MslObject> authdata = mo->getMslObject(KEY_AUTHDATA, encoder);
    EXPECT_EQ(MockPresharedProfileAuthenticationFactory::PSK_ESN, authdata->getString(KEY_PSKID));
    EXPECT_EQ(MockPresharedProfileAuthenticationFactory::PROFILE, authdata->getString(KEY_PROFILE));
}

TEST_F(PresharedProfileAuthenticationDataTest, create)
{
    shared_ptr<PresharedProfileAuthenticationData> data = make_shared<PresharedProfileAuthenticationData>(MockPresharedProfileAuthenticationFactory::PSK_ESN, MockPresharedProfileAuthenticationFactory::PROFILE);
    shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
    shared_ptr<EntityAuthenticationData> entitydata = EntityAuthenticationData::create(ctx, mo);
    EXPECT_TRUE(entitydata);
    EXPECT_TRUE(instanceof<PresharedProfileAuthenticationData>(entitydata));

    shared_ptr<PresharedProfileAuthenticationData> moData = dynamic_pointer_cast<PresharedProfileAuthenticationData>(entitydata);
    EXPECT_EQ(data->getIdentity(), moData->getIdentity());
    EXPECT_EQ(data->getPresharedKeysId(), moData->getPresharedKeysId());
    EXPECT_EQ(data->getProfile(), moData->getProfile());
    EXPECT_EQ(data->getScheme(), moData->getScheme());
    shared_ptr<MslObject> moAuthdata = moData->getAuthData(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moAuthdata);
    EXPECT_EQ(data->getAuthData(encoder, ENCODER_FORMAT), moAuthdata);
    shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_F(PresharedProfileAuthenticationDataTest, missingPskId)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<PresharedProfileAuthenticationData> data = make_shared<PresharedProfileAuthenticationData>(MockPresharedProfileAuthenticationFactory::PSK_ESN, MockPresharedProfileAuthenticationFactory::PROFILE);
    shared_ptr<MslObject> authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    authdata->remove(KEY_PSKID);

    try {
        make_shared<PresharedProfileAuthenticationData>(authdata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(PresharedProfileAuthenticationDataTest, missingProfile)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<PresharedProfileAuthenticationData> data = make_shared<PresharedProfileAuthenticationData>(MockPresharedProfileAuthenticationFactory::PSK_ESN, MockPresharedProfileAuthenticationFactory::PROFILE);
    shared_ptr<MslObject> authdata = data->getAuthData(encoder, ENCODER_FORMAT);
    authdata->remove(KEY_PROFILE);

    try {
        make_shared<PresharedProfileAuthenticationData>(authdata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(PresharedProfileAuthenticationDataTest, equalsPskId)
{
    const string pskIdA = MockPresharedProfileAuthenticationFactory::PSK_ESN + "A";
    const string pskIdB = MockPresharedProfileAuthenticationFactory::PSK_ESN + "B";
    shared_ptr<PresharedProfileAuthenticationData> dataA = make_shared<PresharedProfileAuthenticationData>(pskIdA, MockPresharedProfileAuthenticationFactory::PROFILE);
    shared_ptr<PresharedProfileAuthenticationData> dataB = make_shared<PresharedProfileAuthenticationData>(pskIdB, MockPresharedProfileAuthenticationFactory::PROFILE);
    shared_ptr<EntityAuthenticationData> dataA2 = EntityAuthenticationData::create(ctx, MslTestUtils::toMslObject(encoder, dataA));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(PresharedProfileAuthenticationDataTest, equalsProfile)
{
    const string profileA = MockPresharedProfileAuthenticationFactory::PROFILE + "A";
    const string profileB = MockPresharedProfileAuthenticationFactory::PROFILE + "B";
    shared_ptr<PresharedProfileAuthenticationData> dataA = make_shared<PresharedProfileAuthenticationData>(MockPresharedProfileAuthenticationFactory::PSK_ESN, profileA);
    shared_ptr<PresharedProfileAuthenticationData> dataB = make_shared<PresharedProfileAuthenticationData>(MockPresharedProfileAuthenticationFactory::PSK_ESN, profileB);
    shared_ptr<EntityAuthenticationData> dataA2 = EntityAuthenticationData::create(ctx, MslTestUtils::toMslObject(encoder, dataA));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

}}} // namespace netflix::msl::entityauth
