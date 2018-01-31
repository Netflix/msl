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
#include <gtest/gtest.h>
#include <util/MslContext.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <crypto/Random.h>
#include <crypto/OpenSslLib.h>
#include <io/MslEncoderFormat.h>

#include <util/MockMslContext.h>

using namespace std;
using namespace testing;
using namespace netflix::msl::entityauth;

namespace netflix {
namespace msl {
namespace util {

class MslContextTest : public ::testing::Test
{
};

// ---- ReauthCode

TEST_F(MslContextTest, ReauthCode_Value)
{
    EXPECT_EQ(MslContext::ReauthCode::entity_reauth, MslContext::ReauthCode::ENTITY_REAUTH);
    EXPECT_EQ(MslContext::ReauthCode::entitydata_reauth, MslContext::ReauthCode::ENTITYDATA_REAUTH);
}

TEST_F(MslContextTest, ReauthCode_ValueOf)
{
    EXPECT_EQ(MslContext::ReauthCode::ENTITY_REAUTH, MslContext::ReauthCode::entity_reauth);
    EXPECT_EQ(MslContext::ReauthCode::ENTITYDATA_REAUTH, MslContext::ReauthCode::entitydata_reauth);

    EXPECT_EQ(MslContext::ReauthCode::ENTITY_REAUTH,
            MslContext::ReauthCode::valueOf(MslConstants::ResponseCode::ENTITY_REAUTH));
    EXPECT_EQ(MslContext::ReauthCode::ENTITYDATA_REAUTH,
            MslContext::ReauthCode::valueOf(MslConstants::ResponseCode::ENTITYDATA_REAUTH));
}

TEST_F(MslContextTest, ReauthCode_FromString)
{
    EXPECT_EQ(MslContext::ReauthCode::ENTITY_REAUTH, MslContext::ReauthCode::fromString("ENTITY_REAUTH"));
    EXPECT_EQ(MslContext::ReauthCode::ENTITYDATA_REAUTH, MslContext::ReauthCode::fromString("ENTITYDATA_REAUTH"));
    EXPECT_THROW(MslContext::ReauthCode::fromString("FOO"), IllegalArgumentException);
}

TEST_F(MslContextTest, ReauthCode_ToString)
{
    EXPECT_EQ("ENTITY_REAUTH", MslContext::ReauthCode::ENTITY_REAUTH.toString());
    EXPECT_EQ("ENTITYDATA_REAUTH", MslContext::ReauthCode::ENTITYDATA_REAUTH.toString());
}

// ---- end ReauthCode

TEST_F(MslContextTest, getTime)
{
    MockMslContext ctx(EntityAuthenticationScheme::PSK, false);
    ASSERT_GT(ctx.getTime(), 1461629597783ll);
}

TEST_F(MslContextTest, Random)
{
    const crypto::SecretKey nullKey;
    MockMslContext ctx(EntityAuthenticationScheme::PSK, false);
    const size_t SIZE = 64;
    // generate two random sequences and just test they are not equal
    std::vector<uint8_t> bytes1(SIZE), bytes2(SIZE);
    ctx.getRandom()->nextBytes(bytes1);
    EXPECT_EQ(SIZE, bytes1.size());
    ctx.getRandom()->nextBytes(bytes2);
    EXPECT_EQ(SIZE, bytes2.size());
    EXPECT_NE(bytes1, bytes2);
}

TEST_F(MslContextTest, equals)
{
    shared_ptr<MslContext> ctx1 = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
    shared_ptr<MslContext> ctx2 = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
    EXPECT_TRUE(ctx1->equals(ctx1));
    EXPECT_TRUE(ctx2->equals(ctx2));
    EXPECT_FALSE(ctx1->equals(ctx2));
    EXPECT_FALSE(ctx2->equals(ctx1));
}

} /* namespace util */
} /* namespace msl */
} /* namespace netflix */
