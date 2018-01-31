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
#include <crypto/NullCryptoContext.h>
#include <crypto/Random.h>
#include <io/DefaultMslEncoderFactory.h>
#include <io/MslEncoderFormat.h>

using namespace std;
using namespace netflix::msl::io;

namespace netflix {
namespace msl {
namespace crypto {

class NullCryptoContextTest : public ::testing::Test
{
};

TEST_F(NullCryptoContextTest, Main)
{
	shared_ptr<ByteArray> dataA = make_shared<ByteArray>(128);
	shared_ptr<ByteArray> dataB = make_shared<ByteArray>(128);
    Random random;
    random.nextBytes(*dataA);
    EXPECT_EQ(128u, dataA->size());
    NullCryptoContext ctx;
    shared_ptr<MslEncoderFactory> mef = make_shared<DefaultMslEncoderFactory>();
    MslEncoderFormat fmt = MslEncoderFormat::JSON;


    // encrypt / decrypt
    EXPECT_NO_THROW(dataB = ctx.encrypt(dataA, mef, fmt));
    EXPECT_EQ(*dataA, *dataB);
    EXPECT_NO_THROW(dataA = ctx.decrypt(dataA, mef));
    EXPECT_EQ(*dataB, *dataA);

    // wrap / unwrap
    EXPECT_NO_THROW(dataB = ctx.wrap(dataA, mef, fmt));
    EXPECT_EQ(*dataA, *dataB);
    EXPECT_NO_THROW(dataA = ctx.unwrap(dataB, mef));
    EXPECT_EQ(*dataB, *dataA);

    // sign / verify
    EXPECT_NO_THROW(dataB = ctx.sign(dataA, mef, fmt));
    EXPECT_EQ(0u, dataB->size());
    EXPECT_TRUE(ctx.verify(dataA, dataB, mef));
}

}}} // namespace netflix::msl::crypto
