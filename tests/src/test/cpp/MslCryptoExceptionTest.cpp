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
#include <MslCryptoException.h>

using namespace std;

namespace netflix
{
namespace msl
{

class MslCryptoExceptionTest : public ::testing::Test
{
};

TEST_F(MslCryptoExceptionTest, Constructors)
{
    // Construct a new MSL crypto exception with the specified error
    MslCryptoException mcex1(MslError::CIPHERTEXT_BAD_PADDING);
    EXPECT_EQ(std::shared_ptr<IException>(), mcex1.getCause());
    EXPECT_EQ(1u, mcex1.getDepth());
    EXPECT_EQ(string("Ciphertext contains incorrect padding."), mcex1.what());

    // Construct a new MSL crypto exception with the specified error and details
    MslCryptoException mcex2(MslError::CIPHERTEXT_BAD_PADDING, "foobar");
    EXPECT_EQ(std::shared_ptr<IException>(), mcex2.getCause());
    EXPECT_EQ(1u, mcex2.getDepth());
    EXPECT_EQ(string("Ciphertext contains incorrect padding. [foobar]"), mcex2.what());

    // Construct a new MSL crypto exception with the specified error, details,
    // and cause.
    MslCryptoException mcex3(MslError::DECRYPT_ERROR, "barfoo", mcex2);
    EXPECT_NE(std::shared_ptr<IException>(), mcex3.getCause());
    EXPECT_EQ(2u, mcex3.getDepth());
    EXPECT_EQ(string("Error decrypting ciphertext. [barfoo]"), mcex3.what());
    std::shared_ptr<IException> cause = mcex3.getCause();
    EXPECT_TRUE(instanceof<MslCryptoException>(cause.get()));
    EXPECT_EQ(string("Ciphertext contains incorrect padding. [foobar]"), cause->what());

    // Construct a new MSL crypto exception with the specified error and cause.
    MslCryptoException mcex4(MslError::DECRYPT_ERROR, mcex2);
    EXPECT_NE(std::shared_ptr<IException>(), mcex4.getCause());
    EXPECT_EQ(2u, mcex4.getDepth());
    EXPECT_EQ(string("Error decrypting ciphertext."), mcex4.what());
    cause = mcex4.getCause();
    EXPECT_TRUE(instanceof<MslCryptoException>(cause.get()));
    EXPECT_EQ(string("Ciphertext contains incorrect padding. [foobar]"), cause->what());
}

TEST_F(MslCryptoExceptionTest, Clone)
{
    MslCryptoException mcex1(MslError::DIGEST_ERROR);
    shared_ptr<IException> mcex1Clone = mcex1.clone();
    EXPECT_TRUE(instanceof<MslCryptoException>(mcex1Clone.get()));
}

} /* namespace msl */
} /* namespace netflix */
