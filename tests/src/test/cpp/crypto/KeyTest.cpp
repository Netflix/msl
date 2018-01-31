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
#include <crypto/Key.h>
#include <crypto/Random.h>
#include <IllegalArgumentException.h>
#include <memory>

using namespace std;

namespace netflix {
namespace msl {
namespace crypto {

template <typename T>
class KeyTest : public ::testing::Test
{
public:
    virtual ~KeyTest() {}
    T value_;
};

typedef ::testing::Types<SecretKey, PrivateKey, PublicKey> MyTypes;
TYPED_TEST_CASE(KeyTest, MyTypes);

TYPED_TEST(KeyTest, main)
{
    // error on construction
    EXPECT_THROW(SecretKey(make_shared<ByteArray>(0), "foobar"), IllegalArgumentException);

    // null key
    const TypeParam nullSecretKey;
    EXPECT_TRUE(nullSecretKey.isNull());
    EXPECT_FALSE(nullSecretKey.getEncoded());
    EXPECT_EQ("NULL", nullSecretKey.getAlgorithm());
    EXPECT_EQ(TypeParam::DEFAULT_FORMAT, nullSecretKey.getFormat());

    // normal key
    shared_ptr<ByteArray> bytes = make_shared<ByteArray>(16);
    Random random;
    random.nextBytes(*bytes);
    const TypeParam skey(bytes, "foobar");
    EXPECT_FALSE(skey.isNull());
    EXPECT_EQ(*bytes, *skey.getEncoded());
    EXPECT_EQ("foobar", skey.getAlgorithm());
    EXPECT_EQ(TypeParam::DEFAULT_FORMAT, skey.getFormat());

    // copy constructor
    const TypeParam skeyCopy1(skey);
    EXPECT_EQ(skey.isNull(), skeyCopy1.isNull());
    EXPECT_EQ(*skey.getEncoded(), *skeyCopy1.getEncoded());
    EXPECT_EQ(skey.getAlgorithm(), skeyCopy1.getAlgorithm());
    EXPECT_EQ(skey.getFormat(), skeyCopy1.getFormat());

    // assignment operator
    TypeParam skeyCopy2 = skey;
    EXPECT_EQ(skey.isNull(), skeyCopy2.isNull());
    EXPECT_EQ(*skey.getEncoded(), *skeyCopy2.getEncoded());
    EXPECT_EQ(skey.getAlgorithm(), skeyCopy2.getAlgorithm());
    EXPECT_EQ(skey.getFormat(), skeyCopy2.getFormat());

    // operator== and operator!=
    EXPECT_TRUE(skey == skeyCopy2);
    EXPECT_FALSE(skey == nullSecretKey);
    EXPECT_FALSE(skey != skeyCopy2);
    EXPECT_TRUE(skey != nullSecretKey);
}

} /* namespace crypto */
} /* namespace msl */
} /* namespace netflix */
