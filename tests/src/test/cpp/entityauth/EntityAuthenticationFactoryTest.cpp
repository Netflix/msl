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
#include <entityauth/EntityAuthenticationFactory.h>

using namespace std;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {

struct MyEntityAuthenticationFactory : public EntityAuthenticationFactory
{
    MyEntityAuthenticationFactory(const EntityAuthenticationScheme& scheme)
    : EntityAuthenticationFactory(scheme) {}
    virtual shared_ptr<EntityAuthenticationData> createData(shared_ptr<util::MslContext>,
            shared_ptr<io::MslObject>)
    { return shared_ptr<EntityAuthenticationData>(); }
    virtual shared_ptr<crypto::ICryptoContext> getCryptoContext(shared_ptr<util::MslContext>,
            shared_ptr<EntityAuthenticationData>)
    { return shared_ptr<crypto::ICryptoContext>(); }
};

}

class EntityAuthenticationFactoryTest : public ::testing::Test
{
};

TEST_F(EntityAuthenticationFactoryTest, main)
{
    MyEntityAuthenticationFactory meaf(EntityAuthenticationScheme::RSA);
    EXPECT_EQ(EntityAuthenticationScheme::RSA, meaf.getScheme());
}

}}} // namespace netflix::msl::entityauth
