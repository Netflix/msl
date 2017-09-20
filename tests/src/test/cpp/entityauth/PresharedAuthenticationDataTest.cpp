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

#include <entityauth/EntityAuthenticationScheme.h>
#include <gtest/gtest.h>
#include <entityauth/PresharedAuthenticationData.h>
#include <io/DefaultMslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <MslEncodingException.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {
const string KEY_IDENTITY = "identity";
}

class PresharedAuthenticationDataTest : public ::testing::Test
{
public:
    PresharedAuthenticationDataTest() : format_(MslEncoderFormat::JSON) {}
protected:
    shared_ptr<MslEncoderFactory> encoder_ = make_shared<DefaultMslEncoderFactory>();
    const MslEncoderFormat format_;
};

TEST_F(PresharedAuthenticationDataTest, ctors)
{
    PresharedAuthenticationData pad1("pad1");
    EXPECT_EQ("pad1", pad1.getIdentity());
    EXPECT_EQ(EntityAuthenticationScheme::PSK, pad1.getScheme());

    shared_ptr<MslObject> mo = make_shared<MslObject>();
    try {
        PresharedAuthenticationData pad2(mo);
        ADD_FAILURE() << "PresharedAuthenticationData ctor should have thrown without valid MslObject";
    }
    catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError()) << e.getMessageId();
    }

    mo->put<string>(KEY_IDENTITY, "pad3");
    PresharedAuthenticationData pad3(mo);
    EXPECT_EQ("pad3", pad3.getIdentity());
    EXPECT_EQ(EntityAuthenticationScheme::PSK, pad3.getScheme());
}

TEST_F(PresharedAuthenticationDataTest, operatorEquals)
{
    PresharedAuthenticationData pad1("pad1");
    PresharedAuthenticationData pad2("pad1");
    PresharedAuthenticationData pad3("pad3");
    EXPECT_EQ(pad1, pad2);
    EXPECT_NE(pad1, pad3);
}


}}} // namespace entityauth
