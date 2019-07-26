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
#include <entityauth/EntityAuthenticationScheme.h>
#include <algorithm>
#include <list>
#include <set>

using std::sort;

namespace netflix {
namespace msl {
namespace entityauth {

using namespace std;

namespace {
template<typename T, size_t N>
T * end(T (&ra)[N]) {
    return ra + N;
}
}

class EntityAuthenticationSchemeTest : public ::testing::Test
{
};

TEST_F(EntityAuthenticationSchemeTest, statics)
{
    EXPECT_EQ("PSK", EntityAuthenticationScheme::PSK.name());
    EXPECT_EQ("PSK", EntityAuthenticationScheme::PSK.toString());
    EXPECT_TRUE(EntityAuthenticationScheme::PSK.encrypts());
    EXPECT_TRUE(EntityAuthenticationScheme::PSK.protectsIntegrity());

    EXPECT_EQ("PSK_PROFILE", EntityAuthenticationScheme::PSK_PROFILE.name());
    EXPECT_EQ("PSK_PROFILE", EntityAuthenticationScheme::PSK_PROFILE.toString());
    EXPECT_TRUE(EntityAuthenticationScheme::PSK_PROFILE.encrypts());
    EXPECT_TRUE(EntityAuthenticationScheme::PSK_PROFILE.protectsIntegrity());

    EXPECT_EQ("X509", EntityAuthenticationScheme::X509.name());
    EXPECT_EQ("X509", EntityAuthenticationScheme::X509.toString());
    EXPECT_FALSE(EntityAuthenticationScheme::X509.encrypts());
    EXPECT_TRUE(EntityAuthenticationScheme::X509.protectsIntegrity());

    EXPECT_EQ("RSA", EntityAuthenticationScheme::RSA.name());
    EXPECT_EQ("RSA", EntityAuthenticationScheme::RSA.toString());
    EXPECT_FALSE(EntityAuthenticationScheme::RSA.encrypts());
    EXPECT_TRUE(EntityAuthenticationScheme::RSA.protectsIntegrity());

    EXPECT_EQ("NONE", EntityAuthenticationScheme::NONE.name());
    EXPECT_EQ("NONE", EntityAuthenticationScheme::NONE.toString());
    EXPECT_FALSE(EntityAuthenticationScheme::NONE.encrypts());
    EXPECT_FALSE(EntityAuthenticationScheme::NONE.protectsIntegrity());

    EXPECT_EQ("NONE_SUFFIXED", EntityAuthenticationScheme::NONE_SUFFIXED.name());
    EXPECT_EQ("NONE_SUFFIXED", EntityAuthenticationScheme::NONE_SUFFIXED.toString());
    EXPECT_FALSE(EntityAuthenticationScheme::NONE_SUFFIXED.encrypts());
    EXPECT_FALSE(EntityAuthenticationScheme::NONE_SUFFIXED.protectsIntegrity());

    EXPECT_EQ("MT_PROTECTED", EntityAuthenticationScheme::MT_PROTECTED.name());
    EXPECT_EQ("MT_PROTECTED", EntityAuthenticationScheme::MT_PROTECTED.toString());
    EXPECT_FALSE(EntityAuthenticationScheme::MT_PROTECTED.encrypts());
    EXPECT_FALSE(EntityAuthenticationScheme::MT_PROTECTED.protectsIntegrity());

    EXPECT_EQ("PROVISIONED", EntityAuthenticationScheme::PROVISIONED.name());
    EXPECT_EQ("PROVISIONED", EntityAuthenticationScheme::PROVISIONED.toString());
    EXPECT_FALSE(EntityAuthenticationScheme::PROVISIONED.encrypts());
    EXPECT_FALSE(EntityAuthenticationScheme::PROVISIONED.protectsIntegrity());

    EXPECT_EQ("INVALID", EntityAuthenticationScheme::INVALID.name());
    EXPECT_EQ("INVALID", EntityAuthenticationScheme::INVALID.toString());
    EXPECT_FALSE(EntityAuthenticationScheme::INVALID.encrypts());
    EXPECT_FALSE(EntityAuthenticationScheme::INVALID.protectsIntegrity());
}

TEST_F(EntityAuthenticationSchemeTest, getScheme)
{
    const char *ninit[] = {"PSK", "PSK_PROFILE", "X509", "RSA", "NONE",
            "NONE_SUFFIXED", "MT_PROTECTED", "PROVISIONED"};
    const vector<string> name(ninit, end(ninit));
    for (vector<string>::const_iterator it = name.begin(); it != name.end(); ++it)
        EXPECT_EQ(*it, EntityAuthenticationScheme::getScheme(*it).name());
    EXPECT_EQ(EntityAuthenticationScheme::INVALID, EntityAuthenticationScheme::getScheme("foo"));
}

TEST_F(EntityAuthenticationSchemeTest, values)
{
    const EntityAuthenticationScheme schemesInit[] = {
        EntityAuthenticationScheme::PSK,
        EntityAuthenticationScheme::PSK_PROFILE,
        EntityAuthenticationScheme::X509,
        EntityAuthenticationScheme::RSA,
        EntityAuthenticationScheme::NONE,
        EntityAuthenticationScheme::NONE_SUFFIXED,
        EntityAuthenticationScheme::MT_PROTECTED,
        EntityAuthenticationScheme::PROVISIONED
    };
    const set<EntityAuthenticationScheme> schemes(schemesInit, end(schemesInit));
    const vector<EntityAuthenticationScheme> valuesVec = EntityAuthenticationScheme::values();
    const set<EntityAuthenticationScheme> values(valuesVec.begin(), valuesVec.end());
    for (set<EntityAuthenticationScheme>::const_iterator needle = schemes.begin();
    	 needle != schemes.end();
    	 ++needle)
    {
    	bool found = false;
    	for (vector<EntityAuthenticationScheme>::const_iterator haystack = valuesVec.begin();
    		 haystack != valuesVec.end();
    		 ++haystack)
    	{
    		if (*needle == *haystack) {
    			found = true;
    			break;
    		}
    	}
    	EXPECT_TRUE(found);
    }
}

}}} // namespace netflix::msl::entityauth
