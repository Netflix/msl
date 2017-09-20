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
#include <userauth/UserAuthenticationScheme.h>
#include <set>
#include <vector>

using namespace std;

namespace netflix {
namespace msl {
namespace userauth {

namespace {
template<typename T, size_t N>
T * end(T (&ra)[N]) {
    return ra + N;
}
}

class UserAuthenticationSchemeTest : public ::testing::Test
{
};

// FIXME TODO: Need tests

TEST_F(UserAuthenticationSchemeTest, statics)
{
    EXPECT_EQ("EMAIL_PASSWORD", UserAuthenticationScheme::EMAIL_PASSWORD.name());
    EXPECT_EQ("EMAIL_PASSWORD", UserAuthenticationScheme::EMAIL_PASSWORD.toString());

    EXPECT_EQ("USER_ID_TOKEN", UserAuthenticationScheme::USER_ID_TOKEN.name());
    EXPECT_EQ("USER_ID_TOKEN", UserAuthenticationScheme::USER_ID_TOKEN.toString());

    EXPECT_EQ("INVALID", UserAuthenticationScheme::INVALID.name());
    EXPECT_EQ("INVALID", UserAuthenticationScheme::INVALID.toString());
}

TEST_F(UserAuthenticationSchemeTest, getScheme)
{
    const char *ninit[] = {"EMAIL_PASSWORD", "USER_ID_TOKEN"};
    const vector<string> name(ninit, end(ninit));
    for (vector<string>::const_iterator it = name.begin(); it != name.end(); ++it)
        EXPECT_EQ(*it, UserAuthenticationScheme::getScheme(*it).name());
    EXPECT_EQ(UserAuthenticationScheme::INVALID, UserAuthenticationScheme::getScheme("foo"));
}

TEST_F(UserAuthenticationSchemeTest, values)
{
    const UserAuthenticationScheme schemesInit[] = {
        UserAuthenticationScheme::EMAIL_PASSWORD,
        UserAuthenticationScheme::USER_ID_TOKEN,
    };
    const set<UserAuthenticationScheme> schemes(schemesInit, end(schemesInit));
    const vector<UserAuthenticationScheme> valuesVec = UserAuthenticationScheme::values();
    for (set<UserAuthenticationScheme>::const_iterator needle = schemes.begin();
    	 needle != schemes.end();
    	 ++needle)
    {
    	bool found = false;
    	for (vector<UserAuthenticationScheme>::const_iterator haystack = valuesVec.begin();
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

}}} // namespace netflix::msl::userauth
