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
#include <Macros.h>
#include <MslErrorResponseException.h>

using namespace std;

namespace netflix
{
namespace msl
{

class MslErrorResponseExceptionTest : public ::testing::Test
{
};

TEST_F(MslErrorResponseExceptionTest, Constructors)
{
    Exception ex1("ex1");
    Exception ex2("ex2");
    MslErrorResponseException merex1("foobar", ex1, ex2);
    EXPECT_EQ(string("foobar"), merex1.what());
    EXPECT_NE(shared_ptr<IException>(), merex1.getCause());
    EXPECT_EQ(std::string("ex1"), merex1.getCause()->what());
    EXPECT_EQ(std::string("ex2"), merex1.getRequestCause()->what());
}

TEST_F(MslErrorResponseExceptionTest, Clone)
{
    Exception ex1("ex1");
    Exception ex2("ex2");
    MslErrorResponseException merex1("foobar", ex1, ex2);
    shared_ptr<IException> merex1Clone = merex1.clone();
    EXPECT_TRUE(instanceof<MslErrorResponseException>(merex1Clone.get()));
}

} /* namespace msl */
} /* namespace netflix */
