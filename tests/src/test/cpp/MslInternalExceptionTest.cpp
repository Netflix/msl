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
#include <MslInternalException.h>

using namespace std;

namespace netflix {
namespace msl {

class MslInternalExceptionTest : public ::testing::Test
{
};

TEST_F(MslInternalExceptionTest, Constructors)
{

    // MslInternalException from details string
    MslInternalException miex1("foobar");
    EXPECT_EQ(string("foobar"), miex1.what());
    EXPECT_EQ(shared_ptr<IException>(), miex1.getCause());

    // MslInternalException from details string and Exception cause
    Exception ex1("barfoo");
    MslInternalException miex2("fubar", ex1);
    EXPECT_EQ(string("fubar"), miex2.what());
    shared_ptr<IException> exCause = miex2.getCause();
    EXPECT_NE(shared_ptr<IException>(), exCause);
    EXPECT_TRUE(instanceof<Exception>(exCause.get()));
    EXPECT_EQ(string("barfoo"), exCause->what());
}

TEST_F(MslInternalExceptionTest, Clone)
{
    MslInternalException miex1("foobar");
    shared_ptr<IException> miex1Clone = miex1.clone();
    EXPECT_TRUE(instanceof<MslInternalException>(miex1Clone.get()));
}

}} // namespace netflix::msl
