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
#include <Exception.h>
#include <Macros.h>

using namespace std;

namespace netflix {
namespace msl {

class ExceptionTest : public ::testing::Test
{
};

TEST_F(ExceptionTest, Constructors)
{
    // Exception from std::exception
    std::exception e;
    Exception ex0(e);
    EXPECT_EQ(string("std::exception"), ex0.what());
    EXPECT_EQ(shared_ptr<IException>(), ex0.getCause());

    // Exception from std::runtime_error
    Exception ex1(std::runtime_error("foobar"));
    EXPECT_EQ(string("foobar"), ex1.what());
    EXPECT_EQ(shared_ptr<IException>(), ex1.getCause());

    // Exception from details string
    Exception ex2("barfoo");
    EXPECT_EQ(string("barfoo"), ex2.what());
    EXPECT_EQ(shared_ptr<IException>(), ex2.getCause());

    // Exception from details string and Exception cause
    Exception ex3("fubar", ex2);
    EXPECT_EQ(string("fubar"), ex3.what());
    shared_ptr<IException> exCause = ex3.getCause();
    EXPECT_NE(shared_ptr<IException>(), exCause);
    EXPECT_TRUE(instanceof<Exception>(exCause.get()));
    EXPECT_EQ(string("barfoo"), exCause->what());
}

TEST_F(ExceptionTest, Chaining)
{
    Exception ex1("1");
    Exception ex2("2", ex1);
    Exception ex3("3", ex2);
    Exception ex4("4", ex3);
    EXPECT_EQ(4u, ex4.getDepth());
    EXPECT_EQ(string("4"), ex4.what());
    shared_ptr<IException> exCause = ex4.getCause();
    exCause = exCause->getCause();
    EXPECT_EQ(string("2"), exCause->what());
}

TEST_F(ExceptionTest, Clone)
{
    shared_ptr<IException> ex1(make_shared<Exception>("1"));
    Exception ex2("2", *ex1);

    // make a clone of ex2
    shared_ptr<IException> ex2Clone = ex2.clone();
    EXPECT_TRUE(instanceof<Exception>(ex2Clone.get()));
    EXPECT_EQ(2u, ex2Clone->getDepth());
    EXPECT_EQ(string("2"), ex2Clone->what());
    EXPECT_EQ(string("1"), ex2Clone->getCause()->what());

    // kill the original exception used as ex2's cause to make sure it was copied
    ex1.reset();
    EXPECT_EQ(2u, ex2Clone->getDepth());
    EXPECT_EQ(string("2"), ex2Clone->what());
    EXPECT_EQ(string("1"), ex2Clone->getCause()->what());
}

} /* namespace msl */
} /* namespace netflix */
