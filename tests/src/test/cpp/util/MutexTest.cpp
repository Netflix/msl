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
#include <MslInternalException.h>
#include <util/Mutex.h>

using namespace netflix::msl::util;

class MslMutexTest : public ::testing::Test
{
};

TEST_F(MslMutexTest, MslMutex)
{
    MslMutex mslMutex;
    EXPECT_FALSE(mslMutex.islocked());
    EXPECT_NO_THROW(mslMutex.unlock());

    EXPECT_NO_THROW(mslMutex.lock());
    EXPECT_TRUE(mslMutex.islocked());

    EXPECT_NO_THROW(mslMutex.lock());
    EXPECT_TRUE(mslMutex.islocked());

    EXPECT_NO_THROW(mslMutex.unlock());
    EXPECT_TRUE(mslMutex.islocked());

    EXPECT_NO_THROW(mslMutex.unlock());
    EXPECT_FALSE(mslMutex.islocked());
}

TEST_F(MslMutexTest, LockGuard)
{
    MslMutex mslMutex;
    EXPECT_FALSE(mslMutex.islocked());
    {
        LockGuard lockGuard(mslMutex);
        EXPECT_TRUE(mslMutex.islocked());
    }
    EXPECT_FALSE(mslMutex.islocked());
}

TEST_F(MslMutexTest, synchronized)
{
    MslMutex mslMutex;
    EXPECT_FALSE(mslMutex.islocked());
    synchronized(mslMutex,
    {
        EXPECT_TRUE(mslMutex.islocked());
    });
    EXPECT_FALSE(mslMutex.islocked());
}
