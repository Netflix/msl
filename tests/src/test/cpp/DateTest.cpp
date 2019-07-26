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
#include <Date.h>
#include <sys/time.h>
#include <iostream>
#include <memory>

using namespace std;

namespace netflix {
namespace msl {

namespace {
int64_t now()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return static_cast<int64_t>(static_cast<uint64_t>(tp.tv_sec) * 1000ull + static_cast<uint64_t>(tp.tv_usec) / 1000ull);
}
}

class DateTest : public ::testing::Test
{
};

TEST_F(DateTest, comparison)
{
    shared_ptr<Date> nowDate = Date::now();
    const int64_t nowTime = now();
    const int64_t laterTime = nowTime + 1000;
    shared_ptr<Date> laterDate = make_shared<Date>(laterTime);

    // equality
    EXPECT_TRUE(*nowDate == *nowDate);
    EXPECT_FALSE(*nowDate == *laterDate);
    EXPECT_TRUE(*nowDate != *laterDate);

    // less than
    EXPECT_TRUE(*nowDate < *laterDate);
    EXPECT_TRUE(*nowDate <= *laterDate);

    // greater than
    EXPECT_FALSE(*nowDate > *laterDate);
    EXPECT_FALSE(*nowDate >= *laterDate);

    // before / after
    EXPECT_TRUE(nowDate->before(laterDate));
    EXPECT_FALSE(nowDate->after(laterDate));
    EXPECT_TRUE(laterDate->after(nowDate));
    EXPECT_FALSE(laterDate->before(nowDate));

    // compareTo
    EXPECT_EQ(1, laterDate->compareTo(nowDate));
    EXPECT_EQ(-1, nowDate->compareTo(laterDate));
    EXPECT_EQ(-1, nowDate->compareTo(laterDate));
    EXPECT_EQ(1, laterDate->compareTo(nowDate));
    EXPECT_EQ(0, nowDate->compareTo(nowDate));
}

TEST_F(DateTest, toString)
{
    const int64_t dateVal = 1472833162115;
    const string dateStr = "Fri Sep  2 16:19:22 GMT 2016";
    EXPECT_EQ(dateStr, make_shared<Date>(dateVal)->toString());
    stringstream ss;
    ss << make_shared<Date>(dateVal);
    EXPECT_EQ(dateStr, ss.str());
}

} /* namespace msl */
} /* namespace netflix */
