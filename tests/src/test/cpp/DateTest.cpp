/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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

TEST_F(DateTest, createAndCopy)
{
    const Date nowDate = Date::now();
    EXPECT_FALSE(nowDate.isNull());
    const int64_t nowTime = now();

    Date nowDate2(nowDate);  // copy ctor
    EXPECT_EQ(nowDate, nowDate2);
    EXPECT_TRUE(nowDate2 == nowDate);
    nowDate2 = Date(nowTime); // ctor and operator=
    EXPECT_EQ(nowDate, nowDate2);
    EXPECT_TRUE(nowDate2 == nowDate);
    nowDate2 = nowDate.clone(); // clone() and operator=
    EXPECT_EQ(nowDate, nowDate2);
    EXPECT_TRUE(nowDate2 == nowDate);
    EXPECT_FALSE(nowDate2 != nowDate);
    EXPECT_TRUE(nowDate2 <= nowDate);
    EXPECT_TRUE(nowDate2 >= nowDate);
    EXPECT_TRUE(nowDate2.equals(nowDate));
    EXPECT_EQ(0, nowDate2.compareTo(nowDate));
    EXPECT_EQ(nowTime, nowDate.getTime());
}

TEST_F(DateTest, comparison)
{
    const Date nowDate = Date::now();
    const int64_t nowTime = now();
    const int64_t laterTime = nowTime + 1000;
    const Date laterDate = Date(laterTime);

    // equality
    EXPECT_TRUE(nowDate != laterDate);
    EXPECT_FALSE(nowDate.equals(laterDate));
    EXPECT_FALSE(nowDate == laterDate);
    EXPECT_FALSE(nowDate.equals(laterDate));

    // less than
    EXPECT_TRUE(nowDate < laterDate);
    EXPECT_TRUE(nowDate <= laterDate);

    // greater than
    EXPECT_FALSE(nowDate > laterDate);
    EXPECT_FALSE(nowDate >= laterDate);

    // before / after
    EXPECT_TRUE(nowDate.before(laterDate));
    EXPECT_FALSE(nowDate.after(laterDate));
    EXPECT_TRUE(laterDate.after(nowDate));
    EXPECT_FALSE(laterDate.before(nowDate));

    // compareTo
    EXPECT_EQ(1, laterDate.compareTo(nowDate));
    EXPECT_EQ(-1, nowDate.compareTo(laterDate));
    EXPECT_EQ(-1, nowDate.compareTo(laterDate));
    EXPECT_EQ(1, laterDate.compareTo(nowDate));
    EXPECT_EQ(0, nowDate.compareTo(nowDate));
}

TEST_F(DateTest, toString)
{
    const int64_t dateVal = 1472833162115;
    const string dateStr = "Fri Sep  2 16:19:22 GMT 2016";
    EXPECT_EQ(dateStr, Date(dateVal).toString());
    stringstream ss;
    ss << Date(dateVal);
    EXPECT_EQ(dateStr, ss.str());

    const Date nullDate = Date::null();
    EXPECT_EQ("null", nullDate.toString());
}

TEST_F(DateTest, null)
{
    const Date date1(1234);
    EXPECT_FALSE(date1.isNull());
    EXPECT_EQ(1234, date1.getTime());
    const Date date2(5678);
    EXPECT_FALSE(date2.isNull());
    EXPECT_EQ(5678, date2.getTime());
    const Date nullDate1 = Date::null();
    EXPECT_TRUE(nullDate1.isNull());
    EXPECT_EQ(nullDate1.getTime(), -1);
    const Date nullDate2(5678, true);
    EXPECT_TRUE(nullDate2.isNull());
    EXPECT_EQ(nullDate2.getTime(), 5678);

    // operator==
    // nonnull nonnull, different time, == false
    EXPECT_FALSE(date1 == date2);
    // nonnull nonnull, same time, == true
    EXPECT_TRUE(date1 == date1);
    // null nonnull, different time, == false
    EXPECT_FALSE(nullDate1 == date1);
    // null nonnull, same time, == false
    EXPECT_FALSE(nullDate2 == date2);
    // null null, different time, == true
    EXPECT_TRUE(nullDate1 == nullDate2);
    // null null, same time, == true
    EXPECT_TRUE(nullDate1 == nullDate1);

    // copy ctor
    const Date nullDate22(nullDate2);
    EXPECT_TRUE(nullDate22.isNull());
    EXPECT_EQ(nullDate22.getTime(), 5678);
    EXPECT_EQ(nullDate2, nullDate22);

    // operator=
    Date nullDate11;
    EXPECT_NE(nullDate1, nullDate11);
    nullDate11 = nullDate1;
    EXPECT_TRUE(nullDate11.isNull());
    EXPECT_EQ(nullDate11.getTime(), -1);
    EXPECT_EQ(nullDate1, nullDate11);
}

} /* namespace msl */
} /* namespace netflix */
