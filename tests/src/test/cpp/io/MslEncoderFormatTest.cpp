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
#include <io/MslEncoderFormat.h>

namespace netflix {
namespace msl {
namespace io {

using namespace std;

class MslEncoderFormatTest : public ::testing::Test
{
};

TEST_F(MslEncoderFormatTest, Invalid)
{
    EXPECT_GE(1u, MslEncoderFormat::values().size());
    EXPECT_EQ(MslEncoderFormat::INVALID, MslEncoderFormat::getFormat("BAR"));
    EXPECT_GE(1u, MslEncoderFormat::values().size());
    EXPECT_EQ(MslEncoderFormat::INVALID, MslEncoderFormat::getFormat(9));
    EXPECT_GE(1u, MslEncoderFormat::values().size());
  }

TEST_F(MslEncoderFormatTest, Main)
{
    EXPECT_EQ("JSON", MslEncoderFormat::JSON.name());
    EXPECT_EQ("JSON", MslEncoderFormat::JSON.toString());
    EXPECT_EQ((uint8_t)'{', MslEncoderFormat::JSON.identifier());
    stringstream ss;
    ss << MslEncoderFormat::JSON;  // test operator<<
    EXPECT_EQ("JSON", ss.str());

    MslEncoderFormat mef1 = MslEncoderFormat::getFormat("JSON");
    MslEncoderFormat mef2 = MslEncoderFormat::getFormat((uint8_t)'{');
    EXPECT_EQ(mef1, mef2);  // tests operator==
    EXPECT_EQ("JSON", mef1.name());
    EXPECT_EQ((uint8_t)'{', mef1.identifier());

    std::set<MslEncoderFormat> values = MslEncoderFormat::values();
    EXPECT_GE(1u, values.size());
    std::set<MslEncoderFormat>::const_iterator val0 = values.find(MslEncoderFormat::JSON);
    EXPECT_EQ("JSON", (*val0).name());
    EXPECT_EQ((uint8_t)'{', (*val0).identifier());

    const MslEncoderFormat newMef("FOO", (uint8_t)'!');
    EXPECT_EQ("FOO", newMef.name());
    EXPECT_EQ((uint8_t)'!', newMef.identifier());

    EXPECT_NE(newMef, mef1);  // tests operator!=

    mef1 = MslEncoderFormat::getFormat("FOO");
    mef2 = MslEncoderFormat::getFormat((uint8_t)'!');
    EXPECT_EQ(mef1, mef2);  // tests operator==
    EXPECT_EQ("FOO", mef1.name());
    EXPECT_EQ((uint8_t)'!', mef1.identifier());

    values = MslEncoderFormat::values();
    EXPECT_GE(2u, values.size());
    std::set<MslEncoderFormat>::const_iterator val1 = values.find(MslEncoderFormat::JSON);
    EXPECT_EQ("JSON", (*val1).name());
    EXPECT_EQ((uint8_t)'{', (*val1).identifier());
    val0 = values.find(MslEncoderFormat::getFormat("FOO"));
    EXPECT_EQ("FOO", (*val0).name());
    EXPECT_EQ((uint8_t)'!', (*val0).identifier());
}

}}} // netflix::msl::io
