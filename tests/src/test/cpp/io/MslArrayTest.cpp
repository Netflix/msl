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
#include <io/MslArray.h>
#include <io/MslEncodable.h>
#include <io/MslObject.h>
#include <io/MslEncoderException.h>
#include <IllegalArgumentException.h>
#include <iosfwd>
#include <list>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

class MslArrayTest : public ::testing::Test
{
};

TEST_F(MslArrayTest, Empty)
{
    MslArray ma;
    EXPECT_EQ(0u, ma.size());
}

TEST_F(MslArrayTest, PutGet)
{
    MslArray ma;

    EXPECT_THROW(ma.put(-2, VariantFactory::createNull()), IllegalArgumentException);

    const Variant zero = VariantFactory::create<int32_t>(0);
    ma.put(0, zero);
    EXPECT_EQ(1u, ma.size());

    // implicit empty fill
    const Variant four = VariantFactory::create<int32_t>(4);
    ma.put(4, four);
    EXPECT_EQ(5u, ma.size());

    // replace
    const Variant two = VariantFactory::create<int32_t>(2);
    ma.put(2, two);
    EXPECT_EQ(5u, ma.size());

    // append
    const Variant five = VariantFactory::create<int32_t>(5);
    ma.put(-1, five);
    EXPECT_EQ(6u, ma.size());

    // typed put (replace)
    ma.put<std::string>(5, "five");
    EXPECT_EQ(6u, ma.size()); // no change to size

    // isNull()
    EXPECT_THROW(ma.isNull(-1), IllegalArgumentException); // bad index
    EXPECT_THROW(ma.isNull(9999), IllegalArgumentException); // bad index
    for (size_t i=0; i < ma.size() ; ++i)
    {
        if (i==1 || i==3)
            EXPECT_TRUE(ma.isNull((int)i));
        else
            EXPECT_FALSE(ma.isNull((int)i));
    }

    // Variant get
    EXPECT_THROW(ma.get(-1), IllegalArgumentException); // bad index
    EXPECT_THROW(ma.get(9999), IllegalArgumentException); // bad index
    EXPECT_THROW(ma.get(1), MslEncoderException); // empty slot
    const Variant two_ = ma.get(2);
    EXPECT_EQ(two.get<int>(), two_.get<int>());

    // typed get
    EXPECT_THROW(ma.getInt(5), MslEncoderException);  // bad type
    const std::string fiveStr = ma.getString(5);
    EXPECT_EQ("five", fiveStr);
}

TEST_F(MslArrayTest, Opt)
{
    MslArray ma;
    ma.put<int32_t>(0, 0);
    ma.put<std::string>(1, "one");
    ma.put<int64_t>(3, 3ull);
    // index 2 contains empty
    EXPECT_EQ(4u, ma.size());

    // bad indexes
    EXPECT_THROW(ma.opt(-1), IllegalArgumentException); // bad index
    EXPECT_THROW(ma.opt(9999), IllegalArgumentException); // bad index

    // can get empty
    EXPECT_NO_THROW(ma.opt(2));
    const Variant twoVal = ma.opt(2);
    EXPECT_TRUE(twoVal.isNull());

    // wrong type
    std::string zeroVal = ma.optString(0);
    EXPECT_TRUE(zeroVal.empty());

    // default if empty
    const int64_t twoVali64 = ma.optLong(2, 99);
    EXPECT_EQ(99u, twoVali64);

    // default if wrong type
    const std::string zeroValStr = ma.optString(0, "foobar");
    EXPECT_EQ("foobar", zeroValStr);

}

class Six : public MslEncodable
{
    virtual shared_ptr<ByteArray> toMslEncoding(shared_ptr<MslEncoderFactory> /*encoder*/,
            const MslEncoderFormat& /*format*/) const {
        return make_shared<ByteArray>();
    }
};
bool operator==(const Six&, const Six&) {return true;}

TEST_F(MslArrayTest, Remove)
{
    MslArray ma;
    ma.put<int32_t>(-1, 0);
    ma.put<int32_t>(-1,1);
    ma.put<int64_t>(-1, 2);
    ma.put<double>(-1, 3);
    ma.put(-1, VariantFactory::createNull());
    ma.put<std::string>(-1, "five");
    shared_ptr<MslEncodable> six = make_shared<Six>();
    ma.put(-1, six);
    EXPECT_EQ(7u, ma.size());

    // bad indexes
    EXPECT_THROW(ma.remove(-2), IllegalArgumentException); // bad index
    EXPECT_THROW(ma.remove(9999), IllegalArgumentException); // bad index

    // remove last
    Variant removed = VariantFactory::createNull();
    EXPECT_NO_THROW(removed = ma.remove(-1));
    EXPECT_EQ(6u, ma.size());
    EXPECT_TRUE(removed.isType<shared_ptr<MslEncodable>>());

    // remove middle
    removed = ma.remove(3);
    EXPECT_EQ(5u, ma.size());
    EXPECT_TRUE(removed.isType<double>());
    EXPECT_EQ(3, removed.getOpt<double>());

    // remove first
    removed = ma.remove(0);
    EXPECT_EQ(4u, ma.size());
    EXPECT_TRUE(removed.isType<int32_t>());
    EXPECT_EQ(0, removed.getOpt<int32_t>());
}

TEST_F(MslArrayTest, ToString)
{
    MslArray mslAry0;
    EXPECT_EQ("[]", mslAry0.toString());

    MslArray mslAry1;
    mslAry1.put<double>(-1, 0);
    EXPECT_EQ("[0]", mslAry1.toString());

    shared_ptr<MslArray> mslAry2 = make_shared<MslArray>();
    mslAry2->put<int32_t>(-1, 0);
    mslAry2->put<double>(-1, 1.11);
    mslAry2->put<std::string>(-1, "2");
    EXPECT_EQ("[0,1.11,\"2\"]", mslAry2->toString());

    shared_ptr<MslObject> mslObj2 = make_shared<MslObject>();
    mslObj2->put<int32_t>("one", 1);
    mslObj2->put<double>("two", 2.22);
    mslObj2->put<std::string>("three", "3");

    shared_ptr<MslArray> mslAry3 = make_shared<MslArray>();
    mslAry3->put<std::string>(-1, "a");
    mslAry3->put(-1, mslAry2);
    mslAry3->put(-1, mslObj2);
    EXPECT_EQ("[\"a\",[0,1.11,\"2\"],{\"one\":1,\"three\":\"3\",\"two\":2.22}]", mslAry3->toString());
}

TEST_F(MslArrayTest, Equality)
{
    const MslArray mslAry0;
    const MslArray mslAry1;
    EXPECT_EQ(mslAry0, mslAry0);
    EXPECT_EQ(mslAry0, mslAry1);
    const MslArray mslAry2 = mslAry0; // shallow copy, share underlying data
    EXPECT_EQ(mslAry0, mslAry2);

    shared_ptr<MslObject> mslObj1 = make_shared<MslObject>();
    mslObj1->put<int32_t>("a", 0);
    mslObj1->put<double>("b", 1.11);
    mslObj1->put<std::string>("c", "2");

    shared_ptr<MslObject> mslObj2 = make_shared<MslObject>();
    mslObj2->put<int32_t>("a", 0);
    mslObj2->put<double>("b", 1.11);
    mslObj2->put<std::string>("c", "2");

    shared_ptr<ByteArray> ba = make_shared<ByteArray>();
    ba->push_back(1);
    ba->push_back(2);

    shared_ptr<MslArray> mslAry3 = make_shared<MslArray>();
    mslAry3->put<int32_t>(-1, 1);
    mslAry3->put(-1, mslObj1);
    mslAry3->put(-1, ba);

    shared_ptr<MslArray> mslAry4 = make_shared<MslArray>();
    mslAry4->put<int32_t>(-1, 1);
    mslAry4->put(-1, mslObj2);
    mslAry4->put(-1, ba);

    // element b has identical contents, element c has identical object
    EXPECT_EQ(mslAry3, mslAry4);

    // if we change mslObj2, we change mslAry4's second element, so the
    // top-level objects will no longer be equal
    mslObj2->put<int64_t>("d", 999);
    EXPECT_NE(mslAry3, mslAry4);
}

TEST_F(MslArrayTest, ReplaceElement)
{
    MslArray ma;
    ma.put<int>(-1, 1);
    EXPECT_EQ(1u, ma.size());
    EXPECT_EQ(1, ma.getInt(0));
    ma.put<int>(0, 2);
    ma.put<int>(0, 3);
    ma.put<int>(0, 4);
    EXPECT_EQ(1u, ma.size());
    EXPECT_EQ(4, ma.getInt(0));
}

TEST_F(MslArrayTest, Constructors)
{
    list<int> vl1;
    vl1.push_back(0);
    vl1.push_back(1);
    vl1.push_back(2);
    vl1.push_back(3);
    MslArray ma1(vl1);
    EXPECT_EQ(4u, ma1.size());
    EXPECT_NO_THROW(ma1.getInt(2));
    EXPECT_EQ(2, ma1.getInt(2));
    EXPECT_EQ(2, ma1.getLong(2));

    set<string> ss1;
    ss1.insert("aa");
    ss1.insert("bb");
    ss1.insert("cc");
    ss1.insert("dd");
    MslArray ma2(ss1);
    EXPECT_EQ(4u, ma2.size());
    EXPECT_NO_THROW(ma2.getString(2));
    EXPECT_EQ("cc", ma2.getString(2));
    EXPECT_THROW(ma2.getLong(2), MslEncoderException);
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
