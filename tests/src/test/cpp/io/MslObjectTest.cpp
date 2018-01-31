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
#include <io/MslObject.h>
#include <util/Base64.h>
#include <algorithm>
#include <string>
#include <utility>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

class MslObjectTest : public ::testing::Test
{
};

TEST_F(MslObjectTest, Ctor)
{
    MslObject::MapType map;
    map.insert(make_pair("1", VariantFactory::create<int>(1)));
    map.insert(make_pair("2", VariantFactory::create<int>(2)));
    map.insert(make_pair("3", VariantFactory::create<int>(3)));
    map.insert(make_pair("4", VariantFactory::create<int>(4)));
    EXPECT_EQ(4u, map.size());

    shared_ptr<MslObject> mo = make_shared<MslObject>(map);
    EXPECT_EQ(4u, mo->size());
    EXPECT_EQ(3, mo->getInt("3"));

    // ensure original source map is not affected if the MslObject is changed
    mo->put<double>("5", 5.555);
    EXPECT_EQ(5u, mo->size());
    EXPECT_EQ(4u, map.size());
}

TEST_F(MslObjectTest, Empty)
{
    shared_ptr<MslObject> mslObject = make_shared<MslObject>();
    EXPECT_EQ(0u, mslObject->size());

    // get from empty object
    EXPECT_THROW(mslObject->get("foo"), MslEncoderException);

    // putting an empty Variant should do nothing
    const Variant empty = VariantFactory::createNull();
    EXPECT_NO_THROW(mslObject->put("foo", empty));
    EXPECT_EQ(0u, mslObject->size());

    // put with empty key should throw
    const Variant one = VariantFactory::create<int>(1);
    EXPECT_THROW(mslObject->put("", one), IllegalArgumentException);

    // get with empty key should throw
    EXPECT_THROW(mslObject->get(""), IllegalArgumentException);
    EXPECT_EQ(0u, mslObject->size());

    // get with unknown key should throw
    EXPECT_THROW(mslObject->get("unknown"), MslEncoderException);
    EXPECT_EQ(0u, mslObject->size());

    // repeat these tests on a non-empty MslObject
    EXPECT_NO_THROW(mslObject->put("one", one));
    EXPECT_EQ(1u, mslObject->size());
    EXPECT_NO_THROW(mslObject->put("foo", empty));
    EXPECT_EQ(1u, mslObject->size());
    EXPECT_THROW(mslObject->put("", one), IllegalArgumentException);
    EXPECT_EQ(1u, mslObject->size());
    EXPECT_THROW(mslObject->get(""), IllegalArgumentException);
    EXPECT_EQ(1u, mslObject->size());
    EXPECT_THROW(mslObject->get("unknown"), MslEncoderException);
    EXPECT_EQ(1u, mslObject->size());
}

TEST_F(MslObjectTest, PutGet)
{
    shared_ptr<MslObject> mslObject = make_shared<MslObject>();
    EXPECT_EQ(0u, mslObject->size());

    const Variant null = VariantFactory::createNull();
    const Variant one = VariantFactory::create<int32_t>(1);

    // successful put
    EXPECT_NO_THROW(mslObject->put("one", one));
    EXPECT_EQ(1u, mslObject->size());

    // remove by putting extant empty value
    EXPECT_NO_THROW(mslObject->put("one", null));
    EXPECT_EQ(0u, mslObject->size());

    // noop to put an empty value with a new key
    EXPECT_NO_THROW(mslObject->put("empty", null));
    EXPECT_EQ(0u, mslObject->size());

    // successful put
    EXPECT_NO_THROW(mslObject->put("one", one));
    EXPECT_EQ(1u, mslObject->size());

    // successful typed put
    EXPECT_NO_THROW(mslObject->put<int64_t>("two", 2));
    EXPECT_EQ(2u, mslObject->size());

    // successful Variant get
    try {
        const Variant one_ = mslObject->get("one");
        EXPECT_TRUE(one_.isType<int32_t>());
        EXPECT_EQ(1, one_.get<int32_t>());
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }

    // successful typed get
    try {
        const int oneVal = mslObject->getInt("one");
        EXPECT_EQ(1, oneVal);
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }

    // unsuccessful Variant get already tested in Empty

    // unsuccessful typed get, bad key
    EXPECT_THROW(mslObject->getInt(""), IllegalArgumentException);

    // unsuccessful typed get, unknown key
    EXPECT_THROW(mslObject->getInt("unknown"), MslEncoderException);

    // get empty element, should throw
    EXPECT_THROW(mslObject->get("empty"), MslEncoderException);
}

TEST_F(MslObjectTest, Opt)
{
    shared_ptr<MslObject> mslObject = make_shared<MslObject>();
    const Variant one = VariantFactory::create<int>(1);
    mslObject->put("one", one);

    // unsuccessful Variant opt, bad key
    EXPECT_THROW(mslObject->opt(""), IllegalArgumentException);

    // successful Variant opt
    try {
        const Variant one_ = mslObject->opt("one");
        EXPECT_TRUE(one.isType<int32_t>());
        EXPECT_EQ(1, one_.get<int32_t>());
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }

    // successful Variant opt, bad key
    try {
        const Variant empty = mslObject->opt("two");
        EXPECT_TRUE(empty.isNull());
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }

    // unsuccessful typed opt, bad key
    EXPECT_THROW(mslObject->optInt(""), IllegalArgumentException);

    // successful typed opt
    try {
        const int oneVal = mslObject->optInt("one");
        EXPECT_EQ(1, oneVal);
        const int oneVal_ = mslObject->optInt("one", 10);
        EXPECT_EQ(1, oneVal_);
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }

    // successful typed opt, unknown key
    try {
        const int oneVal = mslObject->optInt("unknown");
        EXPECT_EQ(0, oneVal);
        const int oneVal_ = mslObject->optInt("unknown", 10);
        EXPECT_EQ(10, oneVal_);
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }

    // successful typed opt, known key but incompatible type
    try {
        const int64_t oneVal = mslObject->optLong("one");
        EXPECT_EQ(0u, oneVal);
        const int64_t oneVal_ = mslObject->optLong("one", 10);
        EXPECT_EQ(10u, oneVal_);
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }
}

TEST_F(MslObjectTest, Has)
{
    shared_ptr<MslObject> mslObject = make_shared<MslObject>();
    const Variant one = VariantFactory::create<int>(1);
    mslObject->put("one", one);
    EXPECT_TRUE(mslObject->has("one"));
    EXPECT_FALSE(mslObject->has("two"));
    EXPECT_THROW(mslObject->has(""), IllegalArgumentException);
}

TEST_F(MslObjectTest, Remove)
{
    shared_ptr<MslObject> mslObject = make_shared<MslObject>();
    const Variant two = VariantFactory::create<int>(2);
    mslObject->put("one",   VariantFactory::create<int>(1));
    mslObject->put("two",   two);
    mslObject->put("three", VariantFactory::create<int>(3));
    EXPECT_EQ(3u, mslObject->size());

    EXPECT_THROW(mslObject->remove(""), IllegalArgumentException);

    try {
        EXPECT_TRUE(mslObject->has("two"));
        const Variant removed = mslObject->remove("two");
        EXPECT_EQ(2u, mslObject->size());
        EXPECT_FALSE(mslObject->has("two"));
        EXPECT_EQ(removed.get<int>(), two.get<int>());
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }
}

TEST_F(MslObjectTest, GetKeys)
{
    shared_ptr<MslObject> mslObject = make_shared<MslObject>();
    std::vector<std::string> keys = mslObject->getKeys();
    EXPECT_EQ(0u, keys.size());
    mslObject->put("one",   VariantFactory::create<int32_t>(1));
    mslObject->put("two",   VariantFactory::create<int32_t>(2));
    mslObject->put("three", VariantFactory::create<int32_t>(3));
    keys = mslObject->getKeys();
    std::sort(keys.begin(), keys.end());
    EXPECT_EQ(3u, keys.size());
    std::vector<std::string> check;
    check.push_back("one");
    check.push_back("two");
    check.push_back("three");
    std::sort(check.begin(), check.end());
    EXPECT_EQ(check, keys);
}

TEST_F(MslObjectTest, ByteArray)
{
    typedef std::vector<uint8_t> ByteArray;
    const std::string str = "this is a string stored as binary data";
    shared_ptr<ByteArray> data = make_shared<ByteArray>(str.begin(), str.end());
    shared_ptr<MslObject> mslObj = make_shared<MslObject>();
    mslObj->put<shared_ptr<ByteArray>>("data", data);
    EXPECT_EQ(1u, mslObj->size());
    try {
    	shared_ptr<ByteArray> data_ = mslObj->getBytes("data");
        EXPECT_EQ(str, std::string(data_->begin(), data_->end()));
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }
}

TEST_F(MslObjectTest, ToString)
{
	shared_ptr<MslObject> mslObj0 = make_shared<MslObject>();
    EXPECT_EQ("{}", mslObj0->toString());

    shared_ptr<MslObject> mslObj1 = make_shared<MslObject>();
    mslObj1->put<int>("one", 1);
    EXPECT_EQ("{\"one\":1}", mslObj1->toString());

    shared_ptr<MslObject> mslObj2 = make_shared<MslObject>();
    mslObj2->put<int32_t>("one", 1);
    mslObj2->put<double>("two", 2.22);
    mslObj2->put<std::string>("three", "3");
    EXPECT_EQ("{\"one\":1,\"three\":\"3\",\"two\":2.22}", mslObj2->toString());

    shared_ptr<MslObject> mslObj3 = make_shared<MslObject>();
    mslObj3->put<int32_t>("a", 1);
    mslObj3->put("b", mslObj2);
    mslObj3->put<int32_t>("c", 3);
    EXPECT_EQ("{\"a\":1,\"b\":{\"one\":1,\"three\":\"3\",\"two\":2.22},\"c\":3}", mslObj3->toString());

    shared_ptr<MslArray> mslAry = make_shared<MslArray>();
    mslAry->put<int32_t>(-1, 0);
    mslAry->put<double>(-1, 1.11);
    mslAry->put<std::string>(-1, "2");

    shared_ptr<MslObject> mslObj4 = make_shared<MslObject>();
    mslObj4->put<int32_t>("a", 1);
    mslObj4->put("b", mslAry);
    shared_ptr<ByteArray> ba = make_shared<ByteArray>();
    ba->push_back(1);
    ba->push_back(2);
    mslObj4->put<shared_ptr<ByteArray>>("c", ba);
    EXPECT_EQ("{\"a\":1,\"b\":[0,1.11,\"2\"],\"c\":\"AQI=\"}", mslObj4->toString());
}

TEST_F(MslObjectTest, Equality)
{
    shared_ptr<MslObject> mslObj0 = make_shared<MslObject>();
    shared_ptr<MslObject> mslObj1 = make_shared<MslObject>();
    EXPECT_EQ(mslObj0, mslObj0);
    EXPECT_EQ(mslObj0, mslObj1);
    shared_ptr<MslObject> mslObj2 = make_shared<MslObject>();
    *mslObj2 = *mslObj0; // shallow copy, share underlying data
    EXPECT_EQ(mslObj0, mslObj2);

    shared_ptr<MslArray> mslAry1 = make_shared<MslArray>();
    mslAry1->put<int32_t>(-1, 0);
    mslAry1->put<double>(-1, 1.11);
    mslAry1->put<std::string>(-1, "2");

    shared_ptr<MslArray> mslAry2 = make_shared<MslArray>();
    mslAry2->put<int32_t>(-1, 0);
    mslAry2->put<double>(-1, 1.11);
    mslAry2->put<std::string>(-1, "2");

    shared_ptr<ByteArray> ba = make_shared<ByteArray>();
    ba->push_back(1);
    ba->push_back(2);

    shared_ptr<MslObject> mslObj3 = make_shared<MslObject>();
    mslObj3->put<int32_t>("a", 1);
    mslObj3->put("b", mslAry1);
    mslObj3->put<shared_ptr<ByteArray>>("c", ba);

    shared_ptr<MslObject> mslObj4 = make_shared<MslObject>();
    mslObj4->put<int32_t>("a", 1);
    mslObj4->put("b", mslAry2);
    mslObj4->put<shared_ptr<ByteArray>>("c", ba);

    // element b has identical contents, element c has identical object
    EXPECT_EQ(mslObj3, mslObj4);

    // if we change mslAry2, we change mslObj4's b element, so the top-level
    // objects will no longer be equal
    mslAry2->put<int64_t>(-1, 999);
    EXPECT_NE(mslObj3, mslObj4);
}

TEST_F(MslObjectTest, ReplaceElement)
{
    shared_ptr<MslObject> mo = make_shared<MslObject>();
    mo->put<int>("foo", 1);
    EXPECT_EQ(1u, mo->size());
    EXPECT_EQ(1, mo->getInt("foo"));
    mo->put<int>("foo", 2);
    mo->put<int>("foo", 3);
    mo->put<int>("foo", 4);
    EXPECT_EQ(1u, mo->size());
    EXPECT_EQ(4, mo->getInt("foo"));
}

TEST_F(MslObjectTest, AutoInt64_t)
{
    shared_ptr<MslObject> mo = make_shared<MslObject>();
    mo->put<int32_t>("1", 1);
    mo->put<int64_t>("2", 2);
    mo->put<int64_t>("3", 3);
    mo->put<double>("4", 4);
    mo->put<string>("5", "5");
    EXPECT_EQ(1ll, mo->getLong("1"));
    EXPECT_EQ(2ll, mo->getLong("2"));
    EXPECT_EQ(3ll, mo->getLong("3"));
    EXPECT_EQ(4ll, mo->getLong("4"));
    EXPECT_THROW(mo->getLong("5"), MslEncoderException);
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
