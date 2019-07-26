/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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
#include <io/ByteArrayInputStream.h>
#include <io/DefaultMslEncoderFactory.h>
#include <io/JsonMslObject.h>
#include <io/MslArray.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <io/MslVariant.h>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

namespace {
shared_ptr<ByteArray> makeByteArray(const string s) {return make_shared<ByteArray>(s.begin(), s.end());}
}

class DefaultMslEncoderFactoryTest : public ::testing::Test
{
public:
	virtual ~DefaultMslEncoderFactoryTest() {}

	DefaultMslEncoderFactoryTest()
		: mef(make_shared<DefaultMslEncoderFactory>())
	{}

protected:
	shared_ptr<MslEncoderFactory> mef;
};

TEST_F(DefaultMslEncoderFactoryTest, Main)
{
    Variant nullVar = VariantFactory::createNull();
    EXPECT_EQ("null", mef->stringify(nullVar));

    Variant intVar = VariantFactory::create<int>(5);
    EXPECT_EQ("5", mef->stringify(intVar));
}

TEST_F(DefaultMslEncoderFactoryTest, StringifyPrimitives)
{
    const Variant nullVar = VariantFactory::createNull();
    EXPECT_EQ("null", mef->stringify(nullVar));

    const Variant strVar = VariantFactory::create<string>("foobar");
    EXPECT_EQ("\"foobar\"", mef->stringify(strVar));

    const Variant trueVar = VariantFactory::create<bool>(true);
    EXPECT_EQ("true", mef->stringify(trueVar));
    const Variant falseVar = VariantFactory::create<bool>(false);
    EXPECT_EQ("false", mef->stringify(falseVar));

    const Variant intVar = VariantFactory::create<int32_t>(999);
    EXPECT_EQ("999", mef->stringify(intVar));

    const Variant unsignedVar = VariantFactory::create<int64_t>(4294967295);
    EXPECT_EQ("4294967295", mef->stringify(unsignedVar));

    const Variant i64Var = VariantFactory::create<int64_t>(-9223372036854775807ll);
    EXPECT_EQ("-9223372036854775807", mef->stringify(i64Var));

    const Variant d64Var = VariantFactory::create<double>(static_cast<double>(922337203685477580ull));
    EXPECT_EQ("9.22337e+17", mef->stringify(d64Var));

    const Variant doubleVar = VariantFactory::create<double>(3.141592653589);
    EXPECT_EQ("3.14159", mef->stringify(doubleVar)); // using default precision of 6

    shared_ptr<MslObject> mo = make_shared<MslObject>();
    const Variant mslObjVar = VariantFactory::create(mo);
    EXPECT_EQ("{}", mef->stringify(mslObjVar));

    shared_ptr<MslArray> ma = make_shared<MslArray>();
    const Variant mslAryVar = VariantFactory::create(ma);
    EXPECT_EQ("[]", mef->stringify(mslAryVar));
}

TEST_F(DefaultMslEncoderFactoryTest, StringifyObjects)
{
    // NOTE: To a large degree these are duplicates of the ToString tests in
    // MslObject_test and MslArray_test

    shared_ptr<MslObject> mslObj1 = make_shared<MslObject>();
    mslObj1->put<int32_t>("one", 1);
    EXPECT_EQ("{\"one\":1}", mef->stringify(mslObj1));

    shared_ptr<MslObject> mslObj2 = make_shared<MslObject>();
    mslObj2->put<int32_t>("one", 1);
    mslObj2->put<double>("two", 2.22);
    mslObj2->put<std::string>("three", "3");
    EXPECT_EQ("{\"one\":1,\"three\":\"3\",\"two\":2.22}", mef->stringify(mslObj2));

    shared_ptr<MslObject> mslObj3 = make_shared<MslObject>();
    mslObj3->put<int32_t>("a", 1);
    mslObj3->put("b", mslObj2);
    mslObj3->put<int32_t>("c", 3);
    EXPECT_EQ("{\"a\":1,\"b\":{\"one\":1,\"three\":\"3\",\"two\":2.22},\"c\":3}", mef->stringify(mslObj3));

    shared_ptr<MslArray> mslAry1 = make_shared<MslArray>();
    mslAry1->put<double>(-1, 0);
    EXPECT_EQ("[0]", mef->stringify(mslAry1));

    shared_ptr<MslArray> mslAry2 = make_shared<MslArray>();
    mslAry2->put<int32_t>(-1, 0);
    mslAry2->put<double>(-1, 1.11);
    mslAry2->put<std::string>(-1, "2");
    EXPECT_EQ("[0,1.11,\"2\"]", mef->stringify(mslAry2));

    shared_ptr<MslArray> mslAry3 = make_shared<MslArray>();
    mslAry3->put<std::string>(-1, "a");
    mslAry3->put(-1, mslAry2);
    mslAry3->put(-1, mslObj3);
    EXPECT_EQ("[\"a\",[0,1.11,\"2\"],{\"a\":1,\"b\":{\"one\":1,\"three\":\"3\",\"two\":2.22},\"c\":3}]", mef->stringify(mslAry3));

    shared_ptr<MslObject> mslObj4 = make_shared<MslObject>();
    mslObj4->put<int32_t>("a", 1);
    mslObj4->put("b", mslAry2);
    mslObj4->put<int32_t>("c", 3);
    EXPECT_EQ("{\"a\":1,\"b\":[0,1.11,\"2\"],\"c\":3}", mef->stringify(mslObj4));
}

TEST_F(DefaultMslEncoderFactoryTest, Quote)
{
    // FIXME: TODO
}

TEST_F(DefaultMslEncoderFactoryTest, GetPreferredFormat)
{
    MslEncoderFormat fmt = mef->getPreferredFormat();
    EXPECT_EQ(MslEncoderFormat::JSON, fmt);
    const std::set<MslEncoderFormat> formats; // empty
    fmt = mef->getPreferredFormat(formats);
    EXPECT_EQ(MslEncoderFormat::JSON, fmt);
}

TEST_F(DefaultMslEncoderFactoryTest, CreateObject)
{
    shared_ptr<MslObject> mo1 = mef->createObject();
    EXPECT_EQ(0u, mo1->size());
    MslObject::MapType map;
    shared_ptr<MslObject> mo2 = mef->createObject(map);
    EXPECT_EQ(0u, mo2->size());
    EXPECT_EQ(*mo1, *mo2);

    map.insert(make_pair("1", VariantFactory::create<int32_t>(1)));
    map.insert(make_pair("2", VariantFactory::create<int32_t>(2)));
    map.insert(make_pair("3", VariantFactory::create<int32_t>(3)));
    map.insert(make_pair("4", VariantFactory::create<int32_t>(4)));
    mo1 = mef->createObject(map);
    EXPECT_EQ(4u, mo1->size());
    mo2 = mef->createObject(map);
    EXPECT_EQ(*mo1, *mo2);
    mo2->put<int32_t>("5", 5);
    EXPECT_NE(*mo1, *mo2);
}

TEST_F(DefaultMslEncoderFactoryTest, ParseFormat)
{
    EXPECT_THROW(mef->parseFormat(makeByteArray("")), MslEncoderException);
    EXPECT_THROW(mef->parseFormat(makeByteArray("sdkfgsaflkgd")), MslEncoderException);
    EXPECT_THROW(mef->parseFormat(makeByteArray("[]")), MslEncoderException);
    const MslEncoderFormat format = mef->parseFormat(makeByteArray("{\"a\":1}"));
    EXPECT_EQ(MslEncoderFormat::JSON, format);
}

TEST_F(DefaultMslEncoderFactoryTest, ParseObject)
{
    EXPECT_THROW(mef->parseObject(makeByteArray("sdkfgsaflkgd")), MslEncoderException);

    try {
        shared_ptr<MslObject> mo = mef->parseObject(makeByteArray(
            "{\"a\":[1,{\"aa\":[10,20,{\"ccc\":[100,200,300]},30]},2],\"b\":9.9}"
        ));
        EXPECT_EQ(2u, mo->size());
    } catch (const MslEncoderException& e) {
        ADD_FAILURE() << e.what();
    } catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }
}

TEST_F(DefaultMslEncoderFactoryTest, EncodeObject)
{
	shared_ptr<ByteArray> json = makeByteArray(
        "{\"a\":[1,{\"aa\":[10,20,{\"ccc\":[100,200,300]},30]},2],\"b\":9.9}"
    );
    shared_ptr<MslObject> jmo = make_shared<JsonMslObject>(json);
    EXPECT_THROW(mef->encodeObject(jmo, MslEncoderFormat::INVALID), MslEncoderException);
    try {
    	shared_ptr<ByteArray> encoded = mef->encodeObject(jmo, MslEncoderFormat::JSON);
        EXPECT_EQ(*encoded, *json);
    } catch (const MslEncoderException& e) {
        ADD_FAILURE() << e.what();
    } catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }
}

TEST_F(DefaultMslEncoderFactoryTest, CreateTokenizer)
{
    const string json =
        "{\"a\":[1,{\"aa\":[10,20,{\"ccc\":[100,200,300]},30]},2],\"b\":9.9}";
    shared_ptr<InputStream> is = make_shared<ByteArrayInputStream>(json);

    // explicit format
    shared_ptr<MslTokenizer> mt = mef->createTokenizer(is);
    mt->close();

    // deduced format
    shared_ptr<InputStream> bad = make_shared<ByteArrayInputStream>("afkhadgfk");
    EXPECT_THROW(mef->createTokenizer(bad), MslEncoderException);
    mt = mef->createTokenizer(is);
    mt->close();
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
