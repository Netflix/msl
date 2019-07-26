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
#include <io/MslVariant.h>
#include <io/MslObject.h>
#include <io/MslArray.h>
#include <io/MslEncodable.h>
#include <util/Base64.h>
#include <memory>

using std::make_shared;
using std::shared_ptr;
using std::dynamic_pointer_cast;

namespace netflix {
namespace msl {
namespace io {

class MslEncoderFactory;
class MslEncoderFormat;

namespace { // anonymous

class CustomEncodable : public MslEncodable
{
public:
    CustomEncodable() : value_(0) {}
    explicit CustomEncodable(int value) : value_(value) {}
    int getValue() const {return value_;}
    bool operator==(const CustomEncodable& rhs) const {
        return rhs.value_ == value_;
    }
    virtual shared_ptr<ByteArray> toMslEncoding(shared_ptr<MslEncoderFactory> /*encoder*/,
            const MslEncoderFormat& /*format*/) const {
        return make_shared<ByteArray>();
    }
private:
    const int value_;
};

class CustomObject : public MslObject
{
public:
	CustomObject() { put<int32_t>("KEY", 0); }
	explicit CustomObject(int value) { put<int32_t>("KEY", value); }
	int getValue() const { return getInt("KEY"); }
	bool operator==(const CustomObject& rhs) const {
		return rhs.getValue() == getValue();
	}
};

class CustomArray : public MslArray
{
public:
	CustomArray() { put<int32_t>(0, 0); }
	explicit CustomArray(int value) { put<int32_t>(0, value); }
	int getValue() const { return getInt(0); }
	bool operator==(const CustomArray& rhs) const {
		return rhs.getValue() == getValue();
	}
};

inline shared_ptr<ByteArray> makeByteArray(const std::string& s)
{
    return make_shared<std::vector<std::uint8_t>>(s.begin(), s.end());
}

} // namespace anonymous

class VariantTest : public ::testing::Test
{
};

TEST_F(VariantTest, Main)
{
	{
		const Variant foo = VariantFactory::create<int64_t>(100);
		EXPECT_FALSE(foo.isNull());
		EXPECT_TRUE(foo.isType<int64_t>());
		EXPECT_FALSE(foo.isType<int32_t>());
		EXPECT_EQ(100, foo.get<int64_t>());
		EXPECT_THROW(foo.get<std::string>(), Exception);
		EXPECT_NO_THROW(foo.getOpt<std::string>());
		EXPECT_EQ(std::string(), foo.getOpt<std::string>());
	}

	{
		const Variant bar = VariantFactory::create<std::string>("imavariant");
		EXPECT_FALSE(bar.isNull());
		EXPECT_TRUE(bar.isType<std::string>());
		EXPECT_FALSE(bar.isType<int>());
		EXPECT_EQ("imavariant", bar.get<std::string>());
		EXPECT_THROW(bar.get<uint8_t>(), Exception);
		EXPECT_NO_THROW(bar.getOpt<int32_t>());
		EXPECT_EQ(0, bar.getOpt<int32_t>());
	}

    {
		shared_ptr<MslEncodable> encodable = make_shared<CustomEncodable>(999);
		const Variant variant = VariantFactory::create(encodable);
		EXPECT_TRUE(variant.isType<shared_ptr<MslEncodable>>());
		EXPECT_FALSE(variant.isType<shared_ptr<CustomEncodable>>());
		EXPECT_FALSE(variant.isType<int>());
		EXPECT_FALSE(variant.isType<shared_ptr<MslObject>>());
		EXPECT_NO_THROW(variant.get<shared_ptr<MslEncodable>>());
		shared_ptr<CustomEncodable> custom = dynamic_pointer_cast<CustomEncodable>(variant.get<shared_ptr<MslEncodable>>());
		EXPECT_EQ(999, custom->getValue());
		EXPECT_EQ(encodable, custom);
		EXPECT_THROW(variant.get<std::string>(), Exception);
		EXPECT_NO_THROW(variant.getOpt<std::string>());
		EXPECT_EQ(std::string(), variant.getOpt<std::string>());
    }

    {
		shared_ptr<MslObject> object = make_shared<CustomObject>(999);
		const Variant variant = VariantFactory::create(object);
		EXPECT_TRUE(variant.isType<shared_ptr<MslObject>>());
		EXPECT_FALSE(variant.isType<shared_ptr<CustomObject>>());
		EXPECT_FALSE(variant.isType<int>());
		EXPECT_FALSE(variant.isType<shared_ptr<MslArray>>());
		EXPECT_NO_THROW(variant.get<shared_ptr<MslObject>>());
		shared_ptr<CustomObject> custom = dynamic_pointer_cast<CustomObject>(variant.get<shared_ptr<MslObject>>());
		EXPECT_EQ(999, custom->getValue());
		EXPECT_EQ(object, custom);
		EXPECT_THROW(variant.get<std::string>(), Exception);
		EXPECT_NO_THROW(variant.getOpt<std::string>());
		EXPECT_EQ(std::string(), variant.getOpt<std::string>());
    }

    {
		shared_ptr<MslArray> array = make_shared<CustomArray>(999);
		const Variant variant = VariantFactory::create(array);
		EXPECT_TRUE(variant.isType<shared_ptr<MslArray>>());
		EXPECT_FALSE(variant.isType<shared_ptr<CustomArray>>());
		EXPECT_FALSE(variant.isType<int>());
		EXPECT_FALSE(variant.isType<shared_ptr<MslObject>>());
		EXPECT_NO_THROW(variant.get<shared_ptr<MslArray>>());
		shared_ptr<CustomArray> custom = dynamic_pointer_cast<CustomArray>(variant.get<shared_ptr<MslArray>>());
		EXPECT_EQ(999, custom->getValue());
		EXPECT_EQ(array, custom);
		EXPECT_THROW(variant.get<std::string>(), Exception);
		EXPECT_NO_THROW(variant.getOpt<std::string>());
		EXPECT_EQ(std::string(), variant.getOpt<std::string>());
    }

    {
		const Variant nullVariant = VariantFactory::createNull();
		EXPECT_TRUE(nullVariant.isNull());
    }
}

TEST_F(VariantTest, ToString)
{
    const Variant nullVar = VariantFactory::createNull();
    EXPECT_EQ("null", nullVar.toString());

    const Variant strVar = VariantFactory::create<std::string>("foobar");
    EXPECT_EQ("\"foobar\"", strVar.toString());

    const Variant intVar = VariantFactory::create<int32_t>(999);
    EXPECT_EQ("999", intVar.toString());

    const Variant trueVar = VariantFactory::create<bool>(true);
    EXPECT_EQ("true", trueVar.toString());
    const Variant falseVar = VariantFactory::create<bool>(false);
    EXPECT_EQ("false", falseVar.toString());

    const Variant unsignedVar = VariantFactory::create<int64_t>(4294967295);
    EXPECT_EQ("4294967295", unsignedVar.toString());

    const Variant i64Var = VariantFactory::create<int64_t>(-9223372036854775807ll);
    EXPECT_EQ("-9223372036854775807", i64Var.toString());

    const Variant doubleVar = VariantFactory::create<double>(3.141592653589);
    EXPECT_EQ("3.14159", doubleVar.toString()); // using default precision of 6

    shared_ptr<MslObject> mo = make_shared<MslObject>();
    const Variant mslObjVar = VariantFactory::create(mo);
    EXPECT_EQ("{}", mslObjVar.toString());

    shared_ptr<MslArray> ma = make_shared<MslArray>();
    const Variant mslAryVar = VariantFactory::create(ma);
    EXPECT_EQ("[]", mslAryVar.toString());

    // .toString on a MslObject containing a ByteArray should return the base64
    // encoding of the data.
    const std::string o = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
    const std::string e = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4=";
    shared_ptr<ByteArray> d = makeByteArray(o);
    const Variant dVar = VariantFactory::create<shared_ptr<ByteArray>>(d);
    EXPECT_EQ("\"" + e + "\"", dVar.toString());
}

TEST_F(VariantTest, Equality)
{
    const Variant one = VariantFactory::create<int32_t>(1);
    const Variant two = VariantFactory::create<int32_t>(2);
    EXPECT_NE(one, two);

    // identity
    EXPECT_EQ(one, one);

    // shallow copy should be equal, both point to the same underlying data
    const Variant one_ = one;
    EXPECT_EQ(one, one_);

    // value equality between distinct underlying data
    const Variant anotherOne = VariantFactory::create<int32_t>(1);
    EXPECT_EQ(one, anotherOne);

    // fail equality if different types, even if (cast) values are equal
    const Variant uintOne = VariantFactory::create<int64_t>(1);
    EXPECT_NE(one, uintOne);
    EXPECT_EQ(one.get<int32_t>(), static_cast<int32_t>(uintOne.get<int64_t>()));
}

}}} // namespace netflix::msl::io
