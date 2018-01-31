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
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/JsonMslObject.h>
#include <io/MslArray.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <util/Base64.h>
#include <util/MockMslContext.h>

using namespace std;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace io {

namespace {
shared_ptr<ByteArray> makeByteArray(const string s) {
	return make_shared<ByteArray>(s.begin(), s.end());
}
}

class JsonMslObjectTest : public ::testing::Test
{
public:
	virtual ~JsonMslObjectTest() {}

	JsonMslObjectTest()
	{
    	shared_ptr<MslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
		encoder = ctx->getMslEncoderFactory();
	}

protected:
    shared_ptr<MslEncoderFactory> encoder;
};

TEST_F(JsonMslObjectTest, ElementTypes)
{
	shared_ptr<ByteArray> js = makeByteArray(
        "{"
    	"\"null\" : null, "
        "\"bool\" : true, "
        "\"int\"  : -999, "
        "\"uint\" : 4294967295, "
        "\"int64\" : -9223372036854775807,"
        "\"uint64\" : 9223372036854775808,"
        "\"double\" : 1.23456,"
        "\"string\" : \"hello\","
        "\"array\" : [1, 2.2, \"three\"]"
        "}"
    );
    JsonMslObject jmo(js);
    EXPECT_EQ(8u, jmo.size());

    Variant va = jmo.get("bool");
    EXPECT_TRUE(va.isType<bool>());
    EXPECT_TRUE(va.get<bool>());

    va = jmo.get("int");
    EXPECT_TRUE(va.isType<int32_t>());
    EXPECT_EQ(-999, va.get<int32_t>());

    va = jmo.get("uint");
    EXPECT_TRUE(va.isType<int64_t>());
    EXPECT_EQ(4294967295u, va.get<int64_t>());

    va = jmo.get("int64");
    EXPECT_TRUE(va.isType<int64_t>());
    EXPECT_EQ(-9223372036854775807ll, va.get<int64_t>());

    va = jmo.get("uint64");
    EXPECT_TRUE(va.isType<double>());
    EXPECT_EQ(static_cast<double>(9223372036854775808ull), va.get<double>());

    va = jmo.get("double");
    EXPECT_TRUE(va.isType<double>());
    EXPECT_EQ(1.23456, va.get<double>());

    va = jmo.get("string");
    EXPECT_TRUE(va.isType<string>());
    EXPECT_EQ("hello", va.get<string>());

    va = jmo.get("array");
    EXPECT_TRUE(va.isType<shared_ptr<MslArray>>());
    shared_ptr<MslArray> ma = jmo.getMslArray("array");
    EXPECT_EQ(3u, ma->size());
    EXPECT_TRUE(ma->get(0).isType<int32_t>());
    EXPECT_TRUE(ma->get(1).isType<double>());
    EXPECT_TRUE(ma->get(2).isType<string>());
}

TEST_F(JsonMslObjectTest, NestedObject)
{
	shared_ptr<ByteArray> js = makeByteArray(
        "{"
        "\"level1\" : {"
            "\"l1a\" : 1,"
            "\"l1b\" : 2,"
            "\"level2\": {"
                "\"l2a\" : 1,"
                "\"l2b\" : 2"
                "}"
            "}"
        "}"
    );
    JsonMslObject jmo(js);
    EXPECT_EQ(1u, jmo.size());

    shared_ptr<MslObject> mo = jmo.getMslObject("level1", encoder);
    EXPECT_EQ(3u, mo->size());
    EXPECT_EQ(2, mo->getInt("l1b"));

    mo = jmo.getMslObject("level1", encoder)->getMslObject("level2", encoder);
    EXPECT_EQ(2u, mo->size());
    EXPECT_EQ(1, mo->getInt("l2a"));
}

TEST_F(JsonMslObjectTest, NestedArray)
{
	shared_ptr<ByteArray> js = makeByteArray(
        "{\"a\":[ 1, {\"b\":[10, 20, {\"c\":[100, 200, 300]}, 30]}, 2]}"
    );
    JsonMslObject jmo(js);
    EXPECT_EQ(1u, jmo.size());

    EXPECT_TRUE(jmo.get("a").isType<shared_ptr<MslArray>>());
    shared_ptr<MslArray> a = jmo.getMslArray("a");
    EXPECT_EQ(3u, a->size());

    EXPECT_TRUE(a->get(1).isType<shared_ptr<MslObject>>());
    shared_ptr<MslObject> bo = a->get(1).get<shared_ptr<MslObject>>();
    EXPECT_TRUE(bo->get("b").isType<shared_ptr<MslArray>>());
    shared_ptr<MslArray> b = bo->get("b").get<shared_ptr<MslArray>>();
    EXPECT_EQ(4u, b->size());

    EXPECT_TRUE(b->get(2).isType<shared_ptr<MslObject>>());
    EXPECT_TRUE(b->get(2).get<shared_ptr<MslObject>>()->get("c").isType<shared_ptr<MslArray>>());
    shared_ptr<MslArray> c = b->get(2).get<shared_ptr<MslObject>>()->get("c").get<shared_ptr<MslArray>>();
    EXPECT_EQ(3u, c->size());
    EXPECT_EQ(300, c->getInt(2));
}

TEST_F(JsonMslObjectTest, ExceedMaxNesting)
{
	shared_ptr<ByteArray> js1 = makeByteArray(
        "{\"a\":[ 1, {\"b\":[10, 20, {\"c\":[100, {\"d\":[1,2,3]}, 300]}, 30]}, 2]}"
    );
    EXPECT_THROW({JsonMslObject jmo(js1);}, MslEncoderException);

    shared_ptr<ByteArray> js2 = makeByteArray("{{{{{{}}}}}}");
    EXPECT_THROW({JsonMslObject jmo(js2);}, MslEncoderException);
}

TEST_F(JsonMslObjectTest, EmptyObject)
{
	shared_ptr<ByteArray> js = makeByteArray("{}");
    JsonMslObject jmo(js);
    EXPECT_EQ(0u, jmo.size());
}

TEST_F(JsonMslObjectTest, MalformedJson)
{
	shared_ptr<ByteArray> js = makeByteArray("{\"foobar");
    EXPECT_THROW({JsonMslObject jmo(js);}, MslEncoderException);
}

TEST_F(JsonMslObjectTest, NotObject)
{
    // can't make a JsonMslObject from JSON array
	shared_ptr<ByteArray> js = makeByteArray("[1,2,3]");
    EXPECT_THROW({JsonMslObject jmo(js);}, MslEncoderException);

    // can't make a JsonMslObject from non-JSON
    js = makeByteArray("5");
    EXPECT_THROW({JsonMslObject jmo(js);}, MslEncoderException);
}

TEST_F(JsonMslObjectTest, toJsonString)
{
    const string emptyObjJsStr = "{}";
    shared_ptr<ByteArray> js = makeByteArray(emptyObjJsStr);
    JsonMslObject jmo0(js);
    EXPECT_EQ(emptyObjJsStr, jmo0.toJsonString(encoder));
    EXPECT_EQ(emptyObjJsStr, jmo0.toString());

    const string nestedObjJsStr =
        "{"
        "\"level1\":{"
            "\"l1a\":1,"
            "\"l1b\":2,"
            "\"level2\":{"
                "\"l2a\":1,"
                "\"l2b\":2"
                "}"
            "}"
        "}";
    js = makeByteArray(nestedObjJsStr);
    JsonMslObject jmo1(js);
    EXPECT_EQ(nestedObjJsStr, jmo1.toJsonString(encoder));
    EXPECT_EQ(nestedObjJsStr, jmo1.toString());

    const string nestedArrayJsStr =
        "{\"a\":[1,{\"b\":[10,20,{\"c\":[100,200,300]},30]},2]}";
    js = makeByteArray(nestedArrayJsStr);
    JsonMslObject jmo2(js);
    EXPECT_EQ(nestedArrayJsStr, jmo2.toJsonString(encoder));
    EXPECT_EQ(nestedArrayJsStr, jmo2.toString());

    const string alltypesJsStr =
        "{"
        "\"a\":[1,2.2,\"three\"],"
        "\"b\":true,"
        "\"c\":1.23456,"
        "\"d\":-999,"
        "\"e\":-9223372036854775807,"
        "\"f\":\"hello\","
        "\"g\":4294967295,"
        "\"h\":922337203685477600"
        "}";
    js = makeByteArray(alltypesJsStr);
    JsonMslObject jmo3(js);
    EXPECT_EQ(alltypesJsStr, jmo3.toJsonString(encoder));
    EXPECT_EQ(alltypesJsStr, jmo3.toString());
}

TEST_F(JsonMslObjectTest, getBytes)
{
	shared_ptr<ByteArray> ba1 = make_shared<ByteArray>();
    ba1->push_back(0);
    ba1->push_back(1);
    ba1->push_back(2);
    ba1->push_back(3);

    shared_ptr<ByteArray> ba2 = make_shared<ByteArray>();
    ba2->push_back(3);
    ba2->push_back(2);
    ba2->push_back(1);
    ba2->push_back(0);

    shared_ptr<JsonMslObject> jmo = make_shared<JsonMslObject>(makeByteArray("{}"));
    jmo->put<shared_ptr<ByteArray>>("ba", ba1);
    jmo->put<string>("str", *util::Base64::encode(ba2));
    jmo->put<int32_t>("nonbinary", 999);
    EXPECT_EQ(3u, jmo->size());

    EXPECT_EQ(*ba1, *jmo->getBytes("ba"));
    EXPECT_EQ(*ba2, *jmo->getBytes("str"));
    try {
    	shared_ptr<ByteArray> foo = jmo->getBytes("nonbinary");
    }
    catch (const MslEncoderException& e) {
        EXPECT_EQ("JsonMslObject[nonbinary] is not binary data.", string(e.what()));
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }
}

TEST_F(JsonMslObjectTest, getEncoded)
{
    const string nestedObjJsStr =
        "{"
        "\"level1\":{"
            "\"l1a\":1,"
            "\"l1b\":2,"
            "\"level2\":{"
                "\"l2a\":1,"
                "\"l2b\":2"
                "}"
            "}"
        "}";
    shared_ptr<ByteArray> encoded = makeByteArray(nestedObjJsStr);
    shared_ptr<JsonMslObject> jmo = make_shared<JsonMslObject>(encoded);
    EXPECT_EQ(*encoded, *JsonMslObject::getEncoded(encoder, jmo));
    // ensure jmo is unchanged
    EXPECT_EQ(nestedObjJsStr, jmo->toJsonString(encoder));
}

TEST_F(JsonMslObjectTest, AutoBase64)
{
    // BASE64("foobar") = "Zm9vYmFy"
    const string strVal = "foobar";
    shared_ptr<ByteArray> data = make_shared<ByteArray>(strVal.begin(), strVal.end());
    const string dataB64 = "Zm9vYmFy";
    shared_ptr<MslObject> mo = make_shared<MslObject>();
    mo->put<shared_ptr<ByteArray>>("foo", data);
    mo->put<string>("bar", dataB64);
    shared_ptr<JsonMslObject> jmo = make_shared<JsonMslObject>(mo);
    EXPECT_EQ(*data, *jmo->getBytes("foo"));
    EXPECT_EQ(*data, *jmo->getBytes("bar"));
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
