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
#include <io/JsonMslArray.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <util/Base64.h>
#include <util/MockMslContext.h>

using namespace std;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace io {

class JsonMslArrayTest : public ::testing::Test
{
public:
	virtual ~JsonMslArrayTest() {}

	JsonMslArrayTest()
	{
    	shared_ptr<MslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
		encoder = ctx->getMslEncoderFactory();
	}

protected:
    shared_ptr<MslEncoderFactory> encoder;
};

namespace
{

shared_ptr<ByteArray> makeByteArray(const string s)
{
    return make_shared<ByteArray>(s.begin(), s.end());
}

} // anonymous namespace

// Note: JsonMslArray shares underlying code with JsonMslObject. See
// JsonMslObject_test for more tests.

TEST_F(JsonMslArrayTest, Basic)
{
	shared_ptr<ByteArray> js = makeByteArray(
        "["
            "{\"a\": 1, \"b\": 2},"
            "{\"c\": 3, \"d\": 4},"
            "[1,2,3,4],"
            "3"
        "]"
    );
    JsonMslArray jma(js);
    EXPECT_EQ(4u, jma.size());

    EXPECT_EQ(3, jma.getInt(3));

    const Variant oneVar = jma.get(1);
    EXPECT_TRUE(oneVar.isType<shared_ptr<MslObject>>());
    shared_ptr<MslObject> one = jma.getMslObject(1, encoder);
    EXPECT_EQ(2u, one->size());
    EXPECT_TRUE(one->has("d"));
    EXPECT_EQ(4, one->getInt("d"));

    const Variant twoVar = jma.get(2);
    EXPECT_TRUE(twoVar.isType<shared_ptr<MslArray>>());
    shared_ptr<MslArray> two = jma.getMslArray(2);
    EXPECT_EQ(4u, two->size());
    EXPECT_EQ(3, two->getInt(2));

    EXPECT_EQ(3, jma.get(3).get<int32_t>());
}

TEST_F(JsonMslArrayTest, EmptyArray)
{
	shared_ptr<ByteArray> js = makeByteArray("[]");
    JsonMslArray jma(js);
    EXPECT_EQ(0u, jma.size());
}

TEST_F(JsonMslArrayTest, NotArray)
{
    // can't make a JsonMslArray from JSON object
	shared_ptr<ByteArray> js = makeByteArray("{\"a\": 1, \"b\": 2}");
    EXPECT_THROW({JsonMslArray jma(js);}, MslEncoderException);
}

TEST_F(JsonMslArrayTest, toJsonString)
{
    const string emptyAryJsStr = "[]";
    shared_ptr<ByteArray> js = makeByteArray(emptyAryJsStr);
    JsonMslArray jma0(js);
    EXPECT_EQ(emptyAryJsStr, jma0.toJsonString(encoder));
    EXPECT_EQ(emptyAryJsStr, jma0.toString());

    const string aryJsStr =
        "["
            "{\"a\":1,\"b\":2},"
            "{\"c\":3,\"d\":4},"
            "[1,2,3,4],"
            "3"
        "]";
    js = makeByteArray(aryJsStr);
    JsonMslArray jma1(js);
    EXPECT_EQ(aryJsStr, jma1.toJsonString(encoder));
    EXPECT_EQ(aryJsStr, jma1.toString());
}

TEST_F(JsonMslArrayTest, getBytes)
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

    shared_ptr<JsonMslArray> jma = make_shared<JsonMslArray>(makeByteArray("[]"));
    jma->put<shared_ptr<ByteArray>>(0, ba1);
    jma->put<string>(1, *util::Base64::encode(ba2));
    jma->put<int32_t>(2, 999);
    EXPECT_EQ(3u, jma->size());

    EXPECT_EQ(*ba1, *jma->getBytes(0));
    EXPECT_EQ(*ba2, *jma->getBytes(1));
    try {
    	shared_ptr<ByteArray> foo = jma->getBytes(2);
    }
    catch (const MslEncoderException& e) {
        EXPECT_EQ("JsonMslArray[2] is not binary data.", string(e.what()));
    }
    catch (...) {
        ADD_FAILURE() << "unhandled exception thrown";
    }
}

}}} // namespace netflix::msl::io
