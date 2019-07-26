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
#include <io/ByteArrayInputStream.h>
#include <io/JsonMslObject.h>
#include <io/JsonMslTokenizer.h>
#include <memory>
#include <string>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

namespace {
shared_ptr<JsonMslTokenizer> makeTokenizer(const string& s) {
	shared_ptr<InputStream> is = make_shared<ByteArrayInputStream>(s);
    return make_shared<JsonMslTokenizer>(is);
}
}

class JsonMslTokenizerTest : public ::testing::Test
{
};

TEST_F(JsonMslTokenizerTest, Main)
{
    const std::string json = "\t  \n  {\"a\":1,\"b\":2}{\"c\":3,\"d\":4,\"e\":5}";
    shared_ptr<JsonMslTokenizer> jt = makeTokenizer(json);

    shared_ptr<MslObject> jmo = jt->next();
    EXPECT_EQ(2u, jmo->size());

    jmo = jt->next();
    EXPECT_EQ(3u, jmo->size());

    jmo = jt->next();
    EXPECT_FALSE(jmo);
}

TEST_F(JsonMslTokenizerTest, BadJson)
{
    shared_ptr<MslObject> mo;

    // empty
    const std::string bad0 = "";
    shared_ptr<JsonMslTokenizer> jt0 = makeTokenizer(bad0);
    EXPECT_NO_THROW({mo = jt0->next();});
    EXPECT_FALSE(mo);
    EXPECT_NO_THROW({mo = jt0->next();});
    EXPECT_FALSE(mo);

    // garbage in front
    const std::string bad1 = " \t\n  FOO  {\"a\":1,\"b\":2}{\"c\":3,\"d\":4,\"e\":5}";
    shared_ptr<JsonMslTokenizer> jt1 = makeTokenizer(bad1);
    EXPECT_THROW(jt1->next(), MslEncoderException);
    EXPECT_NO_THROW({mo = jt1->next();});
    EXPECT_EQ(2u, mo->size());
    EXPECT_NO_THROW({mo = jt1->next();});
    EXPECT_EQ(3u, mo->size());
    EXPECT_NO_THROW({mo = jt1->next();});
    EXPECT_FALSE(mo);

    // garbage in between
    const std::string bad2 = "{\"a\":1,\"b\":2} \n FOO \t {\"c\":3,\"d\":4,\"e\":5}";
    shared_ptr<JsonMslTokenizer> jt2 = makeTokenizer(bad2);
    EXPECT_NO_THROW({mo = jt2->next();});
    EXPECT_EQ(2u, mo->size());
    EXPECT_THROW(jt2->next(), MslEncoderException);
    EXPECT_NO_THROW({mo = jt2->next();});
    EXPECT_EQ(3u, mo->size());
    EXPECT_NO_THROW({mo = jt2->next();});
    EXPECT_FALSE(mo);

    // incomplete JSON in front
    const std::string bad3 = "{\"a\":1,\"b\" FOO \n\t  {\"c\":3,\"d\":4,\"e\":5}";
    shared_ptr<JsonMslTokenizer> jt3 = makeTokenizer(bad3);
    EXPECT_THROW(jt3->next(), MslEncoderException);
    EXPECT_NO_THROW({mo = jt3->next();});
    EXPECT_EQ(3u, mo->size());
    EXPECT_NO_THROW({mo = jt3->next();});
    EXPECT_FALSE(mo);

    // incomplete JSON at end
    const std::string bad4 = "{\"a\":1,\"b\":2} \n 5FOO \t {\"c\":3";
    shared_ptr<JsonMslTokenizer> jt4 = makeTokenizer(bad4);
    EXPECT_NO_THROW({mo = jt4->next();});
    EXPECT_EQ(2u, mo->size());
    EXPECT_THROW(jt4->next(), MslEncoderException);  // hits "5", advances to 'F'
    EXPECT_THROW(jt4->next(), MslEncoderException);  // hits "FOO", advances to '{'
    EXPECT_THROW(jt4->next(), MslEncoderException);  // incomplete JSON object, advances to end
    EXPECT_NO_THROW({mo = jt4->next();}); // return empty object from empty stream
    EXPECT_FALSE(mo);

    // garbage at end
    const std::string bad5 = " \t\n{\"a\":1,\"b\":2}  \t {\"c\":3,\"d\":4,\"e\":5} FOO";
    shared_ptr<JsonMslTokenizer> jt5 = makeTokenizer(bad5);
    EXPECT_NO_THROW({mo = jt5->next();});
    EXPECT_EQ(2u, mo->size());
    EXPECT_NO_THROW({mo = jt5->next();});
    EXPECT_EQ(3u, mo->size());
    EXPECT_THROW(jt5->next(), MslEncoderException);
    EXPECT_NO_THROW({mo = jt5->next();});
    EXPECT_FALSE(mo);
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
