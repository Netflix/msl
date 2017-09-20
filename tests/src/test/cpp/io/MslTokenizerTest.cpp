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
#include <io/MslTokenizer.h>
#include <sstream>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

namespace {
shared_ptr<MslTokenizer> makeTokenizer(istringstream& iss) {
	shared_ptr<InputStream> is = make_shared<ByteArrayInputStream>(iss.str());
    return make_shared<JsonMslTokenizer>(is);
}
}

class MslTokenizerTest : public ::testing::Test
{
};

TEST_F(MslTokenizerTest, Main)
{
    // two complete objects
    istringstream iss(
        "{\"a\":1,\"b\":2}{\"c\":3,\"d\":4,\"e\":5}"
    );
    shared_ptr<MslTokenizer> mt = makeTokenizer(iss);

    // get first object
    EXPECT_TRUE(mt->more());
    shared_ptr<MslObject> jmo = mt->nextObject();
    EXPECT_EQ(2u, jmo->size());

    // get second object
    EXPECT_TRUE(mt->more());
    jmo = mt->nextObject();
    EXPECT_EQ(3u, jmo->size());

    // no more
    EXPECT_FALSE(mt->more());
    EXPECT_FALSE(mt->more());
}

TEST_F(MslTokenizerTest, Abort)
{
    // two complete objects
    istringstream iss(
        "{\"a\":1,\"b\":2}{\"c\":3,\"d\":4,\"e\":5}"
    );
    shared_ptr<MslTokenizer> mt = makeTokenizer(iss);

    // get first object
    EXPECT_TRUE(mt->more());
    shared_ptr<MslObject> mo = mt->nextObject();
    EXPECT_EQ(2u, mo->size());

    // get no more after abort
    mt->abort();
    EXPECT_FALSE(mt->more());
    mo = mt->nextObject();
    EXPECT_FALSE(mo);

    EXPECT_FALSE(mt->more());
    mo = mt->nextObject();
    EXPECT_FALSE(mo);
}

TEST_F(MslTokenizerTest, MoreNext)
{
    // two complete objects with intervening partial object garbage
    istringstream iss(
        "{\"a\":1,\"b\":2}{\"c\":3{\"c\":3,\"d\":4,\"e\":5}"
        //                ^^^^^^^^
        //                partial obj
    );
    shared_ptr<MslTokenizer> mt = makeTokenizer(iss);

    // get first object
    EXPECT_TRUE(mt->more());
    shared_ptr<MslObject> mo;
    EXPECT_NO_THROW({mo = mt->nextObject();});
    EXPECT_EQ(2u, mo->size());

    // garbage data should throw
    EXPECT_THROW(mt->more(), MslEncoderException);

    // advance to next object
    EXPECT_TRUE(mt->more());
    EXPECT_NO_THROW({mo = mt->nextObject();});
    EXPECT_EQ(3u, mo->size());

    // no more
    EXPECT_FALSE(mt->more());
}

TEST_F(MslTokenizerTest, Noisy)
{
    istringstream iss(
        "adsfasfds"
        "{\"a\":1}"
        "rklgjhreklgn"
        "{\"b\":2}"
        "lekuhgtekw"
        "{\"c\":3}"
        "/.,/e.rit"
        "{\"d\":4}"
        "t2904fyn4ti3 "
        "{\"e\":5}"
        "\tdgjhdkj234982r"
        "{\"f\":6}"
        "5o8nv45"
        "{\"g\":7}"
        "erygrehher"
        "{\"h\":8}"
        "n v9t73 9tvh4tg9p7 b3 0tv2gpt974 tgvp4whgp94"
    );
    shared_ptr<MslTokenizer> mt = makeTokenizer(iss);

    vector<shared_ptr<MslObject>> mos;
    while(1)
    {
        try {
            if (!mt->more())
                break;
            mos.push_back(mt->nextObject());
        }
        catch (const MslEncoderException& e) {
            //cout << e.what() << endl;
        }
        catch (...) {
            ADD_FAILURE();
        }
    }
    EXPECT_EQ(8u, mos.size());
}

}}} // netflix::msl::io
