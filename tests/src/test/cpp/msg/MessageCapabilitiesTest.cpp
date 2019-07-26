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
#include <io/MslObject.h>
#include <io/MslArray.h>
#include <io/DefaultMslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <msg/MessageCapabilities.h>
#include <MslConstants.h>
#include <MslEncodingException.h>
#include <algorithm>

using namespace std;
using namespace netflix::msl::io;

namespace netflix {
namespace msl {
namespace msg {

namespace {
const std::string KEY_COMPRESSION_ALGOS = "compressionalgos";
const std::string KEY_LANGUAGES = "languages";
const std::string KEY_ENCODER_FORMATS = "encoderformats";

template <typename T> string op(const T& x) { return x.toString(); }

//string toString(MessageCapabilities mc) {
//    MslEncoderFactory mef;
//    const ByteArray ba = mc.toMslEncoding(mef, MslEncoderFormat::JSON);
//    return string(ba.begin(), ba.end());
//}

}

class MessageCapabilitiesTest : public ::testing::Test
{
protected:
    MessageCapabilitiesTest() {
        compressionAlgos_.insert(MslConstants::CompressionAlgorithm::NOCOMPRESSION);
        compressionAlgos_.insert(MslConstants::CompressionAlgorithm::LZW);
        compressionAlgos_.insert(MslConstants::CompressionAlgorithm::GZIP);
        languages_.push_back("aa");
        languages_.push_back("cc");
        languages_.push_back("bb");
        encoderFormats_.insert(MslEncoderFormat::JSON);
    }
    set<MslConstants::CompressionAlgorithm> compressionAlgos_;
    vector<string> languages_;
    set<MslEncoderFormat> encoderFormats_;
};

TEST_F(MessageCapabilitiesTest, simpleCtor)
{
    MessageCapabilities mc(compressionAlgos_, languages_, encoderFormats_);
    EXPECT_EQ(compressionAlgos_, mc.getCompressionAlgorithms());
    EXPECT_EQ(languages_, mc.getLanguages());
    EXPECT_EQ(encoderFormats_, mc.getEncoderFormats());
}

TEST_F(MessageCapabilitiesTest, mslObjectCtor)
{
    // happy path
    shared_ptr<MslObject> mo = make_shared<MslObject>();
    vector<string> ca(compressionAlgos_.size());
    transform(compressionAlgos_.begin(), compressionAlgos_.end(), ca.begin(), op<MslConstants::CompressionAlgorithm>);
    shared_ptr<MslArray> cama = make_shared<MslArray>(ca);
    mo->put(KEY_COMPRESSION_ALGOS, cama);
    shared_ptr<MslArray> lma = make_shared<MslArray>(languages_);
    mo->put(KEY_LANGUAGES, lma);
    vector<string> ef(encoderFormats_.size());
    transform(encoderFormats_.begin(), encoderFormats_.end(), ef.begin(), op<MslEncoderFormat>);
    shared_ptr<MslArray> efma = make_shared<MslArray>(ef);
    mo->put(KEY_ENCODER_FORMATS, efma);
    shared_ptr<MessageCapabilities> mc1 = make_shared<MessageCapabilities>(mo);
    EXPECT_EQ(compressionAlgos_, mc1->getCompressionAlgorithms());
    EXPECT_EQ(languages_, mc1->getLanguages());
    EXPECT_EQ(encoderFormats_, mc1->getEncoderFormats());

    // missing compression algos field
    mo->remove(KEY_COMPRESSION_ALGOS);
    shared_ptr<MessageCapabilities> mc2 = make_shared<MessageCapabilities>(mo);
    EXPECT_TRUE(mc2->getCompressionAlgorithms().empty());
    mo->put(KEY_COMPRESSION_ALGOS, cama);

    // unsupported compression algorithm
    cama->put<string>(-1, "invalidCompressionAlgoName");
    mo->put(KEY_COMPRESSION_ALGOS, cama);
    shared_ptr<MessageCapabilities> mc3 = make_shared<MessageCapabilities>(mo);
    EXPECT_EQ(compressionAlgos_, mc3->getCompressionAlgorithms());

    // missing languages
    mo->remove(KEY_LANGUAGES);
    shared_ptr<MessageCapabilities> mc4 = make_shared<MessageCapabilities>(mo);
    EXPECT_TRUE(mc4->getLanguages().empty());
    mo->put(KEY_LANGUAGES, lma);

    // missing encoder formats
    mo->remove(KEY_ENCODER_FORMATS);
    shared_ptr<MessageCapabilities> mc5 = make_shared<MessageCapabilities>(mo);
    EXPECT_TRUE(mc5->getEncoderFormats().empty());
    mo->put(KEY_ENCODER_FORMATS, efma);

    // unsupported encoder formats
    efma->put<string>(-1, "invalidEncoderFormat");
    mo->put(KEY_ENCODER_FORMATS, efma);
    shared_ptr<MessageCapabilities> mc6 = make_shared<MessageCapabilities>(mo);
    EXPECT_EQ(encoderFormats_, mc6->getEncoderFormats());
}

TEST_F(MessageCapabilitiesTest, toMslEncoding)
{
	// FIXME: This is an error-prone test because there is no guarantee of how
	// a JSON encoding might be constructed or formatted.
    shared_ptr<MessageCapabilities> mc1 = make_shared<MessageCapabilities>(compressionAlgos_, languages_, encoderFormats_);
    shared_ptr<MslEncoderFactory> mef = make_shared<DefaultMslEncoderFactory>();
    shared_ptr<ByteArray> ba1 = mc1->toMslEncoding(mef, MslEncoderFormat::JSON);
    EXPECT_EQ(
        "{\"compressionalgos\":[\"GZIP\",\"LZW\",\"NOCOMPRESSION\"],\"encoderformats\":[\"JSON\"],\"languages\":[\"aa\",\"cc\",\"bb\"]}",
        string(ba1->begin(), ba1->end()));

    shared_ptr<MslObject> mo = make_shared<MslObject>();
    shared_ptr<MessageCapabilities> mc2 = make_shared<MessageCapabilities>(mo);
    shared_ptr<ByteArray> ba2 = mc2->toMslEncoding(mef, MslEncoderFormat::JSON);
    EXPECT_EQ(
        "{\"compressionalgos\":[],\"encoderformats\":[],\"languages\":[]}",
        string(ba2->begin(), ba2->end()));
}

TEST_F(MessageCapabilitiesTest, equality)
{
    set<MslConstants::CompressionAlgorithm> compressionAlgos = compressionAlgos_;
    vector<string> languages = languages_;
    set<MslEncoderFormat> encoderFormats = encoderFormats_;

    shared_ptr<MessageCapabilities> mc1 = make_shared<MessageCapabilities>(compressionAlgos_, languages_, encoderFormats_);
    shared_ptr<MessageCapabilities> mc2 = make_shared<MessageCapabilities>(compressionAlgos, languages, encoderFormats);
    EXPECT_TRUE(*mc1 == *mc2);
    EXPECT_FALSE(*mc1 != *mc2);
    EXPECT_EQ(*mc1, *mc2);

    compressionAlgos.erase(MslConstants::CompressionAlgorithm::LZW);
    shared_ptr<MessageCapabilities> mc3 = make_shared<MessageCapabilities>(compressionAlgos, languages, encoderFormats);
    EXPECT_FALSE(*mc2 == *mc3);
    EXPECT_TRUE(*mc2 != *mc3);
    EXPECT_NE(*mc1, *mc3);
}

TEST_F(MessageCapabilitiesTest, intersection)
{
    // empty intersection with empty should be empty
    const set<MslConstants::CompressionAlgorithm> emptyCompressionAlgos;
    const vector<string> emptyLanguages;
    const set<MslEncoderFormat> emptyEncoderFormats;
    shared_ptr<MessageCapabilities> mc1 = make_shared<MessageCapabilities>(emptyCompressionAlgos, emptyLanguages, emptyEncoderFormats);
    shared_ptr<MessageCapabilities> mc2 = make_shared<MessageCapabilities>(emptyCompressionAlgos, emptyLanguages, emptyEncoderFormats);
    shared_ptr<MessageCapabilities> result = MessageCapabilities::intersection(mc1, mc2);
    EXPECT_TRUE(result->getCompressionAlgorithms().empty());
    EXPECT_TRUE(result->getEncoderFormats().empty());
    EXPECT_TRUE(result->getLanguages().empty());

    // empty intersection with non-empty object should kill the object x3
    shared_ptr<MessageCapabilities> mc3 = make_shared<MessageCapabilities>(compressionAlgos_, languages_, encoderFormats_);
    shared_ptr<MessageCapabilities> emptyMc1 = make_shared<MessageCapabilities>(emptyCompressionAlgos, languages_, encoderFormats_);
    shared_ptr<MessageCapabilities> emptyMc2 = make_shared<MessageCapabilities>(compressionAlgos_, emptyLanguages, encoderFormats_);
    shared_ptr<MessageCapabilities> emptyMc3 = make_shared<MessageCapabilities>(compressionAlgos_, languages_, emptyEncoderFormats);

    result = MessageCapabilities::intersection(mc3, emptyMc1);
    EXPECT_TRUE(result->getCompressionAlgorithms().empty());
    EXPECT_NE(compressionAlgos_, result->getCompressionAlgorithms());
    EXPECT_EQ(languages_, result->getLanguages());
    EXPECT_EQ(encoderFormats_, result->getEncoderFormats());

    result = MessageCapabilities::intersection(mc3, emptyMc2);
    EXPECT_TRUE(result->getLanguages().empty());
    EXPECT_EQ(compressionAlgos_, result->getCompressionAlgorithms());
    EXPECT_NE(languages_, result->getLanguages());
    EXPECT_EQ(encoderFormats_, result->getEncoderFormats());

    result = MessageCapabilities::intersection(mc3, emptyMc3);
    EXPECT_TRUE(result->getEncoderFormats().empty());
    EXPECT_EQ(compressionAlgos_, result->getCompressionAlgorithms());
    EXPECT_EQ(languages_, result->getLanguages());
    EXPECT_NE(encoderFormats_, result->getEncoderFormats());

    // intersection between two non-empty objects should be the lesser object
    set<MslConstants::CompressionAlgorithm> compressionAlgos = compressionAlgos_;
    vector<string> languages = languages_;
    set<MslEncoderFormat> encoderFormats = encoderFormats_;
    compressionAlgos.erase(MslConstants::CompressionAlgorithm::LZW);
    languages.erase(remove(languages.begin(), languages.end(), "bb"), languages.end());
    encoderFormats.erase(MslEncoderFormat::JSON);
    shared_ptr<MessageCapabilities> mc4 = make_shared<MessageCapabilities>(compressionAlgos, languages, encoderFormats);
    result = MessageCapabilities::intersection(mc3, mc4);
    EXPECT_EQ(compressionAlgos, result->getCompressionAlgorithms());
    EXPECT_EQ(languages, result->getLanguages());
    EXPECT_EQ(encoderFormats, result->getEncoderFormats());

    // intersection order should not matter
    shared_ptr<MessageCapabilities> result1 = MessageCapabilities::intersection(mc4, mc3);
    EXPECT_EQ(*result, *result1);
}

}}} // namespace netflix::msl::msg
