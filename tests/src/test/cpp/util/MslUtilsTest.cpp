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
#include <util/MslUtils.h>
#include <util/Base64.h>
#include <MslConstants.h>
#include <MslError.h>
#include <MslException.h>
#include <stdint.h>
#include <vector>

using namespace std;

namespace netflix {
namespace msl {

typedef vector<uint8_t> ByteArray;

namespace util {

namespace {

const std::string str =
		"We have to use some data that is compressible, otherwise payloads "
		"will not always use the compression we request.";

} // namespace anonymous

class MslUtilsTest : public ::testing::Test
{
};

TEST_F(MslUtilsTest, unsupportedCompression)
{
    const ByteArray data(str.begin(), str.end());
    try {
        MslUtils::compress(MslConstants::CompressionAlgorithm::NOCOMPRESSION, data);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::COMPRESSION_ERROR, e.getError());
    }
    try {
        MslUtils::uncompress(MslConstants::CompressionAlgorithm::NOCOMPRESSION, data);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::UNCOMPRESSION_ERROR, e.getError());
    }
}

TEST_F(MslUtilsTest, gzipRoundtrip)
{
    shared_ptr<ByteArray> uncompressed = make_shared<ByteArray>(str.begin(), str.end());
    shared_ptr<ByteArray> compressed = MslUtils::compress(MslConstants::CompressionAlgorithm::GZIP, *uncompressed);
    EXPECT_NE(*compressed, *uncompressed);
    EXPECT_LE(compressed->size(), uncompressed->size());
    shared_ptr<ByteArray> uncompressed2 = MslUtils::uncompress(MslConstants::CompressionAlgorithm::GZIP, *compressed);
    EXPECT_NE(*compressed, *uncompressed2);
    EXPECT_GE(uncompressed2->size(), compressed->size());
    EXPECT_EQ(*uncompressed, *uncompressed2);

    shared_ptr<ByteArray> empty = make_shared<ByteArray>();
    compressed = MslUtils::compress(MslConstants::CompressionAlgorithm::GZIP, *uncompressed);
    EXPECT_NE(*compressed, *uncompressed);
    EXPECT_LE(compressed->size(), uncompressed->size());
    uncompressed2 = MslUtils::uncompress(MslConstants::CompressionAlgorithm::GZIP, *compressed);
    EXPECT_NE(*compressed, *uncompressed2);
    EXPECT_GE(uncompressed2->size(), compressed->size());
    EXPECT_EQ(*uncompressed, *uncompressed2);
}

}}} // namespace netflix::msl::util
