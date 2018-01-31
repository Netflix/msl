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
#include <crypto/OpenSslLib.h>
#include <crypto/Random.h>
#include <IllegalArgumentException.h>
#include <MslCryptoException.h>
#include <util/Hex.h>
#include <memory>
#include <vector>

#include "util.h"

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

#include "vectorsAesKw.h"

struct TestVector
{
    const size_t size;
    vector<shared_ptr<ByteArray>> key;
    vector<shared_ptr<ByteArray>> plaintext;
    vector<shared_ptr<ByteArray>> ciphertext;
    TestVector(const NistData rawData[], size_t s) : size(s)
    {
        for (size_t i = 0; i < size; ++i) {
            key.push_back(fromHex(rawData[i].key));
            plaintext.push_back(fromHex(rawData[i].plaintext));
            ciphertext.push_back(fromHex(rawData[i].ciphertext));
        }
    }
};

template<typename T, size_t S> size_t SizeOf(T(&)[S]) { return S; }

void checkVec(const TestVector& tv, const string& name)
{
    for (size_t i = 0; i < tv.size; ++i) {
    	shared_ptr<ByteArray> result = make_shared<ByteArray>();
        stringstream ss;
        ss << ": " << name << "(" << i << ")";
        EXPECT_NO_THROW(aesKwWrap(*tv.key[i], *tv.plaintext[i], *result)) << ss.str();
        EXPECT_EQ(*tv.ciphertext[i], *result) << ss.str();
        EXPECT_NO_THROW(aesKwUnwrap(*tv.key[i], *tv.ciphertext[i], *result)) << ss.str();
        EXPECT_EQ(*tv.plaintext[i], *result) << ss.str();
    }
}

} // namespace anonymous

class AesKwTest : public ::testing::Test
{
public:
    AesKwTest() {
    	EXPECT_NO_THROW(ensureOpenSslInit());
    	rand = make_shared<crypto::Random>();
    }
protected:
    shared_ptr<ByteArray> getRandomBytes(size_t n) {
    	shared_ptr<ByteArray> bytes = make_shared<ByteArray>(n);
        rand->nextBytes(*bytes);
        return bytes;
    }
    shared_ptr<crypto::IRandom> rand;
};

TEST_F(AesKwTest, NistVectors)
{
    checkVec(TestVector(kwaeData128, SizeOf(kwaeData128)), "kwaeData128");
    checkVec(TestVector(kwaeData192, SizeOf(kwaeData192)), "kwaeData192");
    checkVec(TestVector(kwaeData256, SizeOf(kwaeData256)), "kwaeData256");
}

TEST_F(AesKwTest, RandomRoundTrip)
{
    // Generate random wrapping keys
	shared_ptr<ByteArray> key128 = getRandomBytes(16);
	shared_ptr<ByteArray> key192 = getRandomBytes(24);
	shared_ptr<ByteArray> key256 = getRandomBytes(32);
    //const string key128hex = "key: " + toHex(key128) + " ";
    //const string key192hex = "key: " + toHex(key192) + " ";
    //const string key256hex = "key: " + toHex(key256) + " ";

	shared_ptr<ByteArray> result1 = make_shared<ByteArray>();
	shared_ptr<ByteArray> result2 = make_shared<ByteArray>();
    const int nIterations = 16;
    for (int i = 0; i < nIterations; ++i)
    {
        // Generate random data of random length as the key to wrap
        const unsigned int keyLenBytes = static_cast<unsigned int>((2 + rand->nextInt(511)) * 8);
        shared_ptr<ByteArray> plaintext = getRandomBytes(keyLenBytes);
        //const string dataHex = "data: " + toHex(plaintext);

        // 128-bit key
        EXPECT_NO_THROW(aesKwWrap(*key128, *plaintext, *result1)); // << key128hex << dataHex;
        EXPECT_NE(*result1, *plaintext);
        EXPECT_NO_THROW(aesKwUnwrap(*key128, *result1, *result2)); // << key128hex << dataHex;
        EXPECT_EQ(*plaintext, *result2);

        // 192-bit key
        EXPECT_NO_THROW(aesKwWrap(*key192, *plaintext, *result1)); // << key192hex << dataHex;
        EXPECT_NE(*result1, *plaintext);
        EXPECT_NO_THROW(aesKwUnwrap(*key192, *result1, *result2)); // << key192hex << dataHex;
        EXPECT_EQ(*plaintext, *result2);

        // 256-bit key
        EXPECT_NO_THROW(aesKwWrap(*key256, *plaintext, *result1)); // << key256hex << dataHex;
        EXPECT_NE(*result1, *plaintext);
        EXPECT_NO_THROW(aesKwUnwrap(*key256, *result1, *result2)); // << key256hex << dataHex;
        EXPECT_EQ(*plaintext, *result2);
    }
}

TEST_F(AesKwTest, SadPath)
{
    // AesKwWrap wrapping key size not equal to 16, 24, or 32 bytes
	shared_ptr<ByteArray> badKey = getRandomBytes(17);
	shared_ptr<ByteArray> plaintext = getRandomBytes(32);
	shared_ptr<ByteArray> result = make_shared<ByteArray>();
    EXPECT_THROW(aesKwWrap(*badKey, *plaintext, *result), IllegalArgumentException);

    // AesKwWrap plaintext data less than 16 bytes (still a multiple of 8)
    shared_ptr<ByteArray> key = getRandomBytes(16);
    shared_ptr<ByteArray> shortPlaintext = getRandomBytes(8);
    EXPECT_THROW(aesKwWrap(*key, *shortPlaintext, *result), IllegalArgumentException);

    // AesKwWrap plaintext data not a multiple of 8 bytes (but greater than 16)
    shared_ptr<ByteArray> misalignedPlaintext = getRandomBytes(17);
    EXPECT_THROW(aesKwWrap(*key, *misalignedPlaintext, *result), IllegalArgumentException);

    // AesKwUnwrap ciphertext data empty
    shared_ptr<ByteArray> ciphertext = make_shared<ByteArray>();
    EXPECT_THROW(aesKwUnwrap(*key, *ciphertext, *result), IllegalArgumentException);

    // AesKwUnwrap wrapping key size not equal to 16, 24, or 32 bytes
    ciphertext = getRandomBytes(32);
    EXPECT_THROW(aesKwUnwrap(*badKey, *ciphertext, *result), IllegalArgumentException);

    // AesKwUnwrap corrupt ciphertext
    EXPECT_NO_THROW(aesKwWrap(*key, *plaintext, *result));
    size_t midIdx = result->size() / 2;
    (*result)[midIdx] = static_cast<uint8_t>(~(*result)[midIdx]);
    shared_ptr<ByteArray> result2 = make_shared<ByteArray>();
    EXPECT_THROW(aesKwUnwrap(*key, *result, *result2), MslCryptoException);
}

}}} // namespace netflix::msl::crypto
