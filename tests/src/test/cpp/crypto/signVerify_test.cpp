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
#include <MslCryptoException.h>
#include <util/Hex.h>

#include "util.h"


using netflix::msl::util::fromHex;

using namespace netflix::msl;
using namespace std;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

struct TestData
{
    const char* key;
    const char* msg;
    const char* mac;
};

#include "vectorsHmacSha256.h"
#include "vectorsAesCmac.h"

struct TestVector
{
    const TestData *data;
    const size_t size;
    vector<shared_ptr<ByteArray>> key;
    vector<shared_ptr<ByteArray>> msg;
    vector<shared_ptr<ByteArray>> mac;
    TestVector(const TestData *data, size_t size) : data(data), size(size)
    {
        for (size_t i = 0; i < size; ++i) {
            key.push_back(fromHex(data[i].key));
            msg.push_back(fromHex(data[i].msg));
            mac.push_back(fromHex(data[i].mac));
        }
    }
};

struct TestParameters {
    TestParameters(const string& name,
            size_t keyLen,
            size_t sigSize,
            void (*signFunc)(const ByteArray&, const ByteArray&, ByteArray&),
            bool (*verifyFunc)(const ByteArray&, const ByteArray&, const ByteArray&),
            const TestVector& testVector)
        : name(name)
        , keyLen(keyLen)
        , sigSize(sigSize)
        , signFunc(signFunc)
        , verifyFunc(verifyFunc)
        , testVector(testVector)
    {}
    const string name;
    const size_t keyLen;
    const size_t sigSize;
    void (*signFunc)(const ByteArray& key, const ByteArray& data, ByteArray& sig);
    bool (*verifyFunc)(const ByteArray& key, const ByteArray& data, const ByteArray& sig);
    const TestVector testVector;
    friend std::ostream & operator<<(std::ostream &os, const TestParameters& tp);
};

std::ostream & operator<<(std::ostream& os, const TestParameters& tp) {
    return os << tp.name;
}

string sufx(testing::TestParamInfo<struct TestParameters> tpi) {
    return tpi.param.name;
}

}

class SignVerifyTest : public ::testing::TestWithParam<TestParameters>
{
public:
    SignVerifyTest() {
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

INSTANTIATE_TEST_CASE_P(Crypto, SignVerifyTest, ::testing::Values(
    TestParameters("HmacSha256", 32, 32, signHmacSha256, verifyHmacSha256, TestVector(hmacSha256Data, hmacSha256DataLen)),
    TestParameters("AesCmac",    16, 16, signAesCmac,    verifyAesCmac,    TestVector(aesCmacData,    aesCmacDataLen   ))
), &sufx);

TEST_P(SignVerifyTest, Errors)
{
    // sign with empty key should throw and not modify input signature
	shared_ptr<ByteArray> msg = getRandomBytes(32);
	shared_ptr<ByteArray> emptyKey = make_shared<ByteArray>();
	shared_ptr<ByteArray> signature = getRandomBytes(16);
    const ByteArray sigBak = *signature;
    try {
        GetParam().signFunc(*emptyKey, *msg, *signature);
        ADD_FAILURE() << "signHmacSha256 should have thrown";
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::SIGN_NOT_SUPPORTED, e.getError());
        EXPECT_EQ(sigBak, *signature);
    }

    // sign with empty data should be ok
    shared_ptr<ByteArray> emptyMsg = make_shared<ByteArray>();
    shared_ptr<ByteArray> key = getRandomBytes(GetParam().keyLen);
    EXPECT_NO_THROW(GetParam().signFunc(*key, *emptyMsg, *signature));
    EXPECT_FALSE(signature->empty());

    // verify with empty data should be ok (signature of empty data found above)
    bool verified = false;
    EXPECT_NO_THROW({verified = GetParam().verifyFunc(*key, *emptyMsg, *signature);});
    EXPECT_TRUE(verified);

    // verify with empty key should throw
    try {
        GetParam().verifyFunc(*emptyKey, *msg, *signature);
        ADD_FAILURE() << "verifyHmacSha256 should have thrown";
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::VERIFY_NOT_SUPPORTED, e.getError());
    }

    // reset signature
    EXPECT_NO_THROW(GetParam().signFunc(*key, *msg, *signature));
    EXPECT_NO_THROW({verified = GetParam().verifyFunc(*key, *msg, *signature);});
    EXPECT_TRUE(verified);

    // verify with corrupted msg should return false
    shared_ptr<ByteArray> corruptedMsg = make_shared<ByteArray>();
    *corruptedMsg = *msg;
    size_t midIdx = corruptedMsg->size() / 2;
    (*corruptedMsg)[midIdx] = static_cast<uint8_t>(~(*corruptedMsg)[midIdx]);
    EXPECT_NO_THROW({verified = GetParam().verifyFunc(*key, *corruptedMsg, *signature);});
    EXPECT_FALSE(verified);

    // verify with empty sig should return false
    shared_ptr<ByteArray> emptySignature = make_shared<ByteArray>();
    EXPECT_NO_THROW({verified = GetParam().verifyFunc(*key, *msg, *emptySignature);});
    EXPECT_FALSE(verified);

    // verify with corrupted sig should return false
    shared_ptr<ByteArray> corruptedSig = make_shared<ByteArray>();
    *corruptedSig = *signature;
    midIdx = corruptedSig->size() / 2;
    (*corruptedSig)[midIdx] = static_cast<uint8_t>(~(*corruptedSig)[midIdx]);
    EXPECT_NO_THROW({verified = GetParam().verifyFunc(*key, *msg, *corruptedSig);});
    EXPECT_FALSE(verified);

    // verify with different key should return false
    shared_ptr<ByteArray> differentKey = make_shared<ByteArray>();
    *differentKey = *key;
    midIdx = differentKey->size() / 2;
    (*differentKey)[midIdx] = static_cast<uint8_t>(~(*differentKey)[midIdx]);
    EXPECT_NO_THROW({verified = GetParam().verifyFunc(*differentKey, *msg, *corruptedSig);});
    EXPECT_FALSE(verified);
}

TEST_P(SignVerifyTest, RandomRoundTrip)
{
    const int nIts = 128;
    for (int i = 0; i < nIts; ++i) {
        // generate a random key
    	shared_ptr<ByteArray> key = getRandomBytes(GetParam().keyLen);
        // pick a random msg length (1..1024 bytes)
        const unsigned int msgLen = static_cast<unsigned int>(1 + rand->nextInt(1024));
        // signHmacSha256 random message
        shared_ptr<ByteArray> msg = getRandomBytes(msgLen);
        // sign msg with key
        shared_ptr<ByteArray> signature = make_shared<ByteArray>();
        EXPECT_NO_THROW(GetParam().signFunc(*key, *msg, *signature));
        EXPECT_EQ(GetParam().sigSize, signature->size());
        // verify signature
        bool verified = false;
        EXPECT_NO_THROW({verified = GetParam().verifyFunc(*key, *msg, *signature);});
        EXPECT_TRUE(verified);
        // change signature and show verify fails
        shared_ptr<ByteArray> corruptedSig = make_shared<ByteArray>();
        *corruptedSig = *signature;
        const size_t midIdx = corruptedSig->size() / 2;
        (*corruptedSig)[midIdx] = static_cast<uint8_t>(~(*corruptedSig)[midIdx]);
        EXPECT_NO_THROW({verified = GetParam().verifyFunc(*key, *msg, *corruptedSig);});
        EXPECT_FALSE(verified);
    }
}

TEST_P(SignVerifyTest, NistVectors)
{
//    const ::testing::TestInfo* const test_info =
//      ::testing::UnitTest::GetInstance()->current_test_info();
//    printf("We are in test %s of test case %s.\n",
//           test_info->name(), test_info->test_case_name());
    const TestVector& tv = GetParam().testVector;
    shared_ptr<ByteArray> signature = make_shared<ByteArray>();
    for (size_t i = 0; i < tv.size; ++i)
    {
        EXPECT_NO_THROW(GetParam().signFunc(*tv.key[i], *tv.msg[i], *signature));
        EXPECT_EQ(*tv.mac[i], *signature);
        bool verified = false;
        EXPECT_NO_THROW({verified = GetParam().verifyFunc(*tv.key[i], *tv.msg[i], *tv.mac[i]);});
        EXPECT_TRUE(verified);
    }
}

}}} // namespace netflix::msl::crypto
