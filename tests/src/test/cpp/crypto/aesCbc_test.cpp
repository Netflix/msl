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
#include <limits.h>
#include <MslCryptoException.h>
#include <MslInternalException.h>
#include <util/Hex.h>

namespace netflix {
namespace msl {
namespace crypto {

using namespace netflix::msl;
using namespace std;

namespace
{

const size_t AES_BLOCK_SIZE = 16;

// For AES CBC encryption with PKCS#5 padding, the size of the encrypted
// data may be as large as (plaintext.size() + cipher_block_size - 1), and
// also must be a multiple of the blocksize.
size_t calcAesCbcEncryptedSize(size_t plaintextSize)
{
    size_t outSize = plaintextSize + AES_BLOCK_SIZE - 1;
    if ((outSize % AES_BLOCK_SIZE) != 0)
        outSize = ((outSize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    return outSize;
}

} // namespace anonymous

class AesCbcTest : public ::testing::Test
{
public:
    AesCbcTest() {EXPECT_NO_THROW(ensureOpenSslInit());}
protected:
    void getRandomBytes(ByteArray& bytes) {
        static shared_ptr<crypto::IRandom> rand;
        if (!rand)
            rand = shared_ptr<crypto::IRandom>(make_shared<crypto::Random>());
        return rand->nextBytes(bytes);
    }
};

TEST_F(AesCbcTest, EncryptDecryptHappy)
{
    shared_ptr<ByteArray> key = make_shared<ByteArray>(16);
    getRandomBytes(*key);
    ByteArray iv(AES_BLOCK_SIZE);
    getRandomBytes(iv);
    const size_t MSGSIZE = 32;

    ByteArray messageA(MSGSIZE);
    getRandomBytes(messageA);

    // check plaintext and ciphertext are not equal...
    ByteArray ciphertextA;
    EXPECT_NO_THROW(aesCbcEncrypt(*key, iv, messageA, ciphertextA));
    const size_t expectedCiphertextLen = calcAesCbcEncryptedSize(MSGSIZE);
    EXPECT_EQ(expectedCiphertextLen, ciphertextA.size());
    EXPECT_NE(messageA, ciphertextA);

    // and that ciphertext decrypts to back original
    ByteArray plaintextA;
    EXPECT_NO_THROW(aesCbcDecrypt(*key, iv, ciphertextA, plaintextA));
    EXPECT_EQ(MSGSIZE, plaintextA.size());
    EXPECT_EQ(messageA, plaintextA);

    // encrypt a different message, make sure it is not the same as the first
    ByteArray messageB(MSGSIZE);
    getRandomBytes(messageB);
    ByteArray ciphertextB;
    EXPECT_NO_THROW(aesCbcEncrypt(*key, iv, messageB, ciphertextB));
    EXPECT_NE(ciphertextB, ciphertextA);
    ByteArray plaintextB;
    EXPECT_NO_THROW(aesCbcDecrypt(*key, iv, ciphertextB, plaintextB));
    EXPECT_EQ(plaintextB, messageB);

    // encrypting an empty buffer is ok, returns buffer of pad
    const ByteArray empty;
    EXPECT_NO_THROW(aesCbcEncrypt(*key, iv, empty, ciphertextA));
    EXPECT_EQ(16u, ciphertextA.size());
}

TEST_F(AesCbcTest, EncryptDecryptSad)
{
    shared_ptr<ByteArray> key = make_shared<ByteArray>(16);
    getRandomBytes(*key);
    ByteArray iv(AES_BLOCK_SIZE);
    getRandomBytes(iv);
    const size_t MSGSIZE = 32;
    ByteArray message(MSGSIZE);
    getRandomBytes(message);
    ByteArray ciphertext;

    // data too large
    // Note: this bogs down your machine, but the test passes
//    ByteArray giantMessage(INT_MAX);
//    EXPECT_THROW(aesCbcEncrypt(key, iv, giantMessage, ciphertext), MslCryptoException);

    // empty key
    const ByteArray nullkey;
    EXPECT_THROW(aesCbcEncrypt(nullkey, iv, message, ciphertext), MslCryptoException);

    // wrong size key
    shared_ptr<ByteArray> invalidkey = make_shared<ByteArray>(17);
    EXPECT_THROW(aesCbcEncrypt(*invalidkey, iv, message, ciphertext), MslCryptoException);

    // wrong size iv
    const ByteArray shortiv(AES_BLOCK_SIZE-1);
    EXPECT_THROW(aesCbcEncrypt(*invalidkey, shortiv, message, ciphertext), MslCryptoException);
    const ByteArray longiv(AES_BLOCK_SIZE+1);
    EXPECT_THROW(aesCbcEncrypt(*invalidkey, longiv, message, ciphertext), MslCryptoException);
}

TEST_F(AesCbcTest, TestVectors)
{
    // From a given set of <keyhex>, <ivhex>, and <inputhex>, generate <outputhex>:
    // $ echo -n <inputhex> | perl -pe 's/([0-9a-f]{2})/chr hex $1/gie' > input.bin
    // $ openssl enc -aes-<keylenbits>-cbc -in input.bin -out output.bin -K <keyhex> -iv <ivhex>
    // $ xxd -p output.bin | tr -d '\n'  (gives outputhex)

	shared_ptr<ByteArray> key, iv, plaintext, ciphertext;
	shared_ptr<ByteArray> result = make_shared<ByteArray>();

    // key length = 128
    key = util::fromHex("8809e7dd3a959ee5d8dbb13f501f2274");
    iv = util::fromHex("e5c0bb535d7d54572ad06d170a0e58ae");
    plaintext = util::fromHex("1fd4ee65603e6130cfc2a82ab3d56c24");
    ciphertext = util::fromHex("7ec55f58f047fc9603dcc3fd280a5e10fc99e012f6bbef7aa2d0faa604c8796d");
    EXPECT_NO_THROW(aesCbcEncrypt(*key, *iv, *plaintext, *result));
    EXPECT_EQ(*result, *ciphertext);
    EXPECT_NO_THROW(aesCbcDecrypt(*key, *iv, *ciphertext, *result));
    EXPECT_EQ(*result, *plaintext);

    // keylength = 192
    key = util::fromHex("dea64f83cfe6a0a183ddbe865cfca059b3c615c1623d63fc");
    iv = util::fromHex("426fbc087b50b395c0fc81ef9fd6d1aa");
    plaintext = util::fromHex("cd0b8c8a8179ecb171b64c894a4d60fd");
    ciphertext = util::fromHex("538da8183b7bf6adfe314452ac3dac72b86baa4c3111aecb7b695410b4b23287");
    EXPECT_NO_THROW(aesCbcEncrypt(*key, *iv, *plaintext, *result));
    EXPECT_EQ(*result, *ciphertext);
    EXPECT_NO_THROW(aesCbcDecrypt(*key, *iv, *ciphertext, *result));
    EXPECT_EQ(*result, *plaintext);

    // keylength = 256
    key = util::fromHex("632bac4fe4db44cfcf18cfa90b43f86f378611b8d968595eb89e7ae98624564a");
    iv = util::fromHex("ff8127621be616803e3f002377730185");
    plaintext = util::fromHex("90ed17475f0a62bc381ba1f3ffbfff33");
    ciphertext = util::fromHex("c4c51bb178814440f25994c287255626bdf4f082fd8b497dd8298868bf032bc0");
    EXPECT_NO_THROW(aesCbcEncrypt(*key, *iv, *plaintext, *result));
    EXPECT_EQ(*result, *ciphertext);
    EXPECT_NO_THROW(aesCbcDecrypt(*key, *iv, *ciphertext, *result));
    EXPECT_EQ(*result, *plaintext);
}

}}} // namespace netflix::msl::crypto
