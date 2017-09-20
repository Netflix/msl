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
#include <util/Hex.h>

using namespace std;
using namespace netflix::msl;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

/*
https://www.ietf.org/rfc/rfc3526.txt
3.  2048-bit MODP Group

   This group is assigned id 14.

   This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }

   Its hexadecimal value is:

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF

   The generator is: 2.
*/
const char * modp2048p =
      "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
      "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
      "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
      "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
      "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
      "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
      "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
      "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
      "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
      "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
      "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
const char * modp2048g = "02";

} // namespace anonymous

class DiffieHellmanTest : public ::testing::Test
{
public:
    DiffieHellmanTest() {EXPECT_NO_THROW(ensureOpenSslInit());}
protected:
    shared_ptr<ByteArray> getRandomBytes(size_t n) {
        shared_ptr<ByteArray> bytes = make_shared<ByteArray>(n);
        static shared_ptr<crypto::IRandom> rand;
        if (!rand)
            rand = shared_ptr<crypto::IRandom>(make_shared<crypto::Random>());
        rand->nextBytes(*bytes);
        return bytes;
    }
};

// void dhGenKeyPair(const ByteArray& p, const ByteArray& g, ByteArray& pubKey, ByteArray& privKey)
//void dhComputeSharedSecret(const ByteArray& remotePublicKey, const ByteArray& p,
//          const ByteArray& localPrivateKey, ByteArray& sharedSecret)

TEST_F(DiffieHellmanTest, agreement)
{
    shared_ptr<ByteArray> p = util::fromHex(modp2048p);
    shared_ptr<ByteArray> g = util::fromHex(modp2048g);

    ByteArray pubKeyA, privKeyA;
    dhGenKeyPair(*p, *g, pubKeyA, privKeyA);
    EXPECT_FALSE(pubKeyA.empty());
    EXPECT_FALSE(privKeyA.empty());

    ByteArray pubKeyB, privKeyB;
    dhGenKeyPair(*p, *g, pubKeyB, privKeyB);
    EXPECT_FALSE(pubKeyB.empty());
    EXPECT_FALSE(privKeyB.empty());

    EXPECT_NE(pubKeyA, pubKeyB);
    EXPECT_NE(privKeyA, privKeyB);

    ByteArray sharedSecretA, sharedSecretB;
    dhComputeSharedSecret(pubKeyB, *p, privKeyA, sharedSecretA);
    dhComputeSharedSecret(pubKeyA, *p, privKeyB, sharedSecretB);
    EXPECT_FALSE(sharedSecretA.empty());
    EXPECT_FALSE(sharedSecretB.empty());
    EXPECT_EQ(sharedSecretA, sharedSecretB);
}

}}} // namespace netflix::msl::crypto
