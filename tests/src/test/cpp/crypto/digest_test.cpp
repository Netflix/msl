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
#include <util/Hex.h>
#include <map>
#include <string>

using namespace std;
using namespace netflix::msl;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

struct Vectr
{
    ByteArray msg;
    map<string, ByteArray> md;
};

// NOTE: Using C++11 in this file to statically init maps, because it's really
// cumbersome to do this in C++03

// http://www.di-mgt.com.au/sha_testvectors.html
const map<string, map<string, string>> hexData = {
//Input message: the empty string "", the bit string of length 0.
{"", {
    {"SHA224", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
    {"SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"SHA384", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
    {"SHA512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"}
}},
//Input message: "abc", the bit string (0x)616263 of length 24 bits.
{"616263", {
    {"SHA224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
    {"SHA256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"SHA384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
    {"SHA512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"}
}},
//Input message: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (length 448 bits).
{"6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", {
    {"SHA224", "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"},
    {"SHA256", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    {"SHA384", "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"},
    {"SHA512", "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"}
}},
//Input message: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" (length 896 bits).
{"61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475", {
    {"SHA224", "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"},
    {"SHA256", "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
    {"SHA384", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"},
    {"SHA512", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
}}
};

} // namespace anonymous

class DigestTest : public ::testing::Test
{
public:
    DigestTest()
    {
        EXPECT_NO_THROW(ensureOpenSslInit());
        for (auto data : hexData) {
            Vectr vectr;
            vectr.msg = *util::fromHex(data.first);
            for (auto item : data.second)
                vectr.md.insert(make_pair(item.first, *util::fromHex(item.second)));
            tv.push_back(vectr);
        }
    }
protected:
    vector<Vectr> tv;
};

TEST_F(DigestTest, vectors)
{
    ByteArray md;
    for (auto vectr : tv) {
        for (auto data : vectr.md) {
            const string& algName = data.first;
            const ByteArray& expectedMd = data.second;
            EXPECT_NO_THROW(digest(algName, vectr.msg, md));
            EXPECT_EQ(expectedMd, md);
        }
    }
}

}}} // namespace netflix::msl::crypto
