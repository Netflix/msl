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

//struct TestData
//{
//    const char* key;
//    const char* msg;
//    const char* mac;
//};

// https://tools.ietf.org/html/rfc4493#section-4
const int aesCmacDataLen = 4;
const TestData aesCmacData[aesCmacDataLen] = {
{
"2b7e151628aed2a6abf7158809cf4f3c",
"",
"bb1d6929e95937287fa37d129b756746"
},
{
"2b7e151628aed2a6abf7158809cf4f3c",
"6bc1bee22e409f96e93d7e117393172a",
"070a16b46b4d4144f79bdd9dd04a287c"
},
{
"2b7e151628aed2a6abf7158809cf4f3c",
"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411",
"dfa66747de9ae63030ca32611497c827"
},
{
"2b7e151628aed2a6abf7158809cf4f3c",
"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
"51f0bebf7e3b9d92fc49741779363cfe"

}
};

#if 0
//Count = 23
//Klen = 16
//Mlen = 0
//Tlen = 16
"802047ee1309e548ae81e93a17bff9e7",
"00",
"1472aecaa0a09e45893a14090ed9a17f",
//Result = P
},
{
//Count = 28
//Klen = 16
//Mlen = 0
//Tlen = 16
"9d45f6d97d1573de3cb3488befaf5b7f",
"00",
"96ec3cf234d6704483a93885bd67e6dc",
//Result = P
},
{
//Count = 41
//Klen = 16
//Mlen = 32
//Tlen = 8
"461d7d629778c8b05a688bee4fc01e9f",
"07571a6c9bcb6f97d626796bc74e551d1c45cce38afed761706f6264b7e751d3",
"794b224a85396a27",
//Result = P
},
{
//Count = 49
//Klen = 16
//Mlen = 32
//Tlen = 8
"0e80fa889b1d96a0d23d236d4d642a27",
"f6f094e46cdb2e45fe49b18aff1427ebdac9710fa7f47f75fc9ec7140613ef3e",
"a09774009934c9d4",
//Result = P
},
{
//Count = 50
//Klen = 16
//Mlen = 32
//Tlen = 8
"1f88dfd4f5c52c22b1db47f9f4fb6e2f",
"de433ebd1cdabeac46b94cc00d984f172923535ca8fdfeeb860546357dd8e266",
"bb17b3983faee0db",
//Result = P
},
{
//Count = 55
//Klen = 16
//Mlen = 32
//Tlen = 8
"3c1baf0d915e5aec92bb62babad0ba2c",
"f8f2424c2dc0d0f3821af7244038da0832c547be4ff0850b98c04d4d44a716b1",
"e17ea6862129d6b9",
//Result = P
},
{
//Count = 62
//Klen = 16
//Mlen = 32
//Tlen = 16
"7c0b7db9811f10d00e476c7a0d92f6e0",
"1ee0ec466d46fd849b40c066b4fbbd22a20a4d80a008ac9af17e4fdfd106785e",
"baecdc91e9a1fc3572adf1e4232ae285",
//Result = P
},
{
//Count = 220
//Klen = 16
//Mlen = 65
//Tlen = 16
"c98fc3416457d9eed0fa7ab1dc1b8a6a",
"190ae57ab8bb70464e4a10c112a54c646438301b5662f3536c26d754a02451d1a9c76abd7dbf656115b2a2ac702ec2cadae30cf86e0f0f96da39897d6222889428",
"1bea94a457b2886e9098bf3ded932a3a",
//Result = P
},
};
#endif
