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
#include <MslCryptoException.h>
#include <MslInternalException.h>
#include <cstdint>
#include <vector>
#include <openssl/x509.h>
#include <openssl/opensslv.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace crypto {

namespace {

shared_ptr<ByteArray> extractBignum(const BIGNUM * bn)
{
    if (!bn)
        throw MslInternalException("Null BIGNUM");
    shared_ptr<ByteArray> ba = make_shared<ByteArray>(BN_num_bytes(bn), 0);
    unsigned char * buf = &(*ba)[0];
    BN_bn2bin(bn, &buf[0]);
    return ba;
}

#define RSA_KEY_SIZE_BITS (1024)
#define RSA_PUB_EXP (65537ull)

class RsaKey
{
public:
    RsaKey() {}
    bool init()
    {
        bool keygenSuccess = false;
        uint32_t retryCount = 0;
        const uint32_t MAX_RETRIES=4;
        while (!keygenSuccess && (retryCount < MAX_RETRIES))
        {
            rsa.reset(RSA_generate_key(RSA_KEY_SIZE_BITS, RSA_PUB_EXP, 0, 0));
            if (rsa.get())
                keygenSuccess = (RSA_check_key(rsa.get()) == 1);
            retryCount++;
        }
        return keygenSuccess;
    }
    shared_ptr<ByteArray> getPublicKeySpki() const
    {
        if (!rsa.get())
            throw MslInternalException("RsaKey not initialized");
        int outLen = i2d_RSA_PUBKEY(rsa.get(), NULL);
        shared_ptr<ByteArray> spki = make_shared<ByteArray>(outLen);
        unsigned char * buf = &(*spki)[0];
        i2d_RSA_PUBKEY(rsa.get(), &buf);
        return spki;
    }
    shared_ptr<ByteArray> getPrivateKeyPkcs8() const
    {
        if (!rsa.get())
            throw MslInternalException("RsaKey not initialized");
        ScopedDisposer<EVP_PKEY, void, EVP_PKEY_free> pkey(EVP_PKEY_new());
        if (!pkey.get())
            throw MslInternalException("EVP_PKEY_new() failed");
        int ret = EVP_PKEY_set1_RSA(pkey.get(), rsa.get());
        if (!ret)
            throw MslInternalException("EVP_PKEY_set1_RSA() failed");
        ScopedDisposer<PKCS8_PRIV_KEY_INFO, void, PKCS8_PRIV_KEY_INFO_free> p8inf(EVP_PKEY2PKCS8(pkey.get()));
        if (!p8inf.get())
            throw MslInternalException("EVP_PKEY2PKCS8() failed");
        int outLen = i2d_PKCS8_PRIV_KEY_INFO(p8inf.get(), NULL);
        if (outLen <= 0)
            throw MslInternalException("i2d_PKCS8_PRIV_KEY_INFO() returned bad length");
        shared_ptr<ByteArray> pkcs8 = make_shared<ByteArray>(outLen);
        unsigned char * buf = &(*pkcs8)[0];
        ret = i2d_PKCS8_PRIV_KEY_INFO(p8inf.get(), &buf);
        if (!ret)
            throw MslInternalException("i2d_PKCS8_PRIV_KEY_INFO() failed");
        return pkcs8;
    }
    void getKeyRaw(shared_ptr<ByteArray>& pubMod, shared_ptr<ByteArray>& pubExp,
            shared_ptr<ByteArray>& privExp)
    {
        if (!rsa.get())
            throw MslInternalException("RsaKey not initialized");
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        pubMod = extractBignum(rsa.get()->n);
        pubExp = extractBignum(rsa.get()->e);
        privExp = extractBignum(rsa.get()->d);
#else
        pubMod = extractBignum(RSA_get0_n(rsa.get()));
        pubExp = extractBignum(RSA_get0_e(rsa.get()));
        privExp = extractBignum(RSA_get0_d(rsa.get()));
#endif
    }
private:
    ScopedDisposer<RSA, void, RSA_free> rsa;
};

shared_ptr<RsaKey> getRsaKey()
{
    static shared_ptr<RsaKey> rsaKey;
    if (!rsaKey) {
        rsaKey = make_shared<RsaKey>();
        rsaKey->init();
    }
    return rsaKey;
}

}  // namespace anonymous

class RsaEvpKeyTest : public ::testing::Test
{
public:
    RsaEvpKeyTest() : rsaKey(getRsaKey()) {}
protected:
    shared_ptr<RsaKey> rsaKey;
};

TEST_F(RsaEvpKeyTest, spki)
{
    shared_ptr<ByteArray> sourceSpki = rsaKey->getPublicKeySpki();
    shared_ptr<RsaEvpKey> rsaEvpKey;
    EXPECT_NO_THROW({rsaEvpKey = RsaEvpKey::fromSpki(sourceSpki);});
    EXPECT_TRUE(rsaEvpKey);
    shared_ptr<ByteArray> spki = rsaEvpKey->toSpki();
    EXPECT_EQ(*sourceSpki, *spki);
    try {
        rsaEvpKey->toPkcs8();
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::KEY_EXPORT_ERROR, e.getError());
    }
}

TEST_F(RsaEvpKeyTest, pkcs8)
{
    shared_ptr<ByteArray> sourcePkcs8 = rsaKey->getPrivateKeyPkcs8();
    shared_ptr<RsaEvpKey> rsaEvpKey;
    EXPECT_NO_THROW({rsaEvpKey = RsaEvpKey::fromPkcs8(sourcePkcs8);});
    EXPECT_TRUE(rsaEvpKey);
    shared_ptr<ByteArray> spki, pkcs8;
    EXPECT_NO_THROW({spki = rsaEvpKey->toSpki();});
    EXPECT_EQ(*rsaKey->getPublicKeySpki(), *spki);
    EXPECT_NO_THROW({pkcs8 = rsaEvpKey->toPkcs8();});
    EXPECT_EQ(*sourcePkcs8, *pkcs8);
}

TEST_F(RsaEvpKeyTest, raw)
{
    shared_ptr<ByteArray> pubMod, pubExp, privExp;
    rsaKey->getKeyRaw(pubMod, pubExp, privExp);
    shared_ptr<RsaEvpKey> rsaEvpKey;
    shared_ptr<ByteArray> spki, pkcs8;
    shared_ptr<ByteArray> pubMod2, pubExp2, privExp2;

    // fully-specified key (n,e,d)
    EXPECT_NO_THROW({rsaEvpKey = RsaEvpKey::fromRaw(pubMod, pubExp, privExp);});
    EXPECT_TRUE(rsaEvpKey);
    EXPECT_NO_THROW({spki = rsaEvpKey->toSpki();});
    EXPECT_EQ(*rsaKey->getPublicKeySpki(), *spki);
    EXPECT_NO_THROW({pkcs8 = rsaEvpKey->toPkcs8();});
    EXPECT_EQ(*rsaKey->getPrivateKeyPkcs8(), *pkcs8);
    EXPECT_NO_THROW(rsaEvpKey->toRaw(pubMod2, pubExp2, privExp2));
    EXPECT_EQ(*pubMod, *pubMod2);
    EXPECT_EQ(*pubExp, *pubExp2);
    EXPECT_EQ(*privExp, *privExp2);

    // public (n,e) key
    EXPECT_NO_THROW({rsaEvpKey = RsaEvpKey::fromRaw(pubMod, pubExp, shared_ptr<ByteArray>());});
    EXPECT_TRUE(rsaEvpKey);
    EXPECT_NO_THROW({spki = rsaEvpKey->toSpki();});
    EXPECT_THROW(rsaEvpKey->toPkcs8(), MslCryptoException);
    EXPECT_EQ(*rsaKey->getPublicKeySpki(), *spki);
    EXPECT_NO_THROW(rsaEvpKey->toRaw(pubMod2, pubExp2, privExp2));
    EXPECT_EQ(*pubMod, *pubMod2);
    EXPECT_EQ(*pubExp, *pubExp2);
    EXPECT_FALSE(privExp2);

    // private (n,d) key
    // Note: e/pubExp is deduced to satisfy openssl RSA key requirements
    EXPECT_NO_THROW({rsaEvpKey = RsaEvpKey::fromRaw(pubMod, shared_ptr<ByteArray>(), privExp);});
    EXPECT_TRUE(rsaEvpKey);
    EXPECT_NO_THROW({spki = rsaEvpKey->toSpki();});
    EXPECT_EQ(*rsaKey->getPublicKeySpki(), *spki);
    EXPECT_NO_THROW({pkcs8 = rsaEvpKey->toPkcs8();});
    EXPECT_EQ(*rsaKey->getPrivateKeyPkcs8(), *pkcs8);
    EXPECT_NO_THROW(rsaEvpKey->toRaw(pubMod2, pubExp2, privExp2));
    EXPECT_EQ(*pubMod, *pubMod2);
    EXPECT_EQ(*pubExp, *pubExp2);
    EXPECT_EQ(*privExp, *privExp2);
}

TEST_F(RsaEvpKeyTest, erawImportErrors)
{
    shared_ptr<ByteArray> pubMod, pubExp, privExp;
    rsaKey->getKeyRaw(pubMod, pubExp, privExp);
    shared_ptr<ByteArray> nullBa;
    EXPECT_THROW({RsaEvpKey::fromRaw(nullBa, nullBa, nullBa);}, MslCryptoException);
    EXPECT_THROW({RsaEvpKey::fromRaw(nullBa, pubExp, privExp);}, MslCryptoException);
    EXPECT_THROW({RsaEvpKey::fromRaw(pubMod, nullBa, nullBa);}, MslCryptoException);
    EXPECT_NO_THROW({RsaEvpKey::fromRaw(pubMod, pubExp, nullBa);});
    EXPECT_NO_THROW({RsaEvpKey::fromRaw(pubMod, nullBa, privExp);});
    EXPECT_NO_THROW({RsaEvpKey::fromRaw(pubMod, pubExp, privExp);});
}

}}} // namespace netflix::msl::crypto
