/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
#include <crypto/JcaAlgorithm.h>
#include <crypto/JsonWebKey.h>
#include <crypto/Random.h>
#include <crypto/OpenSslLib.h>
#include <io/MslArray.h>
#include <util/MockMslContext.h>
#include <util/ScopedDisposer.h>
#include <io/MslEncoderUtils.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <memory>
#include <set>
#include <string>

#include "../util/MslTestUtils.h"

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

/** JSON key key type. */
const string KEY_TYPE = "kty";
 /** JSON key usage. */
const string KEY_USAGE = "use";
 /** JSON key key operations. */
const string KEY_KEY_OPS = "key_ops";
 /** JSON key algorithm. */
const string KEY_ALGORITHM = "alg";
 /** JSON key extractable. */
const string KEY_EXTRACTABLE = "extractable";
 /** JSON key key ID. */
const string KEY_KEY_ID = "kid";

 // RSA keys.
 /** JSON key modulus. */
const string KEY_MODULUS = "n";
 /** JSON key public exponent. */
const string KEY_PUBLIC_EXPONENT = "e";
 /** JSON key private exponent. */
const string KEY_PRIVATE_EXPONENT = "d";

 // Symmetric keys.
 /** JSON key key. */
const string KEY_KEY = "k";

const string KEY_ID = "kid";

#define RSA_KEY_SIZE_BITS (1024)
#define RSA_PUB_EXP (65537ull)

shared_ptr<ByteArray> BigNumToByteArray(const BIGNUM *bn)
{
    shared_ptr<ByteArray> buf = make_shared<ByteArray>(BN_num_bytes(bn));
    unsigned char * const pBuf = &(*buf)[0];
    BN_bn2bin(bn, pBuf);
    return buf;
}

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
    shared_ptr<ByteArray> getPublicExponent() const
    {
        return BigNumToByteArray(rsa.get()->e);
    }
    shared_ptr<ByteArray> getPrivateExponent() const
    {
        return BigNumToByteArray(rsa.get()->d);
    }
    shared_ptr<ByteArray> getModulus() const
    {
        return BigNumToByteArray(rsa.get()->n);
    }
private:
    ScopedDisposer<RSA, void, RSA_free> rsa;
};

// poor-man's singleton to make sure we only do keygen once for all tests
shared_ptr<RsaKey> getRsaKey()
{
    static shared_ptr<RsaKey> rsaKey;
    if (!rsaKey) {
        rsaKey = make_shared<RsaKey>();
        rsaKey->init();
    }
    return rsaKey;
}

shared_ptr<ByteArray> getModulus(shared_ptr<PublicKey> key)
{
    assert(key->getFormat() == "SPKI");
    shared_ptr<ByteArray> spki = key->getEncoded();

    const unsigned char * buf = &(*spki)[0];
    ScopedDisposer<RSA, void, RSA_free> rsa(d2i_RSA_PUBKEY(NULL, &buf, (long)spki->size()));
    assert(rsa);

    return BigNumToByteArray(rsa.get()->n);
}

shared_ptr<ByteArray> getPublicExponent(shared_ptr<PublicKey> key)
{
    assert(key->getFormat() == "SPKI");
    shared_ptr<ByteArray> spki = key->getEncoded();

    const unsigned char * buf = &(*spki)[0];
    ScopedDisposer<RSA, void, RSA_free> rsa(d2i_RSA_PUBKEY(NULL, &buf, (long)spki->size()));
    assert(rsa);

    return BigNumToByteArray(rsa.get()->e);
}

shared_ptr<ByteArray> getPrivateExponent(shared_ptr<PrivateKey> key)
{
    assert(key->getFormat() == "PKCS8");
    shared_ptr<ByteArray> pkcs8 = key->getEncoded();

    // OpenSSL does not make it easy to import a private key in PKCS#8 format.

    // make a mem BIO pointing to the incoming PKCS#8 data
    char* const data = reinterpret_cast<char*>(&(*pkcs8)[0]);
    ScopedDisposer<BIO, void, BIO_free_all> bio(BIO_new_mem_buf(data, (int)pkcs8->size()));
    assert(bio.get());

    // get a PKCS8_PRIV_KEY_INFO struct from the BIO
    ScopedDisposer<PKCS8_PRIV_KEY_INFO, void, PKCS8_PRIV_KEY_INFO_free> p8inf(
        d2i_PKCS8_PRIV_KEY_INFO_bio(bio.get(), NULL));
    assert(p8inf.get());

    // create a EVP_PKEY from the PKCS8_PRIV_KEY_INFO
    ScopedDisposer<EVP_PKEY, void, EVP_PKEY_free> pkey(EVP_PKCS82PKEY(p8inf.get()));
    assert(pkey.get());

    // get the RSA struct from the EVP_PKEY
    const RSA * const rsa = EVP_PKEY_get1_RSA(pkey.get());
    assert(rsa);

    return BigNumToByteArray(rsa->d);
}

} // namespace anonymous

/**
 * JSON web key unit tests.
 */
class JsonWebKeyTest : public ::testing::Test
{
public:
    JsonWebKeyTest()
    : NULL_USAGE(JsonWebKey::Usage::invalid)
    , EXTRACTABLE(true)
    , KEY_ID("kid")
    , ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , random(ctx->getRandom())
    , encoder(ctx->getMslEncoderFactory())
    , ENCODER_FORMAT(MslEncoderFormat::JSON)
    {
        ENCRYPT_DECRYPT.insert(JsonWebKey::KeyOp::encrypt);
        ENCRYPT_DECRYPT.insert(JsonWebKey::KeyOp::decrypt);
        WRAP_UNWRAP.insert(JsonWebKey::KeyOp::wrapKey);
        WRAP_UNWRAP.insert(JsonWebKey::KeyOp::unwrapKey);
        SIGN_VERIFY.insert(JsonWebKey::KeyOp::sign);
        SIGN_VERIFY.insert(JsonWebKey::KeyOp::verify);

        MA_SIGN_VERIFY = make_shared<MslArray>();
        MA_SIGN_VERIFY->put(-1, JsonWebKey::KeyOp::sign.name());
        MA_SIGN_VERIFY->put(-1, JsonWebKey::KeyOp::verify.name());

        MA_ENCRYPT_DECRYPT = make_shared<MslArray>();
        MA_ENCRYPT_DECRYPT->put(-1, JsonWebKey::KeyOp::encrypt.name());
        MA_ENCRYPT_DECRYPT->put(-1, JsonWebKey::KeyOp::verify.name());

        MA_WRAP_UNWRAP = make_shared<MslArray>();
        MA_WRAP_UNWRAP->put(-1, JsonWebKey::KeyOp::wrapKey.name());
        MA_WRAP_UNWRAP->put(-1, JsonWebKey::KeyOp::unwrapKey.name());

        shared_ptr<RsaKey> rsaKey = getRsaKey();
        PUBLIC_KEY = make_shared<PublicKey>(rsaKey->getPublicKeySpki(), "RSA");
        PRIVATE_KEY = make_shared<PrivateKey>(rsaKey->getPrivateKeyPkcs8(), "RSA");

        shared_ptr<ByteArray> keydata = make_shared<ByteArray>(16);
        random->nextBytes(*keydata);
        SECRET_KEY = make_shared<SecretKey>(keydata, JcaAlgorithm::AES);
    }

protected:
    // Key operations.
    /** Encrypt/decrypt key operations. */
    set<JsonWebKey::KeyOp> ENCRYPT_DECRYPT;
    /** Wrap/unwrap key operations. */
    set<JsonWebKey::KeyOp> WRAP_UNWRAP;
    /** Sign/verify key operations. */
    set<JsonWebKey::KeyOp> SIGN_VERIFY;

    // Expected key operations MSL arrays.
    /** Sign/verify. */
    shared_ptr<MslArray> MA_SIGN_VERIFY;
    /** Encrypt/decrypt. */
    shared_ptr<MslArray> MA_ENCRYPT_DECRYPT;
    /** Wrap/unwrap. */
    shared_ptr<MslArray> MA_WRAP_UNWRAP;

    /** Null usage. */
    JsonWebKey::Usage NULL_USAGE;
    /** Null key operations. */
    set<JsonWebKey::KeyOp> NULL_KEYOPS;

    const bool EXTRACTABLE = true;
    const string KEY_ID;
    shared_ptr<PublicKey> PUBLIC_KEY;
    shared_ptr<PrivateKey> PRIVATE_KEY;
    shared_ptr<SecretKey> SECRET_KEY;

    shared_ptr<MslContext> ctx;
    shared_ptr<IRandom> random;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    /** Encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;
};

TEST_F(JsonWebKeyTest, evpKey)
{
    shared_ptr<RsaEvpKey> evpKey1 = RsaEvpKey::fromPkcs8(PRIVATE_KEY->getEncoded());
    shared_ptr<ByteArray> pubMod, pubExp, privExp;
    evpKey1->toRaw(pubMod, pubExp, privExp);
    shared_ptr<RsaEvpKey> evpKey2 = RsaEvpKey::fromRaw(pubMod, pubExp, privExp);
    shared_ptr<ByteArray> pkcs8 = evpKey2->toPkcs8();
    EXPECT_EQ(*PRIVATE_KEY->getEncoded(), *pkcs8);
    shared_ptr<RsaEvpKey> evpKey3 = RsaEvpKey::fromPkcs8(pkcs8);
    shared_ptr<ByteArray> n, e, d;
    evpKey3->toRaw(n, e, d);
    EXPECT_EQ(*getPrivateExponent(PRIVATE_KEY), *d);
}

TEST_F(JsonWebKeyTest, rsaUsageCtor)
{
    const JsonWebKey jwk(JsonWebKey::Usage::sig, JsonWebKey::Algorithm::RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
    EXPECT_EQ(EXTRACTABLE, jwk.isExtractable());
    EXPECT_EQ(JsonWebKey::Algorithm::RSA1_5, jwk.getAlgorithm());
    EXPECT_EQ(KEY_ID, *jwk.getId());
    shared_ptr<KeyPair> keypair = jwk.getRsaKeyPair();
    EXPECT_TRUE(keypair);
    EXPECT_EQ(*PUBLIC_KEY, *keypair->publicKey);
    EXPECT_EQ(*PRIVATE_KEY, *keypair->privateKey);
    EXPECT_FALSE(jwk.getSecretKey());
    EXPECT_EQ(JsonWebKey::Type::rsa, jwk.getType());
    EXPECT_EQ(JsonWebKey::Usage::sig, jwk.getUsage());
    EXPECT_EQ(0u, jwk.getKeyOps().size());
    shared_ptr<ByteArray> encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    const JsonWebKey moJwk(encoder->parseObject(encode));
    EXPECT_EQ(jwk.isExtractable(), moJwk.isExtractable());
    EXPECT_EQ(jwk.getAlgorithm(), moJwk.getAlgorithm());
    EXPECT_EQ(*jwk.getId(), *moJwk.getId());
    shared_ptr<KeyPair> moKeypair = moJwk.getRsaKeyPair();
    EXPECT_TRUE(moKeypair);
    EXPECT_EQ(*keypair->publicKey, *moKeypair->publicKey);
    EXPECT_EQ(*getPrivateExponent(keypair->privateKey), *getPrivateExponent(moKeypair->privateKey));
    EXPECT_EQ(*keypair->privateKey, *moKeypair->privateKey);
    EXPECT_FALSE(moJwk.getSecretKey());
    EXPECT_EQ(jwk.getType(), moJwk.getType());
    EXPECT_EQ(jwk.getUsage(), moJwk.getUsage());
    EXPECT_EQ(jwk.getKeyOps(), moJwk.getKeyOps());
    shared_ptr<ByteArray> moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_F(JsonWebKeyTest, rsaKeyOpsCtor)
{
    const JsonWebKey jwk(SIGN_VERIFY, JsonWebKey::Algorithm::RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
    EXPECT_EQ(EXTRACTABLE, jwk.isExtractable());
    EXPECT_EQ(JsonWebKey::Algorithm::RSA1_5, jwk.getAlgorithm());
    EXPECT_EQ(KEY_ID, *jwk.getId());
    shared_ptr<KeyPair> keypair = jwk.getRsaKeyPair();
    EXPECT_TRUE(keypair);
    EXPECT_EQ(*PUBLIC_KEY, *keypair->publicKey);
    EXPECT_EQ(*PRIVATE_KEY, *keypair->privateKey);
    EXPECT_FALSE(jwk.getSecretKey());
    EXPECT_EQ(JsonWebKey::Type::rsa, jwk.getType());
    EXPECT_EQ(JsonWebKey::Usage::invalid, jwk.getUsage());
    EXPECT_EQ(SIGN_VERIFY, jwk.getKeyOps());
    shared_ptr<ByteArray> encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    const JsonWebKey moJwk(encoder->parseObject(encode));
    EXPECT_EQ(jwk.isExtractable(), moJwk.isExtractable());
    EXPECT_EQ(jwk.getAlgorithm(), moJwk.getAlgorithm());
    EXPECT_EQ(*jwk.getId(), *moJwk.getId());
    shared_ptr<KeyPair> moKeypair = moJwk.getRsaKeyPair();
    EXPECT_TRUE(moKeypair);
    EXPECT_EQ(*keypair->publicKey, *keypair->publicKey);
    EXPECT_EQ(*keypair->privateKey, *keypair->privateKey);
    EXPECT_FALSE(moJwk.getSecretKey());
    EXPECT_EQ(jwk.getType(), moJwk.getType());
    EXPECT_EQ(jwk.getUsage(), moJwk.getUsage());
    EXPECT_EQ(jwk.getKeyOps(), moJwk.getKeyOps());
    shared_ptr<ByteArray> moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_F(JsonWebKeyTest, rsaUsageJson)
{
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(JsonWebKey::Usage::sig, JsonWebKey::Algorithm::RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    EXPECT_EQ(EXTRACTABLE, mo->optBoolean(KEY_EXTRACTABLE));
    EXPECT_EQ(JsonWebKey::Algorithm::RSA1_5.name(), mo->getString(KEY_ALGORITHM));
    EXPECT_EQ(KEY_ID, mo->getString(KEY_KEY_ID));
    EXPECT_EQ(JsonWebKey::Type::rsa.name(), mo->getString(KEY_TYPE));
    EXPECT_EQ(JsonWebKey::Usage::sig.name(), mo->getString(KEY_USAGE));
    EXPECT_FALSE(mo->has(KEY_KEY_OPS));

    shared_ptr<string> modulus = MslEncoderUtils::b64urlEncode(getModulus(PUBLIC_KEY));
    shared_ptr<string> pubexp = MslEncoderUtils::b64urlEncode(getPublicExponent(PUBLIC_KEY));
    shared_ptr<string> privexp = MslEncoderUtils::b64urlEncode(getPrivateExponent(PRIVATE_KEY));

    EXPECT_EQ(*modulus, mo->getString(KEY_MODULUS));
    EXPECT_EQ(*pubexp, mo->getString(KEY_PUBLIC_EXPONENT));
    EXPECT_EQ(*privexp, mo->getString(KEY_PRIVATE_EXPONENT));

    EXPECT_FALSE(mo->has(KEY_KEY));
}

TEST_F(JsonWebKeyTest, rsaKeyOpsJson)
{
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(SIGN_VERIFY, JsonWebKey::Algorithm::RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    EXPECT_EQ(EXTRACTABLE, mo->optBoolean(KEY_EXTRACTABLE));
    EXPECT_EQ(JsonWebKey::Algorithm::RSA1_5.name(), mo->getString(KEY_ALGORITHM));
    EXPECT_EQ(KEY_ID, mo->getString(KEY_KEY_ID));
    EXPECT_EQ(JsonWebKey::Type::rsa.name(), mo->getString(KEY_TYPE));
    EXPECT_FALSE(mo->has(KEY_USAGE));
    EXPECT_EQ(MA_SIGN_VERIFY, mo->getMslArray(KEY_KEY_OPS));

    shared_ptr<string> modulus = MslEncoderUtils::b64urlEncode(getModulus(PUBLIC_KEY));
    shared_ptr<string> pubexp = MslEncoderUtils::b64urlEncode(getPublicExponent(PUBLIC_KEY));
    shared_ptr<string> privexp = MslEncoderUtils::b64urlEncode(getPrivateExponent(PRIVATE_KEY));

    EXPECT_EQ(*modulus, mo->getString(KEY_MODULUS));
    EXPECT_EQ(*pubexp, mo->getString(KEY_PUBLIC_EXPONENT));
    EXPECT_EQ(*privexp, mo->getString(KEY_PRIVATE_EXPONENT));

    EXPECT_FALSE(mo->has(KEY_KEY));
}

TEST_F(JsonWebKeyTest, rsaNullCtorPublic)
{
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, JsonWebKey::Algorithm::INVALID, false, "", PUBLIC_KEY, shared_ptr<PrivateKey>());
    EXPECT_FALSE(jwk->isExtractable());
    EXPECT_EQ(JsonWebKey::Algorithm::INVALID, jwk->getAlgorithm());
    EXPECT_EQ("", *jwk->getId());
    std::shared_ptr<KeyPair> keypair = jwk->getRsaKeyPair();
    EXPECT_TRUE(keypair.get());
    EXPECT_EQ(*getModulus(PUBLIC_KEY), *getModulus(keypair->publicKey));
    EXPECT_EQ(*getPublicExponent(PUBLIC_KEY), *getPublicExponent(keypair->publicKey));
    EXPECT_FALSE(keypair->privateKey);
    EXPECT_FALSE(jwk->getSecretKey());
    EXPECT_EQ(JsonWebKey::Type::rsa, jwk->getType());
    EXPECT_EQ(NULL_USAGE, jwk->getUsage());
    EXPECT_EQ(0u, jwk->getKeyOps().size());
#if 0
    shared_ptr<ByteArray> encode = jwk->toMslEncoding(encoder, ENCODER_FORMAT);  // FIXME segfault
    EXPECT_TRUE(encode);

    const JsonWebKey moJwk(encoder->parseObject(encode));
    EXPECT_EQ(jwk->isExtractable(), moJwk.isExtractable());
    EXPECT_EQ(jwk->getAlgorithm(), moJwk.getAlgorithm());
    EXPECT_EQ(jwk->getId(), moJwk.getId());
    std::shared_ptr<KeyPair> moKeypair = moJwk.getRsaKeyPair();
    EXPECT_TRUE(moKeypair);
    EXPECT_EQ(*getModulus(keypair->publicKey), *getModulus(moKeypair->publicKey));
    EXPECT_EQ(*getPublicExponent(keypair->publicKey), *getPublicExponent(moKeypair->publicKey));
    EXPECT_FALSE(moKeypair->privateKey);
    EXPECT_FALSE(moJwk.getSecretKey());
    EXPECT_EQ(jwk->getType(), moJwk.getType());
    EXPECT_EQ(jwk->getUsage(), moJwk.getUsage());
    EXPECT_EQ(jwk->getKeyOps(), moJwk.getKeyOps());
    shared_ptr<ByteArray> moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(encode, moEncode);
#endif
}

#if 0
@Test
public void rsaNullCtorPrivate() throws MslCryptoException, MslEncodingException, MslEncoderException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, null, PRIVATE_KEY);
    EXPECT_FALSE(jwk->isExtractable());
    assertNull(jwk->getAlgorithm());
    assertNull(jwk->getId());
    std::shared_ptr<KeyPair> keypair = jwk->getRsaKeyPair();
    EXPECT_TRUE(keypair);
    final RSAPublicKey pubkey = (RSAPublicKey)keypair.getPublic();
    assertNull(pubkey);
    final RSAPrivateKey privkey = (RSAPrivateKey)keypair.getPrivate();
    EXPECT_EQ(PRIVATE_KEY.getModulus(), privkey.getModulus());
    EXPECT_EQ(PRIVATE_KEY.getPrivateExponent(), privkey.getPrivateExponent());
    assertNull(jwk->getSecretKey());
    EXPECT_EQ(JsonWebKey::Type::rsa, jwk->getType());
    assertNull(jwk->getUsage());
    assertNull(jwk->getKeyOps());
    shared_ptr<ByteArray> encode = jwk->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    shared_ptr<JsonWebKey> moJwk = new JsonWebKey(encoder.parseObject(encode));
    EXPECT_EQ(jwk->isExtractable(), moJwk->isExtractable());
    EXPECT_EQ(jwk->getAlgorithm(), moJwk->getAlgorithm());
    EXPECT_EQ(jwk->getId(), moJwk->getId());
    std::shared_ptr<KeyPair> moKeypair = moJwk->getRsaKeyPair();
    EXPECT_TRUE(moKeypair);
    final RSAPublicKey moPubkey = (RSAPublicKey)moKeypair.getPublic();
    assertNull(moPubkey);
    final RSAPrivateKey moPrivkey = (RSAPrivateKey)moKeypair.getPrivate();
    EXPECT_EQ(privkey.getModulus(), moPrivkey.getModulus());
    EXPECT_EQ(privkey.getPrivateExponent(), moPrivkey.getPrivateExponent());
    assertNull(moJwk->getSecretKey());
    EXPECT_EQ(jwk->getType(), moJwk->getType());
    EXPECT_EQ(jwk->getUsage(), moJwk->getUsage());
    EXPECT_EQ(jwk->getKeyOps(), moJwk->getKeyOps());
    shared_ptr<ByteArray> moEncode = moJwk->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void rsaNullJsonPublic() throws MslEncoderException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, PUBLIC_KEY, null);
    shared_ptr<ByteArray> encode = jwk->toMslEncoding(encoder, ENCODER_FORMAT);
    final MslObject mo = encoder.parseObject(encode);

    EXPECT_FALSE(mo->getBoolean(KEY_EXTRACTABLE));
    EXPECT_FALSE(mo->has(KEY_ALGORITHM));
    EXPECT_FALSE(mo->has(KEY_KEY_ID));
    EXPECT_EQ(JsonWebKey::Type::rsa.name(), mo->getString(KEY_TYPE));
    EXPECT_FALSE(mo->has(KEY_USAGE));
    EXPECT_FALSE(mo->has(KEY_KEY_OPS));

    final String modulus = MslEncoderUtils::b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
    final String pubexp = MslEncoderUtils::b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));

    EXPECT_EQ(modulus, mo->getString(KEY_MODULUS));
    EXPECT_EQ(pubexp, mo->getString(KEY_PUBLIC_EXPONENT));
    EXPECT_FALSE(mo->has(KEY_PRIVATE_EXPONENT));

    EXPECT_FALSE(mo->has(KEY_KEY));
}

@Test
public void rsaNullJsonPrivate() throws MslEncoderException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, null, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    EXPECT_FALSE(mo->getBoolean(KEY_EXTRACTABLE));
    EXPECT_FALSE(mo->has(KEY_ALGORITHM));
    EXPECT_FALSE(mo->has(KEY_KEY_ID));
    EXPECT_EQ(JsonWebKey::Type::rsa.name(), mo->getString(KEY_TYPE));
    EXPECT_FALSE(mo->has(KEY_USAGE));
    EXPECT_FALSE(mo->has(KEY_KEY_OPS));

    final String modulus = MslEncoderUtils::b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
    final String privexp = MslEncoderUtils::b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));

    EXPECT_EQ(modulus, mo->getString(KEY_MODULUS));
    EXPECT_FALSE(mo->has(KEY_PUBLIC_EXPONENT));
    EXPECT_EQ(privexp, mo->getString(KEY_PRIVATE_EXPONENT));

    EXPECT_FALSE(mo->has(KEY_KEY));
}

@Test(expected = MslInternalException.class)
public void rsaCtorNullKeys() {
    new JsonWebKey(NULL_USAGE, null, false, null, null, null);
}

@Test(expected = MslInternalException.class)
public void rsaCtorMismatchedAlgorithm() {
    new JsonWebKey(NULL_USAGE, Algorithm.A128CBC, false, null, PUBLIC_KEY, PRIVATE_KEY);
}

@Test
public void octUsageCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(JsonWebKey::Usage::enc, Algorithm.A128CBC, EXTRACTABLE, KEY_ID, SECRET_KEY);
    EXPECT_EQ(EXTRACTABLE, jwk->isExtractable());
    EXPECT_EQ(Algorithm.A128CBC, jwk->getAlgorithm());
    EXPECT_EQ(KEY_ID, jwk->getId());
    assertNull(jwk->getRsaKeyPair());
    assertArrayEquals(SECRET_KEY.getEncoded(), jwk->getSecretKey().getEncoded());
    EXPECT_EQ(Type.oct, jwk->getType());
    EXPECT_EQ(JsonWebKey::Usage::enc, jwk->getUsage());
    assertNull(jwk->getKeyOps());
    shared_ptr<ByteArray> encode = jwk->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    shared_ptr<JsonWebKey> moJwk = new JsonWebKey(encoder.parseObject(encode));
    EXPECT_EQ(jwk->isExtractable(), moJwk->isExtractable());
    EXPECT_EQ(jwk->getAlgorithm(), moJwk->getAlgorithm());
    EXPECT_EQ(jwk->getId(), moJwk->getId());
    assertNull(moJwk->getRsaKeyPair());
    assertArrayEquals(jwk->getSecretKey().getEncoded(), moJwk->getSecretKey().getEncoded());
    EXPECT_EQ(jwk->getType(), moJwk->getType());
    EXPECT_EQ(jwk->getUsage(), moJwk->getUsage());
    EXPECT_EQ(jwk->getKeyOps(), moJwk->getKeyOps());
    shared_ptr<ByteArray> moEncode = moJwk->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void octKeyOpsCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(ENCRYPT_DECRYPT, Algorithm.A128CBC, EXTRACTABLE, KEY_ID, SECRET_KEY);
    EXPECT_EQ(EXTRACTABLE, jwk->isExtractable());
    EXPECT_EQ(Algorithm.A128CBC, jwk->getAlgorithm());
    EXPECT_EQ(KEY_ID, jwk->getId());
    assertNull(jwk->getRsaKeyPair());
    assertArrayEquals(SECRET_KEY.getEncoded(), jwk->getSecretKey().getEncoded());
    EXPECT_EQ(Type.oct, jwk->getType());
    assertNull(jwk->getUsage());
    EXPECT_EQ(ENCRYPT_DECRYPT, jwk->getKeyOps());
    shared_ptr<ByteArray> encode = jwk->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    shared_ptr<JsonWebKey> moJwk = new JsonWebKey(encoder.parseObject(encode));
    EXPECT_EQ(jwk->isExtractable(), moJwk->isExtractable());
    EXPECT_EQ(jwk->getAlgorithm(), moJwk->getAlgorithm());
    EXPECT_EQ(jwk->getId(), moJwk->getId());
    assertNull(moJwk->getRsaKeyPair());
    assertArrayEquals(jwk->getSecretKey().getEncoded(), moJwk->getSecretKey().getEncoded());
    EXPECT_EQ(jwk->getType(), moJwk->getType());
    EXPECT_EQ(jwk->getUsage(), moJwk->getUsage());
    EXPECT_EQ(jwk->getKeyOps(), moJwk->getKeyOps());
    shared_ptr<ByteArray> moEncode = moJwk->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    // This test will not always pass since the key operations are
    // unordered.
    //assertArrayEquals(encode, moEncode);
}

@Test
public void octUsageJson() throws MslEncoderException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(JsonWebKey::Usage::wrap, Algorithm.A128KW, EXTRACTABLE, KEY_ID, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    EXPECT_EQ(EXTRACTABLE, mo->optBoolean(KEY_EXTRACTABLE));
    EXPECT_EQ(Algorithm.A128KW.name(), mo->getString(KEY_ALGORITHM));
    EXPECT_EQ(KEY_ID, mo->getString(KEY_KEY_ID));
    EXPECT_EQ(Type.oct.name(), mo->getString(KEY_TYPE));
    EXPECT_EQ(JsonWebKey::Usage::wrap.name(), mo->getString(KEY_USAGE));
    EXPECT_FALSE(mo->has(KEY_KEY_OPS));

    EXPECT_FALSE(mo->has(KEY_MODULUS));
    EXPECT_FALSE(mo->has(KEY_PUBLIC_EXPONENT));
    EXPECT_FALSE(mo->has(KEY_PRIVATE_EXPONENT));

    final String key = MslEncoderUtils::b64urlEncode(SECRET_KEY.getEncoded());

    EXPECT_EQ(key, mo->getString(KEY_KEY));
}

@Test
public void octKeyOpsJson() throws MslEncoderException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(WRAP_UNWRAP, Algorithm.A128KW, EXTRACTABLE, KEY_ID, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    EXPECT_EQ(EXTRACTABLE, mo->optBoolean(KEY_EXTRACTABLE));
    EXPECT_EQ(Algorithm.A128KW.name(), mo->getString(KEY_ALGORITHM));
    EXPECT_EQ(KEY_ID, mo->getString(KEY_KEY_ID));
    EXPECT_EQ(Type.oct.name(), mo->getString(KEY_TYPE));
    EXPECT_FALSE(mo->has(KEY_USAGE));
    assertTrue(MslEncoderUtils::equalSets(MA_WRAP_UNWRAP, mo->getMslArray(KEY_KEY_OPS)));

    EXPECT_FALSE(mo->has(KEY_MODULUS));
    EXPECT_FALSE(mo->has(KEY_PUBLIC_EXPONENT));
    EXPECT_FALSE(mo->has(KEY_PRIVATE_EXPONENT));

    final String key = MslEncoderUtils::b64urlEncode(SECRET_KEY.getEncoded());

    EXPECT_EQ(key, mo->getString(KEY_KEY));
}

@Test
public void octNullCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    EXPECT_FALSE(jwk->isExtractable());
    assertNull(jwk->getAlgorithm());
    assertNull(jwk->getId());
    assertNull(jwk->getRsaKeyPair());
    assertArrayEquals(SECRET_KEY.getEncoded(), jwk->getSecretKey().getEncoded());
    EXPECT_EQ(Type.oct, jwk->getType());
    assertNull(jwk->getUsage());
    assertNull(jwk->getKeyOps());
    shared_ptr<ByteArray> encode = jwk->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    shared_ptr<JsonWebKey> moJwk = new JsonWebKey(encoder.parseObject(encode));
    EXPECT_EQ(jwk->isExtractable(), moJwk->isExtractable());
    EXPECT_EQ(jwk->getAlgorithm(), moJwk->getAlgorithm());
    EXPECT_EQ(jwk->getId(), moJwk->getId());
    assertNull(moJwk->getRsaKeyPair());
    assertArrayEquals(jwk->getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded(), moJwk->getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded());
    EXPECT_EQ(jwk->getType(), moJwk->getType());
    EXPECT_EQ(jwk->getUsage(), moJwk->getUsage());
    EXPECT_EQ(jwk->getKeyOps(), moJwk->getKeyOps());
    shared_ptr<ByteArray> moEncode = moJwk->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void octNullJson() throws MslEncoderException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    EXPECT_FALSE(mo->getBoolean(KEY_EXTRACTABLE));
    EXPECT_FALSE(mo->has(KEY_ALGORITHM));
    EXPECT_FALSE(mo->has(KEY_KEY_ID));
    EXPECT_EQ(Type.oct.name(), mo->getString(KEY_TYPE));
    EXPECT_FALSE(mo->has(KEY_USAGE));
    EXPECT_FALSE(mo->has(KEY_KEY_OPS));

    EXPECT_FALSE(mo->has(KEY_MODULUS));
    EXPECT_FALSE(mo->has(KEY_PUBLIC_EXPONENT));
    EXPECT_FALSE(mo->has(KEY_PRIVATE_EXPONENT));

    final String key = MslEncoderUtils::b64urlEncode(SECRET_KEY.getEncoded());

    EXPECT_EQ(key, mo->getString(KEY_KEY));
}

public void usageOnly() throws MslEncoderException, MslCryptoException, MslEncodingException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_USAGE, JsonWebKey::Usage::enc.name());

    shared_ptr<JsonWebKey> moJwk = new JsonWebKey(mo);
    EXPECT_EQ(JsonWebKey::Usage::enc, moJwk->getUsage());
    assertNull(moJwk->getKeyOps());
}

public void keyOpsOnly() throws MslEncoderException, MslCryptoException, MslEncodingException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_KEYOPS, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_KEY_OPS, MA_ENCRYPT_DECRYPT);

    shared_ptr<JsonWebKey> moJwk = new JsonWebKey(mo);
    assertNull(moJwk->getUsage());
    EXPECT_EQ(new HashSet<KeyOp>(Arrays.asList(KeyOp.encrypt, KeyOp.decrypt)), moJwk->getKeyOps());
}

@Test(expected = MslInternalException.class)
public void octCtorMismatchedAlgo() {
    new JsonWebKey(NULL_USAGE, JsonWebKey::Algorithm::RSA1_5, false, null, SECRET_KEY);
}

@Test
public void missingType() throws MslEncoderException, MslCryptoException, MslEncodingException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->remove(KEY_TYPE);

    new JsonWebKey(mo);
}

@Test
public void invalidType() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.UNIDENTIFIED_JWK_TYPE);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_TYPE, "x");

    new JsonWebKey(mo);
}

@Test
public void invalidUsage() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.UNIDENTIFIED_JWK_USAGE);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_USAGE, "x");

    new JsonWebKey(mo);
}

@Test
public void invalidKeyOp() throws MslEncoderException, MslCryptoException, MslEncodingException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.UNIDENTIFIED_JWK_KEYOP);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_KEYOPS, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_KEY_OPS, new JSONArray(Arrays.asList(KeyOp.encrypt.name(), "x", KeyOp.decrypt.name()).toArray()));

    new JsonWebKey(mo);
}

@Test
public void invalidAlgorithm() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.UNIDENTIFIED_JWK_ALGORITHM);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_ALGORITHM, "x");

    new JsonWebKey(mo);
}

@Test
public void missingExtractable() throws MslEncoderException, MslCryptoException, MslEncodingException {
    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<ByteArray> encode = jwk->toMslEncoding(encoder, ENCODER_FORMAT);
    final MslObject mo = encoder.parseObject(encode);

    EXPECT_TRUE(mo->remove(KEY_EXTRACTABLE));

    shared_ptr<JsonWebKey> moJwk = new JsonWebKey(mo);
    EXPECT_EQ(jwk->isExtractable(), moJwk->isExtractable());
    EXPECT_EQ(jwk->getAlgorithm(), moJwk->getAlgorithm());
    EXPECT_EQ(jwk->getId(), moJwk->getId());
    assertNull(moJwk->getRsaKeyPair());
    assertArrayEquals(jwk->getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded(), moJwk->getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded());
    EXPECT_EQ(jwk->getType(), moJwk->getType());
    EXPECT_EQ(jwk->getUsage(), moJwk->getUsage());
    shared_ptr<ByteArray> moEncode = moJwk->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void invalidExtractable() throws MslEncodingException, MslEncoderException, MslCryptoException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_EXTRACTABLE, "x");

    new JsonWebKey(mo);
}

@Test
public void missingKey() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->remove(KEY_KEY);

    new JsonWebKey(mo);
}

@Test
public void emptyKey() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, SECRET_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_KEY, "");

    new JsonWebKey(mo);
}

@Test
public void missingModulus() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->remove(KEY_MODULUS);

    new JsonWebKey(mo);
}

@Test
public void emptyModulus() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_MODULUS, "");

    new JsonWebKey(mo);
}

@Test
public void missingExponents() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->remove(KEY_PUBLIC_EXPONENT);
    mo->remove(KEY_PRIVATE_EXPONENT);

    new JsonWebKey(mo);
}

@Test
public void emptyPublicExponent() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_PUBLIC_EXPONENT, "");

    new JsonWebKey(mo);
}

// This unit test no longer passes because
// Base64.decode() does not error when given invalid
// Base64 encoded data.
@Ignore
@Test
public void invalidPublicExpontent() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_PUBLIC_EXPONENT, "x");

    new JsonWebKey(mo);
}

@Test
public void emptyPrivateExponent() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_PRIVATE_EXPONENT, "");

    new JsonWebKey(mo);
}

// This unit test no longer passes because
// Base64.decode() does not error when given invalid
// Base64 encoded data.
@Ignore
@Test
public void invalidPrivateExponent() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    shared_ptr<JsonWebKey> jwk = make_shared<JsonWebKey>(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, jwk);

    mo->put(KEY_PRIVATE_EXPONENT, "x");

    new JsonWebKey(mo);
}
#endif

}}} // namespace netflix::msl::crypto
