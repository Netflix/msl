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
#include <io/MslArray.h>
#include <util/MockMslContext.h>
#include <memory>
#include <set>
#include <string>
#include <openssl/x509.h>
#include <util/ScopedDisposer.h>

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

    bool EXTRACTABLE = true;
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

TEST_F(JsonWebKeyTest, rsaUsageCtor)
{
}

#if 0
@Test
public void rsaUsageCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(Usage.sig, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
    assertEquals(EXTRACTABLE, jwk.isExtractable());
    assertEquals(Algorithm.RSA1_5, jwk.getAlgorithm());
    assertEquals(KEY_ID, jwk.getId());
    final KeyPair keypair = jwk.getRsaKeyPair();
    assertNotNull(keypair);
    final RSAPublicKey pubkey = (RSAPublicKey)keypair.getPublic();
    assertEquals(PUBLIC_KEY.getModulus(), pubkey.getModulus());
    assertEquals(PUBLIC_KEY.getPublicExponent(), pubkey.getPublicExponent());
    final RSAPrivateKey privkey = (RSAPrivateKey)keypair.getPrivate();
    assertEquals(PRIVATE_KEY.getModulus(), privkey.getModulus());
    assertEquals(PRIVATE_KEY.getPrivateExponent(), privkey.getPrivateExponent());
    assertNull(jwk.getSecretKey());
    assertEquals(Type.rsa, jwk.getType());
    assertEquals(Usage.sig, jwk.getUsage());
    assertNull(jwk.getKeyOps());
    final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(encode);

    final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
    assertEquals(jwk.isExtractable(), moJwk.isExtractable());
    assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
    assertEquals(jwk.getId(), moJwk.getId());
    final KeyPair moKeypair = moJwk.getRsaKeyPair();
    assertNotNull(moKeypair);
    final RSAPublicKey moPubkey = (RSAPublicKey)moKeypair.getPublic();
    assertEquals(pubkey.getModulus(), moPubkey.getModulus());
    assertEquals(pubkey.getPublicExponent(), moPubkey.getPublicExponent());
    final RSAPrivateKey moPrivkey = (RSAPrivateKey)moKeypair.getPrivate();
    assertEquals(privkey.getModulus(), moPrivkey.getModulus());
    assertEquals(privkey.getPrivateExponent(), moPrivkey.getPrivateExponent());
    assertNull(moJwk.getSecretKey());
    assertEquals(jwk.getType(), moJwk.getType());
    assertEquals(jwk.getUsage(), moJwk.getUsage());
    assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
    final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void rsaKeyOpsCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(SIGN_VERIFY, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
    assertEquals(EXTRACTABLE, jwk.isExtractable());
    assertEquals(Algorithm.RSA1_5, jwk.getAlgorithm());
    assertEquals(KEY_ID, jwk.getId());
    final KeyPair keypair = jwk.getRsaKeyPair();
    assertNotNull(keypair);
    final RSAPublicKey pubkey = (RSAPublicKey)keypair.getPublic();
    assertEquals(PUBLIC_KEY.getModulus(), pubkey.getModulus());
    assertEquals(PUBLIC_KEY.getPublicExponent(), pubkey.getPublicExponent());
    final RSAPrivateKey privkey = (RSAPrivateKey)keypair.getPrivate();
    assertEquals(PRIVATE_KEY.getModulus(), privkey.getModulus());
    assertEquals(PRIVATE_KEY.getPrivateExponent(), privkey.getPrivateExponent());
    assertNull(jwk.getSecretKey());
    assertEquals(Type.rsa, jwk.getType());
    assertNull(jwk.getUsage());
    assertEquals(SIGN_VERIFY, jwk.getKeyOps());
    final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(encode);

    final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
    assertEquals(jwk.isExtractable(), moJwk.isExtractable());
    assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
    assertEquals(jwk.getId(), moJwk.getId());
    final KeyPair moKeypair = moJwk.getRsaKeyPair();
    assertNotNull(moKeypair);
    final RSAPublicKey moPubkey = (RSAPublicKey)moKeypair.getPublic();
    assertEquals(pubkey.getModulus(), moPubkey.getModulus());
    assertEquals(pubkey.getPublicExponent(), moPubkey.getPublicExponent());
    final RSAPrivateKey moPrivkey = (RSAPrivateKey)moKeypair.getPrivate();
    assertEquals(privkey.getModulus(), moPrivkey.getModulus());
    assertEquals(privkey.getPrivateExponent(), moPrivkey.getPrivateExponent());
    assertNull(moJwk.getSecretKey());
    assertEquals(jwk.getType(), moJwk.getType());
    assertEquals(jwk.getUsage(), moJwk.getUsage());
    assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
    final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(moEncode);
    // This test will not always pass since the key operations are
    // unordered.
    //assertArrayEquals(encode, moEncode);
}

@Test
public void rsaUsageJson() throws MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(Usage.sig, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    assertEquals(EXTRACTABLE, mo.optBoolean(KEY_EXTRACTABLE));
    assertEquals(Algorithm.RSA1_5.name(), mo.getString(KEY_ALGORITHM));
    assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
    assertEquals(Type.rsa.name(), mo.getString(KEY_TYPE));
    assertEquals(Usage.sig.name(), mo.getString(KEY_USAGE));
    assertFalse(mo.has(KEY_KEY_OPS));

    final String modulus = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
    final String pubexp = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));
    final String privexp = MslEncoderUtils.b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));

    assertEquals(modulus, mo.getString(KEY_MODULUS));
    assertEquals(pubexp, mo.getString(KEY_PUBLIC_EXPONENT));
    assertEquals(privexp, mo.getString(KEY_PRIVATE_EXPONENT));

    assertFalse(mo.has(KEY_KEY));
}

@Test
public void rsaKeyOpsJson() throws MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(SIGN_VERIFY, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    assertEquals(EXTRACTABLE, mo.optBoolean(KEY_EXTRACTABLE));
    assertEquals(Algorithm.RSA1_5.name(), mo.getString(KEY_ALGORITHM));
    assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
    assertEquals(Type.rsa.name(), mo.getString(KEY_TYPE));
    assertFalse(mo.has(KEY_USAGE));
    assertTrue(MslEncoderUtils.equalSets(MA_SIGN_VERIFY, mo.getMslArray(KEY_KEY_OPS)));

    final String modulus = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
    final String pubexp = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));
    final String privexp = MslEncoderUtils.b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));

    assertEquals(modulus, mo.getString(KEY_MODULUS));
    assertEquals(pubexp, mo.getString(KEY_PUBLIC_EXPONENT));
    assertEquals(privexp, mo.getString(KEY_PRIVATE_EXPONENT));

    assertFalse(mo.has(KEY_KEY));
}

@Test
public void rsaNullCtorPublic() throws MslCryptoException, MslEncodingException, MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, null);
    assertFalse(jwk.isExtractable());
    assertNull(jwk.getAlgorithm());
    assertNull(jwk.getId());
    final KeyPair keypair = jwk.getRsaKeyPair();
    assertNotNull(keypair);
    final RSAPublicKey pubkey = (RSAPublicKey)keypair.getPublic();
    assertEquals(PUBLIC_KEY.getModulus(), pubkey.getModulus());
    assertEquals(PUBLIC_KEY.getPublicExponent(), pubkey.getPublicExponent());
    final RSAPrivateKey privkey = (RSAPrivateKey)keypair.getPrivate();
    assertNull(privkey);
    assertNull(jwk.getSecretKey());
    assertEquals(Type.rsa, jwk.getType());
    assertNull(jwk.getUsage());
    assertNull(jwk.getKeyOps());
    final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(encode);

    final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
    assertEquals(jwk.isExtractable(), moJwk.isExtractable());
    assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
    assertEquals(jwk.getId(), moJwk.getId());
    final KeyPair moKeypair = moJwk.getRsaKeyPair();
    assertNotNull(moKeypair);
    final RSAPublicKey moPubkey = (RSAPublicKey)moKeypair.getPublic();
    assertEquals(pubkey.getModulus(), moPubkey.getModulus());
    assertEquals(pubkey.getPublicExponent(), moPubkey.getPublicExponent());
    final RSAPrivateKey moPrivkey = (RSAPrivateKey)moKeypair.getPrivate();
    assertNull(moPrivkey);
    assertNull(moJwk.getSecretKey());
    assertEquals(jwk.getType(), moJwk.getType());
    assertEquals(jwk.getUsage(), moJwk.getUsage());
    assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
    final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void rsaNullCtorPrivate() throws MslCryptoException, MslEncodingException, MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, null, PRIVATE_KEY);
    assertFalse(jwk.isExtractable());
    assertNull(jwk.getAlgorithm());
    assertNull(jwk.getId());
    final KeyPair keypair = jwk.getRsaKeyPair();
    assertNotNull(keypair);
    final RSAPublicKey pubkey = (RSAPublicKey)keypair.getPublic();
    assertNull(pubkey);
    final RSAPrivateKey privkey = (RSAPrivateKey)keypair.getPrivate();
    assertEquals(PRIVATE_KEY.getModulus(), privkey.getModulus());
    assertEquals(PRIVATE_KEY.getPrivateExponent(), privkey.getPrivateExponent());
    assertNull(jwk.getSecretKey());
    assertEquals(Type.rsa, jwk.getType());
    assertNull(jwk.getUsage());
    assertNull(jwk.getKeyOps());
    final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(encode);

    final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
    assertEquals(jwk.isExtractable(), moJwk.isExtractable());
    assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
    assertEquals(jwk.getId(), moJwk.getId());
    final KeyPair moKeypair = moJwk.getRsaKeyPair();
    assertNotNull(moKeypair);
    final RSAPublicKey moPubkey = (RSAPublicKey)moKeypair.getPublic();
    assertNull(moPubkey);
    final RSAPrivateKey moPrivkey = (RSAPrivateKey)moKeypair.getPrivate();
    assertEquals(privkey.getModulus(), moPrivkey.getModulus());
    assertEquals(privkey.getPrivateExponent(), moPrivkey.getPrivateExponent());
    assertNull(moJwk.getSecretKey());
    assertEquals(jwk.getType(), moJwk.getType());
    assertEquals(jwk.getUsage(), moJwk.getUsage());
    assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
    final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void rsaNullJsonPublic() throws MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, null);
    final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    final MslObject mo = encoder.parseObject(encode);

    assertFalse(mo.getBoolean(KEY_EXTRACTABLE));
    assertFalse(mo.has(KEY_ALGORITHM));
    assertFalse(mo.has(KEY_KEY_ID));
    assertEquals(Type.rsa.name(), mo.getString(KEY_TYPE));
    assertFalse(mo.has(KEY_USAGE));
    assertFalse(mo.has(KEY_KEY_OPS));

    final String modulus = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
    final String pubexp = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));

    assertEquals(modulus, mo.getString(KEY_MODULUS));
    assertEquals(pubexp, mo.getString(KEY_PUBLIC_EXPONENT));
    assertFalse(mo.has(KEY_PRIVATE_EXPONENT));

    assertFalse(mo.has(KEY_KEY));
}

@Test
public void rsaNullJsonPrivate() throws MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, null, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    assertFalse(mo.getBoolean(KEY_EXTRACTABLE));
    assertFalse(mo.has(KEY_ALGORITHM));
    assertFalse(mo.has(KEY_KEY_ID));
    assertEquals(Type.rsa.name(), mo.getString(KEY_TYPE));
    assertFalse(mo.has(KEY_USAGE));
    assertFalse(mo.has(KEY_KEY_OPS));

    final String modulus = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
    final String privexp = MslEncoderUtils.b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));

    assertEquals(modulus, mo.getString(KEY_MODULUS));
    assertFalse(mo.has(KEY_PUBLIC_EXPONENT));
    assertEquals(privexp, mo.getString(KEY_PRIVATE_EXPONENT));

    assertFalse(mo.has(KEY_KEY));
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
    final JsonWebKey jwk = new JsonWebKey(Usage.enc, Algorithm.A128CBC, EXTRACTABLE, KEY_ID, SECRET_KEY);
    assertEquals(EXTRACTABLE, jwk.isExtractable());
    assertEquals(Algorithm.A128CBC, jwk.getAlgorithm());
    assertEquals(KEY_ID, jwk.getId());
    assertNull(jwk.getRsaKeyPair());
    assertArrayEquals(SECRET_KEY.getEncoded(), jwk.getSecretKey().getEncoded());
    assertEquals(Type.oct, jwk.getType());
    assertEquals(Usage.enc, jwk.getUsage());
    assertNull(jwk.getKeyOps());
    final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(encode);

    final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
    assertEquals(jwk.isExtractable(), moJwk.isExtractable());
    assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
    assertEquals(jwk.getId(), moJwk.getId());
    assertNull(moJwk.getRsaKeyPair());
    assertArrayEquals(jwk.getSecretKey().getEncoded(), moJwk.getSecretKey().getEncoded());
    assertEquals(jwk.getType(), moJwk.getType());
    assertEquals(jwk.getUsage(), moJwk.getUsage());
    assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
    final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void octKeyOpsCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(ENCRYPT_DECRYPT, Algorithm.A128CBC, EXTRACTABLE, KEY_ID, SECRET_KEY);
    assertEquals(EXTRACTABLE, jwk.isExtractable());
    assertEquals(Algorithm.A128CBC, jwk.getAlgorithm());
    assertEquals(KEY_ID, jwk.getId());
    assertNull(jwk.getRsaKeyPair());
    assertArrayEquals(SECRET_KEY.getEncoded(), jwk.getSecretKey().getEncoded());
    assertEquals(Type.oct, jwk.getType());
    assertNull(jwk.getUsage());
    assertEquals(ENCRYPT_DECRYPT, jwk.getKeyOps());
    final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(encode);

    final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
    assertEquals(jwk.isExtractable(), moJwk.isExtractable());
    assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
    assertEquals(jwk.getId(), moJwk.getId());
    assertNull(moJwk.getRsaKeyPair());
    assertArrayEquals(jwk.getSecretKey().getEncoded(), moJwk.getSecretKey().getEncoded());
    assertEquals(jwk.getType(), moJwk.getType());
    assertEquals(jwk.getUsage(), moJwk.getUsage());
    assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
    final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(moEncode);
    // This test will not always pass since the key operations are
    // unordered.
    //assertArrayEquals(encode, moEncode);
}

@Test
public void octUsageJson() throws MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(Usage.wrap, Algorithm.A128KW, EXTRACTABLE, KEY_ID, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    assertEquals(EXTRACTABLE, mo.optBoolean(KEY_EXTRACTABLE));
    assertEquals(Algorithm.A128KW.name(), mo.getString(KEY_ALGORITHM));
    assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
    assertEquals(Type.oct.name(), mo.getString(KEY_TYPE));
    assertEquals(Usage.wrap.name(), mo.getString(KEY_USAGE));
    assertFalse(mo.has(KEY_KEY_OPS));

    assertFalse(mo.has(KEY_MODULUS));
    assertFalse(mo.has(KEY_PUBLIC_EXPONENT));
    assertFalse(mo.has(KEY_PRIVATE_EXPONENT));

    final String key = MslEncoderUtils.b64urlEncode(SECRET_KEY.getEncoded());

    assertEquals(key, mo.getString(KEY_KEY));
}

@Test
public void octKeyOpsJson() throws MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(WRAP_UNWRAP, Algorithm.A128KW, EXTRACTABLE, KEY_ID, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    assertEquals(EXTRACTABLE, mo.optBoolean(KEY_EXTRACTABLE));
    assertEquals(Algorithm.A128KW.name(), mo.getString(KEY_ALGORITHM));
    assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
    assertEquals(Type.oct.name(), mo.getString(KEY_TYPE));
    assertFalse(mo.has(KEY_USAGE));
    assertTrue(MslEncoderUtils.equalSets(MA_WRAP_UNWRAP, mo.getMslArray(KEY_KEY_OPS)));

    assertFalse(mo.has(KEY_MODULUS));
    assertFalse(mo.has(KEY_PUBLIC_EXPONENT));
    assertFalse(mo.has(KEY_PRIVATE_EXPONENT));

    final String key = MslEncoderUtils.b64urlEncode(SECRET_KEY.getEncoded());

    assertEquals(key, mo.getString(KEY_KEY));
}

@Test
public void octNullCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    assertFalse(jwk.isExtractable());
    assertNull(jwk.getAlgorithm());
    assertNull(jwk.getId());
    assertNull(jwk.getRsaKeyPair());
    assertArrayEquals(SECRET_KEY.getEncoded(), jwk.getSecretKey().getEncoded());
    assertEquals(Type.oct, jwk.getType());
    assertNull(jwk.getUsage());
    assertNull(jwk.getKeyOps());
    final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(encode);

    final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
    assertEquals(jwk.isExtractable(), moJwk.isExtractable());
    assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
    assertEquals(jwk.getId(), moJwk.getId());
    assertNull(moJwk.getRsaKeyPair());
    assertArrayEquals(jwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded(), moJwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded());
    assertEquals(jwk.getType(), moJwk.getType());
    assertEquals(jwk.getUsage(), moJwk.getUsage());
    assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
    final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void octNullJson() throws MslEncoderException {
    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    assertFalse(mo.getBoolean(KEY_EXTRACTABLE));
    assertFalse(mo.has(KEY_ALGORITHM));
    assertFalse(mo.has(KEY_KEY_ID));
    assertEquals(Type.oct.name(), mo.getString(KEY_TYPE));
    assertFalse(mo.has(KEY_USAGE));
    assertFalse(mo.has(KEY_KEY_OPS));

    assertFalse(mo.has(KEY_MODULUS));
    assertFalse(mo.has(KEY_PUBLIC_EXPONENT));
    assertFalse(mo.has(KEY_PRIVATE_EXPONENT));

    final String key = MslEncoderUtils.b64urlEncode(SECRET_KEY.getEncoded());

    assertEquals(key, mo.getString(KEY_KEY));
}

public void usageOnly() throws MslEncoderException, MslCryptoException, MslEncodingException {
    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_USAGE, Usage.enc.name());

    final JsonWebKey moJwk = new JsonWebKey(mo);
    assertEquals(Usage.enc, moJwk.getUsage());
    assertNull(moJwk.getKeyOps());
}

public void keyOpsOnly() throws MslEncoderException, MslCryptoException, MslEncodingException {
    final JsonWebKey jwk = new JsonWebKey(NULL_KEYOPS, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_KEY_OPS, MA_ENCRYPT_DECRYPT);

    final JsonWebKey moJwk = new JsonWebKey(mo);
    assertNull(moJwk.getUsage());
    assertEquals(new HashSet<KeyOp>(Arrays.asList(KeyOp.encrypt, KeyOp.decrypt)), moJwk.getKeyOps());
}

@Test(expected = MslInternalException.class)
public void octCtorMismatchedAlgo() {
    new JsonWebKey(NULL_USAGE, Algorithm.RSA1_5, false, null, SECRET_KEY);
}

@Test
public void missingType() throws MslEncoderException, MslCryptoException, MslEncodingException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.remove(KEY_TYPE);

    new JsonWebKey(mo);
}

@Test
public void invalidType() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.UNIDENTIFIED_JWK_TYPE);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_TYPE, "x");

    new JsonWebKey(mo);
}

@Test
public void invalidUsage() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.UNIDENTIFIED_JWK_USAGE);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_USAGE, "x");

    new JsonWebKey(mo);
}

@Test
public void invalidKeyOp() throws MslEncoderException, MslCryptoException, MslEncodingException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.UNIDENTIFIED_JWK_KEYOP);

    final JsonWebKey jwk = new JsonWebKey(NULL_KEYOPS, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_KEY_OPS, new JSONArray(Arrays.asList(KeyOp.encrypt.name(), "x", KeyOp.decrypt.name()).toArray()));

    new JsonWebKey(mo);
}

@Test
public void invalidAlgorithm() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.UNIDENTIFIED_JWK_ALGORITHM);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_ALGORITHM, "x");

    new JsonWebKey(mo);
}

@Test
public void missingExtractable() throws MslEncoderException, MslCryptoException, MslEncodingException {
    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
    final MslObject mo = encoder.parseObject(encode);

    assertNotNull(mo.remove(KEY_EXTRACTABLE));

    final JsonWebKey moJwk = new JsonWebKey(mo);
    assertEquals(jwk.isExtractable(), moJwk.isExtractable());
    assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
    assertEquals(jwk.getId(), moJwk.getId());
    assertNull(moJwk.getRsaKeyPair());
    assertArrayEquals(jwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded(), moJwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded());
    assertEquals(jwk.getType(), moJwk.getType());
    assertEquals(jwk.getUsage(), moJwk.getUsage());
    final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
    assertNotNull(moEncode);
    assertArrayEquals(encode, moEncode);
}

@Test
public void invalidExtractable() throws MslEncodingException, MslEncoderException, MslCryptoException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_EXTRACTABLE, "x");

    new JsonWebKey(mo);
}

@Test
public void missingKey() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.remove(KEY_KEY);

    new JsonWebKey(mo);
}

@Test
public void emptyKey() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_KEY, "");

    new JsonWebKey(mo);
}

@Test
public void missingModulus() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.remove(KEY_MODULUS);

    new JsonWebKey(mo);
}

@Test
public void emptyModulus() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_MODULUS, "");

    new JsonWebKey(mo);
}

@Test
public void missingExponents() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslEncodingException.class);
    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.remove(KEY_PUBLIC_EXPONENT);
    mo.remove(KEY_PRIVATE_EXPONENT);

    new JsonWebKey(mo);
}

@Test
public void emptyPublicExponent() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_PUBLIC_EXPONENT, "");

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

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_PUBLIC_EXPONENT, "x");

    new JsonWebKey(mo);
}

@Test
public void emptyPrivateExponent() throws MslCryptoException, MslEncodingException, MslEncoderException {
    thrown.expect(MslCryptoException.class);
    thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_PRIVATE_EXPONENT, "");

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

    final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
    final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);

    mo.put(KEY_PRIVATE_EXPONENT, "x");

    new JsonWebKey(mo);
}
#endif

}}} // namespace netflix::msl::crypto
