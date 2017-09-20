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
#include <gmock/gmock.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <crypto/SymmetricCryptoContext.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/Key.h>
#include <crypto/MslCiphertextEnvelope.h>
#include <crypto/Random.h>
#include <io/DefaultMslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <IllegalArgumentException.h>
#include <MslCryptoException.h>
#include <util/Hex.h>
#include <iostream>

#include "../util/MockMslContext.h"

using netflix::msl::io::MslEncoderFactory;
using netflix::msl::io::MslEncoderFormat;
using netflix::msl::util::fromHex;
using netflix::msl::util::MockMslContext;
using netflix::msl::util::MslContext;

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace testing;

namespace netflix {
namespace msl {
namespace crypto {

// NOTE: This test is parameterized for two values of signatureKey: HMAC_SHA256
// and AES_CMAC.

namespace {
struct TestParameters
{
    const string algorithm;
    const size_t keysize;
    TestParameters(const string& a, size_t k) : algorithm(a), keysize(k) {}
    friend ostream & operator<<(ostream &os, const TestParameters& tp);
};
ostream & operator<<(ostream& os, const TestParameters& tp) {
    return os << "algorithm:" << tp.algorithm << " keysize:" << tp.keysize;
}

string sufx(testing::TestParamInfo<struct TestParameters> tpi) {
    return tpi.param.algorithm;
}
} // namespace anonymous

class SymmetricCryptoContextTest : public ::testing::TestWithParam<TestParameters>
{
public:
    SymmetricCryptoContextTest()
    : id_("FOOBAR")
    , encryptionKey_(getRandomBytes(16), JcaAlgorithm::AES)
    , signatureKey_(getRandomBytes(GetParam().keysize), GetParam().algorithm)
    , wrappingKey_(getRandomBytes(16), JcaAlgorithm::AESKW)
    , encoderFormat_(MslEncoderFormat::JSON)
    , KEY_CIPHERTEXT("ciphertext")
    , KEYSET_ID("keysetid")
    , RFC_KEY(fromHex("000102030405060708090A0B0C0D0E0F")) // RFC 3394 encryption key
    , RFC_PLAINTEXT(fromHex("00112233445566778899AABBCCDDEEFF")) // RFC 3394 plaintext (key data)
    , RFC_CIPHERTEXT(fromHex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")) // RFC 3394 ciphertext
    , ctx_(make_shared<MockMslContext >(EntityAuthenticationScheme::PSK, false))
    , cryptoContext_(make_shared<SymmetricCryptoContext>(ctx_, id_, encryptionKey_, signatureKey_, wrappingKey_))
    {}
protected:
    shared_ptr<ByteArray> getRandomBytes(size_t nBytes) {
        static shared_ptr<crypto::IRandom> rand;
        if (!rand)
            rand = shared_ptr<crypto::IRandom>(make_shared<crypto::Random>());
        shared_ptr<ByteArray> ba = make_shared<ByteArray>(nBytes);
        rand->nextBytes(*ba);
        return ba;
    }

protected:
    const string id_;
    const SecretKey encryptionKey_;
    const SecretKey signatureKey_;
    const SecretKey wrappingKey_;
    shared_ptr<MslEncoderFactory> encoder_ = make_shared<DefaultMslEncoderFactory>();
    const MslEncoderFormat encoderFormat_;
    const string KEY_CIPHERTEXT;
    const string KEYSET_ID;
    const SecretKey nullKey_;
    const shared_ptr<ByteArray> RFC_KEY = make_shared<ByteArray>();
    const shared_ptr<ByteArray> RFC_PLAINTEXT = make_shared<ByteArray>();
    const shared_ptr<ByteArray> RFC_CIPHERTEXT = make_shared<ByteArray>();
    shared_ptr<util::MslContext> ctx_;
    shared_ptr<ICryptoContext> cryptoContext_;
};

INSTANTIATE_TEST_CASE_P(Crypto, SymmetricCryptoContextTest,
    ::testing::Values(
            TestParameters(JcaAlgorithm::HMAC_SHA256, 32),
            TestParameters(JcaAlgorithm::AES_CMAC,    16)
    ), &sufx);

TEST_P(SymmetricCryptoContextTest, Constructor)
{
    SecretKey nullKey;
    shared_ptr<ByteArray> bytes = getRandomBytes(16);

    SecretKey encryptionKey(bytes, JcaAlgorithm::AES);
    EXPECT_NO_THROW(SymmetricCryptoContext(ctx_, "foobar", encryptionKey, nullKey, nullKey));

    SecretKey signatureKey(bytes, GetParam().algorithm);
    EXPECT_NO_THROW(SymmetricCryptoContext(ctx_, "foobar", encryptionKey, signatureKey, nullKey));

    SecretKey wrappingKey(bytes, JcaAlgorithm::AESKW);
    EXPECT_NO_THROW(SymmetricCryptoContext(ctx_, "foobar", encryptionKey, signatureKey, wrappingKey));

    // mismatched key algorithms
    EXPECT_THROW(SymmetricCryptoContext(ctx_, "foobar", signatureKey, nullKey, nullKey), IllegalArgumentException);
    EXPECT_THROW(SymmetricCryptoContext(ctx_, "foobar", nullKey, encryptionKey, nullKey), IllegalArgumentException);
    EXPECT_THROW(SymmetricCryptoContext(ctx_, "foobar", nullKey, nullKey, signatureKey), IllegalArgumentException);

    // bad encryption key size
    shared_ptr<ByteArray> fiveBytes = getRandomBytes(5);
    SecretKey encKeyWrongSize(fiveBytes, JcaAlgorithm::AES);
    EXPECT_THROW(SymmetricCryptoContext(ctx_, "foobar", encKeyWrongSize, nullKey, nullKey), IllegalArgumentException);

    // FIXME: also check signature and wrapping key sizes?
}

TEST_P(SymmetricCryptoContextTest, EncryptDecrypt1)
{
    SecretKey nullKey;
    SecretKey encryptionKey(util::fromHex("000102030405060708090a0b0c0d0e0f"), JcaAlgorithm::AES);
    SymmetricCryptoContext scc(ctx_, "foobar", encryptionKey, nullKey, nullKey);

    shared_ptr<MslEncoderFactory> mef = make_shared<DefaultMslEncoderFactory>();
    const MslEncoderFormat fmt = MslEncoderFormat::JSON;
    shared_ptr<ByteArray> data = util::fromHex("00112233445566778899aa");
    shared_ptr<ByteArray> ciphertext = scc.encrypt(data, mef, fmt);

    //cout << string(ciphertext.begin(), ciphertext.end()) << endl;

    shared_ptr<ByteArray> plaintext = make_shared<ByteArray>();
    EXPECT_NO_THROW(plaintext = scc.decrypt(ciphertext, mef));
    EXPECT_EQ(*data, *plaintext);
}

TEST_P(SymmetricCryptoContextTest, EncryptDecrypt2)
{
    shared_ptr<ByteArray> messageA = getRandomBytes(32);

    shared_ptr<ByteArray> ciphertextA = cryptoContext_->encrypt(messageA, encoder_, encoderFormat_);
    EXPECT_FALSE(ciphertextA->empty());
    EXPECT_NE(*messageA, *ciphertextA);

    shared_ptr<ByteArray> plaintextA = cryptoContext_->decrypt(ciphertextA, encoder_);
    EXPECT_FALSE(plaintextA->empty());
    EXPECT_EQ(*messageA, *plaintextA);

    shared_ptr<ByteArray> messageB = getRandomBytes(32);

    shared_ptr<ByteArray> ciphertextB = cryptoContext_->encrypt(messageB, encoder_, encoderFormat_);
    EXPECT_FALSE(ciphertextB->empty());
    EXPECT_NE(*messageB, *ciphertextB);
    EXPECT_NE(*ciphertextB, *ciphertextA);

    shared_ptr<ByteArray> plaintextB = cryptoContext_->decrypt(ciphertextB, encoder_);
    EXPECT_FALSE(plaintextB->empty());
    EXPECT_EQ(*messageB, *plaintextB);
}

TEST_P(SymmetricCryptoContextTest, InvalidCiphertext)
{
    //thrown.expect(MslCryptoException.class);
    //thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

    shared_ptr<ByteArray> message = getRandomBytes(32);

    shared_ptr<ByteArray> data = cryptoContext_->encrypt(message, encoder_, encoderFormat_);
    shared_ptr<MslObject> envelopeMo = encoder_->parseObject(data);
    MslCiphertextEnvelope envelope = createMslCiphertextEnvelope(envelopeMo);

    shared_ptr<ByteArray> ciphertext = envelope.getCiphertext();
    ++(*ciphertext)[ciphertext->size() - 2];
    MslCiphertextEnvelope shortEnvelope(envelope.getKeyId(), envelope.getIv(), ciphertext);
    EXPECT_THROW(cryptoContext_->decrypt(shortEnvelope.toMslEncoding(encoder_, encoderFormat_), encoder_),
            MslCryptoException);
}

TEST_P(SymmetricCryptoContextTest, InsufficientCiphertext)
{
    //thrown.expect(MslCryptoException.class);
    //thrown.expectMslError(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE);

    shared_ptr<ByteArray> message = getRandomBytes(32);

    shared_ptr<ByteArray> data = cryptoContext_->encrypt(message, encoder_, encoderFormat_);
    shared_ptr<MslObject> envelopeMo = encoder_->parseObject(data);
    const MslCiphertextEnvelope envelope = createMslCiphertextEnvelope(envelopeMo);
    shared_ptr<ByteArray> ciphertext = envelope.getCiphertext();

    shared_ptr<ByteArray> shortCiphertext = make_shared<ByteArray>(ciphertext->begin(), ciphertext->end() - 1);
    MslCiphertextEnvelope shortEnvelope(envelope.getKeyId(), envelope.getIv(), shortCiphertext);
    EXPECT_THROW(cryptoContext_->decrypt(shortEnvelope.toMslEncoding(encoder_, encoderFormat_), encoder_),
            MslCryptoException);
}

TEST_P(SymmetricCryptoContextTest, NotEnvelope)
{
    //thrown.expect(MslCryptoException.class);
    //thrown.expectMslError(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR);

    shared_ptr<ByteArray> message = getRandomBytes(32);

    shared_ptr<ByteArray> data = cryptoContext_->encrypt(message, encoder_, encoderFormat_);
    shared_ptr<MslObject> envelopeMo = encoder_->parseObject(data);
    envelopeMo->remove(KEY_CIPHERTEXT);
    EXPECT_THROW(cryptoContext_->decrypt(encoder_->encodeObject(envelopeMo, encoderFormat_), encoder_),
            MslCryptoException);
}

TEST_P(SymmetricCryptoContextTest, CorruptEnvelope)
{
    //thrown.expect(MslCryptoException.class);
    //thrown.expectMslError(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR);

    shared_ptr<ByteArray> message = getRandomBytes(32);

    shared_ptr<ByteArray> data = cryptoContext_->encrypt(message, encoder_, encoderFormat_);
    (*data)[0] = 0;
    EXPECT_THROW(cryptoContext_->decrypt(data, encoder_), MslCryptoException);
}

TEST_P(SymmetricCryptoContextTest, EncryptNullEncryption)
{
    //thrown.expect(MslCryptoException.class);
    //thrown.expectMslError(MslError.ENCRYPT_NOT_SUPPORTED);

    shared_ptr<ICryptoContext> cryptoContext(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, nullKey_, signatureKey_, wrappingKey_));

    shared_ptr<ByteArray> message = getRandomBytes(32);

    EXPECT_THROW(cryptoContext->encrypt(message, encoder_, encoderFormat_), MslCryptoException);
}

TEST_P(SymmetricCryptoContextTest, DecryptNullEncryption)
{
    //thrown.expect(MslCryptoException.class);
    //thrown.expectMslError(MslError.DECRYPT_NOT_SUPPORTED);

    shared_ptr<ICryptoContext> cryptoContext(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, nullKey_, signatureKey_, wrappingKey_));

    shared_ptr<ByteArray> message = getRandomBytes(32);

    EXPECT_THROW(cryptoContext->decrypt(message, encoder_), MslCryptoException);
}

TEST_P(SymmetricCryptoContextTest, EncryptDecryptNullKeys)
{
    shared_ptr<ICryptoContext> cryptoContext(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, encryptionKey_, nullKey_, nullKey_));

    shared_ptr<ByteArray> messageA = getRandomBytes(32);

    shared_ptr<ByteArray> ciphertextA = cryptoContext_->encrypt(messageA, encoder_, encoderFormat_);
    EXPECT_FALSE(ciphertextA->empty());
    EXPECT_NE(*messageA, *ciphertextA);

    shared_ptr<ByteArray> plaintextA = cryptoContext_->decrypt(ciphertextA, encoder_);
    EXPECT_FALSE(plaintextA->empty());
    EXPECT_EQ(*messageA, *plaintextA);

    shared_ptr<ByteArray> messageB = getRandomBytes(32);

    shared_ptr<ByteArray> ciphertextB = cryptoContext_->encrypt(messageB, encoder_, encoderFormat_);
    EXPECT_FALSE(ciphertextB->empty());
    EXPECT_NE(*messageB, *ciphertextB);
    EXPECT_NE(*ciphertextB, *ciphertextA);

    shared_ptr<ByteArray> plaintextB = cryptoContext_->decrypt(ciphertextB, encoder_);
    EXPECT_FALSE(plaintextB->empty());
    EXPECT_EQ(*messageB, *plaintextB);
}

TEST_P(SymmetricCryptoContextTest, EncryptDecryptIdMismatch)
{
    shared_ptr<ICryptoContext> cryptoContextA(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID + "A", encryptionKey_, signatureKey_, wrappingKey_));
    shared_ptr<ICryptoContext> cryptoContextB(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID + "B", encryptionKey_, signatureKey_, wrappingKey_));

    shared_ptr<ByteArray> message = getRandomBytes(32);

    shared_ptr<ByteArray> ciphertext = cryptoContextA->encrypt(message, encoder_, encoderFormat_);
    EXPECT_FALSE(ciphertext->empty());
    EXPECT_NE(*message, *ciphertext);

    shared_ptr<ByteArray> plaintext = cryptoContextB->decrypt(ciphertext, encoder_);
    EXPECT_FALSE(plaintext->empty());
    EXPECT_EQ(*message, *plaintext);
}

TEST_P(SymmetricCryptoContextTest, EncryptDecryptKeysMismatch)
{
    //thrown.expect(MslCryptoException.class);
    //thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

    shared_ptr<ICryptoContext> cryptoContextA(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, encryptionKey_, signatureKey_, wrappingKey_));
    const SecretKey otherEncryptionKey(getRandomBytes(16), JcaAlgorithm::AES);
    shared_ptr<ICryptoContext> cryptoContextB(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, otherEncryptionKey, signatureKey_, wrappingKey_));

    shared_ptr<ByteArray> message = getRandomBytes(32);

    shared_ptr<ByteArray> ciphertext;
    try {
        ciphertext = cryptoContextA->encrypt(message, encoder_, encoderFormat_);
    } catch (const MslCryptoException& e) {
        ADD_FAILURE() << e.what();
        return;
    }

    EXPECT_THROW(cryptoContextB->decrypt(ciphertext, encoder_), MslCryptoException);
}

TEST_P(SymmetricCryptoContextTest, wrapUnwrapMinimum)
{
    const int MINLEN = 16;

    shared_ptr<ByteArray> keydataA = getRandomBytes(MINLEN);
    shared_ptr<ByteArray> ciphertextA;
    EXPECT_NO_THROW(ciphertextA = cryptoContext_->wrap(keydataA, encoder_, encoderFormat_));
    EXPECT_FALSE(ciphertextA->empty());
    EXPECT_NE(*keydataA, *ciphertextA);

    shared_ptr<ByteArray> plaintextA;
    EXPECT_NO_THROW(plaintextA = cryptoContext_->unwrap(ciphertextA, encoder_));
    EXPECT_FALSE(plaintextA->empty());
    EXPECT_EQ(*keydataA, *plaintextA);

    shared_ptr<ByteArray> keydataB = getRandomBytes(MINLEN);
    shared_ptr<ByteArray> ciphertextB;
    EXPECT_NO_THROW(ciphertextB = cryptoContext_->wrap(keydataB, encoder_, encoderFormat_));
    EXPECT_FALSE(ciphertextB->empty());
    EXPECT_NE(*keydataB, *ciphertextB);
    EXPECT_NE(*ciphertextB, *ciphertextA);

    shared_ptr<ByteArray> plaintextB;
    EXPECT_NO_THROW(plaintextB = cryptoContext_->unwrap(ciphertextB, encoder_));
    EXPECT_FALSE(plaintextB->empty());
    EXPECT_EQ(*keydataB, *plaintextB);

}

TEST_P(SymmetricCryptoContextTest, wrapUnwrapBlockAligned)
{
    shared_ptr<ByteArray> keydataA = getRandomBytes(GetParam().keysize);
    shared_ptr<ByteArray> ciphertextA;
    EXPECT_NO_THROW(ciphertextA = cryptoContext_->wrap(keydataA, encoder_, encoderFormat_));
    EXPECT_FALSE(ciphertextA->empty());
    EXPECT_NE(*keydataA, *ciphertextA);

    shared_ptr<ByteArray> plaintextA;
    EXPECT_NO_THROW(plaintextA = cryptoContext_->unwrap(ciphertextA, encoder_));
    EXPECT_FALSE(plaintextA->empty());
    EXPECT_EQ(*keydataA, *plaintextA);

    shared_ptr<ByteArray> keydataB = getRandomBytes(GetParam().keysize);
    shared_ptr<ByteArray> ciphertextB;
    EXPECT_NO_THROW(ciphertextB = cryptoContext_->wrap(keydataB, encoder_, encoderFormat_));
    EXPECT_FALSE(ciphertextB->empty());
    EXPECT_NE(*keydataB, *ciphertextB);
    EXPECT_NE(*ciphertextB, *ciphertextA);

    shared_ptr<ByteArray> plaintextB;
    EXPECT_NO_THROW(plaintextB = cryptoContext_->unwrap(ciphertextB, encoder_));
    EXPECT_FALSE(plaintextB->empty());
    EXPECT_EQ(*keydataB, *plaintextB);
}

TEST_P(SymmetricCryptoContextTest, wrapBlockUnaligned)
{
    shared_ptr<ByteArray> keydataA = getRandomBytes(129);
    try {
        cryptoContext_->wrap(keydataA, encoder_, encoderFormat_);
        ADD_FAILURE();
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::PLAINTEXT_ILLEGAL_BLOCK_SIZE, e.getError());
    }
}

TEST_P(SymmetricCryptoContextTest, unwrapBlockUnaligned)
{
    shared_ptr<ByteArray> ciphertextA = getRandomBytes(129);
    try {
        cryptoContext_->unwrap(ciphertextA, encoder_);
        ADD_FAILURE();
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::CIPHERTEXT_ILLEGAL_BLOCK_SIZE, e.getError());
    }
}

TEST_P(SymmetricCryptoContextTest, wrapNullWrap)
{
    shared_ptr<ICryptoContext> scc(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, encryptionKey_, signatureKey_, nullKey_));
    shared_ptr<ByteArray> messageA = getRandomBytes(32);
    try {
        scc->wrap(messageA, encoder_, encoderFormat_);
        ADD_FAILURE();
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(SymmetricCryptoContextTest, unwrapNullWrap)
{
    shared_ptr<ICryptoContext> scc(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, encryptionKey_, signatureKey_, nullKey_));
    shared_ptr<ByteArray> messageA = getRandomBytes(32);
    shared_ptr<ByteArray> plaintext;
    try {
        plaintext = scc->unwrap(messageA, encoder_);
        ADD_FAILURE();
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNWRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(SymmetricCryptoContextTest, wrapUnwrapNullKeys)
{
    shared_ptr<ICryptoContext> scc(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, nullKey_, nullKey_, wrappingKey_));

    shared_ptr<ByteArray> keydataA = getRandomBytes(GetParam().keysize);

    shared_ptr<ByteArray> ciphertextA;
    EXPECT_NO_THROW(ciphertextA = scc->wrap(keydataA, encoder_, encoderFormat_));
    EXPECT_FALSE(ciphertextA->empty());
    EXPECT_NE(*keydataA, *ciphertextA);

    shared_ptr<ByteArray> plaintextA;
    EXPECT_NO_THROW(plaintextA = scc->unwrap(ciphertextA, encoder_));
    EXPECT_FALSE(plaintextA->empty());
    EXPECT_EQ(*keydataA, *plaintextA);

    shared_ptr<ByteArray> keydataB = getRandomBytes(GetParam().keysize);

    shared_ptr<ByteArray> ciphertextB;
    EXPECT_NO_THROW(ciphertextB = scc->wrap(keydataB, encoder_, encoderFormat_));
    EXPECT_FALSE(ciphertextB->empty());
    EXPECT_NE(*keydataB, *ciphertextB);
    EXPECT_NE(*ciphertextB, *ciphertextA);

    shared_ptr<ByteArray> plaintextB;
    EXPECT_NO_THROW(plaintextB = scc->unwrap(ciphertextB, encoder_));
    EXPECT_FALSE(plaintextB->empty());
    EXPECT_EQ(*keydataB, *plaintextB);
}

TEST_P(SymmetricCryptoContextTest, unwrapUnalignedData)
{
	shared_ptr<ByteArray> keydataA = getRandomBytes(GetParam().keysize - 1);
    shared_ptr<ByteArray> plaintext;
    try {
        plaintext = cryptoContext_->unwrap(keydataA, encoder_);
        ADD_FAILURE();
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::CIPHERTEXT_ILLEGAL_BLOCK_SIZE, e.getError());
    }
}

TEST_P(SymmetricCryptoContextTest, rfcWrapUnwrap)
{
    const SecretKey wrappingKey(RFC_KEY, JcaAlgorithm::AESKW);
    shared_ptr<ICryptoContext> scc(make_shared<SymmetricCryptoContext>(ctx_, "RFC", nullKey_, nullKey_, wrappingKey));

    shared_ptr<ByteArray> wrapped;
    EXPECT_NO_THROW(wrapped = scc->wrap(RFC_PLAINTEXT, encoder_, encoderFormat_));
    EXPECT_EQ(*RFC_CIPHERTEXT, *wrapped);

    shared_ptr<ByteArray> unwrapped;
    EXPECT_NO_THROW(unwrapped = scc->unwrap(wrapped, encoder_));
    EXPECT_EQ(*RFC_PLAINTEXT, *unwrapped);
}

TEST_P(SymmetricCryptoContextTest, signVerify)
{
    shared_ptr<ByteArray> messageA = getRandomBytes(32);

    shared_ptr<ByteArray> signatureA = cryptoContext_->sign(messageA, encoder_, encoderFormat_);
    EXPECT_FALSE(signatureA->empty());
    EXPECT_NE(*messageA, *signatureA);

    EXPECT_TRUE(cryptoContext_->verify(messageA, signatureA, encoder_));

    shared_ptr<ByteArray> messageB = getRandomBytes(32);

    shared_ptr<ByteArray> signatureB = cryptoContext_->sign(messageB, encoder_, encoderFormat_);
    EXPECT_GE(signatureB->size(), 0u);
    EXPECT_NE(*signatureA, *signatureB);

    EXPECT_TRUE(cryptoContext_->verify(messageB, signatureB, encoder_));

    EXPECT_FALSE(cryptoContext_->verify(messageB, signatureA, encoder_));
}

TEST_P(SymmetricCryptoContextTest, signVerifyContextMismatch)
{
    shared_ptr<ByteArray> message = getRandomBytes(32);
    shared_ptr<ByteArray> signature = cryptoContext_->sign(message, encoder_, encoderFormat_);

    const SecretKey signatureKey(getRandomBytes(16), GetParam().algorithm);
    shared_ptr<ICryptoContext> cryptoContext2(make_shared<SymmetricCryptoContext>(ctx_, "foobar", nullKey_, signatureKey, nullKey_));
    EXPECT_FALSE(cryptoContext2->verify(message, signature, encoder_));
}

TEST_P(SymmetricCryptoContextTest, signVerifyNullKeys)
{
    const SecretKey signatureKey(getRandomBytes(16), GetParam().algorithm);
    shared_ptr<ICryptoContext> cc(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, nullKey_, signatureKey, nullKey_));

    shared_ptr<ByteArray> messageA = getRandomBytes(32);

    shared_ptr<ByteArray> signatureA = cc->sign(messageA, encoder_, encoderFormat_);
    EXPECT_FALSE(signatureA->empty());
    EXPECT_TRUE(signatureA->size() > 0);
    EXPECT_NE(*messageA, *signatureA);

    EXPECT_TRUE(cc->verify(messageA, signatureA, encoder_));

    shared_ptr<ByteArray> messageB = getRandomBytes(32);

    shared_ptr<ByteArray> signatureB = cc->sign(messageB, encoder_, encoderFormat_);
    EXPECT_TRUE(signatureB->size() > 0);
    EXPECT_NE(*signatureA, *signatureB);

    EXPECT_TRUE(cc->verify(messageB, signatureB, encoder_));
    EXPECT_FALSE(cc->verify(messageB, signatureA, encoder_));
}

TEST_P(SymmetricCryptoContextTest, signNullHmac)
{
    //thrown.expect(MslCryptoException.class);
    //thrown.expectMslError(MslError.SIGN_NOT_SUPPORTED);

    shared_ptr<ICryptoContext> cc(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, encryptionKey_, nullKey_, wrappingKey_));

    shared_ptr<ByteArray> messageA = getRandomBytes(32);
    shared_ptr<ByteArray> signatureA = make_shared<ByteArray>();
    try {
        cc->sign(messageA, encoder_, encoderFormat_);
        ADD_FAILURE() << "should have thrown MslCryptoException SIGN_NOT_SUPPORTED";
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::SIGN_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(SymmetricCryptoContextTest, verifyNullHmac)
{
    //thrown.expect(MslCryptoException.class);
    //thrown.expectMslError(MslError.VERIFY_NOT_SUPPORTED);

    shared_ptr<ICryptoContext> cc(make_shared<SymmetricCryptoContext>(ctx_, KEYSET_ID, encryptionKey_, nullKey_, wrappingKey_));

    shared_ptr<ByteArray> message = getRandomBytes(32);
    shared_ptr<ByteArray> signature = getRandomBytes(32);
    try {
        cc->verify(message, signature, encoder_);
        ADD_FAILURE() << "should have thrown MslCryptoException VERIFY_NOT_SUPPORTED";
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::VERIFY_NOT_SUPPORTED, e.getError());
    }
}

}}} // namespace netflix::msl::crypto
