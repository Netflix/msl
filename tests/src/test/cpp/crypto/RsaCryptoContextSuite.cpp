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
#include <crypto/JcaAlgorithm.h>
#include <crypto/Key.h>
#include <crypto/RsaCryptoContext.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncoderFormat.h>
#include <MslCryptoException.h>
#include <MslInternalException.h>
#include <memory>

#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;
using namespace testing;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

// This class ensures stuff shared between suites is only created once, since
// RSA stuff can be expensive to create.
class TestSingleton
{
public:
    static shared_ptr<MockMslContext> getMockMslContext() {
        static shared_ptr<MockMslContext> theInstance;
        if (!theInstance)
            theInstance = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
        return theInstance;
    }
    static PublicKey getPublicKeyA() { return keyInstanceA().first; }
    static PrivateKey getPrivateKeyA() { return keyInstanceA().second; }
    static PublicKey getPublicKeyB() { return keyInstanceB().first; }
    static PrivateKey getPrivateKeyB() { return keyInstanceB().second; }
private:
    static pair<PublicKey,PrivateKey> keyInstanceA() {
        static pair<PublicKey,PrivateKey> theInstance;
        if (theInstance.first.isNull())
            theInstance = MslTestUtils::generateRsaKeys(JcaAlgorithm::SHA256withRSA, 512);
        return theInstance;
    }
    static pair<PublicKey,PrivateKey> keyInstanceB() {
        static pair<PublicKey,PrivateKey> theInstance;
        if (theInstance.first.isNull())
        	theInstance = MslTestUtils::generateRsaKeys(JcaAlgorithm::SHA256withRSA, 512);
        return theInstance;
    }
};

// This class holds the stuff common to all the suites in this file.
class BaseTest
{
public:
    BaseTest()
    : publicKeyA(TestSingleton::getPublicKeyA())
    , privateKeyA(TestSingleton::getPrivateKeyA())
    , publicKeyB(TestSingleton::getPublicKeyB())
    , privateKeyB(TestSingleton::getPrivateKeyB())
    , ctx(TestSingleton::getMockMslContext())
    , random(ctx->getRandom())
    , ENCODER_FORMAT(MslEncoderFormat::JSON)
    , encoder(ctx->getMslEncoderFactory())
    {
    }
protected:
    virtual ~BaseTest() {}
    /** RSA public key A. */
    const PublicKey publicKeyA;
    /** RSA private key A. */
    const PrivateKey privateKeyA;
    /** RSA public key B. */
    const PublicKey publicKeyB;
    /** RSA private key B. */
    const PrivateKey privateKeyB;
    /** MSL context. */
    shared_ptr<MockMslContext> ctx;
    /** Random. */
    shared_ptr<IRandom> random;
    /** MSL encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
};

struct TestParameters
{
    const RsaCryptoContext::Mode mode;
    const size_t messageSize;
    TestParameters(const RsaCryptoContext::Mode& m, size_t s) : mode(m), messageSize(s) {}
};
string modeToString(const RsaCryptoContext::Mode& mode) {
    if (mode == RsaCryptoContext::ENCRYPT_DECRYPT_PKCS1)
        return "PKCS1";
    else if (mode == RsaCryptoContext::ENCRYPT_DECRYPT_OAEP)
        return "OAEP";
    else
        return "ERROR";
}
ostream & operator<<(ostream& os, const TestParameters& tp) {
    return os << "mode:" << modeToString(tp.mode) << " messageSize:" << tp.messageSize;
}
string sufx(testing::TestParamInfo<struct TestParameters> tp) {
    return modeToString(tp.param.mode);
}

/** Key pair ID. */
const string KEYPAIR_ID = "keypairid";

} // namespace anonymous

// =============================================================================
/** Encrypt/decrypt mode unit tests. */
// =============================================================================
class RsaCryptoContextEncryptDecryptTest : public ::testing::TestWithParam<TestParameters>,
                                           protected BaseTest
{
};

INSTANTIATE_TEST_CASE_P(Crypto, RsaCryptoContextEncryptDecryptTest,
    ::testing::Values(
            TestParameters(RsaCryptoContext::ENCRYPT_DECRYPT_PKCS1, 32),
            TestParameters(RsaCryptoContext::ENCRYPT_DECRYPT_OAEP, 16)
    ), &sufx);

TEST_P(RsaCryptoContextEncryptDecryptTest, encryptDecrypt)
{
	shared_ptr<ByteArray> messageA = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*messageA);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, GetParam().mode);
    shared_ptr<ByteArray> ciphertextA = cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT);
    EXPECT_FALSE(ciphertextA->empty());
    EXPECT_NE(*messageA, *ciphertextA);

    shared_ptr<ByteArray> plaintextA = cryptoContext.decrypt(ciphertextA, encoder);
    EXPECT_FALSE(plaintextA->empty());
    EXPECT_EQ(*messageA, *plaintextA);

    shared_ptr<ByteArray> messageB = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*messageB);

    shared_ptr<ByteArray> ciphertextB = cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT);
    EXPECT_FALSE(ciphertextB->empty());
    EXPECT_NE(*messageB, *ciphertextB);
    EXPECT_NE(*ciphertextB, *ciphertextA);

    shared_ptr<ByteArray> plaintextB = cryptoContext.decrypt(ciphertextB, encoder);
    EXPECT_FALSE(plaintextB->empty());
    EXPECT_EQ(*messageB, *plaintextB);
}

TEST_P(RsaCryptoContextEncryptDecryptTest, encryptNullPublic)
{
	shared_ptr<ByteArray> messageA = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*messageA);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, PublicKey(), GetParam().mode);
    try {
        cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::ENCRYPT_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(RsaCryptoContextEncryptDecryptTest, decryptNullPrivate)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, PrivateKey(), publicKeyA, GetParam().mode);
    shared_ptr<ByteArray> ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);

    try {
        cryptoContext.decrypt(ciphertext, encoder);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::DECRYPT_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(RsaCryptoContextEncryptDecryptTest, encryptDecryptIdMismatch)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContextA(ctx, KEYPAIR_ID + "A", privateKeyA, publicKeyA, GetParam().mode);
    shared_ptr<ByteArray> ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_FALSE(ciphertext->empty());
    EXPECT_NE(*message, *ciphertext);

    RsaCryptoContext cryptoContextB(ctx, KEYPAIR_ID + "B", privateKeyA, publicKeyA, GetParam().mode);
    shared_ptr<ByteArray> plaintext = cryptoContextB.decrypt(ciphertext, encoder);
    EXPECT_FALSE(plaintext->empty());
    EXPECT_EQ(*message, *plaintext);
}

TEST_P(RsaCryptoContextEncryptDecryptTest, encryptDecryptKeysMismatch)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContextA(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, GetParam().mode);
    shared_ptr<ByteArray> ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);

    RsaCryptoContext cryptoContextB(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, GetParam().mode);
    try {
        cryptoContextB.decrypt(ciphertext, encoder);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        // NOTE: The OpenSSL API does not seem to have standard way of reporting
        // bad padding, so the code just returns a decrypt failure.
        //EXPECT_EQ(MslError::CIPHERTEXT_BAD_PADDING, e.getError());
        EXPECT_EQ(MslError::DECRYPT_ERROR, e.getError());
    }
}

TEST_P(RsaCryptoContextEncryptDecryptTest, wrapUnwrapOneBlock)
{
    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, GetParam().mode);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(8);
    random->nextBytes(*keydataA);
    EXPECT_FALSE(keydataA->empty());

    try {
        cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(RsaCryptoContextEncryptDecryptTest, wrapUnwrapBlockAligned)
{
    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, GetParam().mode);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*keydataA);

    try {
        cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(RsaCryptoContextEncryptDecryptTest, wrapUnwrapBlockUnaligned)
{
    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, GetParam().mode);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(127);
    random->nextBytes(*keydataA);

    try {
        cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(RsaCryptoContextEncryptDecryptTest, wrapNullPublic)
{
    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, PublicKey(), GetParam().mode);

    shared_ptr<ByteArray> messageA = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*messageA);

    try {
        cryptoContext.wrap(messageA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(RsaCryptoContextEncryptDecryptTest, unwrapNullPrivate)
{
    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, PrivateKey(), publicKeyA, GetParam().mode);

    shared_ptr<ByteArray> messageA = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*messageA);

    try {
        cryptoContext.unwrap(messageA, encoder);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNWRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(RsaCryptoContextEncryptDecryptTest, unwrapUnalignedData)
{
    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, GetParam().mode);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(1);
    random->nextBytes(*keydataA);

    try {
        cryptoContext.unwrap(keydataA, encoder);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNWRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_P(RsaCryptoContextEncryptDecryptTest, signVerify)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, GetParam().mode);
    shared_ptr<ByteArray> signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
    EXPECT_TRUE(signature->empty());

    EXPECT_TRUE(cryptoContext.verify(message, signature, encoder));
}

TEST_P(RsaCryptoContextEncryptDecryptTest, signVerifyContextMismatch)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContextA(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, GetParam().mode);
    shared_ptr<ByteArray> signature = cryptoContextA.sign(message, encoder, ENCODER_FORMAT);
    RsaCryptoContext cryptoContextB(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, GetParam().mode);
    EXPECT_TRUE(cryptoContextB.verify(message, signature, encoder));
}

TEST_P(RsaCryptoContextEncryptDecryptTest, signNullPrivate)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, PrivateKey(), publicKeyA, GetParam().mode);
    shared_ptr<ByteArray> signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
    EXPECT_TRUE(signature->empty());

    EXPECT_TRUE(cryptoContext.verify(message, signature, encoder));
}

TEST_P(RsaCryptoContextEncryptDecryptTest, verifyNullPublic)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(GetParam().messageSize);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, PublicKey(), GetParam().mode);
    shared_ptr<ByteArray> signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
    EXPECT_TRUE(signature->empty());

    EXPECT_TRUE(cryptoContext.verify(message, signature, encoder));
}

// =============================================================================
/** Wrap/unwrap mode unit tests. */
// =============================================================================
class RsaCryptoContextWrapUnwrapTest : public ::testing::Test,
                                       protected BaseTest
{
};

TEST_F(RsaCryptoContextWrapUnwrapTest, encryptDecrypt)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    shared_ptr<ByteArray> plaintext = cryptoContext.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}


TEST_F(RsaCryptoContextWrapUnwrapTest, encryptNullPublic)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, PublicKey(), RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    shared_ptr<ByteArray> plaintext = cryptoContext.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}

TEST_F(RsaCryptoContextWrapUnwrapTest, decryptNullPrivate)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, PrivateKey(), publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    shared_ptr<ByteArray> plaintext = cryptoContext.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}

TEST_F(RsaCryptoContextWrapUnwrapTest, encryptDecryptIdMismatch)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContextA(ctx, KEYPAIR_ID + "A", privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    RsaCryptoContext cryptoContextB(ctx, KEYPAIR_ID + "B", privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> plaintext = cryptoContextB.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}

TEST_F(RsaCryptoContextWrapUnwrapTest, encryptDecryptKeysMismatch)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContextA(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    RsaCryptoContext cryptoContextB(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> plaintext = cryptoContextB.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}

#if 0  // disabled tests

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_wrapUnwrapOneBlock)
{
    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::WRAP_UNWRAP);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(8);
    random->nextBytes(*keydataA);

    shared_ptr<ByteArray> ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
    EXPECT_NE(*keydataA, *ciphertextA);

    shared_ptr<ByteArray> plaintextA = cryptoContext.unwrap(ciphertextA, encoder);
    EXPECT_EQ(*keydataA, *plaintextA);

    shared_ptr<ByteArray> keydataB = make_shared<ByteArray>(8);
    random->nextBytes(*keydataB);

    shared_ptr<ByteArray> ciphertextB = cryptoContext.wrap(keydataB, encoder, ENCODER_FORMAT);
    EXPECT_NE(*keydataB, *ciphertextB);
    EXPECT_NE(*ciphertextB, *ciphertextA);

    shared_ptr<ByteArray> plaintextB = cryptoContext.unwrap(ciphertextB, encoder);
    EXPECT_EQ(*keydataB, *plaintextB);
}

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_wrapUnwrapBlockAligned)
{
    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::WRAP_UNWRAP);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(32);
    random->nextBytes(*keydataA);

    shared_ptr<ByteArray> ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
    EXPECT_NE(*keydataA, *ciphertextA);

    shared_ptr<ByteArray> plaintextA = cryptoContext.unwrap(ciphertextA, encoder);
    EXPECT_EQ(*keydataA, *plaintextA);

    shared_ptr<ByteArray> keydataB = make_shared<ByteArray>(32);
    random->nextBytes(*keydataB);

    shared_ptr<ByteArray> ciphertextB = cryptoContext.wrap(keydataB, encoder, ENCODER_FORMAT);
    EXPECT_NE(*keydataB, *ciphertextB);
    EXPECT_NE(*ciphertextB, *ciphertextA);

    shared_ptr<ByteArray> plaintextB = cryptoContext.unwrap(ciphertextB, encoder);
    EXPECT_EQ(*keydataB, *plaintextB);
}

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_wrapUnwrapBlockUnaligned)
{
    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::WRAP_UNWRAP);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(127);
    random->nextBytes(*keydataA);

    shared_ptr<ByteArray> ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
    EXPECT_NE(*keydataA, *ciphertextA);

    shared_ptr<ByteArray> plaintextA = cryptoContext.unwrap(ciphertextA, encoder);
    EXPECT_EQ(*keydataA, *plaintextA);

    shared_ptr<ByteArray> keydataB = make_shared<ByteArray>(127);
    random->nextBytes(*keydataB);

    shared_ptr<ByteArray> ciphertextB = cryptoContext.wrap(keydataB, encoder, ENCODER_FORMAT);
    EXPECT_NE(*keydataB, *ciphertextB);
    EXPECT_NE(*ciphertextB, *ciphertextA);

    shared_ptr<ByteArray> plaintextB = cryptoContext.unwrap(ciphertextB, encoder);
    EXPECT_EQ(*keydataB, *plaintextB);
}

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_wrapNullPublic)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::WRAP_NOT_SUPPORTED);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, PublicKey(), RsaCryptoContext::WRAP_UNWRAP);

    shared_ptr<ByteArray> messageA = make_shared<ByteArray>(32);
    random->nextBytes(*messageA);

    try {
        cryptoContext.wrap(messageA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_unwrapNullPrivate)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::UNWRAP_NOT_SUPPORTED);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, PrivateKey(), publicKeyA, RsaCryptoContext::WRAP_UNWRAP);

    shared_ptr<ByteArray> messageA = make_shared<ByteArray>(32);
    random->nextBytes(*messageA);

    try {
        cryptoContext.unwrap(messageA, encoder);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNWRAP_NOT_SUPPORTED, e.getError());
    }
}

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_unwrapUnalignedData)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::INVALID_WRAP_CIPHERTEXT);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::WRAP_UNWRAP);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(1);
    random->nextBytes(*keydataA);

    try {
        cryptoContext.unwrap(keydataA, encoder);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::INVALID_WRAP_CIPHERTEXT, e.getError());
    }
}

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_signVerify)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::WRAP_UNWRAP);
    shared_ptr<ByteArray> signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
    EXPECT_TRUE(signature->empty());

    EXPECT_TRUE(cryptoContext.verify(message, signature, encoder));
}

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_signVerifyContextMismatch)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContextA(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::WRAP_UNWRAP);
    shared_ptr<ByteArray> signature = cryptoContextA.sign(message, encoder, ENCODER_FORMAT);
    RsaCryptoContext cryptoContextB(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, RsaCryptoContext::WRAP_UNWRAP);
    EXPECT_TRUE(cryptoContextB.verify(message, signature, encoder));
}

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_signNullPrivate)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, PrivateKey(), publicKeyA, RsaCryptoContext::WRAP_UNWRAP);
    shared_ptr<ByteArray> signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
    EXPECT_TRUE(signature->empty());

    EXPECT_TRUE(cryptoContext.verify(message, signature, encoder));
}

// This test is disabled, it never worked in java
TEST_F(RsaCryptoContextWrapUnwrapTest, DISABLED_verifyNullPublic)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, PublicKey(), RsaCryptoContext::WRAP_UNWRAP);
    shared_ptr<ByteArray> signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
    EXPECT_TRUE(signature->empty());

    EXPECT_TRUE(cryptoContext.verify(message, signature, encoder));
}

#endif // end disabled tests

// =============================================================================
/** Sign/verify mode unit tests. */
// =============================================================================
class RsaCryptoContextSignVerifyTest : public ::testing::Test,
                                        protected BaseTest
{
};

TEST_F(RsaCryptoContextSignVerifyTest, encryptDecrypt)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    shared_ptr<ByteArray> plaintext = cryptoContext.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}

TEST_F(RsaCryptoContextSignVerifyTest, encryptNullPublic)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, PublicKey(), RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    shared_ptr<ByteArray> plaintext = cryptoContext.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}

TEST_F(RsaCryptoContextSignVerifyTest, decryptNullPrivate)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, PrivateKey(), publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    shared_ptr<ByteArray> plaintext = cryptoContext.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}

TEST_F(RsaCryptoContextSignVerifyTest, encryptDecryptIdMismatch)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContextA(ctx, KEYPAIR_ID + "A", privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    RsaCryptoContext cryptoContextB(ctx, KEYPAIR_ID + "B", privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> plaintext = cryptoContextB.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}

TEST_F(RsaCryptoContextSignVerifyTest, encryptDecryptKeysMismatch)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContextA(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
    EXPECT_EQ(*message, *ciphertext);

    RsaCryptoContext cryptoContextB(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> plaintext = cryptoContextB.decrypt(ciphertext, encoder);
    EXPECT_EQ(*message, *plaintext);
}

TEST_F(RsaCryptoContextSignVerifyTest, wrapUnwrapOneBlock)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::WRAP_NOT_SUPPORTED);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(8);
    random->nextBytes(*keydataA);

    try {
        cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_F(RsaCryptoContextSignVerifyTest, wrapUnwrapBlockAligned)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::WRAP_NOT_SUPPORTED);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(32);
    random->nextBytes(*keydataA);

    try {
        cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_F(RsaCryptoContextSignVerifyTest, wrapUnwrapBlockUnaligned)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::WRAP_NOT_SUPPORTED);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(127);
    random->nextBytes(*keydataA);

    try {
        cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_F(RsaCryptoContextSignVerifyTest, wrapNullPublic)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::WRAP_NOT_SUPPORTED);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, PublicKey(), RsaCryptoContext::SIGN_VERIFY);

    shared_ptr<ByteArray> messageA = make_shared<ByteArray>(32);
    random->nextBytes(*messageA);

    try {
        cryptoContext.wrap(messageA, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::WRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_F(RsaCryptoContextSignVerifyTest, unwrapNullPrivate)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::UNWRAP_NOT_SUPPORTED);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, PrivateKey(), publicKeyA, RsaCryptoContext::SIGN_VERIFY);

    shared_ptr<ByteArray> messageA = make_shared<ByteArray>(32);
    random->nextBytes(*messageA);

    try {
        cryptoContext.unwrap(messageA, encoder);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNWRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_F(RsaCryptoContextSignVerifyTest, unwrapUnalignedData)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::UNWRAP_NOT_SUPPORTED);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);

    shared_ptr<ByteArray> keydataA = make_shared<ByteArray>(1);
    random->nextBytes(*keydataA);

    try {
        cryptoContext.unwrap(keydataA, encoder);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNWRAP_NOT_SUPPORTED, e.getError());
    }
}

TEST_F(RsaCryptoContextSignVerifyTest, signVerify)
{
    shared_ptr<ByteArray> messageA = make_shared<ByteArray>(32);
    random->nextBytes(*messageA);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> signatureA = cryptoContext.sign(messageA, encoder, ENCODER_FORMAT);
    EXPECT_TRUE(signatureA->size() > 0);
    EXPECT_NE(*messageA, *signatureA);

    EXPECT_TRUE(cryptoContext.verify(messageA, signatureA, encoder));

    shared_ptr<ByteArray> messageB = make_shared<ByteArray>(32);
    random->nextBytes(*messageB);

    shared_ptr<ByteArray> signatureB = cryptoContext.sign(messageB, encoder, ENCODER_FORMAT);
    EXPECT_TRUE(signatureB->size() > 0);
    EXPECT_NE(*signatureA, *signatureB);

    EXPECT_TRUE(cryptoContext.verify(messageB, signatureB, encoder));
    EXPECT_FALSE(cryptoContext.verify(messageB, signatureA, encoder));
}

TEST_F(RsaCryptoContextSignVerifyTest, signVerifyContextMismatch)
{
    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContextA(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> signature = cryptoContextA.sign(message, encoder, ENCODER_FORMAT);
    RsaCryptoContext cryptoContextB(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, RsaCryptoContext::SIGN_VERIFY);
    EXPECT_FALSE(cryptoContextB.verify(message, signature, encoder));
}

TEST_F(RsaCryptoContextSignVerifyTest, signNullPrivate)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::SIGN_NOT_SUPPORTED);

    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, PrivateKey(), publicKeyA, RsaCryptoContext::SIGN_VERIFY);
    try {
        cryptoContext.sign(message, encoder, ENCODER_FORMAT);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::SIGN_NOT_SUPPORTED, e.getError());
    }
}

TEST_F(RsaCryptoContextSignVerifyTest, verifyNullPublic)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::VERIFY_NOT_SUPPORTED);

    shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
    random->nextBytes(*message);

    RsaCryptoContext cryptoContext(ctx, KEYPAIR_ID, privateKeyA, PublicKey(), RsaCryptoContext::SIGN_VERIFY);
    shared_ptr<ByteArray> signature;
    EXPECT_NO_THROW(signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT));
    try {
        cryptoContext.verify(message, signature, encoder);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::VERIFY_NOT_SUPPORTED, e.getError());
    }
}

}}} // namespace netflix::msl::crypto
