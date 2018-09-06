/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
#include <memory>

#include <gtest/gtest.h>
#include <crypto/EccCryptoContext.h>
#include <crypto/IRandom.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <io/MslEncoderFormat.h>
#include <util/MockMslContext.h>

#include "../util/MslTestUtils.h"

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

using Mode = EccCryptoContext::Mode;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace crypto {

namespace {
/** Key pair ID. */
const string KEYPAIR_ID = "keypairid";

/** EC curve q. */
//private static final BigInteger EC_Q = new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839");
/** EC coefficient a. */
//private static final BigInteger EC_A = new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16);
/** EC coefficient b. */
//private static final BigInteger EC_B = new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16);

/** EC base point g. */
//private static final BigInteger EC_G = new BigInteger("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf", 16);
/** EC generator order n. */
//private static final BigInteger EC_N = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");

const PublicKey NULL_PUBKEY;
const PrivateKey NULL_PRIVKEY;
} // namespace anonymous

/**
 * ECC crypto context unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class EccCryptoContextSuite : public ::testing::Test
{
public:
	virtual ~EccCryptoContextSuite() {}

	EccCryptoContextSuite() : format(MslEncoderFormat::JSON) {}

protected:
	const MslEncoderFormat format;
};

/** Encrypt/decrypt mode unit tests. */
class DISABLED_EccCryptoContextSuite_EncryptDecrypt : public EccCryptoContextSuite
{
public:
	virtual ~DISABLED_EccCryptoContextSuite_EncryptDecrypt() {}
};

TEST_F(DISABLED_EccCryptoContextSuite_EncryptDecrypt, EncryptDecrypt)
{
    // Cannot perform ECIES encryption/decryption at the moment.
    EXPECT_TRUE(false) << "Test not yet implemented";   // FIXME TODO
}

/** Sign/verify mode unit tests. */
class DISABLED_EccCryptoContextSuite_SignVerify : public EccCryptoContextSuite
{
public:
	virtual ~DISABLED_EccCryptoContextSuite_SignVerify() {}

	DISABLED_EccCryptoContextSuite_SignVerify()
	{
		shared_ptr<MslContext> ctx = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
		encoder = ctx->getMslEncoderFactory();

//		final ECCurve curve = new ECCurve.Fp(EC_Q, EC_A, EC_B);
//		final AlgorithmParameterSpec paramSpec = new ECParameterSpec(curve, curve.decodePoint(EC_G.toByteArray()), EC_N);
//		final KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
//		keypairGenerator.initialize(paramSpec);
//		final KeyPair keypairA = keypairGenerator.generateKeyPair();
//		privateKeyA = keypairA.getPrivate();
//		publicKeyA = keypairA.getPublic();
//		keypairGenerator.initialize(paramSpec);
//		final KeyPair keypairB = keypairGenerator.generateKeyPair();
//		privateKeyB = keypairB.getPrivate();
//		publicKeyB = keypairB.getPublic();

		random = ctx->getRandom();
	}

protected:
    /** ECC public key A. */
    PublicKey publicKeyA;
    /** ECC private key A. */
    PrivateKey privateKeyA;
    /** ECC public key B. */
    PublicKey publicKeyB;
    /** ECC private key B. */
    PrivateKey privateKeyB;
    /** Random. */
    shared_ptr<IRandom> random;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
};

TEST_F(DISABLED_EccCryptoContextSuite_SignVerify, encryptDecrypt)
{
	shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
	random->nextBytes(*message);

	shared_ptr<EccCryptoContext> cryptoContext = make_shared<EccCryptoContext>(KEYPAIR_ID, privateKeyA, publicKeyA, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> ciphertext = cryptoContext->encrypt(message, encoder, format);
	EXPECT_TRUE(ciphertext);
	EXPECT_EQ(*message, *ciphertext);

	shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
	EXPECT_TRUE(plaintext);
	EXPECT_EQ(*message, *plaintext);
}

TEST_F(DISABLED_EccCryptoContextSuite_SignVerify, encryptNullPublic)
{
	shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
	random->nextBytes(*message);

	shared_ptr<EccCryptoContext> cryptoContext = make_shared<EccCryptoContext>(KEYPAIR_ID, privateKeyA, NULL_PUBKEY, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> ciphertext = cryptoContext->encrypt(message, encoder, format);
	EXPECT_TRUE(ciphertext);
	EXPECT_EQ(*message, *ciphertext);

	shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
	EXPECT_TRUE(plaintext);
	EXPECT_EQ(*message, *plaintext);
}

TEST_F(DISABLED_EccCryptoContextSuite_SignVerify, decryptNullPrivate)
{
	shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
	random->nextBytes(*message);

	shared_ptr<EccCryptoContext> cryptoContext = make_shared<EccCryptoContext>(KEYPAIR_ID, NULL_PRIVKEY, publicKeyA, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> ciphertext = cryptoContext->encrypt(message, encoder, format);
	EXPECT_TRUE(ciphertext);
	EXPECT_EQ(*message, *ciphertext);

	shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
	EXPECT_TRUE(plaintext);
	EXPECT_EQ(*message, *plaintext);
}

TEST_F(DISABLED_EccCryptoContextSuite_SignVerify, encryptDecryptIdMismatch)
{
	shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
	random->nextBytes(*message);

	shared_ptr<EccCryptoContext> cryptoContextA = make_shared<EccCryptoContext>(KEYPAIR_ID + "A", privateKeyA, publicKeyA, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> ciphertext = cryptoContextA->encrypt(message, encoder, format);
	EXPECT_TRUE(ciphertext);
	EXPECT_EQ(*message, *ciphertext);

	shared_ptr<EccCryptoContext> cryptoContextB = make_shared<EccCryptoContext>(KEYPAIR_ID + "B", privateKeyB, publicKeyB, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> plaintext = cryptoContextB->decrypt(ciphertext, encoder);
	EXPECT_TRUE(plaintext);
	EXPECT_EQ(*message, *plaintext);
}

TEST_F(DISABLED_EccCryptoContextSuite_SignVerify, encryptDecryptKeyMismatch)
{
	shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
	random->nextBytes(*message);

	shared_ptr<EccCryptoContext> cryptoContextA = make_shared<EccCryptoContext>(KEYPAIR_ID, privateKeyA, publicKeyA, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> ciphertext = cryptoContextA->encrypt(message, encoder, format);
	EXPECT_TRUE(ciphertext);
	EXPECT_EQ(*message, *ciphertext);

	shared_ptr<EccCryptoContext> cryptoContextB = make_shared<EccCryptoContext>(KEYPAIR_ID, privateKeyB, publicKeyB, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> plaintext = cryptoContextB->decrypt(ciphertext, encoder);
	EXPECT_TRUE(plaintext);
	EXPECT_EQ(*message, *plaintext);
}

TEST_F(DISABLED_EccCryptoContextSuite_SignVerify, signVerify)
{
	shared_ptr<ByteArray> messageA = make_shared<ByteArray>(32);
	random->nextBytes(*messageA);

	shared_ptr<EccCryptoContext> cryptoContext = make_shared<EccCryptoContext>(KEYPAIR_ID, privateKeyA, publicKeyA, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> signatureA = cryptoContext->sign(messageA, encoder, format);
	EXPECT_TRUE(signatureA);
	EXPECT_TRUE(signatureA->size() > 0);
	EXPECT_NE(*messageA, *signatureA);

	EXPECT_TRUE(cryptoContext->verify(messageA, signatureA, encoder));

	shared_ptr<ByteArray> messageB = make_shared<ByteArray>(32);
	random->nextBytes(*messageB);

	shared_ptr<ByteArray> signatureB = cryptoContext->sign(messageB, encoder, format);
	EXPECT_TRUE(signatureB->size() > 0);
	EXPECT_NE(*signatureA, *signatureB);

	EXPECT_TRUE(cryptoContext->verify(messageB, signatureB, encoder));
	EXPECT_FALSE(cryptoContext->verify(messageB, signatureA, encoder));
}

TEST_F(DISABLED_EccCryptoContextSuite_SignVerify, signVerifyContextMismatch)
{
	shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
	random->nextBytes(*message);

	shared_ptr<EccCryptoContext> cryptoContextA = make_shared<EccCryptoContext>(KEYPAIR_ID, privateKeyA, publicKeyA, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> signature = cryptoContextA->sign(message, encoder, format);

	shared_ptr<EccCryptoContext> cryptoContextB = make_shared<EccCryptoContext>(KEYPAIR_ID, privateKeyB, publicKeyB, Mode::SIGN_VERIFY);
	EXPECT_FALSE(cryptoContextB->verify(message, signature, encoder));
}

TEST_F(DISABLED_EccCryptoContextSuite_SignVerify, signNullPrivate)
{
	shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
	random->nextBytes(*message);

	shared_ptr<EccCryptoContext> cryptoContext = make_shared<EccCryptoContext>(KEYPAIR_ID, NULL_PRIVKEY, publicKeyA, Mode::SIGN_VERIFY);
	try {
		cryptoContext->sign(message, encoder, format);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::SIGN_NOT_SUPPORTED, e.getError());
	}
}

TEST_F(DISABLED_EccCryptoContextSuite_SignVerify, verifyNullPublic)
{
	shared_ptr<ByteArray> message = make_shared<ByteArray>(32);
	random->nextBytes(*message);

	shared_ptr<EccCryptoContext> cryptoContext = make_shared<EccCryptoContext>(KEYPAIR_ID, privateKeyA, NULL_PUBKEY, Mode::SIGN_VERIFY);
	shared_ptr<ByteArray> signature = cryptoContext->sign(message, encoder, format);
	try {
		cryptoContext->verify(message, signature, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::VERIFY_NOT_SUPPORTED, e.getError());
	}
}

}}} // namespace netflix::msl::crypto
