/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
#include <crypto/JsonWebEncryptionCryptoContext.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncoderUtils.h>
#include <io/MslArray.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <util/MockMslContext.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <memory>
#include <vector>

#include "../util/MslTestUtils.h"

using namespace std;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace crypto {

using CekCryptoContext = JsonWebEncryptionCryptoContext::CekCryptoContext;
using Encryption = JsonWebEncryptionCryptoContext::Encryption;
using Format = JsonWebEncryptionCryptoContext::Format;

namespace {

/** JSON key recipients. */
const string KEY_RECIPIENTS = "recipients";
/** JSON key header. */
const string KEY_HEADER = "header";
/** JSON key encrypted key. */
const string KEY_ENCRYPTED_KEY = "encrypted_key";
/** JSON key integrity value. */
const string KEY_INTEGRITY_VALUE = "integrity_value";
/** JSON key initialization vector. */
const string KEY_INITIALIZATION_VECTOR = "initialization_vector";
/** JSON key ciphertext. */
const string KEY_CIPHERTEXT = "ciphertext";

/** JSON key wrap algorithm. */
const string KEY_ALGORITHM = "alg";
/** JSON key encryption algorithm. */
const string KEY_ENCRYPTION = "enc";

/** Compact serialization header part index. */
const uint8_t HEADER_INDEX = 0;
/** Compact serialization encrypted content encryption key part index. */
const uint8_t ECEK_INDEX = 1;
/** Compact serialization initialization vector part index. */
const uint8_t IV_INDEX = 2;
/** Compact serialization ciphertext part index. */
const uint8_t CIPHERTEXT_INDEX = 3;
/** Compact serialization authentication tag part index. */
const uint8_t AUTHENTICATION_TAG_INDEX = 4;

/** String 'x' Base64 URL encoded. */
const string XB64 = *MslEncoderUtils::b64urlEncode(make_shared<string>("x"));   // FIXME: static init won't work

/**
 * Replace one part of the provided compact serialization with a specified
 * value.
 *
 * @param serialization compact serialization.
 * @param part zero-based part number to replace.
 * @param value Base64-encoded replacement value.
 * @return the modified compact serialization.
 */
shared_ptr<ByteArray> replace(shared_ptr<ByteArray> serialization, const uint8_t part, const string& value)
{
    string s(serialization->begin(), serialization->end()); // make a copy because we are being destructive
    vector<string> parts;
    size_t pos = 0;
    string token;
    while ((pos = s.find(".")) != std::string::npos) {
        token = s.substr(0, pos);
        parts.push_back(token);
        s.erase(0, pos + 1);
    }
    assert(part < parts.size());
	parts[part] = value;
	stringstream ss(parts[0]);
	for (size_t i = 1; i < parts.size(); ++i)
		ss << "." << parts[i];
	const string result = ss.str();
	return make_shared<ByteArray>(result.begin(), result.end());
}

shared_ptr<ByteArray> replace(shared_ptr<ByteArray> serialization, const uint8_t part, shared_ptr<string> value)
{
    return replace(serialization, part, *value);
}

/**
 * Return the requested value of the provided JSON serialization.
 *
 * @param encoder MSL encoder factory.
 * @param serialization JSON serialization.
 * @param key JSON key.
 * @return the requested Base64-encoded value.
 * @throws MslEncoderException if there is an error parsing the serialization.
 */
shared_ptr<string> get(shared_ptr<MslEncoderFactory> encoder, shared_ptr<ByteArray> serialization, const string& key)
{
	shared_ptr<MslObject> serializationMo = encoder->parseObject(serialization);
	shared_ptr<MslArray> recipients = serializationMo->getMslArray(KEY_RECIPIENTS);
	shared_ptr<MslObject> recipient = recipients->getMslObject(0, encoder);
    if (KEY_HEADER == key ||
        KEY_ENCRYPTED_KEY == key ||
        KEY_INTEGRITY_VALUE == key)
    {
        return make_shared<string>(recipient->getString(key));
    }
    if (KEY_INITIALIZATION_VECTOR == key ||
        KEY_CIPHERTEXT == key)
    {
        return make_shared<string>(serializationMo->getString(key));
    }
    stringstream ss;
    ss << "Unknown JSON key: " << key;
    throw IllegalArgumentException(ss.str());
}

/**
 * Replace one part of the provided JSON serialization with a specified
 * value.
 *
 * @param encoder MSL encoder factory.
 * @param serialization JSON serialization.
 * @param key JSON key.
 * @param value replacement value.
 * @return the modified JSON serialization.
 * @throws MslEncoderException if there is an error modifying the JSON
 *         serialization.
 */
shared_ptr<ByteArray> replace(shared_ptr<MslEncoderFactory> encoder, shared_ptr<ByteArray> serialization, const string& key, const Variant& value)
{
    shared_ptr<MslObject> serializationMo = encoder->parseObject(serialization);
    shared_ptr<MslArray> recipients = serializationMo->getMslArray(KEY_RECIPIENTS);
    shared_ptr<MslObject> recipient = recipients->getMslObject(0, encoder);
    if (KEY_RECIPIENTS == key) {
        // Return immediately after replacing because this creates a
        // malformed serialization.
        serializationMo->put(KEY_RECIPIENTS, value);
        return encoder->encodeObject(serializationMo, MslEncoderFormat::JSON);
    }
    if (KEY_HEADER == key ||
        KEY_ENCRYPTED_KEY == key ||
        KEY_INTEGRITY_VALUE == key)
    {
        recipient->put(key, value);
    } else if (KEY_INITIALIZATION_VECTOR == key ||
               KEY_CIPHERTEXT == key)
    {
        serializationMo->put(key, value);
    } else {
        stringstream ss;
        ss << "Unknown JSON key: " << key;
        throw IllegalArgumentException(ss.str());
    }
    recipients->put(0, recipient);
    serializationMo->put(KEY_RECIPIENTS, recipients);
    return encoder->encodeObject(serializationMo, MslEncoderFormat::JSON);
}
template <typename T>
shared_ptr<ByteArray> replace(shared_ptr<MslEncoderFactory> encoder, shared_ptr<ByteArray> serialization, const string& key, const T& value)
{
	Variant var = VariantFactory::create<T>(value);
	return replace(encoder, serialization, key, var);
}
shared_ptr<ByteArray> replace(shared_ptr<MslEncoderFactory> encoder, shared_ptr<ByteArray> serialization, const string& key, shared_ptr<string> value)
{
	return replace(encoder, serialization, key, *value);
}

/**
 * Remove one part of the provided JSON serialization.
 *
 * @param encoder MSL encoder factory.
 * @param serialization JSON serialization.
 * @param key JSON key.
 * @return the modified JSON serialization.
 * @throws MslEncoderException if there is an error modifying the JSON
 *         serialization.
 */
shared_ptr<ByteArray> remove(shared_ptr<MslEncoderFactory> encoder, shared_ptr<ByteArray> serialization, const string& key)
{
    shared_ptr<MslObject> serializationMo = encoder->parseObject(serialization);
    shared_ptr<MslArray> recipients = serializationMo->getMslArray(KEY_RECIPIENTS);
    shared_ptr<MslObject> recipient = recipients->getMslObject(0, encoder);
    if (KEY_RECIPIENTS == key) {
        // Return immediately after removing because this creates a
        // malformed serialization.
        serializationMo->remove(KEY_RECIPIENTS);
        return encoder->encodeObject(serializationMo, MslEncoderFormat::JSON);
    }
    if (KEY_HEADER == key ||
        KEY_ENCRYPTED_KEY == key ||
        KEY_INTEGRITY_VALUE == key)
    {
        recipient->remove(key);
    } else if (KEY_INITIALIZATION_VECTOR == key ||
               KEY_CIPHERTEXT == key)
    {
        serializationMo->remove(key);
    } else {
        stringstream ss;
        ss << "Unknown JSON key: " << key;
        throw IllegalArgumentException(ss.str());
    }
    recipients->put(0, recipient);
    serializationMo->put(KEY_RECIPIENTS, recipients);
    return encoder->encodeObject(serializationMo, MslEncoderFormat::JSON);
}

} // namespace anonymous

// This class ensures stuff shared between suites is only created once, since
// key generation can be expensive.
class TestSingleton
{
public:
    static shared_ptr<MockMslContext> getMockMslContext() {
        static shared_ptr<MockMslContext> theInstance;
        if (!theInstance)
            theInstance = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
        return theInstance;
    }
    static PublicKey getPublicKey() { return keyInstance().first; }
    static PrivateKey getPrivateKey() { return keyInstance().second; }
private:
    static pair<PublicKey,PrivateKey> keyInstance() {
        static pair<PublicKey,PrivateKey> theInstance;
        if (theInstance.first.isNull())
            theInstance = MslTestUtils::generateRsaKeys(JcaAlgorithm::SHA256withRSA, 512);
        return theInstance;
    }
};

/**
 * JSON Web Encryption crypto context unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class JsonWebEncryptionCryptoContextSuite : public ::testing::Test
{
public:
	virtual ~JsonWebEncryptionCryptoContextSuite() {}

	JsonWebEncryptionCryptoContextSuite()
		: format(MslEncoderFormat::JSON)
		, ctx(TestSingleton::getMockMslContext())
		, encoder(ctx->getMslEncoderFactory())
		, random(ctx->getRandom())
	{
		data = make_shared<ByteArray>(1024);
		random->nextBytes(*data);

		const PrivateKey privateKey = TestSingleton::getPrivateKey();
		const PublicKey publicKey = TestSingleton::getPublicKey();
        rsaCryptoContext = make_shared<JsonWebEncryptionCryptoContext::RsaOaepCryptoContext>(privateKey, publicKey);

        shared_ptr<ByteArray> keydata = make_shared<ByteArray>(16);
        random->nextBytes(*keydata);
        const SecretKey wrappingKey(keydata, JcaAlgorithm::AESKW);
        aesCryptoContext = make_shared<JsonWebEncryptionCryptoContext::AesKwCryptoContext>(wrappingKey);
	}

protected:
	/** MSL encoder format. */
	const MslEncoderFormat format;
    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    /** Random. */
    shared_ptr<IRandom> random;
    /** Random data. */
    shared_ptr<ByteArray> data;
    /** RSA-OAEP content encryption key crypto context. */
    shared_ptr<CekCryptoContext> rsaCryptoContext;
    /** AES key wrap content encryption key crypto context. */
    shared_ptr<CekCryptoContext> aesCryptoContext;
};

/** RSA-OAEP compact serialization unit tests. */

/** RSA-OAEP Compact Serialization. */
class DISABLED_RsaOaepCompactSerialization : public JsonWebEncryptionCryptoContextSuite
{
public:
	virtual ~DISABLED_RsaOaepCompactSerialization() {}

	DISABLED_RsaOaepCompactSerialization() {
		cryptoContext = make_shared<JsonWebEncryptionCryptoContext>(ctx, rsaCryptoContext, Encryption::A128GCM, Format::JWE_CS);
	}

protected:
	shared_ptr<ICryptoContext> cryptoContext;
//	static shared_ptr<ByteArray> RFC_MODULUS;  FIXME
//	static shared_ptr<ByteArray> RFC_PUBLIC_EXPONENT;
//	static shared_ptr<ByteArray> RFC_PRIVATE_EXPONENT;
//	static shared_ptr<ByteArray> RFC_SERIALIZATION;
//	static shared_ptr<ByteArray> RFC_PLAINTEXT;
};

namespace {

const string RFC_SERIALIZATION_STR =
	"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
	"M2XxpbORKezKSzzQL_95-GjiudRBTqn_omS8z9xgoRb7L0Jw5UsEbxmtyHn2T71m"
	"rZLkjg4Mp8gbhYoltPkEOHvAopz25-vZ8C2e1cOaAo5WPcbSIuFcB4DjBOM3t0UA"
	"O6JHkWLuAEYoe58lcxIQneyKdaYSLbV9cKqoUoFQpvKWYRHZbfszIyfsa18rmgTj"
	"zrtLDTPnc09DSJE24aQ8w3i8RXEDthW9T1J6LsTH_vwHdwUgkI-tC2PNeGrnM-dN"
	"SfzF3Y7-lwcGy0FsdXkPXytvDV7y4pZeeUiQ-0VdibIN2AjjfW60nfrPuOjepMFG"
	"6BBBbR37pHcyzext9epOAQ."
	"48V1_ALb6US04U3b."
	"_e21tGGhac_peEFkLXr2dMPUZiUkrw."
	"7V5ZDko0v_mf2PAc4JMiUg";
const string RFC_PLAINTEXT_STR = "Live long and prosper.";

} // namespace anonymous

#if 0  //FIXME
/** RFC RSA-OAEP keypair modulus. */
shared_ptr<ByteArray> RsaOaepCompactSerialization::RFC_MODULUS = make_shared<ByteArray>({
    161, 168, 84, 34, 133, 176, 208, 173,
    46, 176, 163, 110, 57, 30, 135, 227,
    9, 31, 226, 128, 84, 92, 116, 241,
    70, 248, 27, 227, 193, 62, 5, 91,
    241, 145, 224, 205, 141, 176, 184, 133,
    239, 43, 81, 103, 9, 161, 153, 157,
    179, 104, 123, 51, 189, 34, 152, 69,
    97, 69, 78, 93, 140, 131, 87, 182,
    169, 101, 92, 142, 3, 22, 167, 8,
    212, 56, 35, 79, 210, 222, 192, 208,
    252, 49, 109, 138, 173, 253, 210, 166,
    201, 63, 102, 74, 5, 158, 41, 90,
    144, 108, 160, 79, 10, 89, 222, 231,
    172, 31, 227, 197, 0, 19, 72, 81,
    138, 78, 136, 221, 121, 118, 196, 17,
    146, 10, 244, 188, 72, 113, 55, 221,
    162, 217, 171, 27, 57, 233, 210, 101,
    236, 154, 199, 56, 138, 239, 101, 48,
    198, 186, 202, 160, 76, 111, 234, 71,
    57, 183, 5, 211, 171, 136, 126, 64,
    40, 75, 58, 89, 244, 254, 107, 84,
    103, 7, 236, 69, 163, 18, 180, 251,
    58, 153, 46, 151, 174, 12, 103, 197,
    181, 161, 162, 55, 250, 235, 123, 110,
    17, 11, 158, 24, 47, 133, 8, 199,
    235, 107, 126, 130, 246, 73, 195, 20,
    108, 202, 176, 214, 187, 45, 146, 182,
    118, 54, 32, 200, 61, 201, 71, 243,
    1, 255, 131, 84, 37, 111, 211, 168,
    228, 45, 192, 118, 27, 197, 235, 232,
    36, 10, 230, 248, 190, 82, 182, 140,
    35, 204, 108, 190, 253, 186, 186, 27 });
/** RFC RSA-OAEP keypair exponent. */
shared_ptr<ByteArray> RsaOaepCompactSerialization::RFC_PUBLIC_EXPONENT = make_shared<ByteArray>({ 1, 0, 1 });
/** RFC RSA-OAEP private exponent. */
shared_ptr<ByteArray> RsaOaepCompactSerialization::RFC_PRIVATE_EXPONENT = make_shared<ByteArray>({
    144, 183, 109, 34, 62, 134, 108, 57,
    44, 252, 10, 66, 73, 54, 16, 181,
    233, 92, 54, 219, 101, 42, 35, 178,
    63, 51, 43, 92, 119, 136, 251, 41,
    53, 23, 191, 164, 164, 60, 88, 227,
    229, 152, 228, 213, 149, 228, 169, 237,
    104, 71, 151, 75, 88, 252, 216, 77,
    251, 231, 28, 97, 88, 193, 215, 202,
    248, 216, 121, 195, 211, 245, 250, 112,
    71, 243, 61, 129, 95, 39, 244, 122,
    225, 217, 169, 211, 165, 48, 253, 220,
    59, 122, 219, 42, 86, 223, 32, 236,
    39, 48, 103, 78, 122, 216, 187, 88,
    176, 89, 24, 1, 42, 177, 24, 99,
    142, 170, 1, 146, 43, 3, 108, 64,
    194, 121, 182, 95, 187, 134, 71, 88,
    96, 134, 74, 131, 167, 69, 106, 143,
    121, 27, 72, 44, 245, 95, 39, 194,
    179, 175, 203, 122, 16, 112, 183, 17,
    200, 202, 31, 17, 138, 156, 184, 210,
    157, 184, 154, 131, 128, 110, 12, 85,
    195, 122, 241, 79, 251, 229, 183, 117,
    21, 123, 133, 142, 220, 153, 9, 59,
    57, 105, 81, 255, 138, 77, 82, 54,
    62, 216, 38, 249, 208, 17, 197, 49,
    45, 19, 232, 157, 251, 131, 137, 175,
    72, 126, 43, 229, 69, 179, 117, 82,
    157, 213, 83, 35, 57, 210, 197, 252,
    171, 143, 194, 11, 47, 163, 6, 253,
    75, 252, 96, 11, 187, 84, 130, 210,
    7, 121, 78, 91, 79, 57, 251, 138,
    132, 220, 60, 224, 173, 56, 224, 201 });

/** RFC RSA-OAEP wrapped compact serialization. */
shared_ptr<ByteArray> RsaOaepCompactSerialization::RFC_SERIALIZATION = make_shared<ByteArray>(RFC_SERIALIZATION_STR.begin(), RFC_SERIALIZATION_STR.end());
/** RFC RSA-OAEP plaintext. */
shared_ptr<ByteArray> RsaOaepCompactSerialization::RFC_PLAINTEXT = make_shared<ByteArray>(RFC_PLAINTEXT_STR.begin(), RFC_PLAINTEXT_STR.end());

/*{
    76, 105, 118, 101, 32, 108, 111, 110,
    103, 32, 97, 110, 100, 32, 112, 114,
    111, 115, 112, 101, 114, 46 };*/
#endif

TEST_F(DISABLED_RsaOaepCompactSerialization, wrapUnwrap)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	EXPECT_TRUE(wrapped);
	EXPECT_NE(*data, *wrapped);
	shared_ptr<ByteArray> unwrapped = cryptoContext->unwrap(wrapped, encoder);
	EXPECT_EQ(*data, *unwrapped);
}

TEST_F(DISABLED_RsaOaepCompactSerialization, wrapUnwrapShort)
{
	shared_ptr<ByteArray> data = make_shared<ByteArray>(3);
	random->nextBytes(*data);

	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	EXPECT_TRUE(wrapped);
	EXPECT_NE(*data, *wrapped);
	shared_ptr<ByteArray> unwrapped = cryptoContext->unwrap(wrapped, encoder);
	EXPECT_EQ(*data, *unwrapped);
}

TEST_F(DISABLED_RsaOaepCompactSerialization, wrapUnwrapRfc)
{
    //FIXME
    EXPECT_TRUE(false);
#if 0
	final BigInteger modulus = new BigInteger(1, RFC_MODULUS);
	final BigInteger publicExponent = new BigInteger(1, RFC_PUBLIC_EXPONENT);
	final BigInteger privateExponent = new BigInteger(1, RFC_PRIVATE_EXPONENT);
	final KeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
	final KeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
	final KeyFactory factory = KeyFactory.getInstance("RSA");
	const PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
	const PublicKey publicKey = factory.generatePublic(publicKeySpec);

	shared_ptr<CekCryptoContext> cekCryptoContext = make_shared<JsonWebEncryptionCryptoContext::RsaOaepCryptoContext>(privateKey, publicKey);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<JsonWebEncryptionCryptoContext>(ctx, cekCryptoContext, Encryption::A256GCM, Format::JWE_CS);
	shared_ptr<ByteArray> plaintext = cryptoContext->unwrap(RFC_SERIALIZATION, encoder);
	EXPECT_TRUE(plaintext);
	EXPECT_EQ(*RFC_PLAINTEXT, *plaintext);
#endif
}

TEST_F(DISABLED_RsaOaepCompactSerialization, invalidSerialization)
{
    shared_ptr<ByteArray> wrapped = make_shared<ByteArray>();
    wrapped->push_back('x');
	try {
		cryptoContext->unwrap(wrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, shortSerialization)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	const string serialization(wrapped->begin(), wrapped->end());
	const string shortSerialization = serialization.substr(0, serialization.find_last_of('.'));
	shared_ptr<ByteArray> shortWrapped = make_shared<ByteArray>(shortSerialization.begin(), shortSerialization.end());

	try {
		cryptoContext->unwrap(shortWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, longSerialization)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> longWrapped = make_shared<ByteArray>(wrapped->begin(), wrapped->end());
	longWrapped->insert(longWrapped->end(), wrapped->begin(), wrapped->end());

	try {
		cryptoContext->unwrap(longWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, missingHeader)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, "");

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, invalidHeader)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, missingCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, ECEK_INDEX, "");
	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, invalidCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, ECEK_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::CIPHERTEXT_BAD_PADDING, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, missingIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, IV_INDEX, "");

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, invalidIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, IV_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, missingCiphertext)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, CIPHERTEXT_INDEX, "");

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, invalidCiphertext)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, CIPHERTEXT_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, missingAuthenticationTag)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, "");

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, invalidAuthenticationTag)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_ALGORITHM_PARAMS, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, wrongAuthenticationTag)
{
	shared_ptr<ByteArray> at = make_shared<ByteArray>(16);
	random->nextBytes(*at);

	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, MslEncoderUtils::b64urlEncode(at));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, missingAlgorithm)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> wrappedB64 = make_shared<string>(wrapped->begin(), wrapped->end());
	shared_ptr<string> headerB64 = make_shared<string>(wrappedB64->substr(0, wrappedB64->find('.')));
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->remove(KEY_ALGORITHM);

	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, invalidAlgorithm)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> wrappedB64 = make_shared<string>(wrapped->begin(), wrapped->end());
	shared_ptr<string> headerB64 = make_shared<string>(wrappedB64->substr(0, wrappedB64->find('.')));
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->put<string>(KEY_ALGORITHM, "x");
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, missingEncryption)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> wrappedB64 = make_shared<string>(wrapped->begin(), wrapped->end());
	shared_ptr<string> headerB64 = make_shared<string>(wrappedB64->substr(0, wrappedB64->find('.')));
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->remove(KEY_ENCRYPTION);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, invalidEncryption)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> wrappedB64 = make_shared<string>(wrapped->begin(), wrapped->end());
	shared_ptr<string> headerB64 = make_shared<string>(wrappedB64->substr(0, wrappedB64->find('.')));
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->put<string>(KEY_ENCRYPTION, "x");
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, badCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> ecek = make_shared<ByteArray>(137);
	random->nextBytes(*ecek);
	shared_ptr<ByteArray> badWrapped = replace(wrapped, ECEK_INDEX, MslEncoderUtils::b64urlEncode(ecek));

	try {
		cryptoContext->unwrap(badWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, badIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> iv = make_shared<ByteArray>(31);
	random->nextBytes(*iv);
	shared_ptr<ByteArray> badWrapped = replace(wrapped, IV_INDEX, MslEncoderUtils::b64urlEncode(iv));

	try {
		cryptoContext->unwrap(badWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, wrongCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);

	shared_ptr<ByteArray> cek = make_shared<ByteArray>(16);
	random->nextBytes(*cek);
	shared_ptr<ByteArray> ecek = rsaCryptoContext->encrypt(cek, encoder, format);

	shared_ptr<ByteArray> wrongWrapped = replace(wrapped, ECEK_INDEX, MslEncoderUtils::b64urlEncode(ecek));

	try {
		cryptoContext->unwrap(wrongWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepCompactSerialization, wrongIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> iv = make_shared<ByteArray>(16);
	random->nextBytes(*iv);
	shared_ptr<ByteArray> wrongWrapped = replace(wrapped, IV_INDEX, MslEncoderUtils::b64urlEncode(iv));

	try {
		cryptoContext->unwrap(wrongWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

    /** RSA-OAEP JSON serialization unit tests. */
    class DISABLED_RsaOaepJsonSerialization : public JsonWebEncryptionCryptoContextSuite
	{
	public:
    	virtual ~DISABLED_RsaOaepJsonSerialization() {}

    	DISABLED_RsaOaepJsonSerialization()
    		: cryptoContext(make_shared<JsonWebEncryptionCryptoContext>(ctx, rsaCryptoContext, Encryption::A128GCM, Format::JWE_JS))
    	{}

	protected:
    	shared_ptr<ICryptoContext> cryptoContext;
	};

TEST_F(DISABLED_RsaOaepJsonSerialization, wrapUnwrap)
{
            shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
            EXPECT_TRUE(wrapped);
            EXPECT_NE(*data, *wrapped);
            shared_ptr<ByteArray> unwrapped = cryptoContext->unwrap(wrapped, encoder);
            EXPECT_EQ(*data, *unwrapped);
        }

TEST_F(DISABLED_RsaOaepJsonSerialization, wrapUnwrapShort)
{
            shared_ptr<ByteArray> data = make_shared<ByteArray>(3);
            random->nextBytes(*data);

            shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
            EXPECT_TRUE(wrapped);
            EXPECT_NE(*data, *wrapped);
            shared_ptr<ByteArray> unwrapped = cryptoContext->unwrap(wrapped, encoder);
            EXPECT_EQ(*data, *unwrapped);
        }

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidSerialization)
{
	shared_ptr<ByteArray> wrapped = make_shared<ByteArray>();
	wrapped->push_back('x');
	try {
		cryptoContext->unwrap(wrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, missingRecipients)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_RECIPIENTS);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidRecipients)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_RECIPIENTS, string("x"));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, missingRecipient)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_RECIPIENTS, encoder->createArray());

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidRecipient)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	vector<Variant> varvec;
	varvec.push_back(VariantFactory::create<string>("x"));
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_RECIPIENTS, encoder->createArray(varvec));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, missingHeader)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_HEADER);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidHeader)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, missingCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_ENCRYPTED_KEY);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_ENCRYPTED_KEY, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::CIPHERTEXT_BAD_PADDING, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, missingIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_INITIALIZATION_VECTOR);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_INITIALIZATION_VECTOR, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, missingCiphertext)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_CIPHERTEXT);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidCiphertext)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_CIPHERTEXT, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, missingAuthenticationTag)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_INTEGRITY_VALUE);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidAuthenticationTag)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_INTEGRITY_VALUE, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_ALGORITHM_PARAMS, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, wrongAuthenticationTag)
{
	shared_ptr<ByteArray> at = make_shared<ByteArray>(16);
	random->nextBytes(*at);

	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_INTEGRITY_VALUE, MslEncoderUtils::b64urlEncode(at));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, missingAlgorithm)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> headerB64 = get(encoder, wrapped, KEY_HEADER);
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->remove(KEY_ALGORITHM);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidAlgorithm)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> headerB64 = get(encoder, wrapped, KEY_HEADER);
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->put<string>(KEY_ALGORITHM, "x");
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, missingEncryption)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> headerB64 = get(encoder, wrapped, KEY_HEADER);
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->remove(KEY_ENCRYPTION);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, invalidEncryption)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> headerB64 = get(encoder, wrapped, KEY_HEADER);
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->put<string>(KEY_ENCRYPTION, "x");
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, badCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> ecek = make_shared<ByteArray>(137);
	random->nextBytes(*ecek);
	shared_ptr<ByteArray> badWrapped = replace(encoder, wrapped, KEY_ENCRYPTED_KEY, MslEncoderUtils::b64urlEncode(ecek));

	try {
		cryptoContext->unwrap(badWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, badIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> iv = make_shared<ByteArray>(31);
	random->nextBytes(*iv);
	shared_ptr<ByteArray> badWrapped = replace(encoder, wrapped, KEY_INITIALIZATION_VECTOR, MslEncoderUtils::b64urlEncode(iv));

	try {
		cryptoContext->unwrap(badWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, wrongCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);

	shared_ptr<ByteArray> cek = make_shared<ByteArray>(16);
	random->nextBytes(*cek);
	shared_ptr<ByteArray> ecek = rsaCryptoContext->encrypt(cek, encoder, format);

	shared_ptr<ByteArray> wrongWrapped = replace(encoder, wrapped, KEY_ENCRYPTED_KEY, MslEncoderUtils::b64urlEncode(ecek));

	try {
		cryptoContext->unwrap(wrongWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_RsaOaepJsonSerialization, wrongIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> iv = make_shared<ByteArray>(16);
	random->nextBytes(*iv);
	shared_ptr<ByteArray> wrongWrapped = replace(encoder, wrapped, KEY_INITIALIZATION_VECTOR, MslEncoderUtils::b64urlEncode(iv));

	try {
		cryptoContext->unwrap(wrongWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

/** AES key wrap compact serialization unit tests. */

class DISABLED_AesKwCompactSerialization : public JsonWebEncryptionCryptoContextSuite
{
public:
	virtual ~DISABLED_AesKwCompactSerialization() {}

	DISABLED_AesKwCompactSerialization()
		: cryptoContext(make_shared<JsonWebEncryptionCryptoContext>(ctx, aesCryptoContext, Encryption::A256GCM, Format::JWE_CS))
	{}

protected:
	shared_ptr<ICryptoContext> cryptoContext;
//	static shared_ptr<ByteArray> RFC_KEY;
//	static shared_ptr<ByteArray> RFC_SERIALIZATION;
//	static shared_ptr<ByteArray> RFC_PLAINTEXT;
};

namespace {

//const string RFC_SERIALIZATION_STR =   // FIXME
//	"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0."
//	"pP_7AUDIQcgixVGPK9PwJr-htXV3RCxQ."
//	"_dxQGaaYsqhhY0NZ."
//	"4wxZhLkQ-F2RVzWCX3M-aIpgbUd806VnymMVwQTiVOX-apDxJ1aUhKBoWOjkbVUH"
//	"VlCGaqYYXMfSvJm72kXj."
//	"miNQayWUUQZnBDzOq6VxQw";
//
//const string RFC_PLAINTEXT_STR = "The true sign of intelligence is not knowledge but imagination.";

} // namespace anonymous

#if 0 // FIXME
/** RFC AES key wrap symmetric key. */
shared_ptr<ByteArray> DISABLED_AesKwCompactSerialization::RFC_KEY = make_shared<ByteArray>({
	25, 172, 32, 130, 225, 114, 26, 181,
	138, 106, 254, 192, 95, 133, 74, 82 });

/** RFC AES key wrap wrapped compact serialization. */
shared_ptr<ByteArray> DISABLED_AesKwCompactSerialization::RFC_SERIALIZATION = make_shared<ByteArray>(RFC_SERIALIZATION_STR.begin(), RFC_SERIALIZATION_STR.end());
/** RFC AES key wrap plaintext. */
shared_ptr<ByteArray> DISABLED_AesKwCompactSerialization::RFC_PLAINTEXT = make_shared<ByteArray>(RFC_PLAINTEXT_STR.begin(), RFC_PLAINTEXT_STR.end());
#endif

TEST_F(DISABLED_AesKwCompactSerialization, wrapUnwrap)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	EXPECT_TRUE(wrapped);
	EXPECT_NE(*data, *wrapped);
	shared_ptr<ByteArray> unwrapped = cryptoContext->unwrap(wrapped, encoder);
	EXPECT_EQ(*data, *unwrapped);
}

TEST_F(DISABLED_AesKwCompactSerialization, wrapUnwrapShort)
{
	shared_ptr<ByteArray> data = make_shared<ByteArray>(3);
	random->nextBytes(*data);

	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	EXPECT_TRUE(wrapped);
	EXPECT_NE(*data, *wrapped);
	shared_ptr<ByteArray> unwrapped = cryptoContext->unwrap(wrapped, encoder);
	EXPECT_EQ(*data, *unwrapped);
}

#if 0  // FIXME TODO
TEST_F(DISABLED_AesKwCompactSerialization, wrapUnwrapRfc)
{
	const SecretKey key(RFC_KEY, JcaAlgorithm::AESKW);
	shared_ptr<CekCryptoContext> cekCryptoContext = make_shared<JsonWebEncryptionCryptoContext::AesKwCryptoContext>(key);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<JsonWebEncryptionCryptoContext>(ctx, cekCryptoContext, Encryption::A128GCM, Format::JWE_CS);

	shared_ptr<ByteArray> plaintext = cryptoContext->unwrap(RFC_SERIALIZATION, encoder);
	EXPECT_TRUE(plaintext);
	EXPECT_EQ(*RFC_PLAINTEXT, *plaintext);
}
#endif

TEST_F(DISABLED_AesKwCompactSerialization, invalidSerialization)
{
	shared_ptr<ByteArray> wrapped = make_shared<ByteArray>();
	wrapped->push_back('x');
	try {
		cryptoContext->unwrap(wrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, shortSerialization)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> serialization = make_shared<string>(wrapped->begin(), wrapped->end());
	shared_ptr<string> shortSerialization = make_shared<string>(serialization->substr(0, serialization->find_last_of('.')));
	shared_ptr<ByteArray> shortWrapped = make_shared<ByteArray>(shortSerialization->begin(), shortSerialization->end());

	try {
		cryptoContext->unwrap(shortWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, longSerialization)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> longWrapped = make_shared<ByteArray>(wrapped->begin(), wrapped->end());
	longWrapped->insert(longWrapped->end(), wrapped->begin(), wrapped->end());

	try {
		cryptoContext->unwrap(longWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, missingHeader)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, "");

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, invalidHeader)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, missingCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, ECEK_INDEX, "");

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, invalidCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, ECEK_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_SYMMETRIC_KEY, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, missingIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, IV_INDEX, "");

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, invalidIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, IV_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, missingCiphertext)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, CIPHERTEXT_INDEX, "");

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, invalidCiphertext)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, CIPHERTEXT_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, missingAuthenticationTag)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, "");

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, invalidAuthenticationTag)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_ALGORITHM_PARAMS, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, wrongAuthenticationTag)
{
	shared_ptr<ByteArray> at = make_shared<ByteArray>(16);
	random->nextBytes(*at);

	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, AUTHENTICATION_TAG_INDEX, MslEncoderUtils::b64urlEncode(at));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, missingAlgorithm)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> wrappedB64 = make_shared<string>(wrapped->begin(), wrapped->end());
	shared_ptr<string> headerB64 = make_shared<string>(wrappedB64->substr(0, wrappedB64->find('.')));
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->remove(KEY_ALGORITHM);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, invalidAlgorithm)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> wrappedB64 = make_shared<string>(wrapped->begin(), wrapped->end());
	shared_ptr<string> headerB64 = make_shared<string>(wrappedB64->substr(0, wrappedB64->find('.')));
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->put<string>(KEY_ALGORITHM, "x");
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, missingEncryption)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> wrappedB64 = make_shared<string>(wrapped->begin(), wrapped->end());
	shared_ptr<string> headerB64 = make_shared<string>(wrappedB64->substr(0, wrappedB64->find('.')));
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->remove(KEY_ENCRYPTION);
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, invalidEncryption)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> wrappedB64 = make_shared<string>(wrapped->begin(), wrapped->end());
	shared_ptr<string> headerB64 = make_shared<string>(wrappedB64->substr(0, wrappedB64->find('.')));
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->put<string>(KEY_ENCRYPTION, "x");
	shared_ptr<ByteArray> missingWrapped = replace(wrapped, HEADER_INDEX, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, badCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> ecek = make_shared<ByteArray>(137);
	random->nextBytes(*ecek);
	shared_ptr<ByteArray> badWrapped = replace(wrapped, ECEK_INDEX, MslEncoderUtils::b64urlEncode(ecek));

	try {
		cryptoContext->unwrap(badWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_SYMMETRIC_KEY, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, badIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> iv = make_shared<ByteArray>(31);
	random->nextBytes(*iv);
	shared_ptr<ByteArray> badWrapped = replace(wrapped, IV_INDEX, MslEncoderUtils::b64urlEncode(iv));

	try {
		cryptoContext->unwrap(badWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, wrongCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);

	shared_ptr<ByteArray> cek = make_shared<ByteArray>(16);
	random->nextBytes(*cek);
	shared_ptr<ByteArray> ecek = aesCryptoContext->encrypt(cek, encoder, format);

	shared_ptr<ByteArray> wrongWrapped = replace(wrapped, ECEK_INDEX, MslEncoderUtils::b64urlEncode(ecek));

	try {
		cryptoContext->unwrap(wrongWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_SYMMETRIC_KEY, e.getError());
	}
}

TEST_F(DISABLED_AesKwCompactSerialization, wrongIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> iv = make_shared<ByteArray>(16);
	random->nextBytes(*iv);
	shared_ptr<ByteArray> wrongWrapped = replace(wrapped, IV_INDEX, MslEncoderUtils::b64urlEncode(iv));

	try {
		cryptoContext->unwrap(wrongWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

    /** AES key wrap JSON serialization unit tests. */
    class DISABLED_AesKwJsonSerialization : public JsonWebEncryptionCryptoContextSuite
	{
	public:
    	virtual ~DISABLED_AesKwJsonSerialization() {}

    	DISABLED_AesKwJsonSerialization()
    		: cryptoContext(make_shared<JsonWebEncryptionCryptoContext>(ctx, aesCryptoContext, Encryption::A256GCM, Format::JWE_JS))
    	{}

	protected:
    	shared_ptr<ICryptoContext> cryptoContext;
	};

TEST_F(DISABLED_AesKwJsonSerialization, wrapUnwrap)
{
            shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
            EXPECT_TRUE(wrapped);
            EXPECT_NE(*data, *wrapped);
            shared_ptr<ByteArray> unwrapped = cryptoContext->unwrap(wrapped, encoder);
            EXPECT_EQ(*data, *unwrapped);
        }

TEST_F(DISABLED_AesKwJsonSerialization, wrapUnwrapShort)
{
            shared_ptr<ByteArray> data = make_shared<ByteArray>(3);
            random->nextBytes(*data);

            shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
            EXPECT_TRUE(wrapped);
            EXPECT_NE(*data, *wrapped);
            shared_ptr<ByteArray> unwrapped = cryptoContext->unwrap(wrapped, encoder);
            EXPECT_EQ(*data, *unwrapped);
        }

TEST_F(DISABLED_AesKwJsonSerialization, invalidSerialization)
{
	shared_ptr<ByteArray> wrapped = make_shared<ByteArray>();
	wrapped->push_back('x');
	try {
		cryptoContext->unwrap(wrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, missingRecipients)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_RECIPIENTS);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, invalidRecipients)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_RECIPIENTS, string("x"));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, missingRecipient)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_RECIPIENTS, encoder->createArray());

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, invalidRecipient)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
    vector<Variant> varvec;
    varvec.push_back(VariantFactory::create<string>("x"));
    shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_RECIPIENTS, encoder->createArray(varvec));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, missingHeader)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_HEADER);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, invalidHeader)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, missingCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_ENCRYPTED_KEY);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, invalidCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_ENCRYPTED_KEY, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_SYMMETRIC_KEY, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, missingIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_INITIALIZATION_VECTOR);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, invalidIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_INITIALIZATION_VECTOR, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, missingCiphertext)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_CIPHERTEXT);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, invalidCiphertext)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_CIPHERTEXT, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, missingAuthenticationTag)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = remove(encoder, wrapped, KEY_INTEGRITY_VALUE);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, invalidAuthenticationTag)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_INTEGRITY_VALUE, XB64);

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_ALGORITHM_PARAMS, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, wrongAuthenticationTag)
{
	shared_ptr<ByteArray> at = make_shared<ByteArray>(16);
	random->nextBytes(*at);

	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_INTEGRITY_VALUE, MslEncoderUtils::b64urlEncode(at));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, missingAlgorithm)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> headerB64 = get(encoder, wrapped, KEY_HEADER);
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->remove(KEY_ALGORITHM);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, invalidAlgorithm)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> headerB64 = get(encoder, wrapped, KEY_HEADER);
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->put<string>(KEY_ALGORITHM, "x");
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, missingEncryption)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> headerB64 = get(encoder, wrapped, KEY_HEADER);
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->remove(KEY_ENCRYPTION);
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, invalidEncryption)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<string> headerB64 = get(encoder, wrapped, KEY_HEADER);
	shared_ptr<MslObject> header = encoder->parseObject(MslEncoderUtils::b64urlDecode(headerB64));
	header->put<string>(KEY_ENCRYPTION, "x");
	shared_ptr<ByteArray> missingWrapped = replace(encoder, wrapped, KEY_HEADER, MslEncoderUtils::b64urlEncode(encoder->encodeObject(header, MslEncoderFormat::JSON)));

	try {
		cryptoContext->unwrap(missingWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_PARSE_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, badCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> ecek = make_shared<ByteArray>(137);
	random->nextBytes(*ecek);
	shared_ptr<ByteArray> badWrapped = replace(encoder, wrapped, KEY_ENCRYPTED_KEY, MslEncoderUtils::b64urlEncode(ecek));

	try {
		cryptoContext->unwrap(badWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_SYMMETRIC_KEY, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, badIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> iv = make_shared<ByteArray>(31);
	random->nextBytes(*iv);
	shared_ptr<ByteArray> badWrapped = replace(encoder, wrapped, KEY_INITIALIZATION_VECTOR, MslEncoderUtils::b64urlEncode(iv));

	try {
		cryptoContext->unwrap(badWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, wrongCek)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);

	shared_ptr<ByteArray> cek = make_shared<ByteArray>(16);
	random->nextBytes(*cek);
	shared_ptr<ByteArray> ecek = aesCryptoContext->encrypt(cek, encoder, format);

	shared_ptr<ByteArray> wrongWrapped = replace(encoder, wrapped, KEY_ENCRYPTED_KEY, MslEncoderUtils::b64urlEncode(ecek));

	try {
		cryptoContext->unwrap(wrongWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::INVALID_SYMMETRIC_KEY, e.getError());
	}
}

TEST_F(DISABLED_AesKwJsonSerialization, wrongIv)
{
	shared_ptr<ByteArray> wrapped = cryptoContext->wrap(data, encoder, format);
	shared_ptr<ByteArray> iv = make_shared<ByteArray>(16);
	random->nextBytes(*iv);
	shared_ptr<ByteArray> wrongWrapped = replace(encoder, wrapped, KEY_INITIALIZATION_VECTOR, MslEncoderUtils::b64urlEncode(iv));

	try {
		cryptoContext->unwrap(wrongWrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::UNWRAP_ERROR, e.getError());
	}
}

/** JSON Web Encryption unit tests. */
class JWE : public JsonWebEncryptionCryptoContextSuite
{
public:
	virtual ~JWE() {}

	explicit JWE()
	: cryptoContext(make_shared<JsonWebEncryptionCryptoContext>(ctx, rsaCryptoContext, Encryption::A128GCM, Format::JWE_CS))
	{}

protected:
	shared_ptr<ICryptoContext> cryptoContext;
};

class DISABLED_JWE : public JWE
{
public:
    using JWE::JWE;
};

TEST_F(JWE, encrypt)
{
	try {
		cryptoContext->encrypt(make_shared<ByteArray>(0), encoder, format);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::ENCRYPT_NOT_SUPPORTED, e.getError());
	}
}

TEST_F(DISABLED_JWE, decrypt)
{
	try {
		cryptoContext->decrypt(make_shared<ByteArray>(0), encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::ENCRYPT_NOT_SUPPORTED, e.getError());
	}
}

TEST_F(JWE, sign)
{
	try {
		cryptoContext->sign(make_shared<ByteArray>(0), encoder, format);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::SIGN_NOT_SUPPORTED, e.getError());
	}
}

TEST_F(JWE, verify)
{
	try {
		cryptoContext->verify(make_shared<ByteArray>(0), make_shared<ByteArray>(0), encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::VERIFY_NOT_SUPPORTED, e.getError());
	}
}

TEST_F(DISABLED_JWE, algorithmMismatch)
{
	shared_ptr<ICryptoContext> cryptoContextA = make_shared<JsonWebEncryptionCryptoContext>(ctx, rsaCryptoContext, Encryption::A128GCM, Format::JWE_CS);
	shared_ptr<ICryptoContext> cryptoContextB = make_shared<JsonWebEncryptionCryptoContext>(ctx, aesCryptoContext, Encryption::A128GCM, Format::JWE_CS);

	shared_ptr<ByteArray> wrapped = cryptoContextA->wrap(data, encoder, format);
	try {
		cryptoContextB->unwrap(wrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_ALGORITHM_MISMATCH, e.getError());
	}
}

TEST_F(DISABLED_JWE, encryptionMismatch)
{
	shared_ptr<ICryptoContext> cryptoContextA = make_shared<JsonWebEncryptionCryptoContext>(ctx, rsaCryptoContext, Encryption::A128GCM, Format::JWE_CS);
	shared_ptr<ICryptoContext> cryptoContextB = make_shared<JsonWebEncryptionCryptoContext>(ctx, rsaCryptoContext, Encryption::A256GCM, Format::JWE_CS);

	shared_ptr<ByteArray> wrapped = cryptoContextA->wrap(data, encoder, format);
	try {
		cryptoContextB->unwrap(wrapped, encoder);
		ADD_FAILURE() << "should have thrown";
	} catch (const MslCryptoException& e) {
		EXPECT_EQ(MslError::JWE_ALGORITHM_MISMATCH, e.getError());
	}
}

}}} // namespace netflix::msl::crypto
