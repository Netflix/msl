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
#include <crypto/MslSignatureEnvelope.h>
#include <crypto/OpenSslLib.h>
#include <crypto/Random.h>
#include <io/DefaultMslEncoderFactory.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <memory>

using namespace std;
using netflix::msl::io::MslObject;
using std::shared_ptr;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

std::shared_ptr<io::MslEncoderFactory> encoder = std::make_shared<io::DefaultMslEncoderFactory>();
const std::string KEY_VERSION = "version";
const std::string KEY_ALGORITHM = "algorithm";
const std::string KEY_SIGNATURE = "signature";

std::string sufx(const testing::TestParamInfo<MslConstants::SignatureAlgo>& tpi) {
    return tpi.param.toString();
}

}

class MslSignatureEnvelopeTestV1 : public ::testing::Test
{
public:
    MslSignatureEnvelopeTestV1() : ENCODER_FORMAT(io:: MslEncoderFormat::JSON) {
        EXPECT_NO_THROW(ensureOpenSslInit());
        SIGNATURE = getRandomBytes(32);
    }
protected:
    shared_ptr<ByteArray> getRandomBytes(size_t nBytes) {
    	shared_ptr<ByteArray> ba = make_shared<ByteArray>(nBytes);
        random_.nextBytes(*ba);
        return ba;
    }
protected:
    Random random_;
    shared_ptr<ByteArray> SIGNATURE;
    const io::MslEncoderFormat ENCODER_FORMAT;
};

TEST_F(MslSignatureEnvelopeTestV1, ctors)
{
    const MslSignatureEnvelope envelope(SIGNATURE);
    EXPECT_EQ(MslConstants::SignatureAlgo::INVALID, envelope.getAlgorithm());
    EXPECT_EQ(SIGNATURE, envelope.getSignature());
    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(envelopeBytes);

    const MslSignatureEnvelope moEnvelope = MslSignatureEnvelope::parse(envelopeBytes, encoder);
    EXPECT_EQ(envelope.getAlgorithm(), moEnvelope.getAlgorithm());
    EXPECT_EQ(envelope.getSignature(), moEnvelope.getSignature());
    shared_ptr<ByteArray> moEnvelopeBytes = moEnvelope.getBytes(encoder, ENCODER_FORMAT);
    EXPECT_EQ(*envelopeBytes, *moEnvelopeBytes);
}

TEST_F(MslSignatureEnvelopeTestV1, encode)
{
    const MslSignatureEnvelope envelope(SIGNATURE);
    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(envelopeBytes);
    EXPECT_EQ(SIGNATURE, envelopeBytes);
}

// --------------------

// NOTE: This test is parameterized for three values of SignatureAlgo:
// HmacSHA256, SHA256withRSA, and AESCmac

class MslSignatureEnvelopeTestV2 : public ::testing::TestWithParam<MslConstants::SignatureAlgo>
{
public:
    MslSignatureEnvelopeTestV2() : ENCODER_FORMAT(io:: MslEncoderFormat::JSON) {
        EXPECT_NO_THROW(ensureOpenSslInit());
        SIGNATURE = getRandomBytes(32);
    }
protected:
    shared_ptr<ByteArray> getRandomBytes(size_t nBytes) {
    	shared_ptr<ByteArray> ba = make_shared<ByteArray>(nBytes);
        random_.nextBytes(*ba);
        return ba;
    }
protected:
    Random random_;
    shared_ptr<ByteArray> SIGNATURE;
    const io::MslEncoderFormat ENCODER_FORMAT;
};

INSTANTIATE_TEST_CASE_P(MslSignature, MslSignatureEnvelopeTestV2,
        ::testing::Values(MslConstants::SignatureAlgo::HmacSHA256,
                          MslConstants::SignatureAlgo::SHA256withRSA,
                          MslConstants::SignatureAlgo::AESCmac), &sufx);

TEST_P(MslSignatureEnvelopeTestV2, ctors)
{
    const MslSignatureEnvelope envelope(GetParam(), SIGNATURE);
    EXPECT_EQ(GetParam(), envelope.getAlgorithm());
    EXPECT_EQ(*SIGNATURE, *envelope.getSignature());
    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(envelopeBytes);

    const MslSignatureEnvelope moEnvelope = MslSignatureEnvelope::parse(envelopeBytes, encoder);
    EXPECT_EQ(envelope.getAlgorithm(), moEnvelope.getAlgorithm());
    EXPECT_EQ(*envelope.getSignature(), *moEnvelope.getSignature());
    shared_ptr<ByteArray> moEnvelopeBytes = moEnvelope.getBytes(encoder, ENCODER_FORMAT);
    EXPECT_EQ(*envelopeBytes, *moEnvelopeBytes);
}

TEST_P(MslSignatureEnvelopeTestV2, encode)
{
    const MslSignatureEnvelope envelope(GetParam(), SIGNATURE);
    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(envelopeBytes);

    EXPECT_EQ(MslSignatureEnvelope::Version::V2, mo->getInt(KEY_VERSION));
    EXPECT_EQ(GetParam().toString(), mo->getString(KEY_ALGORITHM));
    EXPECT_EQ(*SIGNATURE, *mo->getBytes(KEY_SIGNATURE));
}

TEST_P(MslSignatureEnvelopeTestV2, missingVersion)
{
    const MslSignatureEnvelope envelope(GetParam(), SIGNATURE);

    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject >mo = encoder->parseObject(envelopeBytes);
    mo->remove(KEY_VERSION);

    shared_ptr<ByteArray> moEncode = encoder->encodeObject(mo, ENCODER_FORMAT);
    const MslSignatureEnvelope moEnvelope = MslSignatureEnvelope::parse(moEncode, encoder);
    EXPECT_EQ(MslConstants::SignatureAlgo::INVALID, moEnvelope.getAlgorithm());
    EXPECT_EQ(*moEncode, *moEnvelope.getSignature());
}

TEST_P(MslSignatureEnvelopeTestV2, invalidVersion)
{
    const MslSignatureEnvelope envelope(GetParam(), SIGNATURE);

    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject >mo = encoder->parseObject(envelopeBytes);
    mo->put<std::string>(KEY_VERSION, "x");

    shared_ptr<ByteArray> moEncode = encoder->encodeObject(mo, ENCODER_FORMAT);
    const MslSignatureEnvelope moEnvelope = MslSignatureEnvelope::parse(moEncode, encoder);
    EXPECT_EQ(MslConstants::SignatureAlgo::INVALID, moEnvelope.getAlgorithm());
    EXPECT_EQ(*moEncode, *moEnvelope.getSignature());
}

TEST_P(MslSignatureEnvelopeTestV2, unknownVersion)
{
    const MslSignatureEnvelope envelope(GetParam(), SIGNATURE);

    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject >mo = encoder->parseObject(envelopeBytes);
    mo->put<int>(KEY_VERSION, -1);

    shared_ptr<ByteArray> moEncode = encoder->encodeObject(mo, ENCODER_FORMAT);
    const MslSignatureEnvelope moEnvelope = MslSignatureEnvelope::parse(moEncode, encoder);
    EXPECT_EQ(MslConstants::SignatureAlgo::INVALID, moEnvelope.getAlgorithm());
    EXPECT_EQ(*moEncode, *moEnvelope.getSignature());
}

TEST_P(MslSignatureEnvelopeTestV2, missingAlgorithm)
{
    const MslSignatureEnvelope envelope(GetParam(), SIGNATURE);

    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject >mo = encoder->parseObject(envelopeBytes);
    mo->remove(KEY_ALGORITHM);

    shared_ptr<ByteArray> moEncode = encoder->encodeObject(mo, ENCODER_FORMAT);
    const MslSignatureEnvelope moEnvelope = MslSignatureEnvelope::parse(moEncode, encoder);
    EXPECT_EQ(MslConstants::SignatureAlgo::INVALID, moEnvelope.getAlgorithm());
    EXPECT_EQ(*moEncode, *moEnvelope.getSignature());
}

TEST_P(MslSignatureEnvelopeTestV2, invalidAlgorithm)
{
    const MslSignatureEnvelope envelope(GetParam(), SIGNATURE);

    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject >mo = encoder->parseObject(envelopeBytes);
    mo->put<std::string>(KEY_ALGORITHM, "x");

    shared_ptr<ByteArray> moEncode = encoder->encodeObject(mo, ENCODER_FORMAT);
    const MslSignatureEnvelope moEnvelope = MslSignatureEnvelope::parse(moEncode, encoder);
    EXPECT_EQ(MslConstants::SignatureAlgo::INVALID, moEnvelope.getAlgorithm());
    EXPECT_EQ(*moEncode, *moEnvelope.getSignature());
}

TEST_P(MslSignatureEnvelopeTestV2, missingSignature)
{
    const MslSignatureEnvelope envelope(GetParam(), SIGNATURE);

    shared_ptr<ByteArray> envelopeBytes = envelope.getBytes(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject >mo = encoder->parseObject(envelopeBytes);
    mo->remove(KEY_SIGNATURE);

    shared_ptr<ByteArray> moEncode = encoder->encodeObject(mo, ENCODER_FORMAT);
    const MslSignatureEnvelope moEnvelope = MslSignatureEnvelope::parse(moEncode, encoder);
    EXPECT_EQ(MslConstants::SignatureAlgo::INVALID, moEnvelope.getAlgorithm());
    EXPECT_EQ(*moEncode, *moEnvelope.getSignature());
}

}}} // namespace netflix::msl::crypto
