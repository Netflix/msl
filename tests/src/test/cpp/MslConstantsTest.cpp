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
#include <IllegalArgumentException.h>
#include <MslConstants.h>

using namespace netflix::msl;
using namespace netflix::msl::MslConstants;

class MslConstantsTest : public ::testing::Test
{
};

// ---- CompressionAlgorithm

TEST_F(MslConstantsTest, CompressionAlgorithm_Value)
{
    EXPECT_EQ(CompressionAlgorithm::gzip,          CompressionAlgorithm::GZIP);
    EXPECT_EQ(CompressionAlgorithm::lzw,           CompressionAlgorithm::LZW);
    EXPECT_EQ(CompressionAlgorithm::nocompression, CompressionAlgorithm::NOCOMPRESSION);
}

TEST_F(MslConstantsTest, CompressionAlgorithm_ValueOf)
{
    EXPECT_EQ(CompressionAlgorithm::GZIP, CompressionAlgorithm::valueOf(CompressionAlgorithm::gzip));
    EXPECT_EQ(CompressionAlgorithm::LZW, CompressionAlgorithm::valueOf(CompressionAlgorithm::lzw));
    EXPECT_EQ(CompressionAlgorithm::NOCOMPRESSION, CompressionAlgorithm::valueOf(CompressionAlgorithm::nocompression));
}

TEST_F(MslConstantsTest, CompressionAlgorithm_Preferred)
{
    std::set<CompressionAlgorithm> caSet;
    EXPECT_EQ(CompressionAlgorithm::getPreferredAlgorithm(caSet), CompressionAlgorithm::NOCOMPRESSION);
    caSet.insert(CompressionAlgorithm::NOCOMPRESSION);
    EXPECT_EQ(CompressionAlgorithm::getPreferredAlgorithm(caSet), CompressionAlgorithm::NOCOMPRESSION);
    caSet.insert(CompressionAlgorithm::LZW);
    EXPECT_EQ(CompressionAlgorithm::getPreferredAlgorithm(caSet), CompressionAlgorithm::LZW);
    caSet.insert(CompressionAlgorithm::GZIP);
    EXPECT_EQ(CompressionAlgorithm::getPreferredAlgorithm(caSet), CompressionAlgorithm::GZIP);
}

TEST_F(MslConstantsTest, CompressionAlgorithm_FromString)
{
    EXPECT_EQ(CompressionAlgorithm::GZIP,          CompressionAlgorithm::fromString("GZIP"));
    EXPECT_EQ(CompressionAlgorithm::LZW,           CompressionAlgorithm::fromString("LZW"));
    EXPECT_EQ(CompressionAlgorithm::NOCOMPRESSION, CompressionAlgorithm::fromString("NOCOMPRESSION"));
    EXPECT_THROW(CipherSpec::fromString("FOO"), IllegalArgumentException);
}

TEST_F(MslConstantsTest, CompressionAlgorithm_ToString)
{
    EXPECT_EQ("GZIP",          CompressionAlgorithm::GZIP.toString());
    EXPECT_EQ("LZW",           CompressionAlgorithm::LZW.toString());
    EXPECT_EQ("NOCOMPRESSION", CompressionAlgorithm::NOCOMPRESSION.toString());
}

// ---- EncryptionAlgo

TEST_F(MslConstantsTest, EncryptionAlgo_Value)
{
    EXPECT_EQ(EncryptionAlgo::aes, EncryptionAlgo::AES);
}

TEST_F(MslConstantsTest, EncryptionAlgo_ValueOf)
{
    EXPECT_EQ(EncryptionAlgo::AES, EncryptionAlgo::valueOf(EncryptionAlgo::aes));
}

TEST_F(MslConstantsTest, EncryptionAlgo_FromString)
{
    EXPECT_EQ(EncryptionAlgo::AES, EncryptionAlgo::fromString("AES"));
    EXPECT_THROW(EncryptionAlgo::fromString("FOO"), IllegalArgumentException);
}

TEST_F(MslConstantsTest, EncryptionAlgo_ToString)
{
    EXPECT_EQ("AES", EncryptionAlgo::AES.toString());
}

// ---- CipherSpec

TEST_F(MslConstantsTest, CipherSpec_Value)
{
    EXPECT_EQ(CipherSpec::aes_cbc_pkcs5padding, CipherSpec::AES_CBC_PKCS5Padding);
    EXPECT_EQ(CipherSpec::aeswrap, CipherSpec::AESWrap);
    EXPECT_EQ(CipherSpec::rsa_ecb_pkcs1padding, CipherSpec::RSA_ECB_PKCS1Padding);
}

TEST_F(MslConstantsTest, CipherSpec_ValueOf)
{
    EXPECT_EQ(CipherSpec::AES_CBC_PKCS5Padding, CipherSpec::valueOf(CipherSpec::aes_cbc_pkcs5padding));
    EXPECT_EQ(CipherSpec::AESWrap,              CipherSpec::valueOf(CipherSpec::aeswrap));
    EXPECT_EQ(CipherSpec::RSA_ECB_PKCS1Padding, CipherSpec::valueOf(CipherSpec::rsa_ecb_pkcs1padding));
}

TEST_F(MslConstantsTest, CipherSpec_FromString)
{
    EXPECT_EQ(CipherSpec::AES_CBC_PKCS5Padding, CipherSpec::fromString("AES/CBC/PKCS5Padding"));
    EXPECT_EQ(CipherSpec::AESWrap,              CipherSpec::fromString("AESWrap"));
    EXPECT_EQ(CipherSpec::RSA_ECB_PKCS1Padding, CipherSpec::fromString("RSA/ECB/PKCS1Padding"));
    EXPECT_THROW(CipherSpec::fromString("FOO"), std::exception);
}

TEST_F(MslConstantsTest, CipherSpec_ToString)
{
    EXPECT_EQ("AES/CBC/PKCS5Padding", CipherSpec::AES_CBC_PKCS5Padding.toString());
    EXPECT_EQ("AESWrap",              CipherSpec::AESWrap.toString());
    EXPECT_EQ("RSA/ECB/PKCS1Padding", CipherSpec::RSA_ECB_PKCS1Padding.toString());
}

// ---- SignatureAlgo

TEST_F(MslConstantsTest, SignatureAlgo_Value)
{
    EXPECT_EQ(SignatureAlgo::hmacsha256,    SignatureAlgo::HmacSHA256);
    EXPECT_EQ(SignatureAlgo::sha256withrsa, SignatureAlgo::SHA256withRSA);
    EXPECT_EQ(SignatureAlgo::aescmac,       SignatureAlgo::AESCmac);
}

TEST_F(MslConstantsTest, SignatureAlgo_ValueOf)
{
    EXPECT_EQ(SignatureAlgo::HmacSHA256,    SignatureAlgo::valueOf(SignatureAlgo::hmacsha256));
    EXPECT_EQ(SignatureAlgo::SHA256withRSA, SignatureAlgo::valueOf(SignatureAlgo::sha256withrsa));
    EXPECT_EQ(SignatureAlgo::AESCmac,       SignatureAlgo::valueOf(SignatureAlgo::aescmac));
}

TEST_F(MslConstantsTest, SignatureAlgo_FromString)
{
    EXPECT_EQ(SignatureAlgo::HmacSHA256,    SignatureAlgo::fromString("HmacSHA256"));
    EXPECT_EQ(SignatureAlgo::SHA256withRSA, SignatureAlgo::fromString("SHA256withRSA"));
    EXPECT_EQ(SignatureAlgo::AESCmac,       SignatureAlgo::fromString("AESCmac"));
    EXPECT_THROW(SignatureAlgo::fromString("FOO"), IllegalArgumentException);
}

TEST_F(MslConstantsTest, SignatureAlgo_ToString)
{
    EXPECT_EQ("HmacSHA256",    SignatureAlgo::HmacSHA256.toString());
    EXPECT_EQ("SHA256withRSA", SignatureAlgo::SHA256withRSA.toString());
    EXPECT_EQ("AESCmac",       SignatureAlgo::AESCmac.toString());
}

// ---- ResponseCode

TEST_F(MslConstantsTest, ResponseCode_Value)
{
    EXPECT_EQ(ResponseCode::fail,             ResponseCode::FAIL);
    EXPECT_EQ(ResponseCode::transientFailure, ResponseCode::TRANSIENT_FAILURE);
    EXPECT_EQ(ResponseCode::entityReauth,    ResponseCode::ENTITY_REAUTH);
    EXPECT_EQ(ResponseCode::userReauth,       ResponseCode::USER_REAUTH);
    EXPECT_EQ(ResponseCode::keyxRequired,     ResponseCode::KEYX_REQUIRED);
    EXPECT_EQ(ResponseCode::entitydataReauth, ResponseCode::ENTITYDATA_REAUTH);
    EXPECT_EQ(ResponseCode::userdataReauth,   ResponseCode::USERDATA_REAUTH);
    EXPECT_EQ(ResponseCode::expired,          ResponseCode::EXPIRED);
    EXPECT_EQ(ResponseCode::replayed,         ResponseCode::REPLAYED);
    EXPECT_EQ(ResponseCode::ssotokenRejected, ResponseCode::SSOTOKEN_REJECTED);
    EXPECT_EQ(ResponseCode::invalid,          ResponseCode::INVALID);
}

TEST_F(MslConstantsTest, ResponseCode_ValueOf)
{
    EXPECT_EQ(ResponseCode::FAIL,              ResponseCode::valueOf(ResponseCode::fail));
    EXPECT_EQ(ResponseCode::TRANSIENT_FAILURE, ResponseCode::valueOf(ResponseCode::transientFailure));
    EXPECT_EQ(ResponseCode::ENTITY_REAUTH,     ResponseCode::valueOf(ResponseCode::entityReauth));
    EXPECT_EQ(ResponseCode::USER_REAUTH,       ResponseCode::valueOf(ResponseCode::userReauth));
    EXPECT_EQ(ResponseCode::KEYX_REQUIRED,     ResponseCode::valueOf(ResponseCode::keyxRequired));
    EXPECT_EQ(ResponseCode::ENTITYDATA_REAUTH, ResponseCode::valueOf(ResponseCode::entitydataReauth));
    EXPECT_EQ(ResponseCode::USERDATA_REAUTH,   ResponseCode::valueOf(ResponseCode::userdataReauth));
    EXPECT_EQ(ResponseCode::EXPIRED,           ResponseCode::valueOf(ResponseCode::expired));
    EXPECT_EQ(ResponseCode::REPLAYED,          ResponseCode::valueOf(ResponseCode::replayed));
    EXPECT_EQ(ResponseCode::SSOTOKEN_REJECTED, ResponseCode::valueOf(ResponseCode::ssotokenRejected));
    EXPECT_EQ(ResponseCode::INVALID, ResponseCode::valueOf(ResponseCode::invalid));
    EXPECT_THROW(ResponseCode::valueOf(ResponseCode::invalid+1), IllegalArgumentException);
}

TEST_F(MslConstantsTest, ResponseCode_FromString)
{
    EXPECT_EQ(ResponseCode::FAIL,              ResponseCode::fromString("FAIL"));
    EXPECT_EQ(ResponseCode::TRANSIENT_FAILURE, ResponseCode::fromString("TRANSIENT_FAILURE"));
    EXPECT_EQ(ResponseCode::ENTITY_REAUTH,     ResponseCode::fromString("ENTITY_REAUTH"));
    EXPECT_EQ(ResponseCode::USER_REAUTH,       ResponseCode::fromString("USER_REAUTH"));
    EXPECT_EQ(ResponseCode::KEYX_REQUIRED,     ResponseCode::fromString("KEYX_REQUIRED"));
    EXPECT_EQ(ResponseCode::ENTITYDATA_REAUTH, ResponseCode::fromString("ENTITYDATA_REAUTH"));
    EXPECT_EQ(ResponseCode::USERDATA_REAUTH,   ResponseCode::fromString("USERDATA_REAUTH"));
    EXPECT_EQ(ResponseCode::EXPIRED,           ResponseCode::fromString("EXPIRED"));
    EXPECT_EQ(ResponseCode::REPLAYED,          ResponseCode::fromString("REPLAYED"));
    EXPECT_EQ(ResponseCode::SSOTOKEN_REJECTED, ResponseCode::fromString("SSOTOKEN_REJECTED"));
    EXPECT_EQ(ResponseCode::INVALID,           ResponseCode::fromString("INVALID"));
}

TEST_F(MslConstantsTest, ResponseCode_ToString)
{
    EXPECT_EQ("FAIL",              ResponseCode::FAIL.toString());
    EXPECT_EQ("TRANSIENT_FAILURE", ResponseCode::TRANSIENT_FAILURE.toString());
    EXPECT_EQ("ENTITY_REAUTH",     ResponseCode::ENTITY_REAUTH.toString());
    EXPECT_EQ("USER_REAUTH",       ResponseCode::USER_REAUTH.toString());
    EXPECT_EQ("KEYX_REQUIRED",     ResponseCode::KEYX_REQUIRED.toString());
    EXPECT_EQ("ENTITYDATA_REAUTH", ResponseCode::ENTITYDATA_REAUTH.toString());
    EXPECT_EQ("USERDATA_REAUTH",   ResponseCode::USERDATA_REAUTH.toString());
    EXPECT_EQ("EXPIRED",           ResponseCode::EXPIRED.toString());
    EXPECT_EQ("REPLAYED",          ResponseCode::REPLAYED.toString());
    EXPECT_EQ("SSOTOKEN_REJECTED", ResponseCode::SSOTOKEN_REJECTED.toString());
    EXPECT_EQ("INVALID",           ResponseCode::INVALID.toString());
}
