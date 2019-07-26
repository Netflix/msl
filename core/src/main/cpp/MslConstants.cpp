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
#include "MslConstants.h"
#include <util/MslContext.h>

namespace netflix { namespace msl {

using namespace netflix::msl::MslConstants;

// ---- CompressionAlgorithm

const CompressionAlgorithm CompressionAlgorithm::GZIP(CompressionAlgorithm::gzip, "GZIP");
const CompressionAlgorithm CompressionAlgorithm::LZW(CompressionAlgorithm::lzw, "LZW");
const CompressionAlgorithm CompressionAlgorithm::NOCOMPRESSION(CompressionAlgorithm::nocompression, "NOCOMPRESSION");

// static
const std::vector<CompressionAlgorithm>& CompressionAlgorithm::getValues() {
    static std::vector<CompressionAlgorithm> gValues;
    if (gValues.empty()) {
        gValues.push_back(GZIP);
        gValues.push_back(LZW);
        gValues.push_back(NOCOMPRESSION);
    }
    return gValues;
}

// static
CompressionAlgorithm CompressionAlgorithm::getPreferredAlgorithm(const std::set<CompressionAlgorithm>& algos) {
    // getValues() returns the values in the preferred order as promised above.
    const std::vector<CompressionAlgorithm>& preferredAlgos = getValues();
    for (std::vector<CompressionAlgorithm>::const_iterator it = preferredAlgos.begin();
        it != preferredAlgos.end() && algos.size();
        ++it)
    {
        CompressionAlgorithm preferredAlgo = *it;
        if (algos.count(preferredAlgo))
            return preferredAlgo;
    }
    return NOCOMPRESSION;
}

// ----Encryption Algo

const EncryptionAlgo EncryptionAlgo::AES(EncryptionAlgo(EncryptionAlgo::aes, "AES"));
const EncryptionAlgo EncryptionAlgo::INVALID(EncryptionAlgo(EncryptionAlgo::aes, "INVALID"));

// static
const std::vector<EncryptionAlgo>& EncryptionAlgo::getValues()
{
    static std::vector<EncryptionAlgo> gValues;
    if (gValues.empty()) {
        gValues.push_back(AES);
        gValues.push_back(INVALID);
    }
    return gValues;
}

// ---- CipherSpec

const CipherSpec CipherSpec::AES_CBC_PKCS5Padding(CipherSpec::aes_cbc_pkcs5padding, "AES/CBC/PKCS5Padding");
const CipherSpec CipherSpec::AESWrap(CipherSpec::aeswrap, "AESWrap");
const CipherSpec CipherSpec::RSA_ECB_PKCS1Padding(CipherSpec::rsa_ecb_pkcs1padding, "RSA/ECB/PKCS1Padding");
const CipherSpec CipherSpec::INVALID(CipherSpec::invalid, "INVALID");

CipherSpec::CipherSpec() : Enum(invalid, "INVALID") {}

// static
const std::vector<CipherSpec>& CipherSpec::getValues()
{
    static std::vector<CipherSpec> gValues;
    if (gValues.empty()) {
        gValues.push_back(AES_CBC_PKCS5Padding);
        gValues.push_back(AESWrap);
        gValues.push_back(RSA_ECB_PKCS1Padding);
        gValues.push_back(INVALID);
    }
    return gValues;
}

// ---- SignatureAlgo

const SignatureAlgo SignatureAlgo::HmacSHA256(SignatureAlgo::hmacsha256, "HmacSHA256");
const SignatureAlgo SignatureAlgo::SHA256withRSA(SignatureAlgo::sha256withrsa, "SHA256withRSA");
const SignatureAlgo SignatureAlgo::AESCmac(SignatureAlgo::aescmac, "AESCmac");
const SignatureAlgo SignatureAlgo::INVALID(SignatureAlgo::invalid, "INVALID");

// static
const std::vector<SignatureAlgo>& SignatureAlgo::getValues()
{
    static std::vector<SignatureAlgo> gValues;
    if (gValues.empty()) {
        gValues.push_back(HmacSHA256);
        gValues.push_back(SHA256withRSA);
        gValues.push_back(AESCmac);
        gValues.push_back(INVALID);
    }
    return gValues;
}

// ---- ResponseCode

const ResponseCode ResponseCode::FAIL(ResponseCode::fail, "FAIL");
const ResponseCode ResponseCode::TRANSIENT_FAILURE(ResponseCode::transientFailure, "TRANSIENT_FAILURE");
const ResponseCode ResponseCode::ENTITY_REAUTH(ResponseCode::entityReauth, "ENTITY_REAUTH");
const ResponseCode ResponseCode::USER_REAUTH(ResponseCode::userReauth, "USER_REAUTH");
const ResponseCode ResponseCode::KEYX_REQUIRED(ResponseCode::keyxRequired, "KEYX_REQUIRED");
const ResponseCode ResponseCode::ENTITYDATA_REAUTH(ResponseCode::entitydataReauth, "ENTITYDATA_REAUTH");
const ResponseCode ResponseCode::USERDATA_REAUTH(ResponseCode::userdataReauth, "USERDATA_REAUTH");
const ResponseCode ResponseCode::EXPIRED(ResponseCode::expired, "EXPIRED");
const ResponseCode ResponseCode::REPLAYED(ResponseCode::replayed, "REPLAYED");
const ResponseCode ResponseCode::SSOTOKEN_REJECTED(ResponseCode::ssotokenRejected, "SSOTOKEN_REJECTED");
const ResponseCode ResponseCode::INVALID(ResponseCode::invalid, "INVALID");

// static
const std::vector<ResponseCode>& ResponseCode::getValues()
{
    static std::vector<ResponseCode> gValues;
    if (gValues.empty()) {
        gValues.push_back(FAIL);
        gValues.push_back(TRANSIENT_FAILURE);
        gValues.push_back(ENTITY_REAUTH);
        gValues.push_back(USER_REAUTH);
        gValues.push_back(KEYX_REQUIRED);
        gValues.push_back(ENTITYDATA_REAUTH);
        gValues.push_back(USERDATA_REAUTH);
        gValues.push_back(EXPIRED);
        gValues.push_back(REPLAYED);
        gValues.push_back(SSOTOKEN_REJECTED);
        gValues.push_back(INVALID);
    }
    return gValues;
}


// ---- MslContext::ReauthCode

// MslContext::ReauthCode is statically initialized here since the initialization
// depends on MslConstants::ResponseCode statically defined in this translation
// unit
namespace util
{
const MslContext::ReauthCode MslContext::ReauthCode::ENTITY_REAUTH(
        MslContext::ReauthCode::entity_reauth, "ENTITY_REAUTH",
        MslConstants::ResponseCode::ENTITY_REAUTH);
const MslContext::ReauthCode MslContext::ReauthCode::ENTITYDATA_REAUTH(
        MslContext::ReauthCode::entitydata_reauth, "ENTITYDATA_REAUTH",
        MslConstants::ResponseCode::ENTITYDATA_REAUTH);
const MslContext::ReauthCode MslContext::ReauthCode::INVALID(
        MslContext::ReauthCode::invalid, "INVALID",
        MslConstants::ResponseCode::FAIL);
} // namespace util

}} // namespace netflix::msl
