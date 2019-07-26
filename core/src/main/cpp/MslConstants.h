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

#ifndef SRC_MSLCONSTANTS_H_
#define SRC_MSLCONSTANTS_H_

#include <Enum.h>
#include <stdint.h>
#include <set>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
namespace MslConstants {

/** RFC-4627 defines UTF-8 as the default encoding. */
// FIXME
//static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

/** Maximum long integer value (2^53 limited by JavaScript). */
static const int64_t MAX_LONG_VALUE = 9007199254740992L;

/**
 * The maximum number of MSL messages (requests sent or responses received)
 * to allow before giving up. Six exchanges, or twelve total messages,
 * should be sufficient to capture all possible error recovery and
 * handshake requirements in both trusted network and peer-to-peer modes.
 */
static const int MAX_MESSAGES = 12;

/** Compression algorithm. */
class CompressionAlgorithm : public Enum<CompressionAlgorithm>
{
public:
    static const CompressionAlgorithm
        // In order of most preferred to least preferred.
        /** GZIP */
        GZIP,
        /** LZW */
        LZW,
        NOCOMPRESSION;

    /**
     * Returns the most preferred compression algorithm from the provided
     * set of algorithms.
     *
     * @param algos the set of algorithms to choose from.
     * @return the most preferred compression algorithm or {@code null} if
     *         the algorithm set is empty.
     */
    static CompressionAlgorithm getPreferredAlgorithm(const std::set<CompressionAlgorithm>& algos);

    CompressionAlgorithm() : Enum(nocompression, "NOCOMPRESSION") {}
    enum Value { gzip, lzw, nocompression };
    operator Value() const { return static_cast<Value>(value()); }
    static const std::vector<CompressionAlgorithm>& getValues();

private:
    CompressionAlgorithm(const Value& value, const std::string& strValue)
        : Enum(value, strValue) {}
};

/** Encryption algorithms. */
class EncryptionAlgo : public Enum<EncryptionAlgo>
{
public:
    static const EncryptionAlgo
        /** AES */
        AES,
        /** INVALID */
        INVALID;

    EncryptionAlgo() : Enum(invalid, "INVALID") {}
    enum Value { aes, invalid };
    operator Value() const { return static_cast<Value>(value()); }
    static const std::vector<EncryptionAlgo>& getValues();

private:
    EncryptionAlgo(const Value& value, const std::string& strValue)
        : Enum(value, strValue) {}
};

/** Cipher specifications. */
class CipherSpec : public Enum<CipherSpec>
{
public:
    CipherSpec();
    static const CipherSpec
        /** AES/CBC/PKCS5Padding */
        AES_CBC_PKCS5Padding,
        /** AESWrap */
        AESWrap,
        /** RSA/ECB/PKCS1Padding */
        RSA_ECB_PKCS1Padding,
        /** INVALID */
        INVALID;

    enum Value { aes_cbc_pkcs5padding, aeswrap, rsa_ecb_pkcs1padding, invalid };
    operator Value() const { return static_cast<Value>(value()); }
    operator const std::string() const { return stringValue(); }
    static const std::vector<CipherSpec>& getValues();

private:
    CipherSpec(const Value& value, const std::string& strValue)
        : Enum(value, strValue) {}
};

/** Signature algorithms. */
class SignatureAlgo : public Enum<SignatureAlgo>
{
public:
    static const SignatureAlgo
        /** HmacSHA256 */
        HmacSHA256,
        /** SHA256withRSA */
        SHA256withRSA,
        /** AESCmac. */
        AESCmac,
        /** INVALID */
        INVALID;

    enum Value { hmacsha256, sha256withrsa, aescmac, invalid };
    operator Value() const { return static_cast<Value>(value()); }
    static const std::vector<SignatureAlgo>& getValues();
    SignatureAlgo() : Enum(invalid, "INVALID") {}

private:
    SignatureAlgo(const Value& value, const std::string& strValue)
        : Enum(value, strValue) {}
};

/** Error response codes. */
class ResponseCode : public Enum<ResponseCode>
{
public:
    static const ResponseCode
        /** The message is erroneous and will continue to fail if retried. */
        FAIL,
        /** The message is expected to succeed if retried after a delay. */
        TRANSIENT_FAILURE,
        /** The message is expected to succeed post entity re-authentication. */
        ENTITY_REAUTH,
        /** The message is expected to succeed post user re-authentication. */
        USER_REAUTH,
        /** The message is expected to succeed post key exchange. */
        KEYX_REQUIRED,
        /** The message is expected to succeed with new entity authentication data. */
        ENTITYDATA_REAUTH,
        /** The message is expected to succeed with new user authentication data. */
        USERDATA_REAUTH,
        /** The message is expected to succeed if retried with a renewed master token or renewable message. */
        EXPIRED,
        /** The non-replayable message is expected to succeed if retried with the newest master token. */
        REPLAYED,
        /** The message is expected to succeed with new user authentication data containing a valid single-sign-on token. */
        SSOTOKEN_REJECTED,
        /** Invalid */
        INVALID;

    enum Value
    {
        fail = 1,
        transientFailure = 2,
        entityReauth = 3,
        userReauth = 4,
        keyxRequired = 5,
        entitydataReauth = 6,
        userdataReauth = 7,
        expired = 8,
        replayed = 9,
        ssotokenRejected = 10,
        invalid
    };
    operator Value() const { return static_cast<Value>(value()); }
    static const std::vector<ResponseCode>& getValues();
    ResponseCode() : Enum(invalid, "INVALID") {}
    ResponseCode(const ResponseCode& other) : Enum(other.value(), other.stringValue()) {}

private:
    ResponseCode(const Value& value, const std::string& strValue)
        : Enum(value, strValue) {}
};

}}} // namespace netflix::msl::MslConstants

#endif /* SRC_MSLCONSTANTS_H_ */
