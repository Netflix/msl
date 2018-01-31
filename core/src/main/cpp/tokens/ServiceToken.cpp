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

#include <tokens/ServiceToken.h>
#include <crypto/ICryptoContext.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslInternalException.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <util/Base64.h>
#include <util/MslCompression.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace tokens {

namespace {

/** Key token data. */
const string KEY_TOKENDATA = "tokendata";
/** Key signature. */
const string KEY_SIGNATURE = "signature";

// tokendata
/** Key token name_. */
const string KEY_NAME = "name";
/** Key master token serial number. */
const string KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
/** Key user ID token serial number. */
const string KEY_USER_ID_TOKEN_SERIAL_NUMBER = "uitserialnumber";
/** Key encrypted_. */
const string KEY_ENCRYPTED = "encrypted";
/** Key compression algorithm. */
const string KEY_COMPRESSION_ALGORITHM = "compressionalgo";
/** Key service data. */
const string KEY_SERVICEDATA = "servicedata";

/**
 * <p>Select the appropriate crypto context for the service token
 * represented by the provided MSL object.</p>
 *
 * <p>If the service token name exists as a key in the map of crypto
 * contexts, the mapped crypto context will be returned. Otherwise the
 * default crypto context mapped from the empty string key will be
 * returned. If no explicit or default crypto context exists null will be
 * returned.</p>
 *
 * @param encoder the MSL encoder factory.
 * @param serviceTokenMo the MSL object.
 * @param cryptoContexts the map of service token names onto crypto
 *        contexts used to decrypt and verify service tokens.
 * @return the correct crypto context for the service token or null.
 * @throws MslEncodingException if there is a problem parsing the data.
 */
shared_ptr<ICryptoContext> selectCryptoContext(shared_ptr<MslEncoderFactory> encoder,
        shared_ptr<MslObject> serviceTokenMo, map<string, shared_ptr<ICryptoContext>> cryptoContexts)
{
    try {
    	shared_ptr<ByteArray> tokendata = serviceTokenMo->getBytes(KEY_TOKENDATA);
        if (tokendata->empty())
            throw MslEncodingException(MslError::SERVICETOKEN_TOKENDATA_MISSING, string("servicetoken ") + serviceTokenMo->toString());
        shared_ptr<MslObject> tokenDataMo = encoder->parseObject(tokendata);
        const string name_ = tokenDataMo->getString(KEY_NAME);
        map<string, shared_ptr<ICryptoContext>>::const_iterator it = cryptoContexts.find(name_);
        return (it != cryptoContexts.end()) ? it->second : shared_ptr<ICryptoContext>();
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, string("servicetoken ") + serviceTokenMo->toString(), e);
    }
}

} // namespace anonymous

ServiceToken::ServiceToken(
        shared_ptr<MslContext> ctx,
        const string& name_,
		shared_ptr<ByteArray> data,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken,
        bool encrypted_,
        const MslConstants::CompressionAlgorithm& compressionAlgo,
        shared_ptr<ICryptoContext> cryptoContext)
    : ctx_(ctx)
    , cryptoContext_(cryptoContext)
    , name_(name_)
    , mtSerialNumber_(-1)
    , uitSerialNumber_(-1)
    , encrypted_(encrypted_)
    , servicedata_(data)
    , verified_(true)
{
    // If both master token and user ID token are provided the user ID
    // token must be bound to the master token.
    if (masterToken && userIdToken && !userIdToken->isBoundTo(masterToken))
        throw MslInternalException("Cannot construct a service token bound to a master token and user ID token where the user ID token is not bound to the same master token.");

    // The crypto context may not be null.
    if (!cryptoContext)
        throw MslInternalException("Crypto context may not be null.");

    // Set token properties.
    mtSerialNumber_ = masterToken ? masterToken->getSerialNumber() : -1;
    uitSerialNumber_ = userIdToken ? userIdToken->getSerialNumber() : -1;

    // Optionally compress the service data.
    if (compressionAlgo != MslConstants::CompressionAlgorithm::NOCOMPRESSION)
    {
        shared_ptr<ByteArray> compressed = MslCompression::compress(compressionAlgo, *data);
        // Only use compression if the compressed data is smaller than the
        // uncompressed data.
        if (compressed && compressed->size() < data->size()) {
            compressionAlgo_ = compressionAlgo;
            compressedServicedata_ = compressed;
        } else {
            compressionAlgo_ = MslConstants::CompressionAlgorithm::NOCOMPRESSION;
            compressedServicedata_ = data;
        }
    } else {
        compressionAlgo_ = MslConstants::CompressionAlgorithm::NOCOMPRESSION;
        compressedServicedata_ = data;
    }
}

ServiceToken::ServiceToken(shared_ptr<MslContext> ctx, shared_ptr<MslObject> serviceTokenMo,
        shared_ptr<tokens::MasterToken> masterToken, shared_ptr<tokens::UserIdToken> userIdToken,
        shared_ptr<ICryptoContext> cryptoContext)
    : ctx_(ctx)
    , cryptoContext_(cryptoContext)
    , mtSerialNumber_(-1)
    , uitSerialNumber_(-1)
    , encrypted_(false)
    , verified_(false)
{
    init(ctx, serviceTokenMo, masterToken, userIdToken, cryptoContext);
}


ServiceToken::ServiceToken(shared_ptr<MslContext> ctx, shared_ptr<MslObject> serviceTokenMo,
        shared_ptr<MasterToken> masterToken, shared_ptr<UserIdToken> userIdToken,
        const map<string, shared_ptr<ICryptoContext>>& cryptoContexts)
    : ctx_(ctx)
    , mtSerialNumber_(-1)
    , uitSerialNumber_(-1)
    , encrypted_(false)
    , verified_(false)
{
    init(ctx, serviceTokenMo, masterToken, userIdToken, selectCryptoContext(ctx->getMslEncoderFactory(), serviceTokenMo, cryptoContexts));
}

void ServiceToken::init(shared_ptr<MslContext> ctx, shared_ptr<MslObject> serviceTokenMo,
        shared_ptr<tokens::MasterToken> masterToken, shared_ptr<tokens::UserIdToken> userIdToken,
        shared_ptr<ICryptoContext> cryptoContext)
{
    assert(ctx);
    assert(serviceTokenMo);

    ctx_ = ctx;
    cryptoContext_ = cryptoContext;
    shared_ptr<MslEncoderFactory> encoder = ctx_->getMslEncoderFactory();

    // Verify the data representation.
    try {
        tokendataBytes_ = serviceTokenMo->getBytes(KEY_TOKENDATA);
        if (tokendataBytes_->size() == 0) {
            MslEncodingException mex(MslError::SERVICETOKEN_TOKENDATA_MISSING, string("servicetoken ") + serviceTokenMo->toString());
            mex.setMasterToken(masterToken);  // FIXME: can do this in a better way?
            mex.setUserIdToken(userIdToken);
            throw mex;
        }
        signatureBytes_ = serviceTokenMo->getBytes(KEY_SIGNATURE);
        verified_ = (cryptoContext) ? cryptoContext->verify(tokendataBytes_, signatureBytes_, encoder) : false;
    } catch (const MslEncoderException& e) {
        MslEncodingException mex(MslError::MSL_PARSE_ERROR, string("servicetoken ") + serviceTokenMo->toString(), e);
        mex.setMasterToken(masterToken);
        mex.setUserIdToken(userIdToken);
        throw mex;
    } catch (MslCryptoException& e) {  // FIXME: Ok to catch by non-const?
        e.setMasterToken(masterToken);
        throw e;
    }

    // Pull the token data.
    try {
        shared_ptr<MslObject> tokendata = encoder->parseObject(tokendataBytes_);
        name_ = tokendata->getString(KEY_NAME);
        if (tokendata->has(KEY_MASTER_TOKEN_SERIAL_NUMBER)) {
            mtSerialNumber_ = tokendata->getLong(KEY_MASTER_TOKEN_SERIAL_NUMBER);
            if (mtSerialNumber_ < 0 || mtSerialNumber_ > MslConstants::MAX_LONG_VALUE) {
                throw MslException(MslError::SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, string("servicetokendata ") + tokendata->toString()).setMasterToken(masterToken).setUserIdToken(userIdToken);
            }
        } else {
            mtSerialNumber_ = -1;
        }
        if (tokendata->has(KEY_USER_ID_TOKEN_SERIAL_NUMBER)) {
            uitSerialNumber_ = tokendata->getLong(KEY_USER_ID_TOKEN_SERIAL_NUMBER);
            if (uitSerialNumber_ < 0 || uitSerialNumber_ > MslConstants::MAX_LONG_VALUE)
                throw MslException(MslError::SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, string("servicetokendata ") + tokendata->toString()).setMasterToken(masterToken).setUserIdToken(userIdToken);
        } else {
            uitSerialNumber_ = -1;
        }
        // There has to be a master token serial number if there is a
        // user ID token serial number.

        encrypted_ = tokendata->getBoolean(KEY_ENCRYPTED);
        if (tokendata->has(KEY_COMPRESSION_ALGORITHM)) {
            const string algoName = tokendata->getString(KEY_COMPRESSION_ALGORITHM);
            try {
                compressionAlgo_ = MslConstants::CompressionAlgorithm::fromString(algoName);
            } catch (const IllegalArgumentException& e) {
                throw MslException(MslError::UNIDENTIFIED_COMPRESSION, algoName, e);
            }
        } else {
            compressionAlgo_ = MslConstants::CompressionAlgorithm::NOCOMPRESSION;  // FIXME: java code set this to null here
        }

        // If encrypted_, and we were able to verify the data then we better
        // be able to decrypt it. (An exception is thrown if decryption
        // fails.)
        shared_ptr<ByteArray> data = tokendata->getBytes(KEY_SERVICEDATA);
        if (verified_) {
        	shared_ptr<ByteArray> ciphertext = data;
            if (encrypted_ && ciphertext->size() > 0) {
                compressedServicedata_ = cryptoContext->decrypt(ciphertext, encoder);
            } else {
                compressedServicedata_ = ciphertext;
            }

            if (compressionAlgo_ != MslConstants::CompressionAlgorithm::NOCOMPRESSION) {
                servicedata_ = MslCompression::uncompress(compressionAlgo_, *compressedServicedata_);
            } else {
                servicedata_ = compressedServicedata_;
            }
        } else {
            compressedServicedata_ = data;
            if (data->size() == 0)
            	servicedata_ = make_shared<ByteArray>();
            else
                servicedata_.reset();
        }
    } catch (const MslEncoderException& e) {
        MslEncodingException mex(MslError::MSL_PARSE_ERROR, string("servicetokendata ") + *Base64::encode(tokendataBytes_), e);
        mex.setMasterToken(masterToken);
        mex.setUserIdToken(userIdToken);
        throw mex;
    } catch (MslCryptoException& e) {
        e.setMasterToken(masterToken);
        e.setUserIdToken(userIdToken);
        throw e;
    }

    // Verify serial numbers.
    if (mtSerialNumber_ != -1 && (!masterToken || mtSerialNumber_ != masterToken->getSerialNumber())) {
        stringstream ss;
        ss << "st mtserialnumber " << mtSerialNumber_ << ";";
        if (masterToken)
            ss << "mt " << masterToken->toString();
        throw MslException(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, ss.str()).setMasterToken(masterToken).setUserIdToken(userIdToken);
    }
    if (uitSerialNumber_ != -1 && (!userIdToken || uitSerialNumber_ != userIdToken->getSerialNumber())) {
        stringstream ss;
        ss << "st uitserialnumber " << uitSerialNumber_ << "; uit " << userIdToken;
        throw MslException(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, ss.str()).setMasterToken(masterToken).setUserIdToken(userIdToken);
    }
}

bool ServiceToken::isBoundTo(std::shared_ptr<tokens::MasterToken> masterToken) const {
    return masterToken && masterToken->getSerialNumber() == mtSerialNumber_;
}

bool ServiceToken::isBoundTo(std::shared_ptr<tokens::UserIdToken> userIdToken) const {
    return userIdToken && userIdToken->getSerialNumber() == uitSerialNumber_;
}

shared_ptr<ByteArray> ServiceToken::toMslEncoding(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format) const
{
    // Return any cached encoding.
    map<MslEncoderFormat, shared_ptr<ByteArray>>::const_iterator it = encodings_.find(format);
    if (it != encodings_.end())
        return it->second;

    // If we parsed this token (i.e. did not create it from scratch) then
    // we should not re-encrypt or re-sign as there is no guarantee our MSL
    // crypto context is capable of encrypting and signing with the same
    // keys, even if it is capable of decrypting and verifying.
    shared_ptr<ByteArray> data, signature;
    if (tokendataBytes_ || signatureBytes_) {
        data = tokendataBytes_;
        signature = signatureBytes_;
    }
    //
    // Otherwise create the token data and signature.
    else {
        // Encrypt the service data if the length is > 0. Otherwise encode
        // as empty data to indicate this token should be deleted.
    	shared_ptr<ByteArray> ciphertext = make_shared<ByteArray>();
        try {
            if (encrypted_ && compressedServicedata_->size() > 0) {
                ciphertext = cryptoContext_->encrypt(compressedServicedata_, encoder, format);
            } else {
                ciphertext = compressedServicedata_;
            }
        } catch (const MslCryptoException& e) {
            throw MslEncoderException("Error encrypting the service data.", e);
        }

        // Construct the token data.
        shared_ptr<MslObject> tokendata = encoder->createObject();
        tokendata->put(KEY_NAME, name_);
        if (mtSerialNumber_ != -1)
            tokendata->put(KEY_MASTER_TOKEN_SERIAL_NUMBER, mtSerialNumber_);
        if (uitSerialNumber_ != -1)
            tokendata->put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, uitSerialNumber_);
        tokendata->put(KEY_ENCRYPTED, encrypted_);
        if (compressionAlgo_ != MslConstants::CompressionAlgorithm::NOCOMPRESSION)
            tokendata->put(KEY_COMPRESSION_ALGORITHM, compressionAlgo_.toString());
        tokendata->put(KEY_SERVICEDATA, ciphertext);

        // Sign the token data.
        data = encoder->encodeObject(tokendata, format);
        try {
            signature = cryptoContext_->sign(data, encoder, format);
        } catch (const MslCryptoException& e) {
            throw MslEncoderException("Error signing the token data.", e);
        }
    }

    // Encode the token.
    shared_ptr<MslObject> token = encoder->createObject();
    token->put(KEY_TOKENDATA, data);
    token->put(KEY_SIGNATURE, signature);
    shared_ptr<ByteArray> encoding = encoder->encodeObject(token, format);

    // Cache and return the encoding.
    encodings_.insert(make_pair(format, encoding));
    return encoding;
}

std::string ServiceToken::toString() const
{
    shared_ptr<MslEncoderFactory> encoder = ctx_->getMslEncoderFactory();

    shared_ptr<MslObject> tokendata = encoder->createObject();
    tokendata->put(KEY_NAME, name_);
    tokendata->put(KEY_MASTER_TOKEN_SERIAL_NUMBER, mtSerialNumber_);
    tokendata->put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, uitSerialNumber_);
    tokendata->put<shared_ptr<ByteArray>>(KEY_SERVICEDATA, servicedata_);

    shared_ptr<MslObject> token = encoder->createObject();
    token->put(KEY_TOKENDATA, tokendata);
    token->put<string>(KEY_SIGNATURE, "null");
    return token->toString();
}

string ServiceToken::uniqueKey() const
{
	stringstream ss;
	ss << name_ << ":" << mtSerialNumber_ << ":" << uitSerialNumber_;
	return ss.str();
}

bool ServiceToken::equals(shared_ptr<const ServiceToken> that) const
{
	if (!that) return false;
	if (this == that.get()) return true;
    return name_ == that->name_ &&
           mtSerialNumber_ == that->mtSerialNumber_ &&
           uitSerialNumber_ == that->uitSerialNumber_;
}

bool operator==(const ServiceToken& a, const ServiceToken& b)
{
	shared_ptr<const ServiceToken> ap(&a, &MslUtils::nullDeleter<ServiceToken>);
	shared_ptr<const ServiceToken> bp(&b, &MslUtils::nullDeleter<ServiceToken>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl::tokens
