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

#include <msg/ErrorHeader.h>
#include <crypto/ICryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationFactory.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <msg/HeaderKeys.h>
#include <io/MslEncoderFactory.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <MslMessageException.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <sstream>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace msg {

namespace {
/** Milliseconds per second. */
const int64_t MILLISECONDS_PER_SECOND = 1000;

// Message error data.
/** Key timestamp. */
const string KEY_TIMESTAMP = "timestamp";
/** Key message ID. */
const string KEY_MESSAGE_ID = "messageid";
/** Key error code. */
const string KEY_ERROR_CODE = "errorcode";
/** Key internal code. */
const string KEY_INTERNAL_CODE = "internalcode";
/** Key error message. */
const string KEY_ERROR_MESSAGE = "errormsg";
/** Key user message. */
const string KEY_USER_MESSAGE = "usermsg";

} // namespace anonymous

ErrorHeader::ErrorHeader(shared_ptr<MslContext> ctx, shared_ptr<EntityAuthenticationData> entityAuthData,
        int64_t messageId, const MslConstants::ResponseCode& errorCode,
        int32_t internalCode, const string& errorMsg, const string& userMsg)
    : ctx_(ctx)
    , entityAuthData_(entityAuthData)
    , timestamp_(ctx->getTime() / MILLISECONDS_PER_SECOND)
    , messageId_(messageId)
    , errorCode_(errorCode)
    , internalCode_((internalCode >= 0) ? internalCode : -1)
    , errorMsg_(errorMsg)
    , userMsg_(userMsg)
{
    // Message ID must be within range.
    if (messageId < 0 || messageId > MslConstants::MAX_LONG_VALUE) {
        stringstream ss;
        ss << "Message ID " << messageId << " is out of range.";
        throw MslInternalException(ss.str());
    }

    // Message entity must be provided.
    if (!entityAuthData)
        throw MslMessageException(MslError::MESSAGE_ENTITY_NOT_FOUND);

    // Construct the error data.
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
    errordata_ = encoder->createObject();
    errordata_->put(KEY_TIMESTAMP, timestamp_);
    errordata_->put(KEY_MESSAGE_ID, messageId_);
    errordata_->put(KEY_ERROR_CODE, errorCode_.value());
    if (internalCode_ > 0) errordata_->put(KEY_INTERNAL_CODE, internalCode_);
    if (!errorMsg_.empty()) errordata_->put(KEY_ERROR_MESSAGE, errorMsg_);
    if (!userMsg_.empty()) errordata_->put(KEY_USER_MESSAGE, userMsg_);
}

ErrorHeader::ErrorHeader(shared_ptr<MslContext> ctx, shared_ptr<ByteArray> errordataBytes,
        shared_ptr<EntityAuthenticationData> entityAuthData, shared_ptr<ByteArray> signature)
{
    ctx_ = ctx;

    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();

    shared_ptr<ByteArray> plaintext;
    try {
        // Validate the entity authentication data.
        entityAuthData_ = entityAuthData;
        if (!entityAuthData)
            throw MslMessageException(MslError::MESSAGE_ENTITY_NOT_FOUND);

        // Grab the entity crypto context.
        const EntityAuthenticationScheme scheme = entityAuthData->getScheme();
        shared_ptr<EntityAuthenticationFactory> factory = ctx->getEntityAuthenticationFactory(scheme);
        if (!factory)
            throw MslEntityAuthException(MslError::ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
        shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(ctx, entityAuthData);

        // Verify and decrypt the error data.
        if (!cryptoContext->verify(errordataBytes, signature, encoder))
            throw MslCryptoException(MslError::MESSAGE_VERIFICATION_FAILED).setEntityAuthenticationData(entityAuthData);
        plaintext = cryptoContext->decrypt(errordataBytes, encoder);
    } catch (MslCryptoException& e) {
        e.setEntityAuthenticationData(entityAuthData);
        throw e;
    } catch (MslEntityAuthException& e) {
        e.setEntityAuthenticationData(entityAuthData);
        throw e;
    }

    try {
        errordata_ = encoder->parseObject(plaintext);
        messageId_ = errordata_->getLong(KEY_MESSAGE_ID);
        if (messageId_ < 0 || messageId_ > MslConstants::MAX_LONG_VALUE)
            throw MslMessageException(MslError::MESSAGE_ID_OUT_OF_RANGE, "errordata " + errordata_->toString()).setEntityAuthenticationData(entityAuthData_);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "errordata " + *Base64::encode(plaintext), e).setEntityAuthenticationData(entityAuthData_);
    }

    try {
        timestamp_ = (errordata_->has(KEY_TIMESTAMP)) ? errordata_->getLong(KEY_TIMESTAMP) : -1;

        // If we do not recognize the error code then default to fail.
        MslConstants::ResponseCode code = MslConstants::ResponseCode::FAIL;
        try {
            code = MslConstants::ResponseCode::valueOf(errordata_->getInt(KEY_ERROR_CODE));
        } catch (const IllegalArgumentException& e) {
            code = MslConstants::ResponseCode::FAIL;
        }
        errorCode_ = code;

        if (errordata_->has(KEY_INTERNAL_CODE)) {
            internalCode_ = errordata_->getInt(KEY_INTERNAL_CODE);
            if (internalCode_ < 0)
                throw MslMessageException(MslError::INTERNAL_CODE_NEGATIVE, "errordata " + errordata_->toString()).setEntityAuthenticationData(entityAuthData_).setMessageId(messageId_);
        } else {
            internalCode_ = -1;
        }
        errorMsg_ = errordata_->optString(KEY_ERROR_MESSAGE, string());
        userMsg_ = errordata_->optString(KEY_USER_MESSAGE, string());
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "errordata " + errordata_->toString(), e).setEntityAuthenticationData(entityAuthData_).setMessageId(messageId_);
    }
}

shared_ptr<Date> ErrorHeader::getTimestamp() const
{
    return (timestamp_ != -1) ? make_shared<Date>(timestamp_ * MILLISECONDS_PER_SECOND) : shared_ptr<Date>();
}

shared_ptr<ByteArray> ErrorHeader::toMslEncoding(shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const
{
    // Return any cached encoding.
    std::map<io::MslEncoderFormat, shared_ptr<ByteArray>>::const_iterator it = encodings_.find(format);
    if (it != encodings_.end())
        return it->second;

    // Create the crypto context.
    const EntityAuthenticationScheme scheme = entityAuthData_->getScheme();
    shared_ptr<EntityAuthenticationFactory> factory = ctx_->getEntityAuthenticationFactory(scheme);
    if (!factory)
        throw MslEncoderException("No entity authentication factory found for entity.");
    shared_ptr<ICryptoContext> cryptoContext;
    try {
        cryptoContext = factory->getCryptoContext(ctx_, entityAuthData_);
    } catch (const MslEntityAuthException& e) {
        throw MslEncoderException("Error creating the entity crypto context.", e);
    } catch (const MslCryptoException& e) {
        throw MslEncoderException("Error creating the entity crypto context.", e);
    }

    // Encrypt and sign the error data.
    shared_ptr<ByteArray> plaintext = encoder->encodeObject(errordata_, format);
    shared_ptr<ByteArray> ciphertext;
    try {
    	ciphertext = cryptoContext->encrypt(plaintext, encoder, format);
    } catch (const MslCryptoException& e) {
    	throw MslEncoderException("Error encrypting the error data.", e);
    }
    shared_ptr<ByteArray> signature;
    try {
    	signature = cryptoContext->sign(ciphertext, encoder, format);
    } catch (const MslCryptoException& e) {
    	throw MslEncoderException("Error signing the error data.", e);
    }

    // Create the encoding.
    shared_ptr<MslObject> header = encoder->createObject();
    header->put<shared_ptr<MslEncodable>>(HeaderKeys::KEY_ENTITY_AUTHENTICATION_DATA, entityAuthData_);
    header->put(HeaderKeys::KEY_ERRORDATA, ciphertext);
    header->put(HeaderKeys::KEY_SIGNATURE, signature);
    shared_ptr<ByteArray> encoding = encoder->encodeObject(header, format);

    // Cache and return the encoding.
    encodings_.insert(make_pair(format, encoding));
    return encoding;
}

// In this translation unit, make comparisons of shared_ptr defer to the
// underlying type's operator==.
template <typename T>
bool operator==(const shared_ptr<T>& a, const shared_ptr<T>& b)
{
    if (!a && !b)
        return true;
    if ((!a && b) || (a && !b))
        return false;
    return *a == *b;
}

bool ErrorHeader::equals(shared_ptr<const Header> obj) const
{
	if (!obj) return false;
	if (this == obj.get()) return true;
    if (!instanceof<const ErrorHeader>(obj)) return false;
    shared_ptr<const ErrorHeader> that = dynamic_pointer_cast<const ErrorHeader>(obj);
    // Don't need to check shared_ptr for null, since templated operator==() above does this.
    return (entityAuthData_ == that->entityAuthData_) &&
			(timestamp_ == that->timestamp_) &&
			(messageId_ == that->messageId_) &&
			(errorCode_ == that->errorCode_) &&
			(internalCode_ == that->internalCode_) &&
			(errorMsg_ == that->errorMsg_) &&
			(userMsg_ == that->userMsg_);
}

bool operator==(const ErrorHeader& a, const ErrorHeader& b)
{
	shared_ptr<const ErrorHeader> ap(&a, &MslUtils::nullDeleter<ErrorHeader>);
	shared_ptr<const ErrorHeader> bp(&b, &MslUtils::nullDeleter<ErrorHeader>);
	return ap->equals(bp);
}

ostream& operator<<(ostream& os, const ErrorHeader& /*header*/)
{
	// FIXME
	return os << "placeholder";
}

ostream& operator<<(ostream& os, shared_ptr<ErrorHeader> header)
{
	return os << *header;
}

}}} // namespace netflix::msl::msg
