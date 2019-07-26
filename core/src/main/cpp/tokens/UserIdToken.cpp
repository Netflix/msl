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

#include <crypto/ICryptoContext.h>
#include <tokens/UserIdToken.h>
#include <Date.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <MslInternalException.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslException.h>
#include <tokens/MasterToken.h>
#include <tokens/MslUser.h>
#include <tokens/TokenFactory.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <sstream>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace tokens {

namespace {

/** Milliseconds per second. */
const int64_t MILLISECONDS_PER_SECOND = 1000;

/** Key token data. */
const string KEY_TOKENDATA = "tokendata";
/** Key signature. */
const string KEY_SIGNATURE = "signature";

// tokendata
/** Key renewal window timestamp. */
const string KEY_RENEWAL_WINDOW = "renewalwindow";
/** Key expiration_ timestamp. */
const string KEY_EXPIRATION = "expiration";
/** Key master token serial number. */
const string KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
/** Key user ID token serial number. */
const string KEY_SERIAL_NUMBER = "serialnumber";
/** Key token user data. */
const string KEY_USERDATA = "userdata";

// userdata_
/** Key issuer data. */
const string KEY_ISSUER_DATA = "issuerdata";
/** Key identity. */
const string KEY_IDENTITY = "identity";

} // namespace anonymous

UserIdToken::UserIdToken(shared_ptr<MslContext> ctx, shared_ptr<Date> renewalWindow,
        shared_ptr<Date> expiration, shared_ptr<MasterToken> masterToken, int64_t serialNumber,
        shared_ptr<MslObject> issuerData, shared_ptr<MslUser> user)
    : ctx_(ctx)
    , renewalWindow_(renewalWindow->getTime() / MILLISECONDS_PER_SECOND)
    , expiration_(expiration->getTime() / MILLISECONDS_PER_SECOND)
    , mtSerialNumber_(masterToken ? masterToken->getSerialNumber() : -1)
    , serialNumber_(serialNumber)
    , issuerdata_(issuerData)
    , user_(user)
    , verified_(true)
{
    assert(ctx_);
    assert(user_);

    // The expiration_ must appear after the renewal window.
    if (expiration->before(renewalWindow))
        throw MslInternalException("Cannot construct a user ID token that expires before its renewal window opens.");
    // A master token must be provided.
    if (!masterToken)
        throw MslInternalException("Cannot construct a user ID token without a master token.");
    // The serial number must be within range.
    if (serialNumber_ < 0 || serialNumber_ > MslConstants::MAX_LONG_VALUE) {
        stringstream ss;
        ss << "Serial number " << serialNumber_ << " is outside the valid range.";
        throw MslInternalException(ss.str());
    }

    // Construct the user data.
    shared_ptr<MslEncoderFactory> encoder = ctx_->getMslEncoderFactory();
    userdata_ = encoder->createObject();
    if (issuerdata_)
        userdata_->put(KEY_ISSUER_DATA, issuerdata_);
    userdata_->put(KEY_IDENTITY, user_->getEncoded());
}

UserIdToken::UserIdToken(shared_ptr<MslContext> ctx, shared_ptr<MslObject> userIdTokenMo,
        shared_ptr<MasterToken> masterToken)
    : ctx_(ctx)
    , renewalWindow_(0ll)
    , expiration_(0ll)
    , mtSerialNumber_(masterToken ? masterToken->getSerialNumber() : -1)
    , serialNumber_(-1)
    , verified_(false)
{
    assert(ctx_);

    // Grab the crypto context and encoder->
    shared_ptr<crypto::ICryptoContext> cryptoContext = ctx_->getMslCryptoContext();
    shared_ptr<io::MslEncoderFactory> encoder = ctx_->getMslEncoderFactory();

    if (!userIdTokenMo)
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "null useridtoken").setMasterToken(masterToken);

    // Verify the encoding.
    try {
        tokendataBytes_ = userIdTokenMo->getBytes(KEY_TOKENDATA);
        if (tokendataBytes_->empty()) {
            stringstream ss;
            ss << "useridtoken " << userIdTokenMo;
            throw MslEncodingException(MslError::USERIDTOKEN_TOKENDATA_MISSING, ss.str()).setMasterToken(masterToken);
        }
        signatureBytes_ = userIdTokenMo->getBytes(KEY_SIGNATURE);
        verified_ = cryptoContext->verify(tokendataBytes_, signatureBytes_, encoder);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "useridtoken " + userIdTokenMo->toString(), e).setMasterToken(masterToken);
    }

    // Pull the token data.
    shared_ptr<ByteArray> plaintext;
    try {
        shared_ptr<MslObject> tokendata = encoder->parseObject(tokendataBytes_);
        renewalWindow_ = tokendata->getLong(KEY_RENEWAL_WINDOW);
        expiration_ = tokendata->getLong(KEY_EXPIRATION);
        if (expiration_ < renewalWindow_)
            throw MslException(MslError::USERIDTOKEN_EXPIRES_BEFORE_RENEWAL, "usertokendata " + tokendata->toString()).setMasterToken(masterToken);
        mtSerialNumber_ = tokendata->getLong(KEY_MASTER_TOKEN_SERIAL_NUMBER);
        if (mtSerialNumber_ < 0 || mtSerialNumber_ > MslConstants::MAX_LONG_VALUE)
            throw MslException(MslError::USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokendata->toString()).setMasterToken(masterToken);
        serialNumber_ = tokendata->getLong(KEY_SERIAL_NUMBER);
        if (serialNumber_ < 0 || serialNumber_ > MslConstants::MAX_LONG_VALUE)
            throw MslException(MslError::USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokendata->toString()).setMasterToken(masterToken);
        shared_ptr<ByteArray> ciphertext = tokendata->getBytes(KEY_USERDATA);
        if (ciphertext->empty())
            throw MslException(MslError::USERIDTOKEN_USERDATA_MISSING).setMasterToken(masterToken);
        if (verified_) {
            plaintext = cryptoContext->decrypt(ciphertext, encoder);
        }
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, "usertokendata " + *Base64::encode(tokendataBytes_), e).setMasterToken(masterToken);
    } catch (const MslCryptoException& e) {
        throw MslCryptoException(e).setMasterToken(masterToken);
    }

    // Pull the user data.
    if (plaintext) {
        try {
            userdata_ = encoder->parseObject(plaintext);
            if (userdata_->has(KEY_ISSUER_DATA))
                issuerdata_ = userdata_->getMslObject(KEY_ISSUER_DATA, encoder);
            const string identity = userdata_->getString(KEY_IDENTITY);
            if (identity.empty())
                throw MslException(MslError::USERIDTOKEN_IDENTITY_INVALID, "userdata_ " + userdata_->toString()).setMasterToken(masterToken);
            shared_ptr<TokenFactory> factory = ctx->getTokenFactory();
            user_ = factory->createUser(ctx_, identity);
            if (!user_)
                throw MslInternalException("TokenFactory.createUser() returned null in violation of the interface contract.");
        } catch (const MslEncoderException& e) {
            throw MslEncodingException(MslError::USERIDTOKEN_USERDATA_PARSE_ERROR, "userdata_ " + *Base64::encode(plaintext), e).setMasterToken(masterToken);
        }
    }

    // Verify serial numbers.
    if (!masterToken || (mtSerialNumber_ != masterToken->getSerialNumber())) {
        stringstream ss;
        ss << "uit mtserialnumber " << mtSerialNumber_ << "; mt " << masterToken;
        throw MslException(MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH, ss.str()).setMasterToken(masterToken);
    }
}

shared_ptr<Date> UserIdToken::getRenewalWindow() const
{
    return make_shared<Date>(renewalWindow_ * MILLISECONDS_PER_SECOND);
}

bool UserIdToken::isRenewable(shared_ptr<Date> now) const
{
	if (now)
		return renewalWindow_ * MILLISECONDS_PER_SECOND <= now->getTime();
	if (isVerified())
		return renewalWindow_ * MILLISECONDS_PER_SECOND <= ctx_->getTime();
	return true;
}

shared_ptr<Date> UserIdToken::getExpiration() const
{
    return make_shared<Date>(expiration_ * MILLISECONDS_PER_SECOND);
}

bool UserIdToken::isExpired(shared_ptr<Date> now) const
{
	if (now)
		return expiration_ * MILLISECONDS_PER_SECOND <= now->getTime();
    if (isVerified())
    	return expiration_ * MILLISECONDS_PER_SECOND <= ctx_->getTime();
    return false;
}

bool UserIdToken::isBoundTo(shared_ptr<MasterToken> masterToken)
{
    return masterToken && masterToken->getSerialNumber() == mtSerialNumber_;
}

shared_ptr<ByteArray> UserIdToken::toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder,
        const io::MslEncoderFormat& format) const
{
    // Return any cached encoding.
    const map<MslEncoderFormat, shared_ptr<ByteArray>>::const_iterator it = encodings_.find(format);
    if (it != encodings_.end())
        return it->second;

    // If we parsed this token (i.e. did not create it from scratch) then
    // we should not re-encrypt or re-sign as there is no guarantee out MSL
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
        // Grab the MSL token crypto context.
        shared_ptr<ICryptoContext> cryptoContext;
        try {
            cryptoContext = ctx_->getMslCryptoContext();
        } catch (const MslCryptoException& e) {
            throw MslEncoderException("Error creating the MSL crypto context.", e);
        }

        // Encrypt the user data.
        shared_ptr<ByteArray> plaintext = encoder->encodeObject(userdata_, format);
        shared_ptr<ByteArray> ciphertext;
        try {
            ciphertext = cryptoContext->encrypt(plaintext, encoder, format);
        } catch (const MslCryptoException& e) {
            throw MslEncoderException("Error encrypting the user data.", e);
        }

        // Construct the token data.
        shared_ptr<MslObject> tokendata = encoder->createObject();
        tokendata->put(KEY_RENEWAL_WINDOW, renewalWindow_);
        tokendata->put(KEY_EXPIRATION, expiration_);
        tokendata->put(KEY_MASTER_TOKEN_SERIAL_NUMBER, mtSerialNumber_);
        tokendata->put(KEY_SERIAL_NUMBER, serialNumber_);
        tokendata->put(KEY_USERDATA, ciphertext);

        // Sign the token data.
        data = encoder->encodeObject(tokendata, format);
        try {
            signature = cryptoContext->sign(data, encoder, format);
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

string UserIdToken::toString() const
{
    shared_ptr<MslEncoderFactory> encoder = ctx_->getMslEncoderFactory();

    shared_ptr<MslObject> userdataMo = encoder->createObject();
    if (isDecrypted()) {
        if (issuerdata_)
            userdataMo->put(KEY_ISSUER_DATA, issuerdata_);
        userdataMo->put<string>(KEY_IDENTITY, user_->getEncoded());  // java version just uses default Object.toString here
    }

    shared_ptr<MslObject> tokendataMo = encoder->createObject();
    tokendataMo->put(KEY_RENEWAL_WINDOW, renewalWindow_);
    tokendataMo->put(KEY_EXPIRATION, expiration_);
    tokendataMo->put(KEY_MASTER_TOKEN_SERIAL_NUMBER, mtSerialNumber_);
    tokendataMo->put(KEY_SERIAL_NUMBER, serialNumber_);
    tokendataMo->put(KEY_USERDATA, userdataMo);

    MslObject mslObj;
    mslObj.put(KEY_TOKENDATA, tokendataMo);
    mslObj.put<string>(KEY_SIGNATURE, "");
    return mslObj.toString();
}

string UserIdToken::uniqueKey() const
{
	stringstream ss;
	ss << serialNumber_ << ":" << mtSerialNumber_;
	return ss.str();
}

/**
 * @param obj the reference object with which to compare.
 * @return true if the other object is a user ID token with the same serial
 *         number bound to the same master token.
 * @see java.lang.Object#equals(java.lang.Object)
 */
bool UserIdToken::equals(shared_ptr<const UserIdToken> other) const
{
    if (!other) return false;
    if (this == other.get()) return true;
    return serialNumber_   == other->serialNumber_    &&
           mtSerialNumber_ == other->mtSerialNumber_;
}

bool operator==(const UserIdToken& a, const UserIdToken& b)
{
	shared_ptr<const UserIdToken> ap(&a, &MslUtils::nullDeleter<UserIdToken>);
	shared_ptr<const UserIdToken> bp(&b, &MslUtils::nullDeleter<UserIdToken>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl::tokens
