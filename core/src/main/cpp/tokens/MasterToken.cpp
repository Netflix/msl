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

#include <tokens/MasterToken.h>
#include <Date.h>
#include <crypto/Key.h>
#include <crypto/ICryptoContext.h>
#include <crypto/JcaAlgorithm.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslVariant.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <util/Base64.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>

using namespace std;
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
/** Key expiration timestamp. */
const string KEY_EXPIRATION = "expiration";
/** Key sequence number. */
const string KEY_SEQUENCE_NUMBER = "sequencenumber";
/** Key serial number. */
const string KEY_SERIAL_NUMBER = "serialnumber";
/** Key session data. */
const string KEY_SESSIONDATA = "sessiondata";

// sessiondata
/** Key issuer data. */
const string KEY_ISSUER_DATA = "issuerdata";
/** Key identity. */
const string KEY_IDENTITY = "identity";
/** Key symmetric encryption key. */
const string KEY_ENCRYPTION_KEY = "encryptionkey";
/** Key encryption algorithm. */
const string KEY_ENCRYPTION_ALGORITHM = "encryptionalgorithm";
/** Key symmetric HMAC key. */
const string KEY_HMAC_KEY = "hmackey";
/** Key signature key. */
const string KEY_SIGNATURE_KEY = "signaturekey";
/** Key signature algorithm. */
const string KEY_SIGNATURE_ALGORITHM = "signaturealgorithm";

string moErrStr(const string& msg, shared_ptr<MslObject> mo)
{
    stringstream ss;
    ss << msg << " " << mo->toString();
    return ss.str();
}

} // namespace anonymous

MasterToken::MasterToken(shared_ptr<util::MslContext> ctx,
        shared_ptr<Date> renewalWindow,
        shared_ptr<Date> expiration,
        int64_t sequenceNumber,
        int64_t serialNumber,
        shared_ptr<MslObject> issuerData,
        const string& identity,
        const crypto::SecretKey& encryptionKey,
        const crypto::SecretKey& signatureKey)
    : ctx_(ctx)
    , renewalWindow_(renewalWindow->getTime() / MILLISECONDS_PER_SECOND)
    , expiration_(expiration->getTime() / MILLISECONDS_PER_SECOND)
    , sequenceNumber_(sequenceNumber)
    , serialNumber_(serialNumber)
    , issuerdata_(issuerData ? issuerData : shared_ptr<MslObject>())
    , identity_(identity)
    , encryptionKey_(encryptionKey)
    , signatureKey_(signatureKey)
    , verified_(true)
{
    assert(ctx);

    // The expiration must appear after the renewal window.
    if (expiration->before(renewalWindow))
        throw MslInternalException("Cannot construct a master token that expires before its renewal window opens.");
    // The sequence number and serial number must be within range.
    if (sequenceNumber_ < 0ll || sequenceNumber_ > MslConstants::MAX_LONG_VALUE) {
        stringstream ss;
        ss << "Sequence number " << sequenceNumber_ << " is outside the valid range.";
        throw MslInternalException(ss.str());
    }
    if (serialNumber_ < 0ll || serialNumber_ > MslConstants::MAX_LONG_VALUE) {
        stringstream ss;
        ss << "Serial number " << serialNumber_ << " is outside the valid range.";
        throw MslInternalException(ss.str());
    }

    // Encode algorithm names and session keys.
    MslConstants::EncryptionAlgo encryptionAlgo;
    MslConstants::SignatureAlgo signatureAlgo;
    try {
        encryptionAlgo = MslConstants::EncryptionAlgo::fromString(encryptionKey_.getAlgorithm());
        signatureAlgo = MslConstants::SignatureAlgo::fromString(signatureKey_.getAlgorithm());
    } catch (const IllegalArgumentException& e) {
        throw MslCryptoException(MslError::UNIDENTIFIED_ALGORITHM, "encryption algorithm: " + encryptionKey_.getAlgorithm() + "; signature algorithm: " + signatureKey_.getAlgorithm(), e);
    }
    shared_ptr<ByteArray> encryptionKeyBytes = encryptionKey_.getEncoded();
    shared_ptr<ByteArray> signatureKeyBytes = signatureKey_.getEncoded();

    // Create session data.
    shared_ptr<MslEncoderFactory> encoder = ctx_->getMslEncoderFactory();
    sessiondata_ = encoder->createObject();
    if (issuerdata_)
        sessiondata_->put(KEY_ISSUER_DATA, issuerdata_);
    sessiondata_->put<string>(KEY_IDENTITY, identity_);
    sessiondata_->put<shared_ptr<ByteArray>>(KEY_ENCRYPTION_KEY, encryptionKeyBytes);
    sessiondata_->put<string>(KEY_ENCRYPTION_ALGORITHM, encryptionAlgo.toString());
    sessiondata_->put<shared_ptr<ByteArray>>(KEY_HMAC_KEY, signatureKeyBytes);
    sessiondata_->put<shared_ptr<ByteArray>>(KEY_SIGNATURE_KEY, signatureKeyBytes);
    sessiondata_->put<string>(KEY_SIGNATURE_ALGORITHM, signatureAlgo.toString());

    verified_ = true;
}

MasterToken::MasterToken(shared_ptr<util::MslContext> ctx, shared_ptr<MslObject> masterTokenMo)
    : ctx_(ctx)
    , renewalWindow_(-1)
    , expiration_(-1)
    , sequenceNumber_(-1)
    , serialNumber_(-1)
	, issuerdata_(shared_ptr<MslObject>())
//    , identity_()       // rely on default ctors for other members
//    , encryptionKey_()
//    , signatureKey_()
    , verified_(false)
{
    assert(ctx);

    if (!masterTokenMo)
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "Input MslObject is empty");

    // Grab the crypto context.
    std::shared_ptr<crypto::ICryptoContext> cryptoContext;
    try {
        cryptoContext = ctx_->getMslCryptoContext();
    } catch (const MslCryptoException& e) {
        throw MslEncoderException("Error creating the MSL crypto context.", e);
    }

    // Verify the encoding.
    std::shared_ptr<MslEncoderFactory> encoder = ctx_->getMslEncoderFactory();
    try {
        tokendataBytes_ = masterTokenMo->getBytes(KEY_TOKENDATA);
        if (tokendataBytes_->empty())
            throw MslEncodingException(MslError::MASTERTOKEN_TOKENDATA_MISSING, moErrStr("mastertoken ", masterTokenMo));
        signatureBytes_ = masterTokenMo->getBytes(KEY_SIGNATURE);
        verified_ = cryptoContext->verify(tokendataBytes_, signatureBytes_, encoder);  // FIXME pass encoder as shared ptr??
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, moErrStr("mastertoken", masterTokenMo), e);
    }

    // Pull the token data.
    shared_ptr<ByteArray> plaintext;
    try {
        shared_ptr<MslObject> tokendata = encoder->parseObject(tokendataBytes_);
        renewalWindow_ = tokendata->getLong(KEY_RENEWAL_WINDOW);
        expiration_ = tokendata->getLong(KEY_EXPIRATION);
        if (expiration_ < renewalWindow_)
            throw MslException(MslError::MASTERTOKEN_EXPIRES_BEFORE_RENEWAL, moErrStr("mastertokendata", tokendata));
        sequenceNumber_ = tokendata->getLong(KEY_SEQUENCE_NUMBER);
        if (sequenceNumber_ < 0 || sequenceNumber_ > MslConstants::MAX_LONG_VALUE)
            throw MslException(MslError::MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE, moErrStr("mastertokendata", tokendata));
        serialNumber_ = tokendata->getLong(KEY_SERIAL_NUMBER);
        if (serialNumber_ < 0 || serialNumber_ > MslConstants::MAX_LONG_VALUE)
            throw MslException(MslError::MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, moErrStr("mastertokendata", tokendata));
        shared_ptr<ByteArray> ciphertext = tokendata->getBytes(KEY_SESSIONDATA);
        if (ciphertext->empty())
            throw MslEncodingException(MslError::MASTERTOKEN_SESSIONDATA_MISSING, moErrStr("mastertokendata", tokendata));
        if (verified_) {
            plaintext = cryptoContext->decrypt(ciphertext, encoder);
        }
    } catch (const MslEncoderException& e) {
        stringstream ss;
        ss << "mastertokendata " << Base64::encode(tokendataBytes_);
        throw MslEncodingException(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, ss.str(), e);
    }

    // Pull the session data.
    if (plaintext) {
    	shared_ptr<ByteArray> rawEncryptionKey, rawSignatureKey;
        string encryptionAlgo, signatureAlgo;
        try {
            sessiondata_ = encoder->parseObject(plaintext);
            if (sessiondata_->has(KEY_ISSUER_DATA))
                issuerdata_ = sessiondata_->getMslObject(KEY_ISSUER_DATA, encoder);
            identity_ = sessiondata_->getString(KEY_IDENTITY);
            rawEncryptionKey = sessiondata_->getBytes(KEY_ENCRYPTION_KEY);
            encryptionAlgo = sessiondata_->optString(KEY_ENCRYPTION_ALGORITHM, crypto::JcaAlgorithm::AES);
            rawSignatureKey = (sessiondata_->has(KEY_SIGNATURE_KEY))
                ? sessiondata_->getBytes(KEY_SIGNATURE_KEY)
                : sessiondata_->getBytes(KEY_HMAC_KEY);
            signatureAlgo = sessiondata_->optString(KEY_SIGNATURE_ALGORITHM, crypto::JcaAlgorithm::HMAC_SHA256);
        } catch (const MslEncoderException& e) {
            stringstream ss;
            ss << "sessiondata " << Base64::encode(plaintext);
            throw MslEncodingException(MslError::MASTERTOKEN_SESSIONDATA_PARSE_ERROR, ss.str(), e);
        }

        // Decode algorithm names.
        string jcaEncryptionAlgo, jcaSignatureAlgo;
        try {
            jcaEncryptionAlgo = MslConstants::EncryptionAlgo::fromString(encryptionAlgo).toString();
            jcaSignatureAlgo = MslConstants::SignatureAlgo::fromString(signatureAlgo).toString();
        } catch (const IllegalArgumentException& e) {
            stringstream ss;
            ss << "encryption algorithm: " << encryptionAlgo << "; signature algorithm" << signatureAlgo;
            throw MslCryptoException(MslError::UNIDENTIFIED_ALGORITHM, ss.str(), e);
        }

        // Reconstruct keys.
        try {
            encryptionKey_ = crypto::SecretKey(rawEncryptionKey, jcaEncryptionAlgo);
            signatureKey_ = crypto::SecretKey(rawSignatureKey, jcaSignatureAlgo);
        } catch (const IllegalArgumentException& e) {
            throw MslCryptoException(MslError::MASTERTOKEN_KEY_CREATION_ERROR, e);
        }
    }
}

bool MasterToken::isRenewable(shared_ptr<Date> now) const
{
	if (now)
		return renewalWindow_ * MILLISECONDS_PER_SECOND <= now->getTime();
	if (isVerified())
		return renewalWindow_ * MILLISECONDS_PER_SECOND <= ctx_->getTime();
	return true;
}

shared_ptr<Date> MasterToken::getRenewalWindow() const
{
    return make_shared<Date>(renewalWindow_ * MILLISECONDS_PER_SECOND);
}

bool MasterToken::isExpired(shared_ptr<Date> now) const
{
	if (now)
		return expiration_ * MILLISECONDS_PER_SECOND <= now->getTime();
	if (isVerified())
		return expiration_ * MILLISECONDS_PER_SECOND <= ctx_->getTime();
	return false;
}

shared_ptr<Date> MasterToken::getExpiration() const
{
    return make_shared<Date>(expiration_ * MILLISECONDS_PER_SECOND);
}

/**
 * <p>A master token is considered newer if its sequence number is greater
 * than another master token. If both the sequence numbers are equal, then
 * the master token with the later expiration date is considered newer.</p>
 *
 * <p>Serial numbers are not taken into consideration when comparing which
 * master token is newer because serial numbers will change when new master
 * tokens are created as opposed to renewed. The caller of this function
 * should already be comparing master tokens that can be used
 * interchangeably (i.e. for the same MSL network).</p>
 *
 * @param that the master token to compare with.
 * @return true if this master token is newer than the provided one.
 */
bool MasterToken::isNewerThan(shared_ptr<MasterToken> that) const
{
    // If the sequence numbers are equal then compare the expiration dates.
    if (sequenceNumber_ == that->sequenceNumber_)
        return expiration_ > that->expiration_;

    // If this sequence number is bigger than that sequence number, make
    // sure that sequence number is not less than the cutoff.
    if (sequenceNumber_ > that->sequenceNumber_) {
        const int64_t cutoff = sequenceNumber_ - MslConstants::MAX_LONG_VALUE + 127;
        return that->sequenceNumber_ >= cutoff;
    }

    // If this sequence number is smaller than that sequence number, make
    // sure this sequence number is less than the cutoff.
    const int64_t cutoff = that->sequenceNumber_ - MslConstants::MAX_LONG_VALUE + 127;
    return sequenceNumber_ < cutoff;
}

shared_ptr<ByteArray> MasterToken::toMslEncoding(shared_ptr<MslEncoderFactory> encoder,
        const MslEncoderFormat& format) const
{
    // Return any cached encoding.
    map<io::MslEncoderFormat, shared_ptr<ByteArray>>::const_iterator it = encodings_.find(format);
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
        std::shared_ptr<crypto::ICryptoContext> cryptoContext;
        try {
            cryptoContext = ctx_->getMslCryptoContext();
        } catch (const MslCryptoException& e) {
            throw MslEncoderException("Error creating the MSL crypto context.", e);
        }

        // Encrypt the session data.
        shared_ptr<ByteArray> plaintext = encoder->encodeObject(sessiondata_, format);
        shared_ptr<ByteArray> ciphertext;
        try {
            ciphertext = cryptoContext->encrypt(plaintext, encoder, format);
        } catch (const MslCryptoException& e) {
            throw MslEncoderException("Error encrypting the session data.", e);
        }

        // Construct the token data.
        shared_ptr<MslObject> tokendata = encoder->createObject();
        tokendata->put<int64_t>(KEY_RENEWAL_WINDOW, renewalWindow_);
        tokendata->put<int64_t>(KEY_EXPIRATION, expiration_);
        tokendata->put<int64_t>(KEY_SEQUENCE_NUMBER, sequenceNumber_);
        tokendata->put<int64_t>(KEY_SERIAL_NUMBER, serialNumber_);
        tokendata->put<shared_ptr<ByteArray>>(KEY_SESSIONDATA, ciphertext);

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
    token->put<shared_ptr<ByteArray>>(KEY_TOKENDATA, data);
    token->put<shared_ptr<ByteArray>>(KEY_SIGNATURE, signature);
    shared_ptr<ByteArray> encoding = encoder->encodeObject(token, format);

    // Cache and return the encoding.
    encodings_.insert(make_pair(format, encoding));
    return encoding;
}

string MasterToken::toString() const
{
    shared_ptr<MslEncoderFactory> encoder = ctx_->getMslEncoderFactory();

    shared_ptr<MslObject> sessiondata = encoder->createObject();
    if (isDecrypted()) {
        if (issuerdata_)
            sessiondata->put(KEY_ISSUER_DATA, issuerdata_);
        sessiondata->put<string>(KEY_IDENTITY, identity_);
        sessiondata->put<shared_ptr<ByteArray>>(KEY_ENCRYPTION_KEY, encryptionKey_.getEncoded());
        sessiondata->put<string>(KEY_ENCRYPTION_ALGORITHM, encryptionKey_.getAlgorithm());
        sessiondata->put<shared_ptr<ByteArray>>(KEY_HMAC_KEY, signatureKey_.getEncoded());
        sessiondata->put<shared_ptr<ByteArray>>(KEY_SIGNATURE_KEY, signatureKey_.getEncoded());
        sessiondata->put<string>(KEY_SIGNATURE_ALGORITHM, signatureKey_.getAlgorithm());
    }

    shared_ptr<MslObject> tokendata = encoder->createObject();
    tokendata->put<int64_t>(KEY_RENEWAL_WINDOW, renewalWindow_);
    tokendata->put<int64_t>(KEY_EXPIRATION, expiration_);
    tokendata->put<int64_t>(KEY_SEQUENCE_NUMBER, sequenceNumber_);
    tokendata->put<int64_t>(KEY_SERIAL_NUMBER, serialNumber_);
    tokendata->put(KEY_SESSIONDATA, sessiondata);

    shared_ptr<MslObject> token = encoder->createObject();
    token->put(KEY_TOKENDATA, tokendata);
    token->put(KEY_SIGNATURE, VariantFactory::createNull());
    return token->toString();
}

string MasterToken::uniqueKey() const
{
	stringstream ss;
	ss << serialNumber_ << ":" << sequenceNumber_ << ":" << expiration_;
	return ss.str();
}

bool MasterToken::equals(shared_ptr<const MasterToken> other) const
{
    if (!other) return false;
    if (this == other.get()) return true;
    return ( (serialNumber_ == other->serialNumber_) &&
             (sequenceNumber_ == other->sequenceNumber_) &&
             (expiration_ == other->expiration_)
           );
}

bool operator==(const MasterToken& a, const MasterToken& b)
{
    shared_ptr<const MasterToken> ap(&a, &MslUtils::nullDeleter<MasterToken>);
    shared_ptr<const MasterToken> bp(&b, &MslUtils::nullDeleter<MasterToken>);
    return ap->equals(bp);
}

}}} // namespace netflix::msl::tokens
