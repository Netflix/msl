/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#include "MslError.h"
#include "MslConstants.h"
#include <MslInternalException.h>
#include <sstream>

using namespace netflix::msl::util;

namespace netflix {
namespace msl {

using namespace netflix::msl::MslConstants;

StaticMslMutex& MslError::internalCodesLock()
{
	static StaticMslMutex internalCodesLock;
	return internalCodesLock;
}
std::set<int>& MslError::internalCodes()
{
	static std::set<int> internalCodes;
	return internalCodes;
}

// 0 Message Security Layer
const MslError MslError::MSL_PARSE_ERROR(0, ResponseCode::FAIL, "Error parsing MSL encodable.");
const MslError MslError::MSL_ENCODE_ERROR(1, ResponseCode::FAIL, "Error encoding MSL encodable.");
const MslError MslError::ENVELOPE_HASH_MISMATCH(2, ResponseCode::FAIL, "Computed hash does not match envelope hash.");
const MslError MslError::INVALID_PUBLIC_KEY(3, ResponseCode::FAIL, "Invalid public key provided.");
const MslError MslError::INVALID_PRIVATE_KEY(4, ResponseCode::FAIL, "Invalid private key provided.");
const MslError MslError::PLAINTEXT_ILLEGAL_BLOCK_SIZE(5, ResponseCode::FAIL, "Plaintext is not a multiple of the block size.");
const MslError MslError::PLAINTEXT_BAD_PADDING(6, ResponseCode::FAIL, "Plaintext contains incorrect padding.");
const MslError MslError::CIPHERTEXT_ILLEGAL_BLOCK_SIZE(7, ResponseCode::FAIL, "Ciphertext is not a multiple of the block size.");
const MslError MslError::CIPHERTEXT_BAD_PADDING(8, ResponseCode::FAIL, "Ciphertext contains incorrect padding.");
const MslError MslError::ENCRYPT_NOT_SUPPORTED(9, ResponseCode::FAIL, "Encryption not supported.");
const MslError MslError::DECRYPT_NOT_SUPPORTED(10, ResponseCode::FAIL, "Decryption not supported.");
const MslError MslError::ENVELOPE_KEY_ID_MISMATCH(11, ResponseCode::FAIL, "Encryption envelope key ID does not match crypto context key ID.");
const MslError MslError::CIPHERTEXT_ENVELOPE_PARSE_ERROR(12, ResponseCode::FAIL, "Error parsing ciphertext envelope.");
const MslError MslError::CIPHERTEXT_ENVELOPE_ENCODE_ERROR(13, ResponseCode::FAIL, "Error encoding ciphertext envelope.");
const MslError MslError::SIGN_NOT_SUPPORTED(14, ResponseCode::FAIL, "Sign not supported.");
const MslError MslError::VERIFY_NOT_SUPPORTED(15, ResponseCode::FAIL, "Verify not supported.");
const MslError MslError::SIGNATURE_ERROR(16, ResponseCode::FAIL, "Signature not initialized or unable to process data/signature.");
const MslError MslError::HMAC_ERROR(17, ResponseCode::FAIL, "Error computing HMAC.");
const MslError MslError::ENCRYPT_ERROR(18, ResponseCode::FAIL, "Error encrypting plaintext.");
const MslError MslError::DECRYPT_ERROR(19, ResponseCode::FAIL, "Error decrypting ciphertext.");
const MslError MslError::INSUFFICIENT_CIPHERTEXT(20, ResponseCode::FAIL, "Insufficient ciphertext for decryption.");
const MslError MslError::SESSION_KEY_CREATION_FAILURE(21, ResponseCode::FAIL, "Error when creating session keys.");
const MslError MslError::INVALID_SYMMETRIC_KEY(24, ResponseCode::FAIL, "Invalid symmetric key.");
const MslError MslError::INVALID_ENCRYPTION_KEY(25, ResponseCode::FAIL, "Invalid encryption key.");
const MslError MslError::INVALID_HMAC_KEY(26, ResponseCode::FAIL, "Invalid HMAC key.");
const MslError MslError::WRAP_NOT_SUPPORTED(27, ResponseCode::FAIL, "Wrap not supported.");
const MslError MslError::UNWRAP_NOT_SUPPORTED(28, ResponseCode::FAIL, "Unwrap not supported.");
const MslError MslError::UNIDENTIFIED_JWK_TYPE(29, ResponseCode::FAIL, "Unidentified JSON web key type.");
const MslError MslError::UNIDENTIFIED_JWK_USAGE(30, ResponseCode::FAIL, "Unidentified JSON web key usage.");
const MslError MslError::UNIDENTIFIED_JWK_ALGORITHM(31, ResponseCode::FAIL, "Unidentified JSON web key algorithm.");
const MslError MslError::WRAP_ERROR(32, ResponseCode::FAIL, "Error wrapping plaintext.");
const MslError MslError::UNWRAP_ERROR(33, ResponseCode::FAIL, "Error unwrapping ciphertext.");
const MslError MslError::INVALID_JWK(34, ResponseCode::FAIL, "Invalid JSON web key.");
const MslError MslError::INVALID_JWK_KEYDATA(35, ResponseCode::FAIL, "Invalid JSON web key keydata.");
const MslError MslError::UNSUPPORTED_JWK_ALGORITHM(36, ResponseCode::FAIL, "Unsupported JSON web key algorithm.");
const MslError MslError::WRAP_KEY_CREATION_FAILURE(37, ResponseCode::FAIL, "Error when creating wrapping key.");
const MslError MslError::INVALID_WRAP_CIPHERTEXT(38, ResponseCode::FAIL, "Invalid wrap ciphertext.");
const MslError MslError::UNSUPPORTED_JWE_ALGORITHM(39, ResponseCode::FAIL, "Unsupported JSON web encryption algorithm.");
const MslError MslError::JWE_ENCODE_ERROR(40, ResponseCode::FAIL, "Error encoding JSON web encryption header.");
const MslError MslError::JWE_PARSE_ERROR(41, ResponseCode::FAIL, "Error parsing JSON web encryption header.");
const MslError MslError::INVALID_ALGORITHM_PARAMS(42, ResponseCode::FAIL, "Invalid algorithm parameters.");
const MslError MslError::JWE_ALGORITHM_MISMATCH(43, ResponseCode::FAIL, "JSON web encryption header algorithms mismatch.");
const MslError MslError::KEY_IMPORT_ERROR(44, ResponseCode::FAIL, "Error importing key.");
const MslError MslError::KEY_EXPORT_ERROR(45, ResponseCode::FAIL, "Error exporting key.");
const MslError MslError::DIGEST_ERROR(46, ResponseCode::FAIL, "Error in digest.");
const MslError MslError::UNSUPPORTED_KEY(47, ResponseCode::FAIL, "Unsupported key type or algorithm.");
const MslError MslError::UNSUPPORTED_JWE_SERIALIZATION(48, ResponseCode::FAIL, "Unsupported JSON web encryption serialization.");
const MslError MslError::INVALID_WRAPPING_KEY(51, ResponseCode::FAIL, "Invalid wrapping key.");
const MslError MslError::UNIDENTIFIED_CIPHERTEXT_ENVELOPE(52, ResponseCode::FAIL, "Unidentified ciphertext envelope version.");
const MslError MslError::UNIDENTIFIED_SIGNATURE_ENVELOPE(53, ResponseCode::FAIL, "Unidentified signature envelope version.");
const MslError MslError::UNSUPPORTED_CIPHERTEXT_ENVELOPE(54, ResponseCode::FAIL, "Unsupported ciphertext envelope version.");
const MslError MslError::UNSUPPORTED_SIGNATURE_ENVELOPE(55, ResponseCode::FAIL, "Unsupported signature envelope version.");
const MslError MslError::UNIDENTIFIED_CIPHERSPEC(56, ResponseCode::FAIL, "Unidentified cipher specification.");
const MslError MslError::UNIDENTIFIED_ALGORITHM(57, ResponseCode::FAIL, "Unidentified algorithm.");
const MslError MslError::SIGNATURE_ENVELOPE_PARSE_ERROR(58, ResponseCode::FAIL, "Error parsing signature envelope.");
const MslError MslError::SIGNATURE_ENVELOPE_ENCODE_ERROR(59, ResponseCode::FAIL, "Error encoding signature envelope.");
const MslError MslError::INVALID_SIGNATURE(60, ResponseCode::FAIL, "Invalid signature.");
const MslError MslError::DERIVEKEY_ERROR(61, ResponseCode::FAIL, "Error deriving key.");
const MslError MslError::UNIDENTIFIED_JWK_KEYOP(62, ResponseCode::FAIL, "Unidentified JSON web key key operation.");
const MslError MslError::GENERATEKEY_ERROR(63, ResponseCode::FAIL, "Error generating key.");
const MslError MslError::INVALID_IV(64, ResponseCode::FAIL, "Invalid initialization vector.");
const MslError MslError::INVALID_CIPHERTEXT(65, ResponseCode::FAIL, "Invalid ciphertext.");
const MslError MslError::DATA_TOO_LARGE(66, ResponseCode::FAIL, "Data too large.");
const MslError MslError::CRYPTO_ERROR(67, ResponseCode::FAIL, "Unspecified crypto error.");

// 1 Master Token
const MslError MslError::MASTERTOKEN_UNTRUSTED(1000, ResponseCode::ENTITY_REAUTH, "Master token is not trusted.");
const MslError MslError::MASTERTOKEN_KEY_CREATION_ERROR(1001, ResponseCode::ENTITY_REAUTH, "Unable to construct symmetric keys from master token.");
const MslError MslError::MASTERTOKEN_EXPIRES_BEFORE_RENEWAL(1002, ResponseCode::ENTITY_REAUTH, "Master token expiration timestamp is before the renewal window opens.");
const MslError MslError::MASTERTOKEN_SESSIONDATA_MISSING(1003, ResponseCode::ENTITY_REAUTH, "No master token session data found.");
const MslError MslError::MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE(1004, ResponseCode::ENTITY_REAUTH, "Master token sequence number is out of range.");
const MslError MslError::MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE(1005, ResponseCode::ENTITY_REAUTH, "Master token serial number is out of range.");
const MslError MslError::MASTERTOKEN_TOKENDATA_INVALID(1006, ResponseCode::ENTITY_REAUTH, "Invalid master token data.");
const MslError MslError::MASTERTOKEN_SIGNATURE_INVALID(1007, ResponseCode::ENTITY_REAUTH, "Invalid master token signature.");
const MslError MslError::MASTERTOKEN_SESSIONDATA_INVALID(1008, ResponseCode::ENTITY_REAUTH, "Invalid master token session data.");
const MslError MslError::MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_SYNC(1009, ResponseCode::ENTITY_REAUTH, "Master token sequence number does not have the expected value.");
const MslError MslError::MASTERTOKEN_TOKENDATA_MISSING(1010, ResponseCode::ENTITY_REAUTH, "No master token data found.");
const MslError MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR(1011, ResponseCode::ENTITY_REAUTH, "Error parsing master token data.");
const MslError MslError::MASTERTOKEN_SESSIONDATA_PARSE_ERROR(1012, ResponseCode::ENTITY_REAUTH, "Error parsing master token session data.");
const MslError MslError::MASTERTOKEN_IDENTITY_REVOKED(1013, ResponseCode::ENTITY_REAUTH, "Master token entity identity is revoked.");
const MslError MslError::MASTERTOKEN_REJECTED_BY_APP(1014, ResponseCode::ENTITY_REAUTH, "Master token is rejected by the application.");
const MslError MslError::MASTERTOKEN_ISSUERDATA_ENCODE_ERROR(1015, ResponseCode::FAIL, "Master token issuer data encoding error.");

// 2 User ID Token
const MslError MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH(2000, ResponseCode::USER_REAUTH, "User ID token master token serial number does not match master token serial number.");
const MslError MslError::USERIDTOKEN_NOT_DECRYPTED(2001, ResponseCode::USER_REAUTH, "User ID token is not decrypted or verified.");
const MslError MslError::USERIDTOKEN_MASTERTOKEN_NULL(2002, ResponseCode::USER_REAUTH, "User ID token requires a master token.");
const MslError MslError::USERIDTOKEN_EXPIRES_BEFORE_RENEWAL(2003, ResponseCode::USER_REAUTH, "User ID token expiration timestamp is before the renewal window opens.");
const MslError MslError::USERIDTOKEN_USERDATA_MISSING(2004, ResponseCode::USER_REAUTH, "No user ID token user data found.");
const MslError MslError::USERIDTOKEN_MASTERTOKEN_NOT_FOUND(2005, ResponseCode::USER_REAUTH, "User ID token is bound to an unknown master token.");
const MslError MslError::USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE(2006, ResponseCode::USER_REAUTH, "User ID token master token serial number is out of range.");
const MslError MslError::USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE(2007, ResponseCode::USER_REAUTH, "User ID token serial number is out of range.");
const MslError MslError::USERIDTOKEN_TOKENDATA_INVALID(2008, ResponseCode::USER_REAUTH, "Invalid user ID token data.");
const MslError MslError::USERIDTOKEN_SIGNATURE_INVALID(2009, ResponseCode::USER_REAUTH, "Invalid user ID token signature.");
const MslError MslError::USERIDTOKEN_USERDATA_INVALID(2010, ResponseCode::USER_REAUTH, "Invalid user ID token user data.");
const MslError MslError::USERIDTOKEN_IDENTITY_INVALID(2011, ResponseCode::USER_REAUTH, "Invalid user ID token user identity.");
const MslError MslError::RESERVED_2012(2012, ResponseCode::USER_REAUTH, "The entity is not associated with the user.");
const MslError MslError::USERIDTOKEN_USERAUTH_DATA_MISMATCH(2015, ResponseCode::USER_REAUTH, "The user ID token and user authentication data user identities do not match.");
const MslError MslError::USERIDTOKEN_TOKENDATA_MISSING(2016, ResponseCode::USER_REAUTH, "No user ID token data found.");
const MslError MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR(2017, ResponseCode::USER_REAUTH, "Error parsing user ID token data.");
const MslError MslError::USERIDTOKEN_USERDATA_PARSE_ERROR(2018, ResponseCode::USER_REAUTH, "Error parsing user ID token user data.");
const MslError MslError::USERIDTOKEN_REVOKED(2019, ResponseCode::USER_REAUTH, "User ID token is revoked.");
const MslError MslError::USERIDTOKEN_REJECTED_BY_APP(2020, ResponseCode::USERDATA_REAUTH, "User ID token is rejected by the application.");

// 3 Service Token
const MslError MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH(3000, ResponseCode::FAIL, "Service token master token serial number does not match master token serial number.");
const MslError MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH(3001, ResponseCode::FAIL, "Service token user ID token serial number does not match user ID token serial number.");
const MslError MslError::SERVICETOKEN_SERVICEDATA_INVALID(3002, ResponseCode::FAIL, "Service token data invalid.");
const MslError MslError::SERVICETOKEN_MASTERTOKEN_NOT_FOUND(3003, ResponseCode::FAIL, "Service token is bound to an unknown master token.");
const MslError MslError::SERVICETOKEN_USERIDTOKEN_NOT_FOUND(3004, ResponseCode::FAIL, "Service token is bound to an unknown user ID token.");
const MslError MslError::SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE(3005, ResponseCode::FAIL, "Service token master token serial number is out of range.");
const MslError MslError::SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE(3006, ResponseCode::FAIL, "Service token user ID token serial number is out of range.");
const MslError MslError::SERVICETOKEN_TOKENDATA_INVALID(3007, ResponseCode::FAIL, "Invalid service token data.");
const MslError MslError::SERVICETOKEN_SIGNATURE_INVALID(3008, ResponseCode::FAIL, "Invalid service token signature.");
const MslError MslError::SERVICETOKEN_TOKENDATA_MISSING(3009, ResponseCode::FAIL, "No service token data found.");

// 4 Entity Authentication
const MslError MslError::UNIDENTIFIED_ENTITYAUTH_SCHEME(4000, ResponseCode::FAIL, "Unable to identify entity authentication scheme.");
const MslError MslError::ENTITYAUTH_FACTORY_NOT_FOUND(4001, ResponseCode::FAIL, "No factory registered for entity authentication scheme.");
const MslError MslError::X509CERT_PARSE_ERROR(4002, ResponseCode::ENTITYDATA_REAUTH, "Error parsing X.509 certificate data.");
const MslError MslError::X509CERT_ENCODE_ERROR(4003, ResponseCode::ENTITYDATA_REAUTH, "Error encoding X.509 certificate data.");
const MslError MslError::X509CERT_VERIFICATION_FAILED(4004, ResponseCode::ENTITYDATA_REAUTH, "X.509 certificate verification failed.");
const MslError MslError::ENTITY_NOT_FOUND(4005, ResponseCode::FAIL, "Entity not recognized.");
const MslError MslError::INCORRECT_ENTITYAUTH_DATA(4006, ResponseCode::FAIL, "Entity used incorrect entity authentication data type.");
const MslError MslError::RSA_PUBLICKEY_NOT_FOUND(4007, ResponseCode::ENTITYDATA_REAUTH, "RSA public key not found.");
const MslError MslError::UNSUPPORTED_ENTITYAUTH_DATA(4023, ResponseCode::FAIL, "Unsupported entity authentication data.");
const MslError MslError::ENTITY_REVOKED(4025, ResponseCode::FAIL, "Entity is revoked.");
const MslError MslError::ENTITY_REJECTED_BY_APP(4026, ResponseCode::ENTITYDATA_REAUTH, "Entity is rejected by the application.");
const MslError MslError::X509CERT_EXPIRED(4028, ResponseCode::ENTITYDATA_REAUTH, "X.509 certificate is expired.");
const MslError MslError::X509CERT_NOT_YET_VALID(4029, ResponseCode::ENTITYDATA_REAUTH, "X.509 certificate is not yet valid.");
const MslError MslError::X509CERT_INVALID(4030, ResponseCode::ENTITYDATA_REAUTH, "X.509 certificate is invalid.");
const MslError MslError::RSA_PRIVATEKEY_NOT_FOUND(4031, ResponseCode::ENTITYDATA_REAUTH, "RSA private key not found.");
const MslError MslError::ENTITYAUTH_MASTERTOKEN_NOT_DECRYPTED(4032, ResponseCode::FAIL, "Entity authentication data master token is not decrypted or verified.");
const MslError MslError::ENTITYAUTH_SIGNATURE_INVALID(4033, ResponseCode::ENTITYDATA_REAUTH, "Invalid entity authentication data signature.");
const MslError MslError::ENTITYAUTH_CIPHERTEXT_INVALID(4034, ResponseCode::ENTITYDATA_REAUTH, "Invalid entity authentication data ciphertext.");
const MslError MslError::ENTITYAUTH_VERIFICATION_FAILED(4035, ResponseCode::ENTITYDATA_REAUTH, "Entity authentication data signature verification failed.");
const MslError MslError::ENTITYAUTH_MASTERTOKEN_INVALID(4036, ResponseCode::FAIL, "Invalid entity authentication data master token.");
const MslError MslError::ECC_PUBLICKEY_NOT_FOUND(4037, ResponseCode::ENTITYDATA_REAUTH, "ECC public key not found.");
const MslError MslError::ECC_PRIVATEKEY_NOT_FOUND(4038, ResponseCode::ENTITYDATA_REAUTH, "ECC private key not found.");


// 5 User Authentication
const MslError MslError::UNIDENTIFIED_USERAUTH_SCHEME(5003, ResponseCode::FAIL, "Unable to identify user authentication scheme.");
const MslError MslError::USERAUTH_FACTORY_NOT_FOUND(5004, ResponseCode::FAIL, "No factory registered for user authentication scheme.");
const MslError MslError::EMAILPASSWORD_BLANK(5005, ResponseCode::USERDATA_REAUTH, "Email or password is blank.");
const MslError MslError::EMAILPASSWORD_INCORRECT(5007, ResponseCode::USERDATA_REAUTH, "Email or password is incorrect.");
const MslError MslError::UNSUPPORTED_USERAUTH_DATA(5008, ResponseCode::FAIL, "Unsupported user authentication data.");
const MslError MslError::USERAUTH_USERIDTOKEN_INVALID(5011, ResponseCode::USERDATA_REAUTH, "User authentication data user ID token is invalid.");
const MslError MslError::UNIDENTIFIED_USERAUTH_MECHANISM(5013, ResponseCode::FAIL, "Unable to identify user authentication mechanism.");
const MslError MslError::UNSUPPORTED_USERAUTH_MECHANISM(5014, ResponseCode::FAIL, "Unsupported user authentication mechanism.");
const MslError MslError::USERAUTH_MASTERTOKEN_MISSING(5016, ResponseCode::USERDATA_REAUTH, "User authentication required master token is missing.");
const MslError MslError::USERAUTH_USERIDTOKEN_NOT_DECRYPTED(5021, ResponseCode::USERDATA_REAUTH, "User authentication data user ID token is not decrypted or verified.");
const MslError MslError::USERAUTH_MASTERTOKEN_INVALID(5024, ResponseCode::USERDATA_REAUTH, "User authentication data master token is invalid.");
const MslError MslError::USERAUTH_MASTERTOKEN_NOT_DECRYPTED(5025, ResponseCode::USERDATA_REAUTH, "User authentication data master token is not decrypted or verified.");
const MslError MslError::USERAUTH_USERIDTOKEN_MISSING(5030, ResponseCode::USERDATA_REAUTH, "User authentication required user ID token is missing.");
const MslError MslError::USERAUTH_ENTITY_MISMATCH(5032, ResponseCode::USERDATA_REAUTH, "User authentication data does not match entity identity.");
const MslError MslError::USERAUTH_ENTITY_INCORRECT_DATA(5033, ResponseCode::FAIL, "Entity used incorrect user authentication data type.");
const MslError MslError::USER_REJECTED_BY_APP(5037, ResponseCode::USERDATA_REAUTH, "User is rejected by the application.");
const MslError MslError::USERIDTOKEN_IDENTITY_NOT_ASSOCIATED_WITH_ENTITY(5040, ResponseCode::USERDATA_REAUTH, "The entity is not associated with the user.");
const MslError MslError::USERAUTH_ENTITYUSER_INCORRECT_DATA(5041, ResponseCode::USERDATA_REAUTH, "Entity and user combination used incorrect user authentication data type.");
const MslError MslError::USERAUTH_VERIFICATION_FAILED(5042, ResponseCode::USERDATA_REAUTH, "User authentication data signature verification failed.");
const MslError MslError::USERAUTH_USERIDTOKEN_REVOKE_CHECK_ERROR(5043, ResponseCode::USERDATA_REAUTH, "User ID token could not be checked for revocation.");

// 6 Message
const MslError MslError::UNSUPPORTED_COMPRESSION(6000, ResponseCode::FAIL, "Unsupported compression algorithm.");
const MslError MslError::COMPRESSION_ERROR(6001, ResponseCode::FAIL, "Error compressing data.");
const MslError MslError::UNCOMPRESSION_ERROR(6002, ResponseCode::FAIL, "Error uncompressing data.");
const MslError MslError::MESSAGE_ENTITY_NOT_FOUND(6003, ResponseCode::FAIL, "Message header entity authentication data or master token not found.");
const MslError MslError::PAYLOAD_MESSAGE_ID_MISMATCH(6004, ResponseCode::FAIL, "Payload chunk message ID does not match header message ID .");
const MslError MslError::PAYLOAD_SEQUENCE_NUMBER_MISMATCH(6005, ResponseCode::FAIL, "Payload chunk sequence number does not match expected sequence number.");
const MslError MslError::PAYLOAD_VERIFICATION_FAILED(6006, ResponseCode::FAIL, "Payload chunk payload signature verification failed.");
const MslError MslError::MESSAGE_DATA_MISSING(6007, ResponseCode::FAIL, "No message data found.");
const MslError MslError::MESSAGE_FORMAT_ERROR(6008, ResponseCode::FAIL, "Malformed message data.");
const MslError MslError::MESSAGE_VERIFICATION_FAILED(6009, ResponseCode::FAIL, "Message header/error data signature verification failed.");
const MslError MslError::HEADER_DATA_MISSING(6010, ResponseCode::FAIL, "No header data found.");
const MslError MslError::PAYLOAD_DATA_MISSING(6011, ResponseCode::FAIL, "No payload data found in non-EOM payload chunk.");
const MslError MslError::PAYLOAD_DATA_CORRUPT(6012, ResponseCode::FAIL, "Corrupt payload data found in non-EOM payload chunk.");
const MslError MslError::UNIDENTIFIED_COMPRESSION(6013, ResponseCode::FAIL, "Unidentified compression algorithm.");
const MslError MslError::MESSAGE_EXPIRED(6014, ResponseCode::EXPIRED, "Message expired and not renewable or missing key request data. Rejected.");
const MslError MslError::MESSAGE_ID_OUT_OF_RANGE(6015, ResponseCode::FAIL, "Message ID is is out of range.");
const MslError MslError::INTERNAL_CODE_NEGATIVE(6016, ResponseCode::FAIL, "Error header internal code is negative.");
const MslError MslError::UNEXPECTED_RESPONSE_MESSAGE_ID(6017, ResponseCode::FAIL, "Unexpected response message ID. Possible replay.");
const MslError MslError::RESPONSE_REQUIRES_ENCRYPTION(6018, ResponseCode::KEYX_REQUIRED, "Message response requires encryption.");
const MslError MslError::PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE(6019, ResponseCode::FAIL, "Payload chunk sequence number is out of range.");
const MslError MslError::PAYLOAD_MESSAGE_ID_OUT_OF_RANGE(6020, ResponseCode::FAIL, "Payload chunk message ID is out of range.");
const MslError MslError::MESSAGE_REPLAYED(6021, ResponseCode::REPLAYED, "Non-replayable message replayed.");
const MslError MslError::INCOMPLETE_NONREPLAYABLE_MESSAGE(6022, ResponseCode::FAIL, "Non-replayable message sent without a master token.");
const MslError MslError::HEADER_SIGNATURE_INVALID(6023, ResponseCode::FAIL, "Invalid Header signature.");
const MslError MslError::HEADER_DATA_INVALID(6024, ResponseCode::FAIL, "Invalid header data.");
const MslError MslError::PAYLOAD_INVALID(6025, ResponseCode::FAIL, "Invalid payload.");
const MslError MslError::PAYLOAD_SIGNATURE_INVALID(6026, ResponseCode::FAIL, "Invalid payload signature.");
const MslError MslError::RESPONSE_REQUIRES_MASTERTOKEN(6027, ResponseCode::KEYX_REQUIRED, "Message response requires a master token.");
const MslError MslError::RESPONSE_REQUIRES_USERIDTOKEN(6028, ResponseCode::USER_REAUTH, "Message response requires a user ID token.");
const MslError MslError::REQUEST_REQUIRES_USERAUTHDATA(6029, ResponseCode::FAIL, "User-associated message requires user authentication data.");
const MslError MslError::UNEXPECTED_MESSAGE_SENDER(6030, ResponseCode::FAIL, "Message sender is not the master token entity.");
const MslError MslError::NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN(6031, ResponseCode::FAIL, "Non-replayable message requires a master token.");
const MslError MslError::NONREPLAYABLE_ID_OUT_OF_RANGE(6032, ResponseCode::FAIL, "Non-replayable message non-replayable ID is out of range.");
const MslError MslError::MESSAGE_SERVICETOKEN_MISMATCH(6033, ResponseCode::FAIL, "Service token master token or user ID token serial number does not match the message token serial numbers.");
const MslError MslError::MESSAGE_PEER_SERVICETOKEN_MISMATCH(6034, ResponseCode::FAIL, "Peer service token master token or user ID token serial number does not match the message peer token serial numbers.");
const MslError MslError::RESPONSE_REQUIRES_INTEGRITY_PROTECTION(6035, ResponseCode::KEYX_REQUIRED, "Message response requires integrity protection.");
const MslError MslError::HANDSHAKE_DATA_MISSING(6036, ResponseCode::FAIL, "Handshake message is not renewable or does not contain key request data.");
const MslError MslError::MESSAGE_RECIPIENT_MISMATCH(6037, ResponseCode::FAIL, "Message recipient does not match local identity.");
const MslError MslError::MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED(6038, ResponseCode::ENTITYDATA_REAUTH, "Message header entity-based signature verification failed.");
const MslError MslError::MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED(6039, ResponseCode::ENTITY_REAUTH, "Message header master token-based signature verification failed.");
const MslError MslError::MESSAGE_REPLAYED_UNRECOVERABLE(6040, ResponseCode::ENTITY_REAUTH, "Non-replayable message replayed with a sequence number that is too far out of sync to recover.");
const MslError MslError::UNEXPECTED_LOCAL_MESSAGE_SENDER(6041, ResponseCode::FAIL, "Message sender is equal to the local entity.");
const MslError MslError::UNENCRYPTED_MESSAGE_WITH_USERAUTHDATA(6042, ResponseCode::FAIL, "User authentication data included in unencrypted message header.");
const MslError MslError::MESSAGE_SENDER_MISMATCH(6043, ResponseCode::FAIL, "Message sender entity identity does not match expected identity.");
const MslError MslError::MESSAGE_EXPIRED_NOT_RENEWABLE(6044, ResponseCode::EXPIRED, "Message expired and not renewable. Rejected.");
const MslError MslError::MESSAGE_EXPIRED_NO_KEYREQUEST_DATA(6045, ResponseCode::EXPIRED, "Message expired and missing key request data. Rejected.");

// 7 Key Exchange
const MslError MslError::UNIDENTIFIED_KEYX_SCHEME(7000, ResponseCode::FAIL, "Unable to identify key exchange scheme.");
const MslError MslError::KEYX_FACTORY_NOT_FOUND(7001, ResponseCode::FAIL, "No factory registered for key exchange scheme.");
const MslError MslError::KEYX_REQUEST_NOT_FOUND(7002, ResponseCode::FAIL, "No key request found matching header key response data.");
const MslError MslError::UNIDENTIFIED_KEYX_KEY_ID(7003, ResponseCode::FAIL, "Unable to identify key exchange key ID.");
const MslError MslError::UNSUPPORTED_KEYX_KEY_ID(7004, ResponseCode::FAIL, "Unsupported key exchange key ID.");
const MslError MslError::UNIDENTIFIED_KEYX_MECHANISM(7005, ResponseCode::FAIL, "Unable to identify key exchange mechanism.");
const MslError MslError::UNSUPPORTED_KEYX_MECHANISM(7006, ResponseCode::FAIL, "Unsupported key exchange mechanism.");
const MslError MslError::KEYX_RESPONSE_REQUEST_MISMATCH(7007, ResponseCode::FAIL, "Key exchange response does not match request.");
const MslError MslError::KEYX_PRIVATE_KEY_MISSING(7008, ResponseCode::FAIL, "Key exchange private key missing.");
const MslError MslError::UNKNOWN_KEYX_PARAMETERS_ID(7009, ResponseCode::FAIL, "Key exchange parameters ID unknown or invalid.");
const MslError MslError::KEYX_MASTER_TOKEN_MISSING(7010, ResponseCode::FAIL, "Master token required for key exchange is missing.");
const MslError MslError::KEYX_INVALID_PUBLIC_KEY(7011, ResponseCode::FAIL, "Key exchange public key is invalid.");
const MslError MslError::KEYX_PUBLIC_KEY_MISSING(7012, ResponseCode::FAIL, "Key exchange public key missing.");
const MslError MslError::KEYX_WRAPPING_KEY_MISSING(7013, ResponseCode::FAIL, "Key exchange wrapping key missing.");
const MslError MslError::KEYX_WRAPPING_KEY_ID_MISSING(7014, ResponseCode::FAIL, "Key exchange wrapping key ID missing.");
const MslError MslError::KEYX_INVALID_WRAPPING_KEY(7015, ResponseCode::FAIL, "Key exchange wrapping key is invalid.");
const MslError MslError::KEYX_INCORRECT_DATA(7016, ResponseCode::FAIL, "Entity used incorrect key exchange data type.");
const MslError MslError::KEYX_INCORRECT_MECHANISM(7017, ResponseCode::FAIL, "Entity used incorrect key exchange mechanism.");
const MslError MslError::KEYX_DERIVATION_KEY_MISSING(7018, ResponseCode::FAIL, "Key exchange derivation key missing.");
const MslError MslError::KEYX_INVALID_ENCRYPTION_KEY(7019, ResponseCode::FAIL, "Key exchange encryption key is invalid.");
const MslError MslError::KEYX_INVALID_HMAC_KEY(7020, ResponseCode::FAIL, "Key exchange HMAC key is invalid.");
const MslError MslError::KEYX_INVALID_WRAPDATA(7021, ResponseCode::FAIL, "Key exchange wrap data is invalid.");
const MslError MslError::UNSUPPORTED_KEYX_SCHEME(7022, ResponseCode::FAIL, "Unsupported key exchange scheme.");
const MslError MslError::KEYX_IDENTITY_NOT_FOUND (7023, ResponseCode::FAIL, "Key exchange identity not found.");

// 9 Internal Errors
const MslError MslError::INTERNAL_EXCEPTION(9000, ResponseCode::TRANSIENT_FAILURE, "Internal exception.");
const MslError MslError::MSL_COMMS_FAILURE(9001, ResponseCode::FAIL, "Error communicating with MSL entity.");
const MslError MslError::NONE(9999, ResponseCode::FAIL, "Special unit test error.");

// No error
const MslError MslError::OK(-1, ResponseCode::FAIL, "");

MslError::MslError(int internalCode, const ResponseCode& responseCode, const std::string& msg)
    : internalCode_(internalCode), responseCode_(responseCode), msg_(msg)
{
    // Check for duplicates.
    synchronized (internalCodesLock(),
    {
        if (internalCodes().count(internalCode)) {
            std::stringstream ss;
            ss << "Duplicate MSL error definition for error code " << internalCode << ".";
            throw MslInternalException(ss.str());
        }
        internalCodes().insert(internalCode);
    });

    internalCode_ = BASE + internalCode;
}

MslError::MslError(const MslError& other)
: internalCode_(other.internalCode_)
, responseCode_(other.responseCode_)
, msg_(other.msg_)
{
}

MslError& MslError::operator=(const MslError& other)
{
    internalCode_ = other.internalCode_;
    responseCode_ = other.responseCode_;
    msg_ = other.msg_;
    return *this;
}

std::ostream & operator<<(std::ostream& os, const MslError& me)
{
    return os << "MslError{" << me.internalCode_ << "," << me.responseCode_.intValue() << "," << me.msg_ << "}";
}

}} // namespace netflix::msl
