/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl;

import java.util.HashSet;
import java.util.Set;

import com.netflix.msl.MslConstants.ResponseCode;

/**
 * <p>Message Security Layer error codes and descriptions.</p>
 *
 * <p>Errors are defined with an internal and a response error code. The
 * internal error code is specific to this implementation. The response error
 * codes are sent in error messages to inform the remote entity, who should use
 * it to decide on the correct error handling behavior.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslError {
    /** Internal error code set. */
    private static final Set<Integer> internalCodes = new HashSet<Integer>();

    // 0 Message Security Layer
    public static final MslError MSL_PARSE_ERROR = new MslError(0, ResponseCode.FAIL, "Error parsing MSL encodable.");
    public static final MslError MSL_ENCODE_ERROR = new MslError(1, ResponseCode.FAIL, "Error encoding MSL encodable.");
    public static final MslError ENVELOPE_HASH_MISMATCH = new MslError(2, ResponseCode.FAIL, "Computed hash does not match envelope hash.");
    public static final MslError INVALID_PUBLIC_KEY = new MslError(3, ResponseCode.FAIL, "Invalid public key provided.");
    public static final MslError INVALID_PRIVATE_KEY = new MslError(4, ResponseCode.FAIL, "Invalid private key provided.");
    public static final MslError PLAINTEXT_ILLEGAL_BLOCK_SIZE = new MslError(5, ResponseCode.FAIL, "Plaintext is not a multiple of the block size.");
    public static final MslError PLAINTEXT_BAD_PADDING = new MslError(6, ResponseCode.FAIL, "Plaintext contains incorrect padding.");
    public static final MslError CIPHERTEXT_ILLEGAL_BLOCK_SIZE = new MslError(7, ResponseCode.FAIL, "Ciphertext is not a multiple of the block size.");
    public static final MslError CIPHERTEXT_BAD_PADDING = new MslError(8, ResponseCode.FAIL, "Ciphertext contains incorrect padding.");
    public static final MslError ENCRYPT_NOT_SUPPORTED = new MslError(9, ResponseCode.FAIL, "Encryption not supported.");
    public static final MslError DECRYPT_NOT_SUPPORTED = new MslError(10, ResponseCode.FAIL, "Decryption not supported.");
    public static final MslError ENVELOPE_KEY_ID_MISMATCH = new MslError(11, ResponseCode.FAIL, "Encryption envelope key ID does not match crypto context key ID.");
    public static final MslError CIPHERTEXT_ENVELOPE_PARSE_ERROR = new MslError(12, ResponseCode.FAIL, "Error parsing ciphertext envelope.");
    public static final MslError CIPHERTEXT_ENVELOPE_ENCODE_ERROR = new MslError(13, ResponseCode.FAIL, "Error encoding ciphertext envelope.");
    public static final MslError SIGN_NOT_SUPPORTED = new MslError(14, ResponseCode.FAIL, "Sign not supported.");
    public static final MslError VERIFY_NOT_SUPPORTED = new MslError(15, ResponseCode.FAIL, "Verify not suppoprted.");
    public static final MslError SIGNATURE_ERROR = new MslError(16, ResponseCode.FAIL, "Signature not initialized or unable to process data/signature.");
    public static final MslError HMAC_ERROR = new MslError(17, ResponseCode.FAIL, "Error computing HMAC.");
    public static final MslError ENCRYPT_ERROR = new MslError(18, ResponseCode.FAIL, "Error encrypting plaintext.");
    public static final MslError DECRYPT_ERROR = new MslError(19, ResponseCode.FAIL, "Error decrypting ciphertext.");
    public static final MslError INSUFFICIENT_CIPHERTEXT = new MslError(20, ResponseCode.FAIL, "Insufficient ciphertext for decryption.");
    public static final MslError SESSION_KEY_CREATION_FAILURE = new MslError(21, ResponseCode.FAIL, "Error when creating session keys.");
    public static final MslError INVALID_SYMMETRIC_KEY = new MslError(24, ResponseCode.FAIL, "Invalid symmetric key.");
    public static final MslError INVALID_ENCRYPTION_KEY = new MslError(25, ResponseCode.FAIL, "Invalid encryption key.");
    public static final MslError INVALID_HMAC_KEY = new MslError(26, ResponseCode.FAIL, "Invalid HMAC key.");
    public static final MslError WRAP_NOT_SUPPORTED = new MslError(27, ResponseCode.FAIL, "Wrap not supported.");
    public static final MslError UNWRAP_NOT_SUPPORTED = new MslError(28, ResponseCode.FAIL, "Unwrap not supported.");
    public static final MslError UNIDENTIFIED_JWK_TYPE = new MslError(29, ResponseCode.FAIL, "Unidentified JSON web key type.");
    public static final MslError UNIDENTIFIED_JWK_USAGE = new MslError(30, ResponseCode.FAIL, "Unidentified JSON web key usage.");
    public static final MslError UNIDENTIFIED_JWK_ALGORITHM = new MslError(31, ResponseCode.FAIL, "Unidentified JSON web key algorithm.");
    public static final MslError WRAP_ERROR = new MslError(32, ResponseCode.FAIL, "Error wrapping plaintext.");
    public static final MslError UNWRAP_ERROR = new MslError(33, ResponseCode.FAIL, "Error unwrapping ciphertext.");
    public static final MslError INVALID_JWK = new MslError(34, ResponseCode.FAIL, "Invalid JSON web key.");
    public static final MslError INVALID_JWK_KEYDATA = new MslError(35, ResponseCode.FAIL, "Invalid JSON web key keydata.");
    public static final MslError UNSUPPORTED_JWK_ALGORITHM = new MslError(36, ResponseCode.FAIL, "Unsupported JSON web key algorithm.");
    public static final MslError WRAP_KEY_CREATION_FAILURE = new MslError(37, ResponseCode.FAIL, "Error when creating wrapping key.");
    public static final MslError INVALID_WRAP_CIPHERTEXT = new MslError(38, ResponseCode.FAIL, "Invalid wrap ciphertext.");
    public static final MslError UNSUPPORTED_JWE_ALGORITHM = new MslError(39, ResponseCode.FAIL, "Unsupported JSON web encryption algorithm.");
    public static final MslError JWE_ENCODE_ERROR = new MslError(40, ResponseCode.FAIL, "Error encoding JSON web encryption header.");
    public static final MslError JWE_PARSE_ERROR = new MslError(41, ResponseCode.FAIL, "Error parsing JSON web encryption header.");
    public static final MslError INVALID_ALGORITHM_PARAMS = new MslError(42, ResponseCode.FAIL, "Invalid algorithm parameters.");
    public static final MslError JWE_ALGORITHM_MISMATCH = new MslError(43, ResponseCode.FAIL, "JSON web encryption header algorithms mismatch.");
    public static final MslError KEY_IMPORT_ERROR = new MslError(44, ResponseCode.FAIL, "Error importing key.");
    public static final MslError KEY_EXPORT_ERROR = new MslError(45, ResponseCode.FAIL, "Error exporting key.");
    public static final MslError DIGEST_ERROR = new MslError(46, ResponseCode.FAIL, "Error in digest.");
    public static final MslError UNSUPPORTED_KEY = new MslError(47, ResponseCode.FAIL, "Unsupported key type or algorithm.");
    public static final MslError UNSUPPORTED_JWE_SERIALIZATION = new MslError(48, ResponseCode.FAIL, "Unsupported JSON web encryption serialization.");
    public static final MslError INVALID_WRAPPING_KEY = new MslError(51, ResponseCode.FAIL, "Invalid wrapping key.");
    public static final MslError UNIDENTIFIED_CIPHERTEXT_ENVELOPE = new MslError(52, ResponseCode.FAIL, "Unidentified ciphertext envelope version.");
    public static final MslError UNIDENTIFIED_SIGNATURE_ENVELOPE = new MslError(53, ResponseCode.FAIL, "Unidentified signature envelope version.");
    public static final MslError UNSUPPORTED_CIPHERTEXT_ENVELOPE = new MslError(54, ResponseCode.FAIL, "Unsupported ciphertext envelope version.");
    public static final MslError UNSUPPORTED_SIGNATURE_ENVELOPE = new MslError(55, ResponseCode.FAIL, "Unsupported signature envelope version.");
    public static final MslError UNIDENTIFIED_CIPHERSPEC = new MslError(56, ResponseCode.FAIL, "Unidentified cipher specification.");
    public static final MslError UNIDENTIFIED_ALGORITHM = new MslError(57, ResponseCode.FAIL, "Unidentified algorithm.");
    public static final MslError SIGNATURE_ENVELOPE_PARSE_ERROR = new MslError(58, ResponseCode.FAIL, "Error parsing signature envelope.");
    public static final MslError SIGNATURE_ENVELOPE_ENCODE_ERROR = new MslError(59, ResponseCode.FAIL, "Error encoding signature envelope.");
    public static final MslError INVALID_SIGNATURE = new MslError(60, ResponseCode.FAIL, "Invalid signature.");
    public static final MslError DERIVEKEY_ERROR = new MslError(61, ResponseCode.FAIL, "Error deriving key.");
    public static final MslError UNIDENTIFIED_JWK_KEYOP = new MslError(62, ResponseCode.FAIL, "Unidentified JSON web key key operation.");
    public static final MslError GENERATEKEY_ERROR = new MslError(63, ResponseCode.FAIL, "Error generating key.");
    public static final MslError INVALID_IV = new MslError(64, ResponseCode.FAIL, "Invalid initialization vector.");
    public static final MslError INVALID_CIPHERTEXT = new MslError(65, ResponseCode.FAIL, "Invalid ciphertext.");

    // 1 Master Token
    public static final MslError MASTERTOKEN_UNTRUSTED = new MslError(1000, ResponseCode.ENTITY_REAUTH, "Master token is not trusted.");
    public static final MslError MASTERTOKEN_KEY_CREATION_ERROR = new MslError(1001, ResponseCode.ENTITY_REAUTH, "Unable to construct symmetric keys from master token.");
    public static final MslError MASTERTOKEN_EXPIRES_BEFORE_RENEWAL = new MslError(1002, ResponseCode.ENTITY_REAUTH, "Master token expiration timestamp is before the renewal window opens.");
    public static final MslError MASTERTOKEN_SESSIONDATA_MISSING = new MslError(1003, ResponseCode.ENTITY_REAUTH, "No master token session data found.");
    public static final MslError MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE = new MslError(1004, ResponseCode.ENTITY_REAUTH, "Master token sequence number is out of range.");
    public static final MslError MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE = new MslError(1005, ResponseCode.ENTITY_REAUTH, "Master token serial number is out of range.");
    public static final MslError MASTERTOKEN_TOKENDATA_INVALID = new MslError(1006, ResponseCode.ENTITY_REAUTH, "Invalid master token data.");
    public static final MslError MASTERTOKEN_SIGNATURE_INVALID = new MslError(1007, ResponseCode.ENTITY_REAUTH, "Invalid master token signature.");
    public static final MslError MASTERTOKEN_SESSIONDATA_INVALID = new MslError(1008, ResponseCode.ENTITY_REAUTH, "Invalid master token session data.");
    public static final MslError MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_SYNC = new MslError(1009, ResponseCode.ENTITY_REAUTH, "Master token sequence number does not have the expected value.");
    public static final MslError MASTERTOKEN_TOKENDATA_MISSING = new MslError(1010, ResponseCode.ENTITY_REAUTH, "No master token data found.");
    public static final MslError MASTERTOKEN_TOKENDATA_PARSE_ERROR = new MslError(1011, ResponseCode.ENTITY_REAUTH, "Error parsing master token data.");
    public static final MslError MASTERTOKEN_SESSIONDATA_PARSE_ERROR = new MslError(1012, ResponseCode.ENTITY_REAUTH, "Error parsing master token session data.");
    public static final MslError MASTERTOKEN_IDENTITY_REVOKED = new MslError(1013, ResponseCode.ENTITY_REAUTH, "Master token entity identity is revoked.");
    public static final MslError MASTERTOKEN_REJECTED_BY_APP = new MslError(1014, ResponseCode.ENTITY_REAUTH, "Master token is rejected by the application.");
    public static final MslError MASTERTOKEN_ISSUERDATA_ENCODE_ERROR = new MslError(1015, ResponseCode.FAIL, "Master token issuer data encoding error.");

    // 2 User ID Token
    public static final MslError USERIDTOKEN_MASTERTOKEN_MISMATCH = new MslError(2000, ResponseCode.USER_REAUTH, "User ID token master token serial number does not match master token serial number.");
    public static final MslError USERIDTOKEN_NOT_DECRYPTED = new MslError(2001, ResponseCode.USER_REAUTH, "User ID token is not decrypted or verified.");
    public static final MslError USERIDTOKEN_MASTERTOKEN_NULL = new MslError(2002, ResponseCode.USER_REAUTH, "User ID token requires a master token.");
    public static final MslError USERIDTOKEN_EXPIRES_BEFORE_RENEWAL = new MslError(2003, ResponseCode.USER_REAUTH, "User ID token expiration timestamp is before the renewal window opens.");
    public static final MslError USERIDTOKEN_USERDATA_MISSING = new MslError(2004, ResponseCode.USER_REAUTH, "No user ID token user data found.");
    public static final MslError USERIDTOKEN_MASTERTOKEN_NOT_FOUND = new MslError(2005, ResponseCode.USER_REAUTH, "User ID token is bound to an unknown master token.");
    public static final MslError USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE = new MslError(2006, ResponseCode.USER_REAUTH, "User ID token master token serial number is out of range.");
    public static final MslError USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE = new MslError(2007, ResponseCode.USER_REAUTH, "User ID token serial number is out of range.");
    public static final MslError USERIDTOKEN_TOKENDATA_INVALID = new MslError(2008, ResponseCode.USER_REAUTH, "Invalid user ID token data.");
    public static final MslError USERIDTOKEN_SIGNATURE_INVALID = new MslError(2009, ResponseCode.USER_REAUTH, "Invalid user ID token signature.");
    public static final MslError USERIDTOKEN_USERDATA_INVALID = new MslError(2010, ResponseCode.USER_REAUTH, "Invalid user ID token user data.");
    public static final MslError USERIDTOKEN_IDENTITY_INVALID = new MslError(2011, ResponseCode.USER_REAUTH, "Invalid user ID token user identity.");
    public static final MslError RESERVED_2012 = new MslError(2012, ResponseCode.USER_REAUTH, "The entity is not associated with the user.");
    public static final MslError USERIDTOKEN_USERAUTH_DATA_MISMATCH = new MslError(2015, ResponseCode.USER_REAUTH, "The user ID token and user authentication data user identities do not match.");
    public static final MslError USERIDTOKEN_TOKENDATA_MISSING = new MslError(2016, ResponseCode.USER_REAUTH, "No user ID token data found.");
    public static final MslError USERIDTOKEN_TOKENDATA_PARSE_ERROR = new MslError(2017, ResponseCode.USER_REAUTH, "Error parsing user ID token data.");
    public static final MslError USERIDTOKEN_USERDATA_PARSE_ERROR = new MslError(2018, ResponseCode.USER_REAUTH, "Error parsing user ID token user data.");
    public static final MslError USERIDTOKEN_REVOKED = new MslError(2019, ResponseCode.USER_REAUTH, "User ID token is revoked.");
    public static final MslError USERIDTOKEN_REJECTED_BY_APP = new MslError(2020, ResponseCode.USERDATA_REAUTH, "User ID token is rejected by the application.");

    // 3 Service Token
    public static final MslError SERVICETOKEN_MASTERTOKEN_MISMATCH = new MslError(3000, ResponseCode.FAIL, "Service token master token serial number does not match master token serial number.");
    public static final MslError SERVICETOKEN_USERIDTOKEN_MISMATCH = new MslError(3001, ResponseCode.FAIL, "Service token user ID token serial number does not match user ID token serial number.");
    public static final MslError SERVICETOKEN_SERVICEDATA_INVALID = new MslError(3002, ResponseCode.FAIL, "Service token data invalid.");
    public static final MslError SERVICETOKEN_MASTERTOKEN_NOT_FOUND = new MslError(3003, ResponseCode.FAIL, "Service token is bound to an unknown master token.");
    public static final MslError SERVICETOKEN_USERIDTOKEN_NOT_FOUND = new MslError(3004, ResponseCode.FAIL, "Service token is bound to an unknown user ID token.");
    public static final MslError SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE = new MslError(3005, ResponseCode.FAIL, "Service token master token serial number is out of range.");
    public static final MslError SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE = new MslError(3006, ResponseCode.FAIL, "Service token user ID token serial number is out of range.");
    public static final MslError SERVICETOKEN_TOKENDATA_INVALID = new MslError(3007, ResponseCode.FAIL, "Invalid service token data.");
    public static final MslError SERVICETOKEN_SIGNATURE_INVALID = new MslError(3008, ResponseCode.FAIL, "Invalid service token signature.");
    public static final MslError SERVICETOKEN_TOKENDATA_MISSING = new MslError(3009, ResponseCode.FAIL, "No service token data found.");

    // 4 Entity Authentication
    public static final MslError UNIDENTIFIED_ENTITYAUTH_SCHEME = new MslError(4000, ResponseCode.FAIL, "Unable to identify entity authentication scheme.");
    public static final MslError ENTITYAUTH_FACTORY_NOT_FOUND = new MslError(4001, ResponseCode.FAIL, "No factory registered for entity authentication scheme.");
    public static final MslError X509CERT_PARSE_ERROR = new MslError(4002, ResponseCode.ENTITYDATA_REAUTH, "Error parsing X.509 certificate data.");
    public static final MslError X509CERT_ENCODE_ERROR = new MslError(4003, ResponseCode.ENTITYDATA_REAUTH, "Error encoding X.509 certificate data.");
    public static final MslError X509CERT_VERIFICATION_FAILED = new MslError(4004, ResponseCode.ENTITYDATA_REAUTH, "X.509 certificate verification failed.");
    public static final MslError ENTITY_NOT_FOUND = new MslError(4005, ResponseCode.FAIL, "Entity not recognized.");
    public static final MslError INCORRECT_ENTITYAUTH_DATA = new MslError(4006, ResponseCode.FAIL, "Entity used incorrect entity authentication data type.");
    public static final MslError RSA_PUBLICKEY_NOT_FOUND = new MslError(4007, ResponseCode.ENTITYDATA_REAUTH, "RSA public key not found.");
    public static final MslError UNSUPPORTED_ENTITYAUTH_DATA = new MslError(4023, ResponseCode.FAIL, "Unsupported entity authentication data.");
    public static final MslError ENTITY_REVOKED = new MslError(4025, ResponseCode.FAIL, "Entity is revoked.");
    public static final MslError ENTITY_REJECTED_BY_APP = new MslError(4026, ResponseCode.ENTITYDATA_REAUTH, "Entity is rejected by the application.");
    public static final MslError X509CERT_EXPIRED = new MslError(4028, ResponseCode.ENTITYDATA_REAUTH, "X.509 certificate is expired.");
    public static final MslError X509CERT_NOT_YET_VALID = new MslError(4029, ResponseCode.ENTITYDATA_REAUTH, "X.509 certificate is not yet valid.");
    public static final MslError X509CERT_INVALID = new MslError(4030, ResponseCode.ENTITYDATA_REAUTH, "X.509 certificate is invalid.");
    public static final MslError RSA_PRIVATEKEY_NOT_FOUND = new MslError(4031, ResponseCode.ENTITYDATA_REAUTH, "RSA private key not found.");
    public static final MslError ENTITYAUTH_MASTERTOKEN_NOT_DECRYPTED = new MslError(4032, ResponseCode.FAIL, "Entity authentication data master token is not decrypted or verified.");
    public static final MslError ENTITYAUTH_SIGNATURE_INVALID = new MslError(4033, ResponseCode.ENTITYDATA_REAUTH, "Invalid entity authentication data siganture.");
    public static final MslError ENTITYAUTH_CIPHERTEXT_INVALID = new MslError(4034, ResponseCode.ENTITYDATA_REAUTH, "Invalid entity authentication data ciphertext.");
    public static final MslError ENTITYAUTH_VERIFICATION_FAILED = new MslError(4035, ResponseCode.ENTITYDATA_REAUTH, "Entity authentication data signature verification failed.");
    public static final MslError ENTITYAUTH_MASTERTOKEN_INVALID = new MslError(4036, ResponseCode.FAIL, "Invalid entity authentication data master token.");
    public static final MslError ECC_PUBLICKEY_NOT_FOUND = new MslError(4037, ResponseCode.ENTITYDATA_REAUTH, "ECC public key not found.");
    public static final MslError ECC_PRIVATEKEY_NOT_FOUND = new MslError(4038, ResponseCode.ENTITYDATA_REAUTH, "ECC private key not found.");

    // 5 User Authentication
    public static final MslError UNIDENTIFIED_USERAUTH_SCHEME = new MslError(5003, ResponseCode.FAIL, "Unable to identify user authentication scheme.");
    public static final MslError USERAUTH_FACTORY_NOT_FOUND = new MslError(5004, ResponseCode.FAIL, "No factory registered for user authentication scheme.");
    public static final MslError EMAILPASSWORD_BLANK = new MslError(5005, ResponseCode.USERDATA_REAUTH, "Email or password is blank.");
    public static final MslError EMAILPASSWORD_INCORRECT = new MslError(5007, ResponseCode.USERDATA_REAUTH, "Email or password is incorrect.");
    public static final MslError UNSUPPORTED_USERAUTH_DATA = new MslError(5008, ResponseCode.FAIL, "Unsupported user authentication data.");
    public static final MslError USERAUTH_USERIDTOKEN_INVALID = new MslError(5011, ResponseCode.USERDATA_REAUTH, "User authentication data user ID token is invalid.");
    public static final MslError UNIDENTIFIED_USERAUTH_MECHANISM = new MslError(5013, ResponseCode.FAIL, "Unable to identify user authentication mechanism.");
    public static final MslError UNSUPPORTED_USERAUTH_MECHANISM = new MslError(5014, ResponseCode.FAIL, "Unsupported user authentication mechanism.");
    public static final MslError USERAUTH_MASTERTOKEN_MISSING = new MslError(5016, ResponseCode.USERDATA_REAUTH, "User authentication required master token is missing.");
    public static final MslError USERAUTH_USERIDTOKEN_NOT_DECRYPTED = new MslError(5021, ResponseCode.USERDATA_REAUTH, "User authentication data user ID token is not decrypted or verified.");
    public static final MslError USERAUTH_MASTERTOKEN_INVALID = new MslError(5024, ResponseCode.USERDATA_REAUTH, "User authentication data master token is invalid.");
    public static final MslError USERAUTH_MASTERTOKEN_NOT_DECRYPTED = new MslError(5025, ResponseCode.USERDATA_REAUTH, "User authentication data master token is not decrypted or verified.");
    public static final MslError USERAUTH_USERIDTOKEN_MISSING = new MslError(5030, ResponseCode.USERDATA_REAUTH, "User authentication required user ID token is missing.");
    public static final MslError USERAUTH_ENTITY_MISMATCH = new MslError(5032, ResponseCode.USERDATA_REAUTH, "User authentication data does not match entity identity.");
    public static final MslError USERAUTH_ENTITY_INCORRECT_DATA = new MslError(5033, ResponseCode.FAIL, "Entity used incorrect user authentication data type.");
    public static final MslError USER_REJECTED_BY_APP = new MslError(5037, ResponseCode.USERDATA_REAUTH, "User is rejected by the application.");
    public static final MslError USERIDTOKEN_IDENTITY_NOT_ASSOCIATED_WITH_ENTITY = new MslError(5040, ResponseCode.USERDATA_REAUTH, "The entity is not associated with the user.");
    public static final MslError USERAUTH_ENTITYUSER_INCORRECT_DATA = new MslError(5041, ResponseCode.USERDATA_REAUTH, "Entity and user combination used incorrect user authentication data type.");
    public static final MslError USERAUTH_VERIFICATION_FAILED = new MslError(5042, ResponseCode.USERDATA_REAUTH, "User authentication data signature verification failed.");
    public static final MslError USERAUTH_USERIDTOKEN_REVOKE_CHECK_ERROR = new MslError(5043, ResponseCode.USERDATA_REAUTH, "User ID token could not be checked for revocation.");

    // 6 Message
    public static final MslError UNSUPPORTED_COMPRESSION = new MslError(6000, ResponseCode.FAIL, "Unsupported compression algorithm.");
    public static final MslError COMPRESSION_ERROR = new MslError(6001, ResponseCode.FAIL, "Error compressing data.");
    public static final MslError UNCOMPRESSION_ERROR = new MslError(6002, ResponseCode.FAIL, "Error uncompressing data.");
    public static final MslError MESSAGE_ENTITY_NOT_FOUND = new MslError(6003, ResponseCode.FAIL, "Message header entity authentication data or master token not found.");
    public static final MslError PAYLOAD_MESSAGE_ID_MISMATCH = new MslError(6004, ResponseCode.FAIL, "Payload chunk message ID does not match header message ID .");
    public static final MslError PAYLOAD_SEQUENCE_NUMBER_MISMATCH = new MslError(6005, ResponseCode.FAIL, "Payload chunk sequence number does not match expected sequence number.");
    public static final MslError PAYLOAD_VERIFICATION_FAILED = new MslError(6006, ResponseCode.FAIL, "Payload chunk payload signature verification failed.");
    public static final MslError MESSAGE_DATA_MISSING = new MslError(6007, ResponseCode.FAIL, "No message data found.");
    public static final MslError MESSAGE_FORMAT_ERROR = new MslError(6008, ResponseCode.FAIL, "Malformed message data.");
    public static final MslError MESSAGE_VERIFICATION_FAILED = new MslError(6009, ResponseCode.FAIL, "Message header/error data signature verification failed.");
    public static final MslError HEADER_DATA_MISSING = new MslError(6010, ResponseCode.FAIL, "No header data found.");
    public static final MslError PAYLOAD_DATA_MISSING = new MslError(6011, ResponseCode.FAIL, "No payload data found in non-EOM payload chunk.");
    public static final MslError PAYLOAD_DATA_CORRUPT = new MslError(6012, ResponseCode.FAIL, "Corrupt payload data found in non-EOM payload chunk.");
    public static final MslError UNIDENTIFIED_COMPRESSION = new MslError(6013, ResponseCode.FAIL, "Unidentified compression algorithm.");
    public static final MslError MESSAGE_EXPIRED = new MslError(6014, ResponseCode.EXPIRED, "Message expired and not renewable or missing key request data. Rejected.");
    public static final MslError MESSAGE_ID_OUT_OF_RANGE = new MslError(6015, ResponseCode.FAIL, "Message ID is is out of range.");
    public static final MslError INTERNAL_CODE_NEGATIVE = new MslError(6016, ResponseCode.FAIL, "Error header internal code is negative.");
    public static final MslError UNEXPECTED_RESPONSE_MESSAGE_ID = new MslError(6017, ResponseCode.FAIL, "Unexpected response message ID. Possible replay.");
    public static final MslError RESPONSE_REQUIRES_ENCRYPTION = new MslError(6018, ResponseCode.KEYX_REQUIRED, "Message response requires encryption.");
    public static final MslError PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE = new MslError(6019, ResponseCode.FAIL, "Payload chunk sequence number is out of range.");
    public static final MslError PAYLOAD_MESSAGE_ID_OUT_OF_RANGE = new MslError(6020, ResponseCode.FAIL, "Payload chunk message ID is out of range.");
    public static final MslError MESSAGE_REPLAYED = new MslError(6021, ResponseCode.REPLAYED, "Non-replayable message replayed.");
    public static final MslError INCOMPLETE_NONREPLAYABLE_MESSAGE = new MslError(6022, ResponseCode.FAIL, "Non-replayable message sent without a master token.");
    public static final MslError HEADER_SIGNATURE_INVALID = new MslError(6023, ResponseCode.FAIL, "Invalid Header signature.");
    public static final MslError HEADER_DATA_INVALID = new MslError(6024, ResponseCode.FAIL, "Invalid header data.");
    public static final MslError PAYLOAD_INVALID = new MslError(6025, ResponseCode.FAIL, "Invalid payload.");
    public static final MslError PAYLOAD_SIGNATURE_INVALID = new MslError(6026, ResponseCode.FAIL, "Invalid payload signature.");
    public static final MslError RESPONSE_REQUIRES_MASTERTOKEN = new MslError(6027, ResponseCode.KEYX_REQUIRED, "Message response requires a master token.");
    public static final MslError RESPONSE_REQUIRES_USERIDTOKEN = new MslError(6028, ResponseCode.USER_REAUTH, "Message response requires a user ID token.");
    public static final MslError REQUEST_REQUIRES_USERAUTHDATA = new MslError(6029, ResponseCode.FAIL, "User-associated message requires user authentication data.");
    public static final MslError UNEXPECTED_MESSAGE_SENDER = new MslError(6030, ResponseCode.FAIL, "Message sender is not the master token entity.");
    public static final MslError NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN = new MslError(6031, ResponseCode.FAIL, "Non-replayable message requires a master token.");
    public static final MslError NONREPLAYABLE_ID_OUT_OF_RANGE = new MslError(6032, ResponseCode.FAIL, "Non-replayable message non-replayable ID is out of range.");
    public static final MslError MESSAGE_SERVICETOKEN_MISMATCH = new MslError(6033, ResponseCode.FAIL, "Service token master token or user ID token serial number does not match the message token serial numbers.");
    public static final MslError MESSAGE_PEER_SERVICETOKEN_MISMATCH = new MslError(6034, ResponseCode.FAIL, "Peer service token master token or user ID token serial number does not match the message peer token serial numbers.");
    public static final MslError RESPONSE_REQUIRES_INTEGRITY_PROTECTION = new MslError(6035, ResponseCode.KEYX_REQUIRED, "Message response requires integrity protection.");
    public static final MslError HANDSHAKE_DATA_MISSING = new MslError(6036, ResponseCode.FAIL, "Handshake message is not renewable or does not contain key request data.");
    public static final MslError MESSAGE_RECIPIENT_MISMATCH = new MslError(6037, ResponseCode.FAIL, "Message recipient does not match local identity.");
    public static final MslError MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED = new MslError(6038, ResponseCode.ENTITYDATA_REAUTH, "Message header entity-based signature verification failed.");
    public static final MslError MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED = new MslError(6039, ResponseCode.ENTITY_REAUTH, "Message header master token-based signature verification failed.");
    public static final MslError MESSAGE_REPLAYED_UNRECOVERABLE = new MslError(6040, ResponseCode.ENTITY_REAUTH, "Non-replayable message replayed with a sequence number that is too far out of sync to recover.");
    public static final MslError UNEXPECTED_LOCAL_MESSAGE_SENDER = new MslError(6041, ResponseCode.FAIL, "Message sender is equal to the local entity.");
    public static final MslError UNENCRYPTED_MESSAGE_WITH_USERAUTHDATA = new MslError(6042, ResponseCode.FAIL, "User authentication data included in unencrypted message header.");
    public static final MslError MESSAGE_SENDER_MISMATCH = new MslError(6043, ResponseCode.FAIL, "Message sender entity identity does not match expected identity.");
    public static final MslError MESSAGE_EXPIRED_NOT_RENEWABLE = new MslError(6044, ResponseCode.EXPIRED, "Message expired and not renewable. Rejected.");
    public static final MslError MESSAGE_EXPIRED_NO_KEYREQUEST_DATA = new MslError(6045, ResponseCode.EXPIRED, "Message expired and missing key request data. Rejected.");

    // 7 Key Exchange
    public static final MslError UNIDENTIFIED_KEYX_SCHEME = new MslError(7000, ResponseCode.FAIL, "Unable to identify key exchange scheme.");
    public static final MslError KEYX_FACTORY_NOT_FOUND = new MslError(7001, ResponseCode.FAIL, "No factory registered for key exchange scheme.");
    public static final MslError KEYX_REQUEST_NOT_FOUND = new MslError(7002, ResponseCode.FAIL, "No key request found matching header key response data.");
    public static final MslError UNIDENTIFIED_KEYX_KEY_ID = new MslError(7003, ResponseCode.FAIL, "Unable to identify key exchange key ID.");
    public static final MslError UNSUPPORTED_KEYX_KEY_ID = new MslError(7004, ResponseCode.FAIL, "Unsupported key exchange key ID.");
    public static final MslError UNIDENTIFIED_KEYX_MECHANISM = new MslError(7005, ResponseCode.FAIL, "Unable to identify key exchange mechanism.");
    public static final MslError UNSUPPORTED_KEYX_MECHANISM = new MslError(7006, ResponseCode.FAIL, "Unsupported key exchange mechanism.");
    public static final MslError KEYX_RESPONSE_REQUEST_MISMATCH = new MslError(7007, ResponseCode.FAIL, "Key exchange response does not match request.");
    public static final MslError KEYX_PRIVATE_KEY_MISSING = new MslError(7008, ResponseCode.FAIL, "Key exchange private key missing.");
    public static final MslError UNKNOWN_KEYX_PARAMETERS_ID = new MslError(7009, ResponseCode.FAIL, "Key exchange parameters ID unknown or invalid.");
    public static final MslError KEYX_MASTER_TOKEN_MISSING = new MslError(7010, ResponseCode.FAIL, "Master token required for key exchange is missing.");
    public static final MslError KEYX_INVALID_PUBLIC_KEY = new MslError(7011, ResponseCode.FAIL, "Key exchange public key is invalid.");
    public static final MslError KEYX_PUBLIC_KEY_MISSING = new MslError(7012, ResponseCode.FAIL, "Key exchange public key missing.");
    public static final MslError KEYX_WRAPPING_KEY_MISSING = new MslError(7013, ResponseCode.FAIL, "Key exchange wrapping key missing.");
    public static final MslError KEYX_WRAPPING_KEY_ID_MISSING = new MslError(7014, ResponseCode.FAIL, "Key exchange wrapping key ID missing.");
    public static final MslError KEYX_INVALID_WRAPPING_KEY = new MslError(7015, ResponseCode.FAIL, "Key exchange wrapping key is invalid.");
    public static final MslError KEYX_INCORRECT_DATA = new MslError(7016, ResponseCode.FAIL, "Entity used incorrect key exchange data type.");
    public static final MslError KEYX_INCORRECT_MECHANISM = new MslError(7017, ResponseCode.FAIL, "Entity used incorrect key exchange mecahnism.");
    public static final MslError KEYX_DERIVATION_KEY_MISSING = new MslError(7018, ResponseCode.FAIL, "Key exchange derivation key missing.");
    public static final MslError KEYX_INVALID_ENCRYPTION_KEY = new MslError(7019, ResponseCode.FAIL, "Key exchange encryption key is invalid.");
    public static final MslError KEYX_INVALID_HMAC_KEY = new MslError(7020, ResponseCode.FAIL, "Key exchange HMAC key is invalid.");
    public static final MslError KEYX_INVALID_WRAPDATA = new MslError(7021, ResponseCode.FAIL, "Key exchange wrap data is invalid.");
    public static final MslError UNSUPPORTED_KEYX_SCHEME = new MslError(7022, ResponseCode.FAIL, "Unsupported key exchange scheme.");
    public static final MslError KEYX_IDENTITY_NOT_FOUND = new MslError(7023, ResponseCode.FAIL, "Key exchange identity not found.");

    // 9 Internal Errors
    public static final MslError INTERNAL_EXCEPTION = new MslError(9000, ResponseCode.TRANSIENT_FAILURE, "Internal exception.");
    public static final MslError MSL_COMMS_FAILURE = new MslError(9001, ResponseCode.FAIL, "Error communicating with MSL entity.");
    public static final MslError NONE = new MslError(9999, ResponseCode.FAIL, "Special unit test error.");

    /** Internal error code base value. */
    private static final int BASE = 100000;

    /**
     * Construct a MSL error with the specified internal and response error
     * codes and message.
     *
     * @param internalCode internal error code.
     * @param responseCode response error code.
     * @param msg developer-consumable error message.
     */
    protected MslError(final int internalCode, final ResponseCode responseCode, final String msg) {
        // Check for duplicates.
        synchronized (internalCodes) {
            if (internalCodes.contains(internalCode))
                throw new MslInternalException("Duplicate MSL error definition for error code " + internalCode + ".");
            internalCodes.add(internalCode);
        }

        this.internalCode = MslError.BASE + internalCode;
        this.responseCode = responseCode;
        this.msg = msg;
    }

    /**
     * @return the internal error code.
     */
    public int getInternalCode() {
        return internalCode;
    }

    /**
     * @return the response error code.
     */
    public ResponseCode getResponseCode() {
        return responseCode;
    }

    /**
     * @return the error message.
     */
    public String getMessage() {
        return msg;
    }

    /**
     * @param o the reference object with which to compare.
     * @return true if the internal code and response code are equal.
     * @see #hashCode()
     */
    @Override
    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof MslError)) return false;
        final MslError that = (MslError)o;
        return this.internalCode == that.internalCode &&
            this.responseCode == that.responseCode;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return Integer.valueOf(internalCode).hashCode() ^ responseCode.hashCode();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "MslError{" + internalCode + "," + responseCode.intValue() + "," + msg + "}";
    }

    /** Internal error code. */
    private final int internalCode;
    /** Response error code. */
    private final ResponseCode responseCode;
    /** Error message. */
    private final String msg;
}
