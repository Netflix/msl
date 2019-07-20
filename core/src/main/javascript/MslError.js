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
(function(require, module) {
	"use strict";
	
	var Class = require('./util/Class.js');
	var MslConstants = require('./MslConstants.js');
	
	/**
	 * Construct a MSL error with the specified internal and response error
	 * internalCodes and message.
	 *
	 * @param {number} internalCode internal error code.
	 * @param {number} responseCode response error code.
	 * @param {string} msg developer-consumable error message.
	 * @constructor
	 */
	var MslError = module.exports = function MslError(internalCode, responseCode, msg) {
	    /** Internal error code base value. */
	    var BASE = 100000;
	    
	    var toString = function toString() {
            return "MslError{" + this.internalCode + "," + this.responseCode + "," + this.message + "}";
        };
	
	    // The properties.
	    var props = {
	        internalCode: { value: BASE + internalCode, writable: false, configurable: false },
	        responseCode: { value: responseCode, writable: false, configurable: false },
	        message: { value: msg, writable: false, configurable: false },
	        toString: { value: toString, writable: false, enumerable: false },
	    };
	
	    Object.defineProperties(this, props);
	};
	
	Class.mixin(MslError,
	/** @lends {MslError} */
	({
	    // 0 Message Security Layer
	    MSL_PARSE_ERROR : new MslError(0, MslConstants.ResponseCode.FAIL, "Error parsing MSL encodable."),
	    MSL_ENCODE_ERROR : new MslError(1, MslConstants.ResponseCode.FAIL, "Error encoding MSL encodable."),
	    ENVELOPE_HASH_MISMATCH : new MslError(2, MslConstants.ResponseCode.FAIL, "Computed hash does not match envelope hash."),
	    INVALID_PUBLIC_KEY : new MslError(3, MslConstants.ResponseCode.FAIL, "Invalid public key provided."),
	    INVALID_PRIVATE_KEY : new MslError(4, MslConstants.ResponseCode.FAIL, "Invalid private key provided."),
	    PLAINTEXT_ILLEGAL_BLOCK_SIZE : new MslError(5, MslConstants.ResponseCode.FAIL, "Plaintext is not a multiple of the block size."),
	    PLAINTEXT_BAD_PADDING : new MslError(6, MslConstants.ResponseCode.FAIL, "Plaintext contains incorrect padding."),
	    CIPHERTEXT_ILLEGAL_BLOCK_SIZE : new MslError(7, MslConstants.ResponseCode.FAIL, "Ciphertext is not a multiple of the block size."),
	    CIPHERTEXT_BAD_PADDING : new MslError(8, MslConstants.ResponseCode.FAIL, "Ciphertext contains incorrect padding."),
	    ENCRYPT_NOT_SUPPORTED : new MslError(9, MslConstants.ResponseCode.FAIL, "Encryption not supported."),
	    DECRYPT_NOT_SUPPORTED : new MslError(10, MslConstants.ResponseCode.FAIL, "Decryption not supported."),
	    ENVELOPE_KEY_ID_MISMATCH : new MslError(11, MslConstants.ResponseCode.FAIL, "Encryption envelope key ID does not match crypto context key ID."),
	    CIPHERTEXT_ENVELOPE_PARSE_ERROR : new MslError(12, MslConstants.ResponseCode.FAIL, "Error parsing ciphertext envelope."),
	    CIPHERTEXT_ENVELOPE_ENCODE_ERROR : new MslError(13, MslConstants.ResponseCode.FAIL, "Error encoding ciphertext envelope."),
	    SIGN_NOT_SUPPORTED : new MslError(14, MslConstants.ResponseCode.FAIL, "Sign not supported."),
	    VERIFY_NOT_SUPPORTED : new MslError(15, MslConstants.ResponseCode.FAIL, "Verify not suppoprted."),
	    SIGNATURE_ERROR : new MslError(16, MslConstants.ResponseCode.FAIL, "Signature not initialized or unable to process data/signature."),
	    HMAC_ERROR : new MslError(17, MslConstants.ResponseCode.FAIL, "Error computing HMAC."),
	    ENCRYPT_ERROR : new MslError(18, MslConstants.ResponseCode.FAIL, "Error encrypting plaintext."),
	    DECRYPT_ERROR : new MslError(19, MslConstants.ResponseCode.FAIL, "Error decrypting ciphertext."),
	    INSUFFICIENT_CIPHERTEXT : new MslError(20, MslConstants.ResponseCode.FAIL, "Insufficient ciphertext for decryption."),
	    SESSION_KEY_CREATION_FAILURE : new MslError(21, MslConstants.ResponseCode.FAIL, "Error when creating session keys."),
	    INVALID_SYMMETRIC_KEY : new MslError(24, MslConstants.ResponseCode.FAIL, "Invalid symmetric key provided."),
	    INVALID_ENCRYPTION_KEY : new MslError(25, MslConstants.ResponseCode.FAIL, "Invalid encryption key."),
	    INVALID_HMAC_KEY : new MslError(26, MslConstants.ResponseCode.FAIL, "Invalid HMAC key."),
	    WRAP_NOT_SUPPORTED : new MslError(27, MslConstants.ResponseCode.FAIL, "Wrap not supported."),
	    UNWRAP_NOT_SUPPORTED : new MslError(28, MslConstants.ResponseCode.FAIL, "Unwrap not supported."),
	    UNIDENTIFIED_JWK_TYPE : new MslError(29, MslConstants.ResponseCode.FAIL, "Unidentified JSON web key type."),
	    UNIDENTIFIED_JWK_USAGE : new MslError(30, MslConstants.ResponseCode.FAIL, "Unidentified JSON web key usage."),
	    UNIDENTIFIED_JWK_ALGORITHM : new MslError(31, MslConstants.ResponseCode.FAIL, "Unidentified JSON web key algorithm."),
	    WRAP_ERROR : new MslError(32, MslConstants.ResponseCode.FAIL, "Error wrapping plaintext."),
	    UNWRAP_ERROR : new MslError(33, MslConstants.ResponseCode.FAIL, "Error unwrapping ciphertext."),
	    INVALID_JWK : new MslError(34, MslConstants.ResponseCode.FAIL, "Invalid JSON web key."),
	    INVALID_JWK_KEYDATA : new MslError(35, MslConstants.ResponseCode.FAIL, "Invalid JSON web key keydata."),
	    UNSUPPORTED_JWK_ALGORITHM : new MslError(36, MslConstants.ResponseCode.FAIL, "Unsupported JSON web key algorithm."),
	    WRAP_KEY_CREATION_FAILURE : new MslError(37, MslConstants.ResponseCode.FAIL, "Error when creating wrapping key."),
	    INVALID_WRAP_CIPHERTEXT : new MslError(38, MslConstants.ResponseCode.FAIL, "Invalid wrap ciphertext."),
	    UNSUPPORTED_JWE_ALGORITHM : new MslError(39, MslConstants.ResponseCode.FAIL, "Unsupported JSON web encryption algorithm."),
	    JWE_ENCODE_ERROR : new MslError(40, MslConstants.ResponseCode.FAIL, "Error encoding JSON web encryption header."),
	    JWE_PARSE_ERROR : new MslError(41, MslConstants.ResponseCode.FAIL, "Error parsing JSON web encryption header."),
	    INVALID_ALGORITHM_PARAMS : new MslError(42, MslConstants.ResponseCode.FAIL, "Invalid algorithm parameters."),
	    JWE_ALGORITHM_MISMATCH : new MslError(43, MslConstants.ResponseCode.FAIL, "JSON web encryption header algorithms mismatch."),
	    KEY_IMPORT_ERROR : new MslError(44, MslConstants.ResponseCode.FAIL, "Error importing key."),
	    KEY_EXPORT_ERROR : new MslError(45, MslConstants.ResponseCode.FAIL, "Error exporting key."),
	    DIGEST_ERROR : new MslError(46, MslConstants.ResponseCode.FAIL, "Error in digest."),
	    UNSUPPORTED_KEY : new MslError(47, MslConstants.ResponseCode.FAIL, "Unsupported key type or algorithm."),
	    UNSUPPORTED_JWE_SERIALIZATION : new MslError(48, MslConstants.ResponseCode.FAIL, "Unsupported JSON web encryption serialization."),
	    INVALID_WRAPPING_KEY : new MslError(51, MslConstants.ResponseCode.FAIL, "Invalid wrapping key."),
	    UNIDENTIFIED_CIPHERTEXT_ENVELOPE : new MslError(52, MslConstants.ResponseCode.FAIL, "Unidentified ciphertext envelope version."),
	    UNIDENTIFIED_SIGNATURE_ENVELOPE : new MslError(53, MslConstants.ResponseCode.FAIL, "Unidentified signature envelope version."),
	    UNSUPPORTED_CIPHERTEXT_ENVELOPE : new MslError(54, MslConstants.ResponseCode.FAIL, "Unsupported ciphertext envelope version."),
	    UNSUPPORTED_SIGNATURE_ENVELOPE : new MslError(55, MslConstants.ResponseCode.FAIL, "Unsupported signature envelope version."),
	    UNIDENTIFIED_CIPHERSPEC : new MslError(56, MslConstants.ResponseCode.FAIL, "Unidentified cipher specification."),
	    UNIDENTIFIED_ALGORITHM : new MslError(57, MslConstants.ResponseCode.FAIL, "Unidentified algorithm."),
	    SIGNATURE_ENVELOPE_PARSE_ERROR : new MslError(58, MslConstants.ResponseCode.FAIL, "Error parsing signature envelope."),
	    SIGNATURE_ENVELOPE_ENCODE_ERROR : new MslError(59, MslConstants.ResponseCode.FAIL, "Error encoding signature envelope."),
	    INVALID_SIGNATURE : new MslError(60, MslConstants.ResponseCode.FAIL, "Invalid signature."),
	    DERIVEKEY_ERROR : new MslError(61, MslConstants.ResponseCode.FAIL, "Error deriving key."),
	    UNIDENTIFIED_JWK_KEYOP : new MslError(62, MslConstants.ResponseCode.FAIL, "Unidentified JSON web key key operation."),
	    GENERATEKEY_ERROR : new MslError(63, MslConstants.ResponseCode.FAIL, "Error generating key."),
	    INVALID_IV : new MslError(64, MslConstants.ResponseCode.FAIL, "Invalid initialization vector."),
	    INVALID_CIPHERTEXT : new MslError(65, MslConstants.ResponseCode.FAIL, "Invalid ciphertext."),
	
	    // 1 Master Token
	    MASTERTOKEN_UNTRUSTED : new MslError(1000, MslConstants.ResponseCode.ENTITY_REAUTH, "Master token is not trusted."),
	    MASTERTOKEN_KEY_CREATION_ERROR : new MslError(1001, MslConstants.ResponseCode.ENTITY_REAUTH, "Unable to construct symmetric keys from master token."),
	    MASTERTOKEN_EXPIRES_BEFORE_RENEWAL : new MslError(1002, MslConstants.ResponseCode.ENTITY_REAUTH, "Master token expiration timestamp is before the renewal window opens."),
	    MASTERTOKEN_SESSIONDATA_MISSING : new MslError(1003, MslConstants.ResponseCode.ENTITY_REAUTH, "No master token session data found."),
	    MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE : new MslError(1004, MslConstants.ResponseCode.ENTITY_REAUTH, "Master token sequence number is out of range."),
	    MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE : new MslError(1005, MslConstants.ResponseCode.ENTITY_REAUTH, "Master token serial number is out of range."),
	    MASTERTOKEN_TOKENDATA_INVALID : new MslError(1006, MslConstants.ResponseCode.ENTITY_REAUTH, "Invalid master token data."),
	    MASTERTOKEN_SIGNATURE_INVALID : new MslError(1007, MslConstants.ResponseCode.ENTITY_REAUTH, "Invalid master token signature."),
	    MASTERTOKEN_SESSIONDATA_INVALID : new MslError(1008, MslConstants.ResponseCode.ENTITY_REAUTH, "Invalid master token session data."),
	    MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_SYNC : new MslError(1009, MslConstants.ResponseCode.ENTITY_REAUTH, "Master token sequence number does not have the expected value."),
	    MASTERTOKEN_TOKENDATA_MISSING : new MslError(1010, MslConstants.ResponseCode.ENTITY_REAUTH, "No master token data found."),
	    MASTERTOKEN_TOKENDATA_PARSE_ERROR : new MslError(1011, MslConstants.ResponseCode.ENTITY_REAUTH, "Error parsing master token data."),
	    MASTERTOKEN_SESSIONDATA_PARSE_ERROR : new MslError(1012, MslConstants.ResponseCode.ENTITY_REAUTH, "Error parsing master token session data."),
	    MASTERTOKEN_IDENTITY_REVOKED : new MslError(1013, MslConstants.ResponseCode.ENTITY_REAUTH, "Master token entity identity is revoked."),
	    MASTERTOKEN_REJECTED_BY_APP : new MslError(1014, MslConstants.ResponseCode.ENTITY_REAUTH, "Master token is rejected by the application."),
	    MASTERTOKEN_ISSUERDATA_ENCODE_ERROR : new MslError(1015, MslConstants.ResponseCode.FAIL, "Master token issuer data encoding error."),
	
	    // 2 User ID Token
	    USERIDTOKEN_MASTERTOKEN_MISMATCH : new MslError(2000, MslConstants.ResponseCode.USER_REAUTH, "User ID token master token serial number does not match master token serial number."),
	    USERIDTOKEN_NOT_DECRYPTED : new MslError(2001, MslConstants.ResponseCode.USER_REAUTH, "User ID token is not decrypted or verified."),
	    USERIDTOKEN_MASTERTOKEN_NULL : new MslError(2002, MslConstants.ResponseCode.USER_REAUTH, "User ID token requires a master token."),
	    USERIDTOKEN_EXPIRES_BEFORE_RENEWAL : new MslError(2003, MslConstants.ResponseCode.USER_REAUTH, "User ID token expiration timestamp is before the renewal window opens."),
	    USERIDTOKEN_USERDATA_MISSING : new MslError(2004, MslConstants.ResponseCode.USER_REAUTH, "No user ID token user data found."),
	    USERIDTOKEN_MASTERTOKEN_NOT_FOUND : new MslError(2005, MslConstants.ResponseCode.USER_REAUTH, "User ID token is bound to an unknown master token."),
	    USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE : new MslError(2006, MslConstants.ResponseCode.USER_REAUTH, "User ID token master token serial number is out of range."),
	    USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE : new MslError(2007, MslConstants.ResponseCode.USER_REAUTH, "User ID token serial number is out of range."),
	    USERIDTOKEN_TOKENDATA_INVALID : new MslError(2008, MslConstants.ResponseCode.USER_REAUTH, "Invalid user ID token data."),
	    USERIDTOKEN_SIGNATURE_INVALID : new MslError(2009, MslConstants.ResponseCode.USER_REAUTH, "Invalid user ID token signature."),
	    USERIDTOKEN_USERDATA_INVALID : new MslError(2010, MslConstants.ResponseCode.USER_REAUTH, "Invalid user ID token user data."),
	    USERIDTOKEN_IDENTITY_INVALID : new MslError(2011, MslConstants.ResponseCode.USER_REAUTH, "Invalid user ID token user identity."),
	    RESERVED_2012 : new MslError(2012, MslConstants.ResponseCode.USER_REAUTH, "The entity is not associated with the user."),
	    USERIDTOKEN_IDENTITY_NOT_FOUND : new MslError(2013, MslConstants.ResponseCode.USER_REAUTH, "The user identity was not found."),
	    USERIDTOKEN_PASSWORD_VERSION_CHANGED : new MslError(2014, MslConstants.ResponseCode.USER_REAUTH, "The user identity must be reauthenticated because the password version changed."),
	    USERIDTOKEN_USERAUTH_DATA_MISMATCH : new MslError(2015, MslConstants.ResponseCode.USER_REAUTH, "The user ID token and user authentication data user identities do not match."),
	    USERIDTOKEN_TOKENDATA_MISSING : new MslError(2016, MslConstants.ResponseCode.USER_REAUTH, "No user ID token data found."),
	    USERIDTOKEN_TOKENDATA_PARSE_ERROR : new MslError(2017, MslConstants.ResponseCode.USER_REAUTH, "Error parsing user ID token data."),
	    USERIDTOKEN_USERDATA_PARSE_ERROR : new MslError(2018, MslConstants.ResponseCode.USER_REAUTH, "Error parsing user ID token user data."),
	    USERIDTOKEN_REVOKED : new MslError(2019, MslConstants.ResponseCode.USER_REAUTH, "User ID token is revoked."),
	    USERIDTOKEN_REJECTED_BY_APP : new MslError(2020, MslConstants.ResponseCode.USERDATA_REAUTH, "User ID token is rejected by the application."),

        // 3 Service Token
	    SERVICETOKEN_MASTERTOKEN_MISMATCH : new MslError(3000, MslConstants.ResponseCode.FAIL, "Service token master token serial number does not match master token serial number."),
	    SERVICETOKEN_USERIDTOKEN_MISMATCH : new MslError(3001, MslConstants.ResponseCode.FAIL, "Service token user ID token serial number does not match user ID token serial number."),
	    SERVICETOKEN_SERVICEDATA_INVALID : new MslError(3002, MslConstants.ResponseCode.FAIL, "Service token data invalid."),
	    SERVICETOKEN_MASTERTOKEN_NOT_FOUND : new MslError(3003, MslConstants.ResponseCode.FAIL, "Service token is bound to an unknown master token."),
	    SERVICETOKEN_USERIDTOKEN_NOT_FOUND : new MslError(3004, MslConstants.ResponseCode.FAIL, "Service token is bound to an unknown user ID token."),
	    SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE : new MslError(3005, MslConstants.ResponseCode.FAIL, "Service token master token serial number is out of range."),
	    SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE : new MslError(3006, MslConstants.ResponseCode.FAIL, "Service token user ID token serial number is out of range."),
	    SERVICETOKEN_TOKENDATA_INVALID : new MslError(3007, MslConstants.ResponseCode.FAIL, "Invalid service token data."),
	    SERVICETOKEN_SIGNATURE_INVALID : new MslError(3008, MslConstants.ResponseCode.FAIL, "Invalid service token signature."),
	    SERVICETOKEN_TOKENDATA_MISSING : new MslError(3009, MslConstants.ResponseCode.FAIL, "No service token data found."),
	
	    // 4 Entity Authentication
	    UNIDENTIFIED_ENTITYAUTH_SCHEME : new MslError(4000, MslConstants.ResponseCode.FAIL, "Unable to identify entity authentication scheme."),
	    ENTITYAUTH_FACTORY_NOT_FOUND : new MslError(4001, MslConstants.ResponseCode.FAIL, "No factory registered for entity authentication scheme."),
	    X509CERT_PARSE_ERROR : new MslError(4002, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "Error parsing X.509 certificate data."),
	    X509CERT_ENCODE_ERROR : new MslError(4003, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "Error encoding X.509 certificate data."),
	    X509CERT_VERIFICATION_FAILED : new MslError(4004, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "X.509 certificate verification failed."),
	    ENTITY_NOT_FOUND : new MslError(4005, MslConstants.ResponseCode.FAIL, "Entity not recognized."),
	    INCORRECT_ENTITYAUTH_DATA : new MslError(4006, MslConstants.ResponseCode.FAIL, "Entity used incorrect entity authentication data type."),
	    RSA_PUBLICKEY_NOT_FOUND : new MslError(4007, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "RSA public key not found."),
	    UNSUPPORTED_ENTITYAUTH_DATA : new MslError(4023, MslConstants.ResponseCode.FAIL, "Unsupported entity authentication data."),
	    ENTITY_REVOKED : new MslError(4025, MslConstants.ResponseCode.FAIL, "Entity is revoked."),
	    ENTITY_REJECTED_BY_APP : new MslError(4026, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "Entity is rejected by the application."),
	    X509CERT_EXPIRED : new MslError(4028, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "X.509 certificate is expired."),
	    X509CERT_NOT_YET_VALID : new MslError(4029, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "X.509 certificate is not yet valid."),
	    X509CERT_INVALID : new MslError(4030, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "X.509 certificate is invalid."),
	    RSA_PRIVATEKEY_NOT_FOUND : new MslError(4031, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "RSA private key not found."),
	    ENTITYAUTH_MASTERTOKEN_NOT_DECRYPTED : new MslError(4032, MslConstants.ResponseCode.FAIL, "Entity authentication data master token is not decrypted or verified."),
	    ENTITYAUTH_SIGNATURE_INVALID : new MslError(4033, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "Invalid entity authentication data siganture."),
	    ENTITYAUTH_CIPHERTEXT_INVALID : new MslError(4034, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "Invalid entity authentication data ciphertext."),
	    ENTITYAUTH_VERIFICATION_FAILED : new MslError(4035, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "Entity authentication data signature verification failed."),
	    ENTITYAUTH_MASTERTOKEN_INVALID : new MslError(4036, MslConstants.ResponseCode.FAIL, "Invalid entity authentication data master token."),
	    ECC_PUBLICKEY_NOT_FOUND : new MslError(4037, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "ECC public key not found."),
	    ECC_PRIVATEKEY_NOT_FOUND : new MslError(4038, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "ECC private key not found."),
	    
	    // 5 User Authentication
	    UNIDENTIFIED_USERAUTH_SCHEME : new MslError(5003, MslConstants.ResponseCode.FAIL, "Unable to identify user authentication scheme."),
	    USERAUTH_FACTORY_NOT_FOUND : new MslError(5004, MslConstants.ResponseCode.FAIL, "No factory registered for user authentication scheme."),
	    EMAILPASSWORD_BLANK : new MslError(5005, MslConstants.ResponseCode.USERDATA_REAUTH, "Email or password is blank."),
	    EMAILPASSWORD_INCORRECT : new MslError(5007, MslConstants.ResponseCode.USERDATA_REAUTH, "Email or password is incorrect."),
	    UNSUPPORTED_USERAUTH_DATA : new MslError(5008, MslConstants.ResponseCode.FAIL, "Unsupported user authentication data."),
	    USERAUTH_USERIDTOKEN_INVALID : new MslError(5011, MslConstants.ResponseCode.USERDATA_REAUTH, "User authentication data user ID token is invalid."),
	    UNIDENTIFIED_USERAUTH_MECHANISM : new MslError(5013, MslConstants.ResponseCode.FAIL, "Unable to identify user authentication mechanism."),
	    UNSUPPORTED_USERAUTH_MECHANISM : new MslError(5014, MslConstants.ResponseCode.FAIL, "Unsupported user authentication mechanism."),
	    USERAUTH_MASTERTOKEN_MISSING : new MslError(5016, MslConstants.ResponseCode.USERDATA_REAUTH, "User authentication required master token is missing."),
	    USERAUTH_USERIDTOKEN_NOT_DECRYPTED : new MslError(5021, MslConstants.ResponseCode.USERDATA_REAUTH, "User authentication data user ID token is not decrypted or verified."),
	    USERAUTH_MASTERTOKEN_INVALID : new MslError(5024, MslConstants.ResponseCode.USERDATA_REAUTH, "User authentication data master token is invalid."),
	    USERAUTH_MASTERTOKEN_NOT_DECRYPTED : new MslError(5025, MslConstants.ResponseCode.USERDATA_REAUTH, "User authentication data master token is not decrypted or verified."),
	    USERAUTH_USERIDTOKEN_MISSING : new MslError(5030, MslConstants.ResponseCode.USERDATA_REAUTH, "User authentication required user ID token is missing."),
	    USERAUTH_ENTITY_MISMATCH : new MslError(5032, MslConstants.ResponseCode.USERDATA_REAUTH, "User authentication data does not match entity identity."),
	    USERAUTH_ENTITY_INCORRECT_DATA : new MslError(5033, MslConstants.ResponseCode.FAIL, "Entity used incorrect user authentication data type."),
	    USER_REJECTED_BY_APP : new MslError(5037, MslConstants.ResponseCode.USERDATA_REAUTH, "User is rejected by the application."),
	    USERIDTOKEN_IDENTITY_NOT_ASSOCIATED_WITH_ENTITY : new MslError(5040, MslConstants.ResponseCode.USER_REAUTH, "The entity is not associated with the user."),
	    USERAUTH_ENTITYUSER_INCORRECT_DATA : new MslError(5041, MslConstants.ResponseCode.USERDATA_REAUTH, "Entity and user combination used incorrect user authentication data type."),
	    USERAUTH_VERIFICATION_FAILED : new MslError(5042, MslConstants.ResponseCode.USERDATA_REAUTH, "User authentication data signature verification failed."),
        USERAUTH_USERIDTOKEN_REVOKE_CHECK_ERROR : new MslError(5043, MslConstants.ResponseCode.USERDATA_REAUTH, "User ID token could not be checked for revocation."),

        // 6 Message
	    UNSUPPORTED_COMPRESSION : new MslError(6000, MslConstants.ResponseCode.FAIL, "Unsupported compression algorithm."),
	    COMPRESSION_ERROR : new MslError(6001, MslConstants.ResponseCode.FAIL, "Error compressing data."),
	    UNCOMPRESSION_ERROR : new MslError(6002, MslConstants.ResponseCode.FAIL, "Error uncompressing data."),
	    MESSAGE_ENTITY_NOT_FOUND : new MslError(6003, MslConstants.ResponseCode.FAIL, "Message header entity authentication data or master token not found."),
	    PAYLOAD_MESSAGE_ID_MISMATCH : new MslError(6004, MslConstants.ResponseCode.FAIL, "Payload chunk message ID does not match header message ID ."),
	    PAYLOAD_SEQUENCE_NUMBER_MISMATCH : new MslError(6005, MslConstants.ResponseCode.FAIL, "Payload chunk sequence number does not match expected sequence number."),
	    PAYLOAD_VERIFICATION_FAILED : new MslError(6006, MslConstants.ResponseCode.FAIL, "Payload chunk payload signature verification failed."),
	    MESSAGE_DATA_MISSING : new MslError(6007, MslConstants.ResponseCode.FAIL, "No message data found."),
	    MESSAGE_FORMAT_ERROR : new MslError(6008, MslConstants.ResponseCode.FAIL, "Malformed message data."),
	    MESSAGE_VERIFICATION_FAILED : new MslError(6009, MslConstants.ResponseCode.FAIL, "Message header/error data signature verification failed."),
	    HEADER_DATA_MISSING : new MslError(6010, MslConstants.ResponseCode.FAIL, "No header data found."),
	    PAYLOAD_DATA_MISSING : new MslError(6011, MslConstants.ResponseCode.FAIL, "No payload data found in non-EOM payload chunk."),
	    PAYLOAD_DATA_CORRUPT : new MslError(6012, MslConstants.ResponseCode.FAIL, "Corrupt payload data found in non-EOM payload chunk."),
	    UNIDENTIFIED_COMPRESSION : new MslError(6013, MslConstants.ResponseCode.FAIL, "Unidentified compression algorithm."),
	    MESSAGE_EXPIRED : new MslError(6014, MslConstants.ResponseCode.EXPIRED, "Message expired and not renewable. Rejected."),
	    MESSAGE_ID_OUT_OF_RANGE : new MslError(6015, MslConstants.ResponseCode.FAIL, "Message ID is out of range."),
	    INTERNAL_CODE_NEGATIVE : new MslError(6016, MslConstants.ResponseCode.FAIL, "Error header internal code is negative."),
	    UNEXPECTED_RESPONSE_MESSAGE_ID : new MslError(6017, MslConstants.ResponseCode.FAIL, "Unexpected response message ID. Possible replay."),
	    RESPONSE_REQUIRES_ENCRYPTION : new MslError(6018, MslConstants.ResponseCode.KEYX_REQUIRED, "Message response requires encryption."),
	    PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE : new MslError(6019, MslConstants.ResponseCode.FAIL, "Payload chunk sequence number is out of range."),
	    PAYLOAD_MESSAGE_ID_OUT_OF_RANGE : new MslError(6020, MslConstants.ResponseCode.FAIL, "Payload chunk message ID is out of range."),
	    MESSAGE_REPLAYED : new MslError(6021, MslConstants.ResponseCode.REPLAYED, "Non-replayable message replayed."),
	    INCOMPLETE_NONREPLAYABLE_MESSAGE : new MslError(6022, MslConstants.ResponseCode.FAIL, "Non-replayable message sent without a master token."),
	    HEADER_SIGNATURE_INVALID : new MslError(6023, MslConstants.ResponseCode.FAIL, "Invalid Header signature."),
	    HEADER_DATA_INVALID : new MslError(6024, MslConstants.ResponseCode.FAIL, "Invalid header data."),
	    PAYLOAD_INVALID : new MslError(6025, MslConstants.ResponseCode.FAIL, "Invalid payload."),
	    PAYLOAD_SIGNATURE_INVALID : new MslError(6026, MslConstants.ResponseCode.FAIL, "Invalid payload signature."),
	    RESPONSE_REQUIRES_MASTERTOKEN : new MslError(6027, MslConstants.ResponseCode.KEYX_REQUIRED, "Message response requires a master token."),
	    RESPONSE_REQUIRES_USERIDTOKEN : new MslError(6028, MslConstants.ResponseCode.USER_REAUTH, "Message response requires a user ID token."),
	    REQUEST_REQUIRES_USERAUTHDATA : new MslError(6029, MslConstants.ResponseCode.FAIL, "User-associated message requires user authentication data."),
	    UNEXPECTED_MESSAGE_SENDER : new MslError(6030, MslConstants.ResponseCode.FAIL, "Message sender is equal to the local entity or not the master token entity."),
	    NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN : new MslError(6031, MslConstants.ResponseCode.FAIL, "Non-replayable message requires a master token."),
	    NONREPLAYABLE_ID_OUT_OF_RANGE : new MslError(6032, MslConstants.ResponseCode.FAIL, "Non-replayable message non-replayable ID is out of range."),
	    MESSAGE_SERVICETOKEN_MISMATCH : new MslError(6033, MslConstants.ResponseCode.FAIL, "Service token master token or user ID token serial number does not match the message token serial numbers."),
	    MESSAGE_PEER_SERVICETOKEN_MISMATCH : new MslError(6034, MslConstants.ResponseCode.FAIL, "Peer service token master token or user ID token serial number does not match the message peer token serial numbers."),
	    RESPONSE_REQUIRES_INTEGRITY_PROTECTION : new MslError(6035, MslConstants.ResponseCode.KEYX_REQUIRED, "Message response requires integrity protection."),
	    HANDSHAKE_DATA_MISSING : new MslError(6036, MslConstants.ResponseCode.FAIL, "Handshake message is not renewable or does not contain key request data."),
	    MESSAGE_RECIPIENT_MISMATCH : new MslError(6037, MslConstants.ResponseCode.FAIL, "Message recipient does not match local identity."),
	    MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED : new MslError(6038, MslConstants.ResponseCode.ENTITYDATA_REAUTH, "Message header entity-based signature verification failed."),
	    MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED : new MslError(6039, MslConstants.ResponseCode.ENTITY_REAUTH, "Message header master token-based signature verification failed."),
	    MESSAGE_REPLAYED_UNRECOVERABLE : new MslError(6040, MslConstants.ResponseCode.ENTITY_REAUTH, "Non-replayable message replayed with a sequence number that is too far out of sync to recover."),
	    UNEXPECTED_LOCAL_MESSAGE_SENDER : new MslError(6041, MslConstants.ResponseCode.FAIL, "Message sender is equal to the local entity."),
	    UNENCRYPTED_MESSAGE_WITH_USERAUTHDATA : new MslError(6042, MslConstants.ResponseCode.FAIL, "User authentication data included in unencrypted message header."),
	    MESSAGE_SENDER_MISMATCH : new MslError(6043, MslConstants.ResponseCode.FAIL, "Message sender entity identity does not match expected identity."),
	    MESSAGE_EXPIRED_NOT_RENEWABLE : new MslError(6044, MslConstants.ResponseCode.EXPIRED, "Message expired and not renewable. Rejected."),
	    MESSAGE_EXPIRED_NO_KEYREQUEST_DATA : new MslError(6045, MslConstants.ResponseCode.EXPIRED, "Message expired and missing key request data. Rejected."),

	    // 7 Key Exchange
	    UNIDENTIFIED_KEYX_SCHEME : new MslError(7000, MslConstants.ResponseCode.FAIL, "Unable to identify key exchange scheme."),
	    KEYX_FACTORY_NOT_FOUND : new MslError(7001, MslConstants.ResponseCode.FAIL, "No factory registered for key exchange scheme."),
	    KEYX_REQUEST_NOT_FOUND : new MslError(7002, MslConstants.ResponseCode.FAIL, "No key request found matching header key response data."),
	    UNIDENTIFIED_KEYX_KEY_ID : new MslError(7003, MslConstants.ResponseCode.FAIL, "Unable to identify key exchange key ID."),
	    UNSUPPORTED_KEYX_KEY_ID : new MslError(7004, MslConstants.ResponseCode.FAIL, "Unsupported key exchange key ID."),
	    UNIDENTIFIED_KEYX_MECHANISM : new MslError(7005, MslConstants.ResponseCode.FAIL, "Unable to identify key exchange mechanism."),
	    UNSUPPORTED_KEYX_MECHANISM : new MslError(7006, MslConstants.ResponseCode.FAIL, "Unsupported key exchange mechanism."),
	    KEYX_RESPONSE_REQUEST_MISMATCH : new MslError(7007, MslConstants.ResponseCode.FAIL, "Key exchange response does not match request."),
	    KEYX_PRIVATE_KEY_MISSING : new MslError(7008, MslConstants.ResponseCode.FAIL, "Key exchange private key missing."),
	    UNKNOWN_KEYX_PARAMETERS_ID : new MslError(7009, MslConstants.ResponseCode.FAIL, "Key exchange parameters ID unknown or invalid."),
	    KEYX_MASTER_TOKEN_MISSING : new MslError(7010, MslConstants.ResponseCode.FAIL, "Master token required for key exchange is missing."),
	    KEYX_INVALID_PUBLIC_KEY : new MslError(7011, MslConstants.ResponseCode.FAIL, "Key exchange public key is invalid."),
	    KEYX_PUBLIC_KEY_MISSING : new MslError(7012, MslConstants.ResponseCode.FAIL, "Key exchange public key missing."),
	    KEYX_WRAPPING_KEY_MISSING : new MslError(7013, MslConstants.ResponseCode.FAIL, "Key exchange wrapping key missing."),
	    KEYX_WRAPPING_KEY_ID_MISSING : new MslError(7014, MslConstants.ResponseCode.FAIL, "Key exchange wrapping key ID missing."),
	    KEYX_INVALID_WRAPPING_KEY : new MslError(7015, MslConstants.ResponseCode.FAIL, "Key exchange wrapping key is invalid."),
	    KEYX_INCORRECT_DATA : new MslError(7016, MslConstants.ResponseCode.FAIL, "Entity used incorrect key exchange data type."),
	    KEYX_INCORRECT_MECHANISM : new MslError(7017, MslConstants.ResponseCode.FAIL, "Entity used incorrect key exchange mecahnism."),
	    KEYX_DERIVATION_KEY_MISSING : new MslError(7018, MslConstants.ResponseCode.FAIL, "Key exchange derivation key missing."),
	    KEYX_INVALID_ENCRYPTION_KEY : new MslError(7019, MslConstants.ResponseCode.FAIL, "Key exchange encryption key is invalid."),
	    KEYX_INVALID_HMAC_KEY : new MslError(7020, MslConstants.ResponseCode.FAIL, "Key exchange HMAC key is invalid."),
	    KEYX_INVALID_WRAPDATA : new MslError(7021, MslConstants.ResponseCode.FAIL, "Key exchange wrap data is invalid."),
	    UNSUPPORTED_KEYX_SCHEME : new MslError(7022, MslConstants.ResponseCode.FAIL, "Unsupported key exchange scheme."),
	    KEYX_IDENTITY_NOT_FOUND : new MslError(7023, MslConstants.ResponseCode.FAIL, "Key exchange identity not found."),
	
	    // 9 Internal Errors
	    INTERNAL_EXCEPTION : new MslError(9000, MslConstants.ResponseCode.TRANSIENT_FAILURE, "Internal exception."),
	    MSL_COMMS_FAILURE : new MslError(9001, MslConstants.ResponseCode.FAIL, "Error communicating with MSL entity."),
	    NONE : new MslError(9999, MslConstants.ResponseCode.FAIL, "Special unit test error.")
	}));
	Object.freeze(MslError);
})(require, (typeof module !== 'undefined') ? module : mkmodule('MslError'));
