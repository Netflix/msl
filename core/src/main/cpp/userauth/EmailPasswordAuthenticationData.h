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

#ifndef SRC_USERAUTH_EMAILPASSWORDAUTHENTICATIONDATA_H_
#define SRC_USERAUTH_EMAILPASSWORDAUTHENTICATIONDATA_H_

#include <userauth/UserAuthenticationData.h>
#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace io { class MslEncoderFactory; class MslEncoderFormat; class MslObject; }
namespace userauth {

/**
 * <p>Email/password-based user authentication data.</p>
 *
 * <p>
 * {@code {
 *   "#mandatory" : [ "email", "password" ],
 *   "email" : "string",
 *   "password" : "string"
 * }} where:
 * <ul>
 * <li>{@code email} is the user email address</li>
 * <li>{@code password} is the user password</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class EmailPasswordAuthenticationData: public UserAuthenticationData
{
public:
    virtual ~EmailPasswordAuthenticationData() {}

    /**
     * Construct a new email/password authentication data instance from the
     * specified email and password.
     *
     * @param email the email address.
     * @param password the password.
     */
    EmailPasswordAuthenticationData(const std::string email, const std::string password);

    /**
     * Construct a new email/password authentication data instance from the
     * provided MSL object.
     *
     * @param emailPasswordAuthMo the MSL object.
     * @throws MslEncodingException if there is an error parsing the data.
     */
    EmailPasswordAuthenticationData(std::shared_ptr<io::MslObject> emailPasswordAuthMo);

    /**
     * @return the email address.
     */
    std::string getEmail() const { return email_; }

    /**
     * @return the password.
     */
    std::string getPassword() const { return password_; }

    virtual std::shared_ptr<io::MslObject> getAuthData(std::shared_ptr<io::MslEncoderFactory> encoder,
            const io::MslEncoderFormat& format) const;

    virtual bool equals(std::shared_ptr<const UserAuthenticationData> that) const;

private:
    EmailPasswordAuthenticationData();  // not implemented
private:
    /** Email. */
    std::string email_;
    /** Password. */
    std::string password_;
};

bool operator==(const EmailPasswordAuthenticationData& a, const EmailPasswordAuthenticationData& b);
inline bool operator!=(const EmailPasswordAuthenticationData& a, const EmailPasswordAuthenticationData& b) { return !(a == b); }

}}} // netflix::msl::userauth

#endif /* SRC_USERAUTH_EMAILPASSWORDAUTHENTICATIONDATA_H_ */
