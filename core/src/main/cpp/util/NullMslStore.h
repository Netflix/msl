/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_UTIL_NULLMSLSTORE_H_
#define SRC_UTIL_NULLMSLSTORE_H_

#include <util/MslStore.h>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace tokens { class MasterToken; class ServiceToken; class UserIdToken; }
namespace util {

/**
 * <p>A MSL store where all operations are no-ops.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class NullMslStore : public MslStore
{
public:
	virtual ~NullMslStore() {}

    /** @inheritDoc */
    virtual void setCryptoContext(std::shared_ptr<tokens::MasterToken>, std::shared_ptr<crypto::ICryptoContext>) {}

    /** @inheritDoc */
    virtual std::shared_ptr<tokens::MasterToken> getMasterToken();

    /** @inheritDoc */
    virtual int64_t getNonReplayableId(std::shared_ptr<tokens::MasterToken> /*masterToken*/) {
        return 1;
    }

    /** @inheritDoc */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(std::shared_ptr<tokens::MasterToken> masterToken);

    /** @inheritDoc */
    virtual void removeCryptoContext(std::shared_ptr<tokens::MasterToken> /*masterToken*/) {}

    /** @inheritDoc */
    virtual void clearCryptoContexts() {}

    /** @inheritDoc */
    virtual void addUserIdToken(const std::string& /*userId*/, std::shared_ptr<tokens::UserIdToken> /*userIdToken*/) {}

    /** @inheritDoc */
    virtual std::shared_ptr<tokens::UserIdToken> getUserIdToken(const std::string& /*userId*/);

    /** @inheritDoc */
    virtual void removeUserIdToken(std::shared_ptr<tokens::UserIdToken> /*userIdToken*/) {}

    /** @inheritDoc */
    virtual void clearUserIdTokens() {}

    /** @inheritDoc */
    virtual void addServiceTokens(std::set<std::shared_ptr<tokens::ServiceToken>> /*tokens*/) {}

    /** @inheritDoc */
    virtual std::set<std::shared_ptr<tokens::ServiceToken>> getServiceTokens(std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken);

    /** @inheritDoc */
    virtual void removeServiceTokens(std::shared_ptr<std::string> name, std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken);

    /** @inheritDoc */
    virtual void clearServiceTokens() {}
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_NULLMSLSTORE_H_ */
