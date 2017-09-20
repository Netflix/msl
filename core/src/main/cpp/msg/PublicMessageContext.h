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

#ifndef SRC_MSG_PUBLICMESSAGECONTEXT_H_
#define SRC_MSG_PUBLICMESSAGECONTEXT_H_

#include <msg/MessageContext.h>

namespace netflix {
namespace msl {
namespace msg {

/**
 * <p>A message context implementation that can be extended for use with
 * messages that do not require contents to be encrypted, only to be integrity
 * protected. If encryption is possible the message contents will be
 * encrypted.</p>
 *
 * <p>Example uses of the public message context would be for the broadcast of
 * authenticated public announcements or the transmission of information that
 * is useless after a short period of time.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class PublicMessageContext : public MessageContext
{
public:
	virtual ~PublicMessageContext() {}

    /** @inheritDoc */
    virtual bool isEncrypted() { return false; }

    /** @inheritDoc */
    virtual bool isIntegrityProtected() { return true; }

    /** @inheritDoc */
    virtual bool isNonReplayable() { return false; }
};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_PUBLICMESSAGECONTEXT_H_ */

