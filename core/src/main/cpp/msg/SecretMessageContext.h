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

#ifndef SRC_MSG_SECRETMESSAGECONTEXT_H_
#define SRC_MSG_SECRETMESSAGECONTEXT_H_

#include <msg/MessageContext.h>

namespace netflix {
namespace msl {
namespace msg {

/**
 * <p>A message context implementation that can be extended for use with
 * messages that have secret contents which must be protected from the view of
 * unauthorized parties. The contents will be encrypted and integrity protected
 * but still replayable.</p>
 *
 * <p>Most messages should be considered secret messages. Examples would
 * private conversations between individuals or the transmission of personal
 * information.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class SecretMessageContext : public MessageContext
{
public:
	virtual ~SecretMessageContext() {}

    /** @inheritDoc */
    virtual bool isEncrypted() { return true; }

    /** @inheritDoc */
    virtual bool isIntegrityProtected() { return true; }

    /** @inheritDoc */
    virtual bool isNonReplayable() { return false; }
};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_SECRETMESSAGECONTEXT_H_ */
