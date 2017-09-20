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

#ifndef SRC_MSG_MESSAGEDEBUGCONTEXT_H_
#define SRC_MSG_MESSAGEDEBUGCONTEXT_H_

#include <memory>

namespace netflix {
namespace msl {
namespace msg {
class Header;

/**
 * <p>A message debug context is used to provide debugging callbacks to
 * {@link com.netflix.msl.msg.MslControl}.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageDebugContext
{
public:
	virtual ~MessageDebugContext() {}

    /**
     * Called just prior to sending a message with the message header or error
     * header that will be sent. An error may occur preventing successful
     * transmission of the header after this method is called.
     *
     * @param header message header or error header.
     */
    virtual void sentHeader(std::shared_ptr<Header> header) = 0;

    /**
     * Called just after receiving a message, before performing additional
     * validation, with the message header or error header.
     *
     * @param header message header or error header.
     */
    virtual void receivedHeader(std::shared_ptr<Header> header) = 0;
};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_MESSAGEDEBUGCONTEXT_H_ */
