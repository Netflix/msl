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

#include <msg/MessageStreamFactory.h>
#include <msg/MessageInputStream.h>
#include <msg/MessageOutputStream.h>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace msg {

shared_ptr<MessageInputStream> MessageStreamFactory::createInputStream(
		shared_ptr<MslContext> ctx,
		shared_ptr<InputStream> source,
		set<shared_ptr<keyx::KeyRequestData>> keyRequestData,
		map<string,shared_ptr<ICryptoContext>> cryptoContexts)
{
	return make_shared<MessageInputStream>(ctx, source, keyRequestData, cryptoContexts);
}

shared_ptr<MessageOutputStream> MessageStreamFactory::createOutputStream(
		shared_ptr<MslContext> ctx,
		shared_ptr<OutputStream> destination,
		shared_ptr<ErrorHeader> header,
		const MslEncoderFormat& format)
{
	return make_shared<MessageOutputStream>(ctx, destination, header, format);
}

shared_ptr<MessageOutputStream> MessageStreamFactory::createOutputStream(
		shared_ptr<MslContext> ctx,
		shared_ptr<OutputStream> destination,
		shared_ptr<MessageHeader> header,
		shared_ptr<ICryptoContext> cryptoContext)
{
	return make_shared<MessageOutputStream>(ctx, destination, header, cryptoContext);
}

}}} // namespace netflix::mslg::msg
