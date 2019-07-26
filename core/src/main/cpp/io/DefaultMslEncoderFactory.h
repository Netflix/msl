/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_IO_DEFAULTMSLENCODERFACTORY_H_
#define SRC_IO_DEFAULTMSLENCODERFACTORY_H_

#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <memory>
#include <set>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io {
class InputStream; class MslObject; class MslTokenizer;

/**
 * <p>Default {@link MslEncoderFactory} implementation that supports the
 * following encoder formats:
 * <ul>
 * <li>JSON: backed by RapidJSON.</li>
 * </ul>
 * </p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class DefaultMslEncoderFactory : public MslEncoderFactory
{
public:
	virtual ~DefaultMslEncoderFactory() {}
	DefaultMslEncoderFactory() {}

	/** @inheritDoc */
	virtual MslEncoderFormat getPreferredFormat(const std::set<MslEncoderFormat>& formats = std::set<MslEncoderFormat>());

protected:
	/** @inheritDoc */
	virtual std::shared_ptr<MslTokenizer> generateTokenizer(std::shared_ptr<InputStream> source, const MslEncoderFormat& format);

public:
	/** @inheritDoc */
	virtual std::shared_ptr<MslObject> parseObject(std::shared_ptr<ByteArray> encoding);

	/** @inheritDoc */
	virtual std::shared_ptr<ByteArray> encodeObject(std::shared_ptr<MslObject> object, const MslEncoderFormat& format);
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_DEFAULTMSLENCODERFACTORY_H_ */
