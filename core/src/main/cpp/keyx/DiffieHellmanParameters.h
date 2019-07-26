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

#ifndef SRC_KEYX_DIFFIEHELLMANPARAMETERS_H_
#define SRC_KEYX_DIFFIEHELLMANPARAMETERS_H_

#include <stdint.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace keyx {

class DHParameterSpec
{
public:
    DHParameterSpec() {}
    DHParameterSpec(std::shared_ptr<ByteArray> p, std::shared_ptr<ByteArray> g)
    : p(p), g(g) {}
    std::shared_ptr<ByteArray> getP() const { return p; }
    std::shared_ptr<ByteArray> getG() const { return g; }
private:
    std::shared_ptr<ByteArray> p;
    std::shared_ptr<ByteArray> g;

};

class DiffieHellmanParameters
{
public:
    /**
     * @return the map of Diffie-Hellman parameters by parameter ID.
     * @throws MslKeyExchangeException if there is an error accessing the
     *         parameters.
     */
    virtual std::map<std::string, DHParameterSpec> getParameterSpecs() const = 0;

    /**
     * Returns the Diffie-Hellman parameter specification identified by the
     * parameters ID.
     *
     * @param id the parameters ID.
     * @return the parameter specification or null if the parameters ID is
     *         not recognized.
     * @throws MslKeyExchangeException if there is an error accessing the
     *         parameter specification.
     */
    virtual DHParameterSpec getParameterSpec(const std::string& id) const = 0;

protected:
    virtual ~DiffieHellmanParameters() {}
};

}}} // namespace netflix::msl:keyx

#endif /* SRC_KEYX_DIFFIEHELLMANPARAMETERS_H_ */
