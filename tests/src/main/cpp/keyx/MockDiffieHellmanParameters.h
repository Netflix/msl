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

#ifndef TEST_KEYX_MOCKDIFFIEHELLMANPARAMETERS_H_
#define TEST_KEYX_MOCKDIFFIEHELLMANPARAMETERS_H_

#include <keyx/DiffieHellmanParameters.h>
#include <map>
#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace keyx {

/**
 * Test Diffie-Hellman parameters.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MockDiffieHellmanParameters: public DiffieHellmanParameters
{
public:
    virtual ~MockDiffieHellmanParameters() {}

    /** Default parameter ID. */
    static std::string DEFAULT_ID();

    /**
     * Returns the default test parameters containing a single set of Diffie-
     * Hellman parameters associated the default parameter ID.
     *
     * @return the default test parameters.
     */
    static std::shared_ptr<MockDiffieHellmanParameters> getDefaultParameters();

    /**
     * Add Diffie-Hellman parameters.
     *
     * @param id parameters ID.
     * @param spec Diffie-Hellman parameters.
     */
    void addParameterSpec(const std::string& id, const DHParameterSpec& spec);

    /**
     * Remove all known parameter specs.
     */
    void clear();

    /** @inheritDoc */
    virtual std::map<std::string, DHParameterSpec> getParameterSpecs() const;

    /** @inheritDoc */
    virtual DHParameterSpec getParameterSpec(const std::string& id) const;

private:
    /** Diffie-Hellman parameters. */
    std::map<std::string, DHParameterSpec> params;
};

}}} // namespace netflix::msl::keyx

#endif /* TEST_KEYX_MOCKDIFFIEHELLMANPARAMETERS_H_ */
