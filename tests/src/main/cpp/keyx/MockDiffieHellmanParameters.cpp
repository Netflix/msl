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


#include "MockDiffieHellmanParameters.h"
#include <MslKeyExchangeException.h>
#include <util/Hex.h>

using namespace std;
using netflix::msl::util::fromHex;

namespace netflix {
namespace msl {
namespace keyx {

namespace {

/** Default parameters. */
const string pHex = "C2048E076B268761DB1427BA3AD98473D32B0ABDEE98C0827923426F294EDA3392BF0032A1D8092055B58BAA07586A7D3E271C39A8C891F5CEEA4DEBDFA6B023";
const string gHex = "02";

} // namespace anonymous

// static
std::string MockDiffieHellmanParameters::DEFAULT_ID()
{
    return "default1";
}

// static
shared_ptr<MockDiffieHellmanParameters> MockDiffieHellmanParameters::getDefaultParameters()
{
    shared_ptr<MockDiffieHellmanParameters> params = make_shared<MockDiffieHellmanParameters>();
    const DHParameterSpec paramSpec(util::fromHex(pHex), util::fromHex(gHex));
    params->addParameterSpec(DEFAULT_ID(), paramSpec);
    return params;
}

void MockDiffieHellmanParameters::addParameterSpec(const std::string& id, const DHParameterSpec& spec)
{
    params.insert(make_pair(id, spec));
}

void MockDiffieHellmanParameters::clear()
{
    params.clear();
}

map<string, DHParameterSpec> MockDiffieHellmanParameters::getParameterSpecs() const
{
    return params;
}

DHParameterSpec MockDiffieHellmanParameters::getParameterSpec(const std::string& id) const
{
    map<string, DHParameterSpec>::const_iterator it = params.find(id);
    if (it == params.end())
        throw MslKeyExchangeException(MslError::UNKNOWN_KEYX_PARAMETERS_ID, id);
    return it->second;
}

}}} // namespace netflix::msl::keyx
