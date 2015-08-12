/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
package kancolle.keyx;

import java.math.BigInteger;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.DHParameterSpec;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.DiffieHellmanParameters;

/**
 * <p>KanColle Diffie-Hellman parameters.</p>
 * 
 * <p>Currently only one set of parameters is supported, and this is hard-coded
 * into the class.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColleDiffieHellmanParameters implements DiffieHellmanParameters {
    /** Default parameters. */
    private static BigInteger p = new BigInteger("C2048E076B268761DB1427BA3AD98473D32B0ABDEE98C0827923426F294EDA3392BF0032A1D8092055B58BAA07586A7D3E271C39A8C891F5CEEA4DEBDFA6B023", 16);
    private static BigInteger g = new BigInteger("02", 16);

    /** Diffie-Hellman parameter ID. */
    public static final String PARAM_ID = "KanColle";
    /** Diffie-Hellman parameter specification. */
    private static final DHParameterSpec paramSpec = new DHParameterSpec(p, g);
    
    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.DiffieHellmanParameters#getParameterSpecs()
     */
    @Override
    public Map<String,DHParameterSpec> getParameterSpecs() throws MslKeyExchangeException {
        final Map<String,DHParameterSpec> params = new HashMap<String,DHParameterSpec>();
        params.put(PARAM_ID, paramSpec);
        return Collections.unmodifiableMap(params);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.DiffieHellmanParameters#getParameterSpec(java.lang.String)
     */
    @Override
    public DHParameterSpec getParameterSpec(final String id) throws MslKeyExchangeException {
        if (PARAM_ID.equals(id))
            return paramSpec;
        return null;
    }

}
