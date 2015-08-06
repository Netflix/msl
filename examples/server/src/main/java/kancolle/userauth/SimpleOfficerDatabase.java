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
package kancolle.userauth;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>A simple in-memory officer database.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleOfficerDatabase implements OfficerDatabase {
    /**
     * <p>Create a new simple officer database instance that is unaware of any
     * existing officers.</p>
     */
    public SimpleOfficerDatabase() {
    }

    /**
     * <p>Set the officer data. This adds the officer if previously
     * unknown.</p>
     * 
     * @param name officer name.
     * @param state officer state.
     */
    public void setOfficer(final String name, final Status state, final byte[] fingerprint) {
        if (state == null)
            throw new IllegalArgumentException("Officer state cannot be null.");
        if (fingerprint == null)
            throw new IllegalArgumentException("Officer fingerprint cannot be null.");
        
        states.put(name, state);
        fingerprints.put(name, fingerprint);
    }
    
    /**
     * <p>Set the officer state. The officer must already be known.</p>
     * 
     * @param name officer name.
     * @param state officer state.
     * @throws IllegalStateException if the ship is not known.
     */
    public void setState(final String name, final Status state) {
        if (state == null)
            throw new IllegalArgumentException("Officer state cannot be null.");
        
        if (!states.containsKey(name))
            throw new IllegalStateException("Officer " + name + " is not known.");
        states.put(name, state);
    }
    
    /* (non-Javadoc)
     * @see kancolle.userauth.OfficerDatabase#getStatus(java.lang.String)
     */
    @Override
    public Status getStatus(final String name) {
        return states.get(name);
    }

    @Override
    public byte[] getFingerprint(final String name) {
        return fingerprints.get(name);
    }

    /** Officer states by name. */
    private final Map<String,Status> states = new HashMap<String,Status>();
    /** Officer fingerprints by name. */
    private final Map<String,byte[]> fingerprints = new HashMap<String,byte[]>();
}
