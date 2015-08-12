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
package com.netflix.msl.tokens;

/**
 * <p>A MSL user. The {@link #equals(Object)} and {@link #hashCode()} methods
 * must be implemented.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface MslUser {
    /**
     * <p>Returns a serialized data encoding of the MSL user. This is the value
     * that will be used by the MSL stack during transport and to reconstruct
     * the MSL user instance.</p>
     * 
     * @return the MSL user encoding.
     */
    public String getEncoded();
    
    /**
     * <p>Compares this object against the provided object. This method must
     * return true if the provided object is a {@code MslUser} referencing the
     * same MSL user.</p>
     * 
     * @param obj the object with which to compare.
     * @return {@code true} if the object is a {@code MslUser} that references
     *         the same MSL user.
     * @see #hashCode()
     */
    @Override
    public boolean equals(final Object obj);
    
    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode();
}
