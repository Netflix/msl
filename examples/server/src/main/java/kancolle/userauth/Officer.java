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

import com.netflix.msl.tokens.MslUser;

/**
 * <p>An officer is identified by a name.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class Officer implements MslUser {
    /**
     * Create an officer with the given name.
     * 
     * @param name officer name.
     */
    public Officer(final String name) {
        this.name = name;
    }
    
    /**
     * @return the officer name.
     */
    public String getName() {
        return name;
    }
    
    /**
     * @return the officer name.
     * @see com.netflix.msl.tokens.MslUser#getEncoded()
     */
    @Override
    public String getEncoded() {
        return name;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return name.hashCode();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof Officer)) return false;
        final Officer that = (Officer)obj;
        return this.name.equals(that.name);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return name;
    }

    /** Officer name. */
    private final String name;
}
