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
package kancolle.entityauth;

/**
 * Provides access to naval port data.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface NavalPortDatabase {
    /** Kanmusu status. */
    public static enum Status {
        /** Active. */
        ACTIVE,
        /** Inactive. */
        INACTIVE,
        /** Presumed captured. */
        CAPTURED,
        /** Confirmed destroyed. */
        DESTROYED
    }
    
    /**
     * Return the current status of the specified naval port.
     * 
     * @param callsign the naval port callsign.
     * @return the port's current status or {@code null} if the port is not
     *         recognized.
     */
    public Status getStatus(final String callsign);
    
    /**
     * Return the code book for the specified naval port.
     * 
     * @param callsign the naval port callsign.
     * @return the port's code book or {@code null} if the port is not
     *         recognized.
     */
    public CodeBook getCodeBook(final String callsign);
}
