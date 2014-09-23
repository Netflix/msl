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
 * Provides access to Kanmusu data.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface KanmusuDatabase {
    /** Kanmusu status. */
    public static enum Status {
        /** Active. */
        ACTIVE,
        /** Presumed captured. */
        CAPTURED,
        /** Presumed missing. */
        MISSING,
        /** Confirmed destroyed. */
        DESTROYED
    }
    
    /**
     * Return the current status of the specified Kanmusu ship.
     * 
     * @param type ship type.
     * @param name ship name.
     * @return the ship's current status or {@code null} if the ship is not
     *         recognized.
     */
    public Status getStatus(final String type, final String name);
    
    /**
     * Return the passphrase for the specified Kanmusu ship.
     * 
     * @param type ship type.
     * @param name ship name.
     * @return the generated passphrase or {@code null} if the ship is not
     *         recognized or accepted.
     */
    public String getPassphrase(final String type, final String name);
}
