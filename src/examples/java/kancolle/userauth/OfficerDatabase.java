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

/**
 * Provides access to officer data.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface OfficerDatabase {
    /** Officer status. */
    public static enum Status {
        /** Active. */
        ACTIVE,
        /** Honorably discharged. */
        DISCHARGED,
        /** Court martialed. */
        COURT_MARTIALED,
        /** Presumed prisoner of war. */
        POW,
        /** Presumed missing in action. */
        MIA,
        /** Confirmed killed in action. */
        KIA,
        /** Confirmed deceased. */
        DECEASED,
    }
    
    /**
     * Return the current status of the specified officer.
     * 
     * @param name the officer name.
     * @return the officer's current status or {@code null} if the officer
     *         is not recognized.
     */
    public Status getStatus(final String name);
    
    /**
     * Return the fingerprint SHA-256 hash of the named officer.
     * 
     * @param name officer name.
     * @return the fingerprint hash or {@code null} if the officer name is
     *         not recognized.
     */
    public byte[] getFingerprint(final String name);
}