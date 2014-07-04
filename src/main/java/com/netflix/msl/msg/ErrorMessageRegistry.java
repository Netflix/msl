/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.msg;

import java.util.List;

import com.netflix.msl.MslError;

/**
 * <p>The error message registry is used to provide localized user-consumable
 * messages for specific MSL errors.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface ErrorMessageRegistry {
    /**
     * Returns the user-consumable message associated with the given MSL error,
     * localized according to the list of preferred languages.
     * 
     * @param err MSL error.
     * @param languages preferred languages as BCP-47 codes in descending
     *        order. May be {@code null}.
     * @return the localized user message or {@code null} if there is none.
     */
    public String getUserMessage(final MslError err, final List<String> languages);
    
    /**
     * Returns the user-consumable message associated with a given non-MSL
     * error, localized according to the list of preferred languages.
     * 
     * @param err non-MSL error.
     * @param languages preferred languages as BCP-47 codes in descending
     *        order. May be {@code null}.
     * @return the localized user message or {@code null} if there is none.
     */
    public String getUserMessage(final Throwable err, final List<String> languages);
}
