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
package burp.msl;

/**
 * <p>Thrown when a wiretap exception occurs.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class WiretapException extends Exception {
    private static final long serialVersionUID = 664626450364720991L;

    /**
     * <p>Create a new wiretap exception with the provided message.</p>
     * 
     * @param message the detail message.
     */
    public WiretapException(final String message) {
        super(message);
    }

    /**
     * <p>Create a new wiretap exception with the provided message and
     * cause.</p>
     * 
     * @param message the detail message.
     * @param cause the cause. May be {@code null}.
     */
    public WiretapException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
