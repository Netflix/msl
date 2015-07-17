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

package mslcli.common.util;

/**
 * <p>ConfigurationException class for MSL CLI configuration file errors.</p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */
public class ConfigurationException extends Exception {
    /** serial version for serialization */
    private static final long serialVersionUID = 8802095343158937216L;
    /** Default Ctor */
    public ConfigurationException() {
        super();
    }
    /**
     * @param message exception message
     */
    public ConfigurationException(String message) {
        super(message);
    }
    /**
     * @param message exception message
     * @param cause exception cause
     */
    public ConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
    /**
     * @param cause exception cause
     */
    public ConfigurationException(Throwable cause) {
        super(cause);
    }
}

