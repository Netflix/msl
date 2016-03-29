/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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

/**
 * <p>Common header JSON keys.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class HeaderKeys {
    /** JSON key entity authentication data. */
    public static final String KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
    /** JSON key master token. */
    public static final String KEY_MASTER_TOKEN = "mastertoken";
    /** JSON key header data. */
    public static final String KEY_HEADERDATA = "headerdata";
    /** JSON key error data. */
    public static final String KEY_ERRORDATA = "errordata";
    /** JSON key signature. */
    public static final String KEY_SIGNATURE = "signature";
}
