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
package com.netflix.msl.server.servlet;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.server.common.RespondServlet;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;

/**
 * User: skommidi
 * Date: 8/27/14
 */
public class NullServlet extends RespondServlet {
    private static final long serialVersionUID = -2879936348232394823L;
    
    private static final long SEQUENCE_NUMBER = 8L;
    private static final int NUM_THREADS = 0;

    public NullServlet() throws Exception {
        super(NUM_THREADS, EntityAuthenticationScheme.NONE, TokenFactoryType.NOT_ACCEPT_NON_REPLAYABLE_ID,
                SEQUENCE_NUMBER, false, false, null, null, null, true, true);
        System.out.println("======================>> Null Servlet Initialization Ended <<======================");
    }
}
