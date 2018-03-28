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

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.server.common.RespondServlet;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;

/**
 * User: skommidi
 * Date: 7/24/14
 */
public class EchoServlet extends RespondServlet {
    private static final long serialVersionUID = 3781170196441547122L;
    
    private static final long SEQUENCE_NUMBER = 8L;
    private static final int NUM_THREADS = 0;

    public EchoServlet() throws Exception {
        super(NUM_THREADS, EntityAuthenticationScheme.NONE, TokenFactoryType.NOT_ACCEPT_NON_REPLAYABLE_ID,
                SEQUENCE_NUMBER, false, false, null, null, null, false, false);
        System.out.println("======================>> Echo Servlet Initialization Ended <<======================");
    }

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final PrintWriter out = response.getWriter();
        //Doing raw output of request
        out.println("<<<<Start>>>>\n" + getBody(request) + "\n<<<<End>>>>");
        out.close();
    }
}
