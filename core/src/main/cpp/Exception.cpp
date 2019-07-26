/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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

#include <Exception.h>
#include <Macros.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <algorithm>
#include <sstream>
#include <iostream>

using namespace std;

namespace netflix {
namespace msl {

int g_exBacktraceDepth = 0; // used by main.cpp to input desired backtrace depth

namespace {

char buf[1024];

string bt(int skip = 1)
{
    void *callstack[128];
    const int nMaxFrames = sizeof(callstack) / sizeof(callstack[0]);
    int nFrames = backtrace(callstack, nMaxFrames);
    char **symbols = backtrace_symbols(callstack, nFrames);
    int showFrames = min(nFrames, g_exBacktraceDepth);
    ostringstream trace_buf;
    for (int i = skip; i < showFrames; i++) {
        //printf("%s\n", symbols[i]);
        Dl_info info;
        if (dladdr(callstack[i], &info) && info.dli_sname) {
            char *demangled = NULL;
            int status = -1;
            if (info.dli_sname[0] == '_')
                demangled = abi::__cxa_demangle(info.dli_sname, NULL, 0, &status);
            snprintf(buf, sizeof(buf), "%-3d %*p %s + %zd\n",
                     i, int(2 + sizeof(void*) * 2), callstack[i],
                     status == 0 ? demangled :
                     info.dli_sname == 0 ? symbols[i] : info.dli_sname,
                     (char *)callstack[i] - (char *)info.dli_saddr);
            free(demangled);
        } else {
            snprintf(buf, sizeof(buf), "%-3d %*p %s\n",
                     i, int(2 + sizeof(void*) * 2), callstack[i], symbols[i]);
        }
        trace_buf << buf;
    }
    free(symbols);
    if (nFrames == nMaxFrames)
        trace_buf << "[truncated]\n";
    return trace_buf.str();
}

} // namespace anonymous

Exception::Exception(const exception& ex) : runtime_error(ex.what())
{
    if (g_exBacktraceDepth) cout << "Exception: " << ex.what() << endl << bt() << endl;
}

Exception::Exception(const string& details) : runtime_error(details)
{
    if (g_exBacktraceDepth) cout << "Exception: " << details << endl << bt() << endl;
}

Exception::Exception(const string& details, const IException& cause)
    : runtime_error(details)
{
    if (g_exBacktraceDepth) cout << "Exception: " << details << endl << bt() << endl;
    // Make our own copy of cause so we control its lifetime
    shared_ptr<IException> temp = cause.clone();
    cause_.swap(temp);
}

uint32_t Exception::getDepth() const
{
    const shared_ptr<IException> cause = getCause();
    if (cause && instanceof<Exception>(cause.get()))
    {
        const shared_ptr<Exception> mslCause =
                dynamic_pointer_cast<Exception>(cause);
        return 1 + mslCause->getDepth();
    }
    return 1;
}

} /* namespace msl */
} /* namespace netflix */
