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

package mslcli.common;

import mslcli.common.util.SharedUtil;

/**
 * <p>Generic data object class for holding 3 values. Values can be null.</p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class Triplet<X,Y,Z> {
    /** first value of type X */
    public final X x;
    /** second value of type Y */
    public final Y y;
    /** third value of type Z */
    public final Z z;
    /**
     * Constructor.
     *
     * @param x first value of type X
     * @param y second value of type Y
     * @param z second value of type Z
     */
    public Triplet(X x, Y y, Z z) {
      this.x = x;
      this.y = y;
      this.z = z;
    }

    @Override
    public String toString() {
        return SharedUtil.toString(this);
    }
}
