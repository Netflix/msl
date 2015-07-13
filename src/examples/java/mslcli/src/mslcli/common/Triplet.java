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

/**
 * Generic data object class for storing triplet values. Values can be null.
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class Triplet<X,Y,Z> {
    public final X x;
    public final Y y;
    public final Z z;
    public Triplet(X x, Y y, Z z) {
      this.x = x;
      this.y = y;
      this.z = z;
    }
}
