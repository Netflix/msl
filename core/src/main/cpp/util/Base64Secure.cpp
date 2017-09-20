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

#include <util/Base64Secure.h>
#include <ctype.h>
#include <iterator>
#include <algorithm>
#include <ios>
#include <IllegalArgumentException.h>

using namespace std;

namespace netflix {
namespace msl {
namespace util {

namespace // anonymous
{

static const signed char ENCODE_MAP[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const signed char DECODE_MAP[] = { // reverse LUT for base-64 decoding
        -1,-1,-1,-1,-1,-1,-1,-1,    -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,    -1,-1,-1,-1,-1,-1,-1,-1,
      //    !  "  #  $  %  &  '      (  )  *  +  ,  -  .  /
        -1,-1,-1,-1,-1,-1,-1,-1,    -1,-1,-1,62,-1,-1,-1,63,
      // 0  1  2  3  4  5  6  7      8  9  :  ;  <   =  >  ?
        52,53,54,55,56,57,58,59,    60,61,-1,-1,-1,127,-1,-1,
      //    A  B  C  D  E  F  G      H  I  J  K  L  M  N  O
        -1, 0, 1, 2, 3, 4, 5, 6,     7, 8, 9,10,11,12,13,14,
      // P  Q  R  S  T  U  V  W      X  Y  Z  [  \  ]  ^  _
        15,16,17,18,19,20,21,22,    23,24,25,-1,-1,-1,-1,-1,
      // @  a  b  c  d  e  f  g      h  i  j  k  l  m  n  o
        -1,26,27,28,29,30,31,32,    33,34,35,36,37,38,39,40,
      // p  q  r  s  t  u  v  w      x  y  z  {  |  }  ~
        41,42,43,44,45,46,47,48,    49,50,51,-1,-1,-1,-1,-1
};
/** Tab character value. */
const uint8_t TAB = 9;
/** Newline character value. */
const uint8_t NEWLINE = 10;
/** Carriage return character value. */
const uint8_t CARRIAGE_RETURN = 13;
/** Space character value. */
const uint8_t SPACE = 32;
/** Padding character sentinel value. */
const uint8_t PADDING = 127;
/** Padding character. */
static const signed char PADDING_CHAR = '=';

// FIXME: Must check for over/underflow
inline size_t base64Length(size_t n) { return ((4 * n / 3) + 3) & ~3u; }
inline size_t lengthBound(size_t n)  { return n * 3 / 4; }

typedef std::string::const_iterator StringConstIterator;
typedef ByteArray::const_iterator ByteArrayConstIterator;
typedef std::back_insert_iterator<std::string> StringAppendIterator;
typedef std::back_insert_iterator<ByteArray> ByteArrayAppendIterator;

//inline bool isAllowedChar(uint8_t c) {
//  return (isalnum(c) || (c == '+') || (c == '/') || (c == '='));
//}

} // namespace anonymous

std::shared_ptr<std::string> Base64Secure::encode(const ByteArray& b) {
    std::shared_ptr<std::string> value = std::make_shared<std::string>();
    value->reserve(base64Length(b.size()));
    StringAppendIterator out = std::back_inserter(*value);

    ByteArrayConstIterator p = b.begin();
    while (p != b.end()) {
        signed char buf[4] = { PADDING_CHAR, PADDING_CHAR, PADDING_CHAR, PADDING_CHAR };
        const uint8_t v = *p;
        buf[0] = ENCODE_MAP[v >> 2];
        int index1 = (v & 0x3) << 4; // must defer
        if (++p != b.end()) {
            const uint8_t v = *p;
            index1 |= v >> 4;
            int index2 = (v & 0xf) << 2; // must defer
            if (++p != b.end()) {
                const uint8_t v = *p;
                index2 |= v >> 6;
                buf[3] = ENCODE_MAP[v & 0x3f];
                ++p;
            }
            buf[2] = ENCODE_MAP[index2];
        }
        buf[1] = ENCODE_MAP[index1];
        std::copy(buf, buf + sizeof buf, out);
    }

    return value;
}

std::shared_ptr<ByteArray> Base64Secure::decode(const std::string& s) {
	std::shared_ptr<ByteArray> value = std::make_shared<ByteArray>();
	value->reserve(lengthBound(s.size()));
	ByteArrayAppendIterator out = back_inserter(*value);

	// Flag to remember if we've encountered an invalid character or have
    // reached the end of the string prematurely.
    bool invalid = false;

    // Convert each quadruplet to three bytes.
    int quadruplet[4] = { -1, -1, -1, -1 };
    int q = 0;
    bool lastQuad = false;
    StringConstIterator p = s.begin();
    while (p != s.end()) {
    	const char c = *p++;

    	// Ensure the character is not "negative".
    	if (c & 0x80) {
    		invalid = true;
    		continue;
    	}

    	// Lookup the character in the decoder map.
    	const char b = DECODE_MAP[c & 0x7f];

    	// Skip invalid characters.
    	if (b == -1) {
    		// Flag invalid for non-whitespace.
    		if (c != SPACE && c != TAB && c != NEWLINE && c != CARRIAGE_RETURN)
    			invalid = true;
    		continue;
    	}

        // If we already saw the last quadruplet we shouldn't see anymore.
        if (lastQuad)
        	invalid = true;

        // Append value to quadruplet.
        quadruplet[q++] = b;

        // If the quadruplet is full, append it to the destination buffer.
        if (q == 4) {
			// If the quadruplet starts with padding, flag invalid.
			if (quadruplet[0] == PADDING || quadruplet[1] == PADDING)
				invalid = true;

			// If the quadruplet ends with padding, this better be the last
			// quadruplet.
			if (quadruplet[2] == PADDING || quadruplet[3] == PADDING)
				lastQuad = true;

			// Decode into the destination buffer.
			*out++ = static_cast<uint8_t>((quadruplet[0] << 2) | (quadruplet[1] >> 4));
			if (quadruplet[2] != PADDING)
				*out++ = static_cast<uint8_t>(((quadruplet[1] & 0xf) << 4) | (quadruplet[2] >> 2));
			if (quadruplet[3] != PADDING)
				*out++ = static_cast<uint8_t>(((quadruplet[2] & 0x3) << 6) | quadruplet[3]);

            // Reset the quadruplet index.
            q = 0;
        }
    }

    // If the quadruplet is not empty, flag invalid.
    if (q != 0)
        invalid = true;

    // If invalid throw an exception.
    if (invalid)
        throw IllegalArgumentException("Invalid Base64 encoded string: " + s);

    // Return the destination buffer.
    return value;
}

}}} // namespace netflix::msl::util
