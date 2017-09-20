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

#include <gtest/gtest.h>
#include <util/Base64.h>
#include <IllegalArgumentException.h>

namespace netflix {
namespace msl {
namespace util {

class Base64Test : public ::testing::Test
{
protected:
    /** Standard Base64 examples. */
    static const int NEXAMPLES = 3;
    const std::string EXAMPLE_STR[NEXAMPLES] = {
        "The long winded author is going for a walk while the light breeze bellows in his ears.",
        "Sometimes porcupines need beds to sleep on.",
        "Even the restless dreamer enjoys home-cooked foods."
    };
    const std::string EXAMPLE_B64[NEXAMPLES] = {
          "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgYSB3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4=",
          "U29tZXRpbWVzIHBvcmN1cGluZXMgbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg==",
          "RXZlbiB0aGUgcmVzdGxlc3MgZHJlYW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu"
    };
    static const int NINVALID_EXAMPLES = 9;
    const std::string INVALID_EXAMPLE_B64[NINVALID_EXAMPLES] = {
            "AAAAA",
            "AAAAAAA",
            "%$#@=",
            "ZZZZZZZZZZ=",
            "ZZZZZZZZZ==",
            "U29tZXRpbWVzIHBvcmN1cGluZX=gbmVlZCBiZWRzIHRvIHNsZWVwIG9uLg==",
            "RXZlbiB0aGUgcmVzdGxlc3MgZHJ=YW1lciBlbmpveXMgaG9tZS1jb29rZWQgZm9vZHMu",
            "RXZlbiB0aGUgcmVzdGxlc3MgZHJ=Y",
            "VGhlIGxvbmcgd2luZGVkIGF1dGhvciBpcyBnb2luZyBmb3IgY幸B3YWxrIHdoaWxlIHRoZSBsaWdodCBicmVlemUgYmVsbG93cyBpbiBoaXMgZWFycy4=",
    };
};

namespace
{

inline std::shared_ptr<std::vector<std::uint8_t>> makevec(const std::string& s)
{
    return std::make_shared<std::vector<std::uint8_t>>(s.begin(), s.end());
}

inline size_t base64Len(size_t inlen) { return ((4ul * inlen / 3ul) + 3ul) & ~3ul; }

} // anonymous namespace

TEST_F(Base64Test, Encode)
{
    // https://tools.ietf.org/html/rfc4648#page-12
    // BASE64("") = ""
    // BASE64("f") = "Zg=="
    // BASE64("fo") = "Zm8="
    // BASE64("foo") = "Zm9v"
    // BASE64("foob") = "Zm9vYg=="
    // BASE64("fooba") = "Zm9vYmE="
    // BASE64("foobar") = "Zm9vYmFy"

    std::shared_ptr<std::string> s;
    std::shared_ptr<std::vector<uint8_t>> v;

    v = makevec("");
    s = Base64::encode(v);
    EXPECT_EQ("", *s);
    EXPECT_EQ(s->size(), base64Len(v->size()));

    v = makevec("f");
    s = Base64::encode(v);
    EXPECT_EQ("Zg==", *s);
    EXPECT_EQ(s->size(), base64Len(v->size()));

    v = makevec("fo");
    s = Base64::encode(v);
    EXPECT_EQ("Zm8=", *s);
    EXPECT_EQ(s->size(), base64Len(v->size()));

    v = makevec("foo");
    s = Base64::encode(v);
    EXPECT_EQ("Zm9v", *s);
    EXPECT_EQ(s->size(), base64Len(v->size()));

    v = makevec("foob");
    s = Base64::encode(v);
    EXPECT_EQ("Zm9vYg==", *s);
    EXPECT_EQ(s->size(), base64Len(v->size()));

    v = makevec("fooba");
    s = Base64::encode(v);
    EXPECT_EQ("Zm9vYmE=", *s);
    EXPECT_EQ(s->size(), base64Len(v->size()));

    v = makevec("foobar");
    s = Base64::encode(v);
    EXPECT_EQ("Zm9vYmFy", *s);
    EXPECT_EQ(s->size(), base64Len(v->size()));
}

TEST_F(Base64Test, Decode)
{
    EXPECT_EQ(*makevec(""), *Base64::decode(std::make_shared<std::string>("")));
    EXPECT_EQ(*makevec("f"), *Base64::decode(std::make_shared<std::string>("Zg==")));
    EXPECT_EQ(*makevec("fo"), *Base64::decode(std::make_shared<std::string>("Zm8=")));
    EXPECT_EQ(*makevec("foo"), *Base64::decode(std::make_shared<std::string>("Zm9v")));
    EXPECT_EQ(*makevec("foob"), *Base64::decode(std::make_shared<std::string>("Zm9vYg==")));
    EXPECT_EQ(*makevec("fooba"), *Base64::decode(std::make_shared<std::string>("Zm9vYmE=")));
    EXPECT_EQ(*makevec("foobar"), *Base64::decode(std::make_shared<std::string>("Zm9vYmFy")));
}

TEST_F(Base64Test, Standard)
{
    for (int i = 0; i < NEXAMPLES; ++i)
    {
        // Prepare.
        std::shared_ptr<ByteArray> data = makevec(EXAMPLE_STR[i]);
        std::shared_ptr<std::string> base64 = std::make_shared<std::string>(EXAMPLE_B64[i]);

        // Encode/Decode.
        std::shared_ptr<std::string> encoded = Base64::encode(data);
        std::shared_ptr<ByteArray> decoded = Base64::decode(base64);

        // Validate.
        EXPECT_EQ(*base64, *encoded) << "example " << i;
        EXPECT_EQ(*data, *decoded) << "example " << i;
    }
}

TEST_F(Base64Test, Whitespace)
{
    for (int i = 0; i < NEXAMPLES; ++i)
    {
        // Prepare.
        std::shared_ptr<ByteArray> data = makevec(EXAMPLE_STR[i]);
        std::shared_ptr<std::string> base64 = std::make_shared<std::string>(EXAMPLE_B64[i]);

        // Modify.
        const size_t half = base64->length() / 2;
        std::shared_ptr<std::string> modifiedBase64 = std::make_shared<std::string>("  \t" + base64->substr(0, half) + "\r\n \r\n\t" + base64->substr(half) + " \t \n");

        // Encode/Decode.
        std::shared_ptr<std::string> encoded = Base64::encode(data);
        std::shared_ptr<ByteArray> decoded = Base64::decode(modifiedBase64);

        // Validate.
        EXPECT_EQ(*base64, *encoded) << "example " << i;
        EXPECT_EQ(*data, *decoded) << "example " << i;
    }
}

TEST_F(Base64Test, InvalidPadding)
{
	 for (int i = 0; i < NEXAMPLES; ++i)
	 {
		 // Prepare.
		 std::shared_ptr<std::string> base64 = std::make_shared<std::string>(EXAMPLE_B64[i]);

		 // Modify.
		 std::shared_ptr<std::string> modifiedBase64 = std::make_shared<std::string>(*base64 + "=");

		 // Decode.
		 bool invalid = false;
		 try {
			 Base64::decode(modifiedBase64);
		 } catch (const IllegalArgumentException&) {
			 invalid = true;
		 }
		 EXPECT_TRUE(invalid);
	 }
}

TEST_F(Base64Test, InjectedPadding)
{
	 for (int i = 0; i < NEXAMPLES; ++i)
	 {
		 // Prepare.
		 std::shared_ptr<std::string> base64 = std::make_shared<std::string>(EXAMPLE_B64[i]);

		 // Modify.
		 const size_t half = base64->length() / 2;
		 std::shared_ptr<std::string> modifiedBase64 = std::make_shared<std::string>(base64->substr(0, half) + "=" + base64->substr(half));

		 // Decode.
		 bool invalid = false;
		 try {
			 Base64::decode(modifiedBase64);
		 } catch (const IllegalArgumentException&) {
			 invalid = true;
		 }
		 EXPECT_TRUE(invalid);
	 }
}

TEST_F(Base64Test, InvalidCharacter)
{
	 for (int i = 0; i < NEXAMPLES; ++i)
	 {
		 // Prepare.
		 std::shared_ptr<std::string> base64 = std::make_shared<std::string>(EXAMPLE_B64[i]);

		 // Modify.
		 const size_t half = base64->length() / 2;
		 std::shared_ptr<std::string> modifiedBase64 = std::make_shared<std::string>(base64->substr(0, half) + "|" + base64->substr(half));

		 // Decode.
		 bool invalid = false;
		 try {
			 Base64::decode(modifiedBase64);
		 } catch (const IllegalArgumentException&) {
			 invalid = true;
		 }
		 EXPECT_TRUE(invalid);
	 }
}

TEST_F(Base64Test, OutOfRangeCharacter)
{
	 for (int i = 0; i < NEXAMPLES; ++i)
	 {
		 // Prepare.
		 std::shared_ptr<std::string> base64 = std::make_shared<std::string>(EXAMPLE_B64[i]);

		 // Modify.
		 const size_t half = base64->length() / 2;
		 std::shared_ptr<std::string> modifiedBase64 = std::make_shared<std::string>(base64->substr(0, half) + static_cast<char>(128) + base64->substr(half));

		 // Decode.
		 bool invalid = false;
		 try {
			 Base64::decode(modifiedBase64);
		 } catch (const IllegalArgumentException&) {
			 invalid = true;
		 }
		 EXPECT_TRUE(invalid);
	 }
}

TEST_F(Base64Test, InvalidLength)
{
	 for (int i = 0; i < NEXAMPLES; ++i)
	 {
		 // Prepare.
		 std::shared_ptr<std::string> base64 = std::make_shared<std::string>(EXAMPLE_B64[i]);

		 // Modify.
		 std::shared_ptr<std::string> modifiedBase64 = std::make_shared<std::string>(base64->substr(1));

		 // Decode.
		 bool invalid = false;
		 try {
			 Base64::decode(modifiedBase64);
		 } catch (const IllegalArgumentException&) {
			 invalid = true;
		 }
		 EXPECT_TRUE(invalid);
	 }
}

TEST_F(Base64Test, Invalid)
{
	 for (int i = 0; i < NINVALID_EXAMPLES; ++i)
	 {
		 std::shared_ptr<std::string> base64 = std::make_shared<std::string>(INVALID_EXAMPLE_B64[i]);
		 bool invalid = false;
		 try {
			 Base64::decode(base64);
		 } catch (const IllegalArgumentException&) {
			 invalid = true;
		 }
		 EXPECT_TRUE(invalid);
	 }
}

TEST_F(Base64Test, RoundTrip)
{
    typedef std::vector<uint8_t> ByteArray;
    const std::string o = // original text
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut eu egestas"
        " nibh, vitae tristique ex. Cras et dui dolor. Cras auctor libero tellu"
        "s, porttitor cursus tellus pulvinar ac. Aenean suscipit mi libero, vit"
        "ae suscipit lorem facilisis et. Quisque gravida leo sapien, sit amet f"
        "inibus augue interdum ac. Vestibulum tristique sed arcu ac aliquet. Cu"
        "m sociis natoque penatibus et magnis dis parturient montes, nascetur r"
        "idiculus mus. Nunc eget malesuada risus";
    // o base64-encoded offline
    std::shared_ptr<std::string> s = std::make_shared<std::string>(
        "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZW"
        "xpdC4gVXQgZXUgZWdlc3RhcyBuaWJoLCB2aXRhZSB0cmlzdGlxdWUgZXguIENyYXMgZXQg"
        "ZHVpIGRvbG9yLiBDcmFzIGF1Y3RvciBsaWJlcm8gdGVsbHVzLCBwb3J0dGl0b3IgY3Vyc3"
        "VzIHRlbGx1cyBwdWx2aW5hciBhYy4gQWVuZWFuIHN1c2NpcGl0IG1pIGxpYmVybywgdml0"
        "YWUgc3VzY2lwaXQgbG9yZW0gZmFjaWxpc2lzIGV0LiBRdWlzcXVlIGdyYXZpZGEgbGVvIH"
        "NhcGllbiwgc2l0IGFtZXQgZmluaWJ1cyBhdWd1ZSBpbnRlcmR1bSBhYy4gVmVzdGlidWx1"
        "bSB0cmlzdGlxdWUgc2VkIGFyY3UgYWMgYWxpcXVldC4gQ3VtIHNvY2lpcyBuYXRvcXVlIH"
        "BlbmF0aWJ1cyBldCBtYWduaXMgZGlzIHBhcnR1cmllbnQgbW9udGVzLCBuYXNjZXR1ciBy"
        "aWRpY3VsdXMgbXVzLiBOdW5jIGVnZXQgbWFsZXN1YWRhIHJpc3Vz");
    std::shared_ptr<ByteArray> d = util::Base64::decode(s);
    std::shared_ptr<std::string> s_ = util::Base64::encode(d);
    EXPECT_EQ(*s, *s_);
    EXPECT_EQ(ByteArray(o.begin(), o.end()), *d);
}

}}} // namespace netflix::msl::util
