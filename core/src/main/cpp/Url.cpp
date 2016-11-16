//
//  URL.cpp
//  mslcpp
//
//  Created by John Doornbos on 9/7/16.
//  Copyright © 2016 John Doornbos. All rights reserved.
//

#include <string>
#include <stdlib.h>
#include <Url.h>

// https://jdoe:opensesame@subdomain.example.com:443/path/to/nowhere?arg1=value1&arg2=value2#fragment
// https://subdomain.example.com:4443/path/to/nowhere#fragment
// https://example.com/index.html

namespace netflix {
namespace msl {

using namespace std;


Url::Url(const string& urlstring)
: urlstring_(urlstring)
{
    //parseURL();
}

void Url::parseAuthority()
{
    string user;
    string password;
    size_t start = 0, end = string::npos;
    end = authority_.find("@");
    if(end != string::npos) {
        size_t subend = authority_.find(":");
        if(subend < end) {
            user = authority_.substr(start, subend - start);
            start = subend+1;
            password = authority_.substr(start, end - start);
        }
        start = end+1;
    }
    end = authority_.find(":", start);
    if(end != string::npos) {
        host_ = authority_.substr(start, end - start);
        start = end + 1;
        port_ = authority_.substr(start, string::npos);
    } else {
        host_ = authority_.substr(start, string::npos);
    }
    if(user.length() > 0) {
        userinfo_ = user;
    }
    if(password.length() > 0) {
        userinfo_ += ":";
        userinfo_ += password;
    }
}

void Url::parsePath()
{
    size_t start = path_.rfind("/");    
    file_ = path_.substr(start+1, string::npos);
}

void Url::parseURL()
{
    if(scheme_.length() > 0) {
        return;
    }
    size_t start = 0, end = string::npos;
    end = urlstring_.find("://");
    scheme_ = urlstring_.substr(start, end - start);
    start = end + 3;
    end = urlstring_.find('/', start);
    authority_ = urlstring_.substr(start, end - start);
    parseAuthority();
    start = end;
    end = urlstring_.find('?', start);
    if(end != string::npos) {
        // we have a query part
        path_ = urlstring_.substr(start, end - start);
        start = end;
        end = urlstring_.find("#", start);
        query_ = urlstring_.substr(start, end - start);
    } else {
        end = urlstring_.find("#", start);
        path_ = urlstring_.substr(start, end - start);
    }
    parsePath();    
    if(end != string::npos) {
        start = end;
        end = string::npos;
        ref_ = urlstring_.substr(start, string::npos);
    }
}
            
const string& Url::getAuthority()
{
    parseURL();
    return authority_;
}

int Url::getDefaultPort()
{
    return 80;
}

const string& Url::getFile()
{
    parseURL();
    return file_;
}

const string& Url::getHost()
{
    parseURL();
    return host_;
}

const string& Url::getPath()
{
    parseURL();
    return path_;
}

int	   Url::getPort()
{
    parseURL();
    return atoi(port_.c_str());
}

const string& Url::getProtocol()
{
    parseURL();
    return scheme_;
}

const string& Url::getQuery()
{
    parseURL();
    return query_;
}

const string& Url::getRef()
{
    parseURL();
    return ref_;
}

const string& Url::getUserInfo()
{
    parseURL();
    return userinfo_;
}

string Url::toString() const
{
    return urlstring_;
}

//ostream & operator<<(ostream &os, const Url& p)
//{
//    os << p.toString();
//    return os;
//}
    
} // msl
} // netflix
