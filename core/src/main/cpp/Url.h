#ifndef _NETFLIX_MSL_URL_H_
#define _NETFLIX_MSL_URL_H_

#include <string>

namespace netflix {
namespace msl {
    
class Url;
    
inline bool operator==(const Url& a, const Url& b);
inline bool operator!=(const Url& a, const Url& b);
inline bool operator<(const Url& a, const Url& b);
inline bool operator>=(const Url& a, const Url& b);
inline bool operator>(const Url& a, const Url& b);
inline bool operator<=(const Url& a, const Url& b);

class Url
{
protected:
    std::string urlstring_;
    
    std::string scheme_;
    std::string authority_;
    std::string userinfo_;
    std::string host_;
    std::string port_;
    std::string path_;
    std::string query_;
    std::string ref_;
    std::string file_;
    
    void parseURL();
    void parseAuthority();
    void parsePath();
    
public:
    Url(const std::string& urlstring);

    const std::string& getAuthority();
    int	  getDefaultPort();
    const std::string& getFile();
    const std::string& getHost();
    const std::string& getPath();
    int	  getPort();
    const std::string& getProtocol();
    const std::string& getQuery();
    const std::string& getRef();
    const std::string& getUserInfo();
    
    std::string toString() const;
};
    
inline bool operator==(const Url& a, const Url& b) { return a.toString() == b.toString(); }
inline bool operator!=(const Url& a, const Url& b) { return a.toString() != b.toString(); }
inline bool operator< (const Url& a, const Url& b) { return a.toString() <  b.toString(); }
inline bool operator<=(const Url& a, const Url& b) { return a.toString() <= b.toString(); }
inline bool operator> (const Url& a, const Url& b) { return a.toString() >  b.toString(); }
inline bool operator>=(const Url& a, const Url& b) { return a.toString() >= b.toString(); }
//std::ostream & operator<<(std::ostream &os, const Url& p);

}
}
    

#endif
