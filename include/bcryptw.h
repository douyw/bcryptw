#ifndef __BCRYPTW_H__
#define __BCRYPTW_H__

#include <string>

namespace bcryptw {
    std::string digest(std::string secret, unsigned long streches);
    bool compare(std::string password, std::string hashed_password);
}

#endif // __BCRYPTW_H__
