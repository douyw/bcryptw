#ifndef __BCRYPTW_H__
#define __BCRYPTW_H__

#include <string>

namespace bcryptw {
    std::string digest(std::string secret, unsigned long streches);
    bool compare(std::string password, std::string hashed_password);

    std::string random_salt_bytes();
    std::string random_string(std::uint8_t length);

    std::string md5_raw(std::string const& buf);
    std::string md5_hex(std::string const& buf);

    std::string string_to_hex(const std::string& input);
    std::string hex_to_string(const std::string& input);
}

#endif // __BCRYPTW_H__
