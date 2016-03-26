#include "bcryptw.h"

#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <iterator>
#include <vector>
#include <tuple>

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "ow-crypt.h"
#ifdef __cplusplus
}
#endif


#include "openssl/rand.h"
#include "openssl/md5.h"

// see: @@streaches in devise.rb file
const int k_default_cost = 11;
const int MAX_SALT_LENGTH = 16;
//
const int MIN_COST = 4;

//std::string bcrypt_c1y::impl::s_prefix;
//std::string bcrypt_c1y::impl::s_pepper;

#define OUTPUT_ERR(err)  std::cerr << err << std::endl;


static
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

static
std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}


/* Given a logarithmic cost parameter, generates a salt for use with +bc_crypt+.
*/
static std::string bc_salt(const char* prefix, unsigned long count, std::string const& input) {
    std::string ret;
    char * salt = crypt_gensalt_ra( prefix, count, input.c_str(), input.length() );
    if (salt) {
        ret.assign(salt);
        free(salt);
    } else {
        std::cerr << "crypt_gensalt_ra(...) failed! err: " << errno << '\n';
    }
    return ret;
}

/* Given a secret and a salt, generates a salted hash (which you can then store safely).
*/
static std::string bc_crypt(std::string key, std::string setting) {
    std::string ret;
    void * data = NULL;
    int size = 0xDEADBEEF;
    char* value = crypt_ra( key.c_str(), setting.c_str(), &data, &size );
    if (value) {
        ret.assign(value);
        free(data);
    } else {
        std::cerr << "crypt_ra(...) failed!\n";
    }
    return ret;
}

namespace bcryptw {
/* ruby code
  def valid_hash?(h)
    h =~ /^\$[0-9a-z]{2}\$[0-9]{2}\$[A-Za-z0-9\.\/]{53}$/
  end
*/
bool is_valid_salt(std::string /*salt*/) {
    // TODO: verity salt, translate ruby code.
    return true;
}

std::string hash_secret(std::string secret, std::string salt) {
    if (is_valid_salt(salt))
        return bc_crypt(secret, salt);
    return "";
}

std::tuple<std::string, unsigned long, std::string, std::string>
extract_salt(std::string const& hashed_password) {
    std::string version, salt, hash;
    unsigned long cost = k_default_cost;

    std::vector<std::string> vv = split(hashed_password, '$');
    if (vv.size() == 4) {
        version = vv[1];
        cost = std::atol(vv[2].c_str());
        std::string mash = vv[3];
        salt.assign((char *)hashed_password.c_str(), 30);
        hash = mash.substr(mash.length() - 31);
//        std::cout << "\nversion: " << version
//                  << "\n   cost: " << cost
//                  << "\n   salt: " << salt
//                  << "\n   hash: " << hash
//                  << "\n";
    } else {
        OUTPUT_ERR("bad hashed password.");
    }
    return std::make_tuple(version, cost, salt, hash);
}

std::string digest(std::string const& secret, unsigned long streches) {
    unsigned long cost = streches == 0 ? k_default_cost : streches;
    if (cost <= 31) {
        static char prefix[] = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
        char buf[MAX_SALT_LENGTH];
        RAND_bytes((unsigned char *)buf, MAX_SALT_LENGTH);
//        buf[MAX_SALT_LENGTH] = '\0';
        std::string salt = bc_salt(prefix, cost, std::string(buf, MAX_SALT_LENGTH));
        return hash_secret(secret, salt);
    }
    return "";
}

bool compare(std::string const& password, std::string const& hashed_password) {
    auto t = extract_salt(hashed_password);
    std::string salt = std::get<2>(t);
//    std::cout << "\n----- salt: " << salt << '\n';
    std::string new_hashed_password = hash_secret(password, salt);
    return new_hashed_password == hashed_password;
}

std::string md5_raw(std::string const& buf) {
    unsigned char digest[16];
    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, buf.c_str(), buf.length());
    MD5_Final(digest, &context);
    std::string ret;
    ret.assign((char *)&digest[0], 16);
    return ret;
}

std::string md5_hex(std::string const& buf) {
    unsigned char digest[16];
    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, buf.c_str(), buf.length());
    MD5_Final(digest, &context);
    char md5string[33];
    for(int i = 0; i < 16; ++i)
        sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
    return md5string;
}

std::string random_salt_bytes() {
    char buf[MAX_SALT_LENGTH+1];
    RAND_bytes((unsigned char *)buf, MAX_SALT_LENGTH);
    buf[MAX_SALT_LENGTH] = '\0';
    return buf;
}

std::string random_string(std::uint8_t length) {
    static std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    static bool seeded = false;
    if (!seeded) {
        srand(time(NULL));
        seeded = true;
    }
    std::string result;
    result.resize(length);
    for (int i = 0; i < length; i++)
        result[i] = charset[rand() % charset.length()];

    return result;
}

std::string string_to_hex(const std::string& input) {
    static const char* const lut = "0123456789abcdef"; // "0123456789ABCDEF";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

std::string hex_to_string(const std::string& input) {
    static const char* const lut = "0123456789abcdef"; // "0123456789ABCDEF";
    size_t len = input.length();
    if (len & 1) throw std::invalid_argument("odd length");

    std::string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) throw std::invalid_argument("not a hex digit");

        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) throw std::invalid_argument("not a hex digit");

        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}

} // end of bcrypt
