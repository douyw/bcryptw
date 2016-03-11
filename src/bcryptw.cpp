#include "bcryptw.h"

#include <string>
#include <sstream>
#include <vector>
#include <iostream>
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

// see: @@streaches in devise.rb file
const int k_default_cost = 11;
const int MAX_SALT_LENGTH = 16;
//
const int MIN_COST = 4;

//std::string bcrypt_c1y::impl::s_prefix;
//std::string bcrypt_c1y::impl::s_pepper;

#define OUTPUT_ERR(err)  std::cerr << err << std::endl;


std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


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

std::string digest(std::string secret, unsigned long streches) {
    unsigned long cost = streches == 0 ? k_default_cost : streches;
    if (cost <= 31) {
        static char prefix[] = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
        char buf[MAX_SALT_LENGTH+1];
        RAND_bytes((unsigned char *)buf, MAX_SALT_LENGTH);
        buf[MAX_SALT_LENGTH] = '\0';
        std::string salt = bc_salt(prefix, cost, buf);
        return hash_secret(secret, salt);
    }
    return "";
}

bool compare(std::string password, std::string hashed_password) {
    auto t = extract_salt(hashed_password);
    std::string salt = std::get<2>(t);
//    std::cout << "\n----- salt: " << salt << '\n';
    std::string new_hashed_password = hash_secret(password, salt);
    return new_hashed_password == hashed_password;
}

} // end of bcrypt
