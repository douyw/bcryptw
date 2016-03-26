
#include "bcryptw.h"

#include <iostream>

#include <openssl/md5.h>

//std::string md5_raw(std::string const& buf) {
//    unsigned char digest[16];
//    MD5_CTX context;
//    MD5_Init(&context);
//    MD5_Update(&context, buf.c_str(), buf.length());
//    MD5_Final(digest, &context);
//    std::string ret;
//    ret.assign((char *)&digest[0], 16);
//    return ret;
//}

//std::string md5_hex(std::string const& buf) {
//    unsigned char digest[16];
//    MD5_CTX context;
//    MD5_Init(&context);
//    MD5_Update(&context, buf.c_str(), buf.length());
//    MD5_Final(digest, &context);
//    char md5string[33];
//    for(int i = 0; i < 16; ++i)
//        sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
//    return md5string;
//}


static int test1(int argc, char* argv[]) {
    std::string salt = bcryptw::random_string(24);
    std::string password = "qwert12345";
    password += salt;
    std::cout << "\n salt(raw): " << salt;
    std::cout << "\n salt(hex): " << bcryptw::string_to_hex(salt);
    std::string password_md5 = bcryptw::md5_raw(password);
    std::cout << "\n password_md5(raw): " << password_md5;
    std::cout << "\n password_md5(hex): " << bcryptw::string_to_hex(password_md5);
    std::string hashed_password;
    if (argc > 1) {
//        hashed_password = argv[1];
        // TODO: find a way to pass the encrtyped password from command line.
        hashed_password = "$2a$10$McyxE4iUweHov7KiA/iUg.0bveupN2B6m1aw6IMcmePJpcu0U046q";
    } else {
        hashed_password = bcryptw::digest(password_md5, 10);
    }
    bool ok = bcryptw::compare(password_md5, hashed_password);
    std::cout << "\nok = " << ok << "\n";
    std::cout << "\n       password: " << password
              << "\n   password_md5: " << password_md5
              << "\nhashed_password: " << hashed_password
              << "\n";
    return 0;
}

const int k_password_salt_max_length = 24;
const int k_default_streches = 10;
static void test2() {
    std::string password = "qwert12345";
    std::string password_salt = bcryptw::random_string(k_password_salt_max_length);
    std::string passwd_encrypted_at_client = bcryptw::md5_hex(password+password_salt);
    std::string encrypted_password = bcryptw::digest(passwd_encrypted_at_client.c_str(), k_default_streches);

    int i=0;
    while (i<100) {
        if (encrypted_password.empty()) {
            std::cout << "\ni: " << i << "\n";
            break;
        }
        encrypted_password = bcryptw::digest(passwd_encrypted_at_client.c_str(), k_default_streches);
        ++i;
    }
}

int main(int argc, char* argv[]) {
//    test1(argc, argv);
    test2();
    return 0;
}
