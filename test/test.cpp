
#include "bcryptw.h"

#include <iostream>
#include <algorithm>

#include <openssl/md5.h>

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

int main(int argc, char* argv[]) {

    std::cout << "argc = " << argc;
    for (int i=0; i< argc; ++i) {
        std::cout << "\n argv[" << i<< "]: " << argv[i];
    }
    std::string password = "qwert12345";
    std::string password_md5 = md5_raw(password);
    std::string hashed_password;
    if (argc > 1) {
        hashed_password = argv[1];
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