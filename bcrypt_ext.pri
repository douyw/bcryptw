
BCRYPT_EXT=$$PWD/bcrypt-ruby/ext/mri
INCLUDEPATH += $$BCRYPT_EXT

HEADERS += \
  $$BCRYPT_EXT/ow-crypt.h
#  $$BCRYPT_EXT/crypt.h

SOURCES += \
  $$BCRYPT_EXT/crypt_blowfish.c   \
  $$BCRYPT_EXT/crypt_gensalt.c \
#  $$BCRYPT_EXT/wrapper.c
# $$BCRYPT_EXT/bcrypt_ext.c
#  $$BCRYPT_EXT/crypt.c
