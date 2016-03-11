TEMPLATE = lib
#CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += staticlib

TARGET = bcryptw

include(../bcryptw.pri)

#INCLUDEPATH += /usr/include/ruby-1.9.1

include(../bcrypt_ext.pri)

SOURCES += bcryptw.cpp wrapper1.c
HEADERS += $$PWD/../include/bcryptw.h
