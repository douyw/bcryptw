TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

include(../bcryptw.pri)

SOURCES += test.cpp

LIBS += -lbcryptw -lcrypto
