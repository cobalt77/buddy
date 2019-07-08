#-------------------------------------------------
#
# Project created by QtCreator 2019-07-07T17:38:53
#
#-------------------------------------------------

QT       -= gui

TARGET = buddy
TEMPLATE = lib

DEFINES += BUDDY_LIBRARY

DEFINES += QT_DEPRECATED_WARNINGS

LIBS += -lqgpgme -lgpgmepp

SOURCES += \
    file.cpp

HEADERS += \
    libbuddy_global.h \
    file.h

headers.files = libbuddy_global.h file.h file
headers.path = /usr/include/buddy/

target.path = /usr/lib/

INSTALLS += headers target
