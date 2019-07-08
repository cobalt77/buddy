QT -= gui

CONFIG += c++11 console
CONFIG -= app_bundle

TARGET = buddy

DEFINES += QT_DEPRECATED_WARNINGS

LIBS += -lqgpgme -lgpgmepp -lbuddy

SOURCES += \
        main.cpp

target.path = /usr/bin
INSTALLS += target
