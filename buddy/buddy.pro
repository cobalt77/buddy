QT -= gui

CONFIG += c++11 console
CONFIG -= app_bundle

DEFINES += QT_DEPRECATED_WARNINGS

LIBS += -lqgpgme -lgpgmepp -lbuddy

SOURCES += \
        main.cpp

