TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c
LIBS += -lpcap
LIBS += -lpthread
