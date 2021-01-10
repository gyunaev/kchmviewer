
TEMPLATE = lib
TARGET = chm
CONFIG *= c++11 warn_on qt staticlib

HEADERS = \
    chm_lib.h \
    lzx.h

SOURCES = \
    chm_lib.c \
    enum_chmLib.c \
    enumdir_chmLib.c \
    extract_chmLib.c \
    lzx.c
