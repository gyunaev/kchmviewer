
TEMPLATE = subdirs
SUBDIRS = lib/libchm lib/libebook src
src.depends = lib/libchm lib/libebook
