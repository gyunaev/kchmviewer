# don't warn about missing AUTHORS, NEWS, ChangeLog .. files
AUTOMAKE_OPTIONS = foreign 1.4

SUBDIRS = $(EXTRA_SUBDIRS) libchmfile
DIST_SUBDIRS = chmlib kio-msits libchmfile

package-messages:
	$(MAKE) -f admin/Makefile.common package-messages
	$(MAKE) -C po merge

# Uncomment this line before opening the project in kdevelop for the first time!
#SUBDIRS = chmlib kio-msits libchmfile
