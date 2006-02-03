# don't warn about missing AUTHORS, NEWS, ChangeLog .. files
AUTOMAKE_OPTIONS = foreign 1.4

if BUILD_CHMLIB
	DIR_CHMLIB = chmlib
endif

if BUILD_KIOMSITS
	DIR_KIOMSITS = kio-msits
endif

SUBDIRS = $(DIR_CHMLIB) src $(DIR_KIOMSITS)

package-messages:
	$(MAKE) -f admin/Makefile.common package-messages
	$(MAKE) -C po merge

# Uncomment this line before opening the project in kdevelop for the first time!
#SUBDIRS = chmlib src kio-msits
