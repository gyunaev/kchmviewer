# don't warn about missing AUTHORS, NEWS, ChangeLog .. files
AUTOMAKE_OPTIONS = foreign 1.4

SUBDIRS = lib src


package-messages:
	$(MAKE) -f admin/Makefile.common package-messages
	$(MAKE) -C po merge
