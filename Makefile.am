AUTOMAKE_OPTIONS = foreign 1.6

SUBDIRS = lib src

package-messages:
	$(MAKE) -f admin/Makefile.common package-messages
	$(MAKE) -C po merge
