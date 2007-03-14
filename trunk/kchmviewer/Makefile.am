AUTOMAKE_OPTIONS = foreign 1.6

SUBDIRS = lib src po

package-messages:
	$(MAKE) -f admin/Makefile.common package-messages
	$(MAKE) -C po merge
