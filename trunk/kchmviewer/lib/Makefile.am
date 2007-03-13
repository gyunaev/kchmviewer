if AMC_USE_KDE
SUBDIR_KIO = kio-msits
endif

if AMC_BUILD_CHMLIB
SUBDIR_CHMLIB = chmlib
endif	

SUBDIRS = $(SUBDIR_CHMLIB) $(SUBDIR_KIO) libchmfile 
DIST_SUBDIRS = chmlib kio-msits libchmfile

package-messages:
	$(MAKE) -f admin/Makefile.common package-messages
	$(MAKE) -C po merge

# Uncomment this line before opening the project in kdevelop for the first time!
#SUBDIRS = chmlib kio-msits libchmfile
