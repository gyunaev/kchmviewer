Summary: Free CHM files viewer application
Name: kchmviewer
Version: 0.7
Release: 1
License: GPLv3+
Group: Applications/Office
Packager: kchmviewer@ulduzsoft.com
URL: http://www.kchmviewer.net
%description
Kchmviewer is a free, open-source chm (MS HTML help file format) viewer,
which uses Qt toolkit. Its main advantage is the best support for non-English
languages. Unlike other viewers, kchmviewer in most cases is able to correctly
detect the chm file encoding and show it. It correctly shows the index and
table of context in Russian, Spanish, Romanian, Korean, Chinese and Arabic help
files, and with new search engine is able to search in any chm file no matter what
language it is written.
 
Author:
-------
George Yunaev

Requires: libqt4 >= 4.5.0
%files
%defattr(-,root,root)
/usr/bin/kchmviewer
%defattr(-,root,root)
/usr/share/applications/kchmviewer.desktop
%defattr(-,root,root)
/usr/share/pixmaps/kchmviewer.png
