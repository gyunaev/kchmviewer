#!/bin/sh
rm -rf qt kde kde-int qt-int

(mkdir kde && cd kde && ../../configure --with-kde && make) || exit 1;
(mkdir qt && cd qt && ../../configure && make) || exit 1;

(mkdir kde-int && cd kde-int && ../../configure --with-kde --with-builtin-chmlib && make) || exit 1;
(mkdir qt-int && cd qt-int && ../../configure  --with-builtin-chmlib && make) || exit 1;

