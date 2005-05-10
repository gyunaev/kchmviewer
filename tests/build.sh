#!/bin/sh
rm -rf qt kde

(mkdir kde && cd kde && ../../configure --with-kde && make) || exit 1;
(mkdir qt && cd qt && ../../configure && make) || exit 1;

