#!/bin/sh
rm -rf qt kde

(mkdir qt && cd qt && ../../configure && make) || exit 1;
(mkdir kde && cd kde && ../../configure --with-kde && make) || exit 1;

