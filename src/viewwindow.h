#ifndef VIEWWINDOW_H
#define VIEWWINDOW_H

// We support both engines
#if defined (USE_WEBENGINE)
    #include "viewwindow_webengine.h"
#else
    #include "viewwindow_webkit.h"
#endif

#endif // VIEWWINDOW_H
