#ifndef DATAPROVIDER_QWEBENGINE_H
#define DATAPROVIDER_QWEBENGINE_H

#include <QWebEngineUrlSchemeHandler>

class DataProvider_QWebEngine : public QWebEngineUrlSchemeHandler
{
    public:
        DataProvider_QWebEngine( QObject *parent );

        void requestStarted( QWebEngineUrlRequestJob *request );
};

#endif // DATAPROVIDER_QWEBENGINE_H
