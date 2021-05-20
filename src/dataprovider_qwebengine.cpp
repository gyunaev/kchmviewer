#include <QBuffer>
#include <QWebEngineUrlRequestJob>

#include "mainwindow.h"
#include "dataprovider_qwebengine.h"

DataProvider_QWebEngine::DataProvider_QWebEngine( QObject *parent )
    : QWebEngineUrlSchemeHandler( parent )
{
}

void DataProvider_QWebEngine::requestStarted( QWebEngineUrlRequestJob *request )
{
    QUrl url = request->requestUrl();
    bool htmlfile = url.path().endsWith( ".html" ) || url.path().endsWith( ".htm" ) || url.path().endsWith( ".xhtml" );

    // Retreive the data from ebook file
    QByteArray buf;

    if ( !::mainWindow->chmFile()->getFileContentAsBinary( buf, url ) )
    {
        qWarning( "Could not resolve file %s\n", qPrintable( url.toString() ) );
        request->fail( QWebEngineUrlRequestJob::UrlNotFound );
        return;
    }

    const char * mimetype = "application/octet-stream";

    // Specify the encoding in case the page content is not UTF-8 - this is ignored by WebEngine
    if ( htmlfile )
        mimetype = "text/html";

    // We will use the buffer because reply() requires the QIODevice.
    // This buffer must be valid until the request is deleted.
    QBuffer * outbuf = new QBuffer;
    outbuf->setData( buf );
    outbuf->close();

    // Only delete the buffer when the request is deleted too
    connect( request, SIGNAL(destroyed()), outbuf, SLOT(deleteLater()) );

    // We're good to go
    request->reply( mimetype, outbuf );
}
