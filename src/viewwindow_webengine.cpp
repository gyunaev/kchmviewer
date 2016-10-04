/*
 *  Kchmviewer - a CHM and EPUB file viewer with broad language support
 *  Copyright (C) 2004-2014 George Yunaev, gyunaev@ulduzsoft.com
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <QRegExp>
#include <QString>
#include <QPrinter>
#include <QPrintDialog>
#include <QWebEngineHistory>
#include <QWebEngineView>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineSettings>

#include "config.h"
#include "viewwindow_webengine.h"
#include "mainwindow.h"
#include "viewwindowmgr.h"


static const qreal ZOOM_FACTOR_CHANGE = 0.1;


ViewWindow::ViewWindow( QWidget * parent )
    : QWebEngineView ( parent )
{
    invalidate();
    m_contextMenu = 0;
    m_contextMenuLink = 0;
    m_storedScrollbarPosition = 0;

    //QWebEnginePage *page

    // Use our network emulation layer. I don't know if we transfer the ownership when we install it, so we create
    // one per page. May be unnecessary.
    m_provider = new DataProvider_QWebEngine( this );
    page()->profile()->installUrlSchemeHandler( ::mainWindow->chmFile()->ebookURLscheme().toUtf8(), m_provider );

    // All links are going through us
    //page()->setLinkDelegationPolicy( QWebPage::DelegateAllLinks );

    connect( this, SIGNAL( loadFinished(bool)), this, SLOT( onLoadFinished(bool)) );

    // Search results highlighter
    QPalette pal = palette();
    pal.setColor( QPalette::Inactive, QPalette::Highlight, pal.color(QPalette::Active, QPalette::Highlight) );
    pal.setColor( QPalette::Inactive, QPalette::HighlightedText, pal.color(QPalette::Active, QPalette::HighlightedText) );
    setPalette( pal );
}

ViewWindow::~ViewWindow()
{
}

void ViewWindow::invalidate( )
{
    m_newTabLinkKeeper = QString::null;
    m_storedScrollbarPosition = 0;
    reload();
}

bool ViewWindow::openUrl ( const QUrl& url )
{
    //qDebug("ViewWindow::openUrl %s", qPrintable(url.toString()));

    // Do not use setContent() here, it resets QWebHistory
    load( url );

    m_newTabLinkKeeper.clear();
    mainWindow->viewWindowMgr()->setTabName( this );

    return true;
}

QMenu * ViewWindow::createStandardContextMenu( QWidget * parent )
{
    QMenu * contextMenu = new QMenu( parent );

    contextMenu->addAction( "&Copy", ::mainWindow, SLOT(slotBrowserCopy()) );
    contextMenu->addAction( "&Select all", ::mainWindow, SLOT(slotBrowserSelectAll()) );

    return contextMenu;
}


QMenu * ViewWindow::getContextMenu( const QUrl & link, QWidget * parent )
{
    if ( link.isEmpty() )
    {
        // standard context menu
        if ( !m_contextMenu )
            m_contextMenu = createStandardContextMenu( parent );

        return m_contextMenu;
    }
    else
    {
        // Open in New Tab context menu
        // standard context menu
        if ( !m_contextMenuLink )
        {
            m_contextMenuLink = createStandardContextMenu( parent );
            m_contextMenuLink->addSeparator();

            m_contextMenuLink->addAction( "&Open this link in a new tab", ::mainWindow, SLOT(onOpenPageInNewTab()), QKeySequence("Shift+Enter") );

            m_contextMenuLink->addAction( "&Open this link in a new background tab", ::mainWindow, SLOT(onOpenPageInNewBackgroundTab()), QKeySequence("Ctrl+Enter") );
        }

        setTabKeeper( link );
        return m_contextMenuLink;
    }
}

QString ViewWindow::title() const
{
    QString title = ::mainWindow->chmFile()->getTopicByUrl( url() );

    // If no title is found, use the path (without the first /)
    if ( title.isEmpty() )
        title = url().path().mid( 1 );

    return title;
}


void ViewWindow::navigateForward()
{
    forward();
}

void ViewWindow::navigateBack( )
{
    back();
}

void ViewWindow::navigateHome( )
{
    ::mainWindow->openPage( ::mainWindow->chmFile()->homeUrl() );
}

void ViewWindow::setTabKeeper( const QUrl& link )
{
    m_newTabLinkKeeper = link;
}

bool ViewWindow::printCurrentPage()
{
/*    QPrinter printer( QPrinter::HighResolution );
    QPrintDialog dlg( &printer, this );

    if ( dlg.exec() != QDialog::Accepted )
    {
        ::mainWindow->showInStatusBar( i18n( "Printing aborted") );
        return false;
    }

    print( &printer );
    ::mainWindow->showInStatusBar( i18n( "Printing finished") );
*/
    return true;
}

void ViewWindow::setZoomFactor(qreal zoom)
{
    QWebEngineView::setZoomFactor( zoom );
}

qreal ViewWindow::getZoomFactor() const
{
    return zoomFactor();
}

void ViewWindow::zoomIncrease()
{
    setZoomFactor( zoomFactor() + ZOOM_FACTOR_CHANGE );
}

void ViewWindow::zoomDecrease()
{
    setZoomFactor( zoomFactor() - ZOOM_FACTOR_CHANGE );
}

int ViewWindow::getScrollbarPosition()
{
    QAtomicInt value = -1;

    page()->runJavaScript("document.body.scrollTop", [&value](const QVariant &v) { qDebug( "value retrieved: %d\n", v.toInt()); value = v.toInt(); });

    while ( value == -1 )
    {
        QApplication::processEvents();
    }

    qDebug( "scroll value %d", value.load() );
    return value;
}

void ViewWindow::setScrollbarPosition(int pos, bool force)
{
    /*
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
    if ( !force )
         m_storedScrollbarPosition = pos;
     else
         page()->scrollPosition() ScurrentFrame()->setScrollBarValue( Qt::Vertical, pos );

#else
    return 0;
#endi
*/
}

void ViewWindow::clipSelectAll()
{
    triggerPageAction( QWebEnginePage::SelectAll );
}

void ViewWindow::clipCopy()
{
    triggerPageAction( QWebEnginePage::Copy );
}

void ViewWindow::updateHistoryIcons()
{
    if ( mainWindow )
    {
        mainWindow->navSetBackEnabled( history()->canGoBack() );
        mainWindow->navSetForwardEnabled( history()->canGoForward() );
    }
}

void ViewWindow::contextMenuEvent(QContextMenuEvent *e)
{
    // From Qt Assistant
    QMenu *m = new QMenu(0);
/*    QString link = anchorAt( e->pos() );

    if ( !link.isEmpty() )
    {
        m->addAction( i18n("Open Link in a new tab\tShift+LMB"), ::mainWindow, SLOT( onOpenPageInNewTab() ) );
        m->addAction( i18n("Open Link in a new background tab\tCtrl+LMB"), ::mainWindow, SLOT( onOpenPageInNewBackgroundTab() ) );
        m->addSeparator();
        setTabKeeper( link );
    }
*/
    ::mainWindow->setupPopupMenu( m );
    m->exec( e->globalPos() );
    delete m;
}

void ViewWindow::onLoadFinished ( bool )
{
/*    if ( m_storedScrollbarPosition > 0 )
    {
        page()->currentFrame()->setScrollBarValue( Qt::Vertical, m_storedScrollbarPosition );
        m_storedScrollbarPosition = 0;
    }
*/
    updateHistoryIcons();

    emit dataLoaded( this );
}

void ViewWindow::applySettings()
{
    QWebEngineSettings * setup = QWebEngineSettings::globalSettings();

    setup->setAttribute( QWebEngineSettings::AutoLoadImages, pConfig->m_browserEnableImages );
    setup->setAttribute( QWebEngineSettings::JavascriptEnabled, pConfig->m_browserEnableJS );
    //setup->setAttribute( QWebEngineSettings::JavaEnabled, pConfig->m_browserEnableJava );
    setup->setAttribute( QWebEngineSettings::PluginsEnabled, pConfig->m_browserEnablePlugins );
    //setup->setAttribute( QWebEngineSettings::OfflineStorageDatabaseEnabled, pConfig->m_browserEnableOfflineStorage );
    //setup->setAttribute( QWebEngineSettings::LocalStorageDatabaseEnabled, pConfig->m_browserEnableLocalStorage );
    setup->setAttribute( QWebEngineSettings::LocalStorageEnabled, pConfig->m_browserEnableLocalStorage );
}
