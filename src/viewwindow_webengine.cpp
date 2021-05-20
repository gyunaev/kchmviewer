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
#include <QWebEngineContextMenuData>

#include "config.h"
#include "viewwindow_webengine.h"
#include "mainwindow.h"
#include "viewwindowmgr.h"
#include "ebook_chm.h"
#include "ebook_epub.h"

static const qreal ZOOM_FACTOR_CHANGE = 0.1;

void ViewWindow::initialize()
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0))
    // Register URL schemes
    QWebEngineUrlScheme::Flags flags = QWebEngineUrlScheme::SecureScheme | QWebEngineUrlScheme::LocalScheme | QWebEngineUrlScheme::ViewSourceAllowed | QWebEngineUrlScheme::LocalAccessAllowed;

    QWebEngineUrlScheme chmscheme( EBook_CHM::urlScheme() );
    chmscheme.setSyntax( QWebEngineUrlScheme::Syntax::Path );
    chmscheme.setFlags( flags );
    QWebEngineUrlScheme::registerScheme( chmscheme );

    QWebEngineUrlScheme epubscheme( EBook_EPUB::urlScheme() );
    epubscheme.setSyntax( QWebEngineUrlScheme::Syntax::Path );
    epubscheme.setFlags( flags );
    QWebEngineUrlScheme::registerScheme( epubscheme );
#endif
}


ViewWindow::ViewWindow( QWidget * parent )
    : QWebEngineView ( parent )
{
    invalidate();
    m_contextMenu = 0;
    m_contextMenuLink = 0;
    m_storedScrollbarPosition = -1; // see header

    // Use our network emulation layer. I don't know if we transfer the ownership when we install it,
    // so we create one per page. May be unnecessary.
    m_provider = new DataProvider_QWebEngine( this );

    page()->profile()->installUrlSchemeHandler( EBook_CHM::urlScheme(), m_provider );
    page()->profile()->installUrlSchemeHandler( EBook_EPUB::urlScheme(), m_provider );

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
    qDebug("ViewWindow::openUrl %s", qPrintable(url.toString()));

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
    // Has to be a pointer because printing happens later, and it will get out of scope
    QPrinter * printer = new QPrinter( QPrinter::HighResolution );
    QPrintDialog dlg( printer, this );

    if ( dlg.exec() != QDialog::Accepted )
    {
        ::mainWindow->showInStatusBar( i18n( "Printing aborted") );
        return false;
    }

    page()->print( printer, [printer](bool ok){
            ::mainWindow->showInStatusBar( ok ? i18n( "Printing finished successfully") : i18n( "Failed to print") );
            delete printer;
        });

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

    return value;
}

void ViewWindow::setScrollbarPosition(int pos, bool )
{
    // m_storedScrollbarPosition means the page isn't loaded yet. Thus it makes no sense to touch scrollbar.
    if ( m_storedScrollbarPosition == -1 )
    {
        m_storedScrollbarPosition = pos;
        return;
    }

    // See https://forum.qt.io/topic/60091/scroll-a-qwebengineview/4
    page()->runJavaScript( QString("window.scrollTo( { top : %1 } );").arg( pos ) );
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
    QMenu *m = new QMenu(0);

    // See https://stackoverflow.com/questions/48126230/pyqt5-right-click-and-open-in-new-tab
    QString link = page()->contextMenuData().linkUrl().toString();

    if ( !link.isEmpty() )
    {
        m->addAction( i18n("Open Link in a new tab\tShift+LMB"), ::mainWindow, SLOT( onOpenPageInNewTab() ) );
        m->addAction( i18n("Open Link in a new background tab\tCtrl+LMB"), ::mainWindow, SLOT( onOpenPageInNewBackgroundTab() ) );
        m->addSeparator();
        setTabKeeper( link );
    }

    ::mainWindow->setupPopupMenu( m );
    m->exec( e->globalPos() );
    delete m;
}

void ViewWindow::onLoadFinished ( bool )
{
    // If m_storedScrollbarPosition is -1 this means we have not had a request to set the scrollbar; change to 0
    if ( m_storedScrollbarPosition == -1 )
        m_storedScrollbarPosition = 0;
    else if ( m_storedScrollbarPosition > 0 )
    {
        // The scrollbar was requested to change after the document is loaded, so do it now.
        // However delay it after this handler finishes, as JS cannot be executed here
        QTimer::singleShot( 0, [this]() { setScrollbarPosition( m_storedScrollbarPosition ); });
    }

    updateHistoryIcons();

    emit dataLoaded( this );
}

void ViewWindow::applySettings()
{
    QWebEngineSettings * setup = QWebEngineSettings::globalSettings();

    setup->setAttribute( QWebEngineSettings::AutoLoadImages, pConfig->m_browserEnableImages );
    setup->setAttribute( QWebEngineSettings::JavascriptEnabled, pConfig->m_browserEnableJS );
    setup->setAttribute( QWebEngineSettings::PluginsEnabled, pConfig->m_browserEnablePlugins );
    setup->setAttribute( QWebEngineSettings::LocalStorageEnabled, pConfig->m_browserEnableLocalStorage );
}
