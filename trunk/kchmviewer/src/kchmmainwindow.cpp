/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "kde-qt.h"

#include <QEvent>
#include <QShowEvent>
#include <QCloseEvent>
#include <QShortcut>

#include "libchmfile.h"
#include "libchmfileimpl.h"
#include "libchmurlfactory.h"

#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "kchmindexwindow.h"
#include "kchmsearchwindow.h"
#include "kchmbookmarkwindow.h"
#include "kchmtreeviewitem.h"
#include "kchmsearchtoolbar.h"
#include "kchmsettings.h"
#include "kchmsetupdialog.h"
#include "kchmviewwindow.h"
#include "kchmviewwindowmgr.h"
#include "kchmkeyeventfilter.h"
#include "kchmcontentswindow.h"

#if !defined (USE_KDE)
	#include "kqrunprocess.h"
#endif



KCHMMainWindow::KCHMMainWindow()
	: QMainWindow ( 0 ), Ui::MainWindow()
{
	const unsigned int WND_X_SIZE = 700;
	const unsigned int WND_Y_SIZE = 500;
	const unsigned int SPLT_X_SIZE = 200;

	// Delete the pointer when the window is closed
	setAttribute( Qt::WA_DeleteOnClose );
	
	// UIC stuff
	setupUi( this );
	
	m_FirstTimeShow = true;
	m_chmFile = 0;
	
	m_indexTab = 0;
	m_searchTab = 0;
	m_contentsTab = 0;
	m_viewWindowMgr = 0;

	m_tabContextPage = -1;
	m_tabIndexPage = -1;
	m_tabSearchPage = -1;
	m_tabBookmarkPage = -1;
	
	setupSignals();

	m_currentSettings = new KCHMSettings;
		
	// Create the initial layout - a splitter with tab window in left, and text browser in right
	m_windowSplitter = new QSplitter(this);
	m_tabWidget = new KQTabWidget( m_windowSplitter );
	m_viewWindowMgr = new KCHMViewWindowMgr( m_windowSplitter );
	
	m_bookmarkWindow = new KCHMBookmarkWindow( m_tabWidget );

	// Add the tabs
	m_tabWidget->addTab( m_bookmarkWindow, i18n("Bookmarks") );

	// Splitter is a central widget
	setCentralWidget( m_windowSplitter );
	
	// Setting up splitter sizes
	QList<int> sizes;
	sizes.push_back( SPLT_X_SIZE );
	sizes.push_back( WND_X_SIZE - SPLT_X_SIZE );
	m_windowSplitter->setSizes( sizes );
	
	// Set up things
	setupActions();
	setupLangEncodingMenu();

	// Resize main window
	resize( WND_X_SIZE, WND_Y_SIZE );	

#if defined (ENABLE_AUTOTEST_SUPPORT)
	m_autotestlistiterator = 0;
	m_autoteststate = STATE_OFF;
	m_useShortAutotest = false;
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */

	/* FIXME: accelerators -> actions
	accel->connectItem ( accel->insertItem ( Key_F3 ), m_searchToolbar, SLOT ( onBtnNextSearchResult() ) );
*/
	statusBar()->show();
	setIcon( QPixmap(":/images/application.png") );

	m_aboutDlgMenuText = i18n( "%1 version %2\n\nCopyright (C) George Yunaev,"
			"gyunaev@ulduzsoft.com, 2004-2007\nhttp://www.kchmviewer.net\n\n"
			"Licensed under GNU GPL license.\n\n"
			"Please check my another project, http://www.transientmail.com - temporary "
			"e-mail address, which expires automatically." )
			. arg(APP_NAME) . arg(APP_VERSION);
}


KCHMMainWindow::~KCHMMainWindow()
{
}



bool KCHMMainWindow::loadChmFile ( const QString &fileName, bool call_open_page )
{
	LCHMFile * new_chmfile = new LCHMFile();
	
	if ( new_chmfile->loadFile( fileName ) )
	{
		// The new file is opened, so we can close the old one
		if ( m_chmFile )
		{
			closeChmFile( );
			delete m_chmFile;
		}
	
		m_chmFile = new_chmfile;
		
		// Show current encoding in status bar
		showInStatusBar( i18n("Detected file encoding: %1 ( %2 )") 
		                 .arg( m_chmFile->currentEncoding()->family)
		                 .arg( m_chmFile->currentEncoding()->qtcodec) );

		// Make the file name absolute; we'll need it later
		QDir qd;
		qd.setPath (fileName);
		m_chmFilename = qd.absPath();
		
		// Qt's 'dirname' does not work well
		QFileInfo qf ( m_chmFilename );
		appConfig.m_lastOpenedDir = qf.dirPath(true);

		// Order the tabulations
		int number_of_pages = 0;
		
		if ( m_chmFile->hasTableOfContents() )
			m_tabContextPage = number_of_pages++;
		else
			m_tabContextPage = -1;

		if ( m_chmFile->hasIndexTable() )
			m_tabIndexPage = number_of_pages++;
		else
			m_tabIndexPage = -1;

		// We always show search
		m_tabSearchPage = number_of_pages++;

		m_tabBookmarkPage = number_of_pages;

		showOrHideContextWindow( m_tabContextPage );
		showOrHideIndexWindow( m_tabIndexPage );
		showOrHideSearchWindow( m_tabSearchPage );
		
		m_bookmarkWindow->invalidate();
		navSetBackEnabled( false );
		navSetForwardEnabled( false );
		m_viewWindowMgr->invalidate();
		refreshCurrentBrowser();

		if ( m_currentSettings->loadSettings (fileName) )
		{
			const LCHMTextEncoding * encoding = 
					m_chmFile->impl()->lookupByQtCodec(  m_currentSettings->m_activeEncoding );

			m_tabWidget->setCurrentPage( m_currentSettings->m_activetabsystem );
			
			if ( encoding )
			{
				setTextEncoding( encoding );
			}
			
			if ( m_searchTab )
				m_searchTab->restoreSettings (m_currentSettings->m_searchhistory);
				
			m_bookmarkWindow->restoreSettings (m_currentSettings->m_bookmarks);

			if ( call_open_page )
			{
				m_viewWindowMgr->restoreSettings( m_currentSettings->m_viewwindows );
				m_viewWindowMgr->setCurrentPage( m_currentSettings->m_activetabwindow );
			}
			
			// Restore the main window size
			QList<int> sizes;
			sizes.push_back( m_currentSettings->m_window_size_splitter );
			sizes.push_back( m_currentSettings->m_window_size_x - m_currentSettings->m_window_size_splitter );
			
			m_windowSplitter->setSizes( sizes );
			resize( m_currentSettings->m_window_size_x, m_currentSettings->m_window_size_y );
		}
		else
		{
			m_tabWidget->setCurrentPage (0);
			setTextEncoding( m_chmFile->currentEncoding() );
			
			if ( call_open_page )
				openPage( m_chmFile->homeUrl() );
		}

		appConfig.addRecentFile( m_chmFilename );
		recentFilesUpdate();
		return true;
	}
	else
	{
		QMessageBox mbox(
				i18n("%1 - failed to load the chm file") . arg(APP_NAME),
				i18n("Unable to load the chm file %1") . arg(fileName), 
				QMessageBox::Critical, 
				QMessageBox::Ok, 
				Qt::NoButton, 
				Qt::NoButton);
		mbox.exec();
		
		statusBar()->message( 
				i18n("Could not load file %1").arg(fileName),
				2000 );
		delete new_chmfile;	
		return false;
	}
}



void KCHMMainWindow::refreshCurrentBrowser( )
{
	QString title = m_chmFile->title();
	
	if ( title.isEmpty() )
		title = APP_NAME;
	// KDE adds application name automatically, so we don't need it here	
#if !defined (USE_KDE)
	else
		title = (QString) APP_NAME + " - " + title;
#endif	
	
	setCaption ( title );
	
	currentBrowser()->invalidate();
	
	if ( m_contentsTab )
		m_contentsTab->refillTableOfContents();
}



void KCHMMainWindow::activateLink ( const QString & link, bool& follow_link )
{
	if ( link.isEmpty() )
		return;
	
	if ( gKeyEventFilter.isShiftPressed() )
	{
		openPage( link, OPF_NEW_TAB | OPF_CONTENT_TREE );
		follow_link = false;
	}
	else if ( gKeyEventFilter.isCtrlPressed() )
	{
		openPage( link, OPF_NEW_TAB | OPF_BACKGROUND );
		follow_link = false;
	}
	else
		// If the openPage failed, we do not need to follow the link.
		follow_link = openPage( link, OPF_CONTENT_TREE | OPF_ADD2HISTORY );
}


bool KCHMMainWindow::openPage( const QString & srcurl, unsigned int flags )
{
	QString p1, p2, url = srcurl;
	
	if ( url == "/" )
		url = m_chmFile->homeUrl();

	if ( LCHMUrlFactory::isRemoteURL (url, p1) )
	{
		switch ( appConfig.m_onExternalLinkClick )
		{
		case KCHMConfig::ACTION_DONT_OPEN:
			break;

		case KCHMConfig::ACTION_ASK_USER:
	   		if ( QMessageBox::question(this,
				 i18n("%1 - remote link clicked - %2") . arg(APP_NAME) . arg(p1),
				 i18n("A remote link %1 will start the external program to open it.\n\nDo you want to continue?").arg( url ),
				 i18n("&Yes"), i18n("&No"),
				 QString::null, 0, 1 ) )
					return false;
				
			// no break! should continue to open.

		case KCHMConfig::ACTION_ALWAYS_OPEN:
		{
#if defined (USE_KDE)
			new KRun ( url );
#else
			run_process( appConfig.m_QtBrowserPath, url );
#endif
		}
		break;
		}

		return false; // do not change the current page.
	}
		
	// Filter the URLs which do not need to be opened at all by Qt version
	if ( LCHMUrlFactory::isJavascriptURL (url) )
	{
		QMessageBox::information( this, 
			i18n( "%1 - JavsScript link clicked") . arg(APP_NAME),
			i18n( "You have clicked a JavaScript link.\nTo prevent security-related issues JavaScript URLs are disabled in CHM files.") );
		
		return false;
	}

	if ( LCHMUrlFactory::isNewChmURL (url, p1, p2) && p1 != m_chmFilename )
	{
   		if ( QMessageBox::question( this,
			i18n( "%1 - link to a new CHM file clicked"). arg(APP_NAME),
			i18n( "You have clicked a link, which leads to a new CHM file %1.\nThe current file will be closed.\n\nDo you want to continue?").arg( p1 ),
			i18n( "&Yes" ), i18n( "&No" ),
			QString::null, 0, 1 ) )
				return false;

		// Because chm file always contain relative link, and current filename is not changed,
		// we need to form a new path
		QFileInfo qfi( m_chmFilename );
		QString newfilename = qfi.dirPath(true) + "/" + p1;
		
		QStringList event_args;
		event_args.push_back( newfilename );
		event_args.push_back( p2 ); // url
		
		qApp->postEvent( this, new KCHMUserEvent( "loadAndOpen", event_args ) );
		return false;
	}
	
	KCHMViewWindow * vwnd = currentBrowser();
	if ( flags & OPF_NEW_TAB )
		vwnd = m_viewWindowMgr->addNewTab( !(flags & OPF_BACKGROUND) );
	
	// Store current page and position to add it to history if we change it
	int hist_scrollpos = currentBrowser()->getScrollbarPosition();
	QString hist_url = currentBrowser()->getOpenedPage();
	
	if ( vwnd->openUrl (url) )
	{
		// Open all the tree items to show current item (if needed)
		if ( (flags & OPF_CONTENT_TREE) != 0 )
			locateInContentTree( vwnd->getOpenedPage() );
		
		if ( flags & OPF_ADD2HISTORY )
			currentBrowser()->addNavigationHistory( hist_url, hist_scrollpos );
	}
	
	return true;
}


void KCHMMainWindow::showEvent( QShowEvent * )
{
	if ( !m_FirstTimeShow )
		return;

	m_FirstTimeShow = false;
	
	if ( !parseCmdLineArgs( ) )
	{
		if ( appConfig.m_LoadLatestFileOnStartup && appConfig.m_recentFiles.size() > 0 )
		{
			if ( loadChmFile( appConfig.m_recentFiles[0] ) )
				return;
		}
		
		emit actionOpenFile();
	}
}


void KCHMMainWindow::setTextEncoding( const LCHMTextEncoding * encoding )
{
	m_chmFile->setCurrentEncoding( encoding );
	
	// Find the appropriate encoding item in "Set encodings" menu
	const QList<QAction *> encodings = m_encodingActions->actions();
	
	for ( QList<QAction *>::const_iterator it = encodings.begin();
	      it != encodings.end();
	      ++it )
	{
		const LCHMTextEncoding * enc = (const LCHMTextEncoding *) (*it)->data().value< void* > ();
		
		if ( !strcmp( enc->qtcodec, encoding->qtcodec ) )
		{
			if ( !(*it)->isChecked() )
				(*it)->setChecked( true );
			
			break;
		}
	}
	
	// Because updateView() will call view->invalidate(), which clears the view->getOpenedPage(),
	// we have to make a copy of it.
	QString url = currentBrowser()->getOpenedPage();
	
	// Regenerate the content and index trees	
	refreshCurrentBrowser();
	
	currentBrowser()->openUrl( url );
}

void KCHMMainWindow::closeChmFile( )
{
	// Prepare the settings
	if ( appConfig.m_HistoryStoreExtra )
	{
		m_currentSettings->m_activeEncoding = m_chmFile->currentEncoding()->qtcodec;
		m_currentSettings->m_activetabsystem = m_tabWidget->currentPageIndex( );
		m_currentSettings->m_activetabwindow = m_viewWindowMgr->currentPageIndex( );
		
		m_currentSettings->m_window_size_x = width();
		m_currentSettings->m_window_size_y = height();
		m_currentSettings->m_window_size_splitter = m_windowSplitter->sizes()[0];
		
		if ( m_searchTab )
			m_searchTab->saveSettings (m_currentSettings->m_searchhistory);
				
		m_bookmarkWindow->saveSettings( m_currentSettings->m_bookmarks );

		m_viewWindowMgr->saveSettings( m_currentSettings->m_viewwindows );

		m_currentSettings->saveSettings( );
	}
	
	appConfig.save();
}


void KCHMMainWindow::closeEvent ( QCloseEvent * e )
{
	// Save the settings if we have something opened
	if ( m_chmFile )
	{
		closeChmFile( );
		delete m_chmFile;
		m_chmFile = 0;
	}

	QMainWindow::closeEvent ( e );
}

bool KCHMMainWindow::parseCmdLineArgs( )
{
	QString filename = QString::null, search_query = QString::null;
	QString search_index = QString::null, search_bookmark = QString::null;
	bool do_autotest = false;

#if defined (USE_KDE)
	KCmdLineArgs *args = KCmdLineArgs::parsedArgs();

	if ( args->isSet("autotestmode") )
		do_autotest = true;
	
	if ( args->isSet("shortautotestmode") )
		do_autotest = m_useShortAutotest = true;

	search_query = args->getOption ("search");
	search_index = args->getOption ("sindex");
	
	if ( args->count() > 0 )
		filename = args->arg(0);
#else
	// argv[0] in Qt is still a program name
	for ( int i = 1; i < qApp->argc(); i++  )
	{
		if ( !strcmp (qApp->argv()[i], "-h") || !strcmp (qApp->argv()[i], "--help") )
		{
			fprintf (stderr, "Usage: %s [chmfile]\n", qApp->argv()[0]);
			exit (1);
		}
#if defined (ENABLE_AUTOTEST_SUPPORT)
		else if ( !strcmp (qApp->argv()[i], "--autotestmode") )
			do_autotest = m_useShortAutotest = true;
		else if ( !strcmp (qApp->argv()[i], "--shortautotestmode") )
			do_autotest = true;
#endif		
		else if ( !strcmp (qApp->argv()[i], "--search") )
			search_query = qApp->argv()[++i];
		else if ( !strcmp (qApp->argv()[i], "--sindex") )
			search_index = qApp->argv()[++i];
		else
			filename = qApp->argv()[i];
	}
#endif

	if ( !filename.isEmpty() )
	{
		if ( !loadChmFile( QString::fromLocal8Bit( filename )) )
			return true; // skip the latest checks, but do not exit from the program

		if ( !search_index.isEmpty() )
		{
			QStringList event_args;
			event_args.push_back( search_index );
			qApp->postEvent( this, new KCHMUserEvent( "findInIndex", event_args ) );
		}
		
		if ( !search_query.isEmpty() )	
		{
			QStringList event_args;
			event_args.push_back( search_query );
			qApp->postEvent( this, new KCHMUserEvent( "searchQuery", event_args ) );
		}
		
		if ( do_autotest )
		{
#if defined (ENABLE_AUTOTEST_SUPPORT)
			if ( filename.isEmpty() )
				qFatal ("Could not use Auto Test mode without a chm file!");

			m_autoteststate = STATE_INITIAL;
			showMinimized ();
			runAutoTest();
#else
			qFatal ("Auto Test mode support is not compiled in.");
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */
		}
		return true;
	}
	
	return false;
}



void KCHMMainWindow::setupSignals( )
{
#if defined(HAVE_SIGACTION)
	struct sigaction sa;
    memset ((char *)&sa, 0, sizeof(sa));
	sigemptyset (&sa.sa_mask);
	sigaddset (&sa.sa_mask, SIGCHLD);

#ifdef SA_RESTART
	sa.sa_flags = SA_RESTART;
#endif
	
	sa.sa_handler = SIG_IGN;
	sigaction (SIGCHLD, &sa, (struct sigaction *)0);
#else /* !HAVE_SIGACTION */
	signal (SIGCHLD, SIG_IGN);
#endif /* HAVE_SIGACTION */
}


void KCHMMainWindow::showOrHideContextWindow( int tabindex )
{
	if ( tabindex == -1 )
	{
		if ( m_contentsTab )
		{
			m_tabWidget->removePage (m_contentsTab);
			delete m_contentsTab;
			m_contentsTab = 0;
		}
		
		nav_actionPreviousPage->setEnabled( false );
		nav_actionNextPageToc->setEnabled( false );
	}
	else
	{
		if ( !m_contentsTab )
		{
			m_contentsTab = new KCHMContentsWindow( m_tabWidget );
			m_tabWidget->insertTab (m_contentsTab, i18n( "Contents" ), tabindex);
		}
	
		nav_actionPreviousPage->setEnabled( true );
		nav_actionNextPageToc->setEnabled( true );
	}
}

void KCHMMainWindow::showOrHideIndexWindow( int tabindex )
{
	// Test whether to show/invalidate the index window
	if ( tabindex == -1 )
	{
		if ( m_indexTab )
		{
			m_tabWidget->removePage (m_indexTab);
			delete m_indexTab;
			m_indexTab = 0;
		}
	}
	else
	{
		if ( !m_indexTab )
		{
			m_indexTab = new KCHMIndexWindow (m_tabWidget);
			m_tabWidget->insertTab (m_indexTab, i18n( "Index" ), tabindex);
		}
		else
			m_indexTab->invalidate();
	}
}

void KCHMMainWindow::showOrHideSearchWindow( int tabindex )
{
	if ( tabindex == -1 )
	{
		if ( m_searchTab )
		{
			m_tabWidget->removePage (m_searchTab);
			delete m_searchTab;
			m_searchTab = 0;
		}
	}
	else
	{
		if ( !m_searchTab )
		{
			m_searchTab = new KCHMSearchWindow (m_tabWidget);
			m_tabWidget->insertTab (m_searchTab, i18n( "Search" ), tabindex);
		}
		else
			m_searchTab->invalidate();
	}
}


KCHMViewWindow * KCHMMainWindow::currentBrowser( ) const
{
	return m_viewWindowMgr->current();
}

void KCHMMainWindow::slotOpenPageInNewTab( )
{
	openPage( currentBrowser()->getNewTabLink(), OPF_NEW_TAB | OPF_CONTENT_TREE );
}

void KCHMMainWindow::slotOpenPageInNewBackgroundTab( )
{
	openPage( currentBrowser()->getNewTabLink(), OPF_NEW_TAB | OPF_BACKGROUND );
}

void KCHMMainWindow::slotBrowserChanged( KCHMViewWindow * newbrowser )
{
	locateInContentTree( newbrowser->getOpenedPage() );
}

void KCHMMainWindow::locateInContentTree( const QString & url )
{
	if ( !m_contentsTab )
		return;
	
	KCHMIndTocItem * treeitem = m_contentsTab->getTreeItem( url );
	
	if ( treeitem )
	{
		KCHMIndTocItem * itemparent = treeitem;
		while ( (itemparent = (KCHMIndTocItem*) itemparent->parent()) != 0 )
			itemparent->setExpanded(true);
			
		m_contentsTab->showItem( treeitem );
	}
}

bool KCHMMainWindow::event( QEvent * e )
{
	if ( e->type() == QEvent::User )
		return handleUserEvent( (KCHMUserEvent*) e );
	
	return QWidget::event( e );
}

bool KCHMMainWindow::handleUserEvent( const KCHMUserEvent * event )
{
	if ( event->m_action == "loadAndOpen" )
	{
		if ( event->m_args.size() != 1 && event->m_args.size() != 2 )
			qFatal("handleUserEvent: event loadAndOpen must receive 1 or 2 args");
		
		QString chmfile = event->m_args[0];
		QString openurl = event->m_args.size() > 1 ? event->m_args[1] : "/";
				
		return loadChmFile( chmfile, false ) && openPage( openurl );
	}
	else if ( event->m_action == "openPage" )
	{
		if ( event->m_args.size() != 1 )
			qFatal("handleUserEvent: event openPage must receive 1 arg");
		
		return openPage( event->m_args[0] );
	}
	else if ( event->m_action == "findInIndex" )
	{
		if ( event->m_args.size() != 1 )
			qFatal( "handleUserEvent: event searchQuery must receive 1 arg" );
		
		if ( m_tabIndexPage == -1 )
			return false;

		actionSwitchToIndexTab();
		m_indexTab->search( event->m_args[0] );
		return true;
	}
	else if ( event->m_action == "searchQuery" )
	{
		if ( event->m_args.size() != 1 )
			qFatal( "handleUserEvent: event searchQuery must receive 1 arg" );
		
		if ( m_tabSearchPage == -1 )
			return false;

		actionSwitchToSearchTab();
		m_searchTab->execSearchQueryInGui( event->m_args[0] );
		return true;
	}
	else
		qWarning( "Unknown user event received: %s", event->m_action.ascii() );
	
	return false;
}


#if defined (ENABLE_AUTOTEST_SUPPORT)
void KCHMMainWindow::runAutoTest()
{
	KCHMIndTocItem * item;

	switch (m_autoteststate)
	{
	case STATE_INITIAL:
		if ( m_contentsTab && !m_useShortAutotest )
		{
			m_autotestlistiterator = Q3ListViewItemIterator (m_contentsTab);
			m_autoteststate = STATE_CONTENTS_OPENNEXTPAGE;
		}
		else
			m_autoteststate = STATE_OPEN_INDEX;
		
		QTimer::singleShot (500, this, SLOT(runAutoTest()) );
		break; // allow to finish the initialization sequence
		
	case STATE_CONTENTS_OPENNEXTPAGE:
		if ( (item = (KCHMIndTocItem *) m_autotestlistiterator.current()) != 0 )
		{
			openPage( item->getUrl(), OPF_CONTENT_TREE | OPF_ADD2HISTORY );
			m_autotestlistiterator++;
		}
		else
			m_autoteststate = STATE_OPEN_INDEX;
		
		QTimer::singleShot (50, this, SLOT(runAutoTest()) );
		break;

	case STATE_OPEN_INDEX:
		if ( m_indexTab )
			m_tabWidget->setCurrentPage (1);
		
		m_autoteststate = STATE_SHUTDOWN;
		QTimer::singleShot (500, this, SLOT(runAutoTest()) );
		break;

	case STATE_SHUTDOWN:
		qApp->quit();
		break;
		
	default:
		break;
	}
}
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */


void KCHMMainWindow::showInStatusBar(const QString & text)
{
	statusBar()->message( text, 2000 );
}

void KCHMMainWindow::actionNavigateBack()
{
	currentBrowser()->navigateBack();
}

void KCHMMainWindow::actionNavigateForward()
{
	currentBrowser()->navigateForward();
}

void KCHMMainWindow::actionNavigateHome()
{
	currentBrowser()->navigateHome();
}

void KCHMMainWindow::actionOpenFile()
{
#if defined (USE_KDE)
	QString fn = KFileDialog::getOpenFileName( appConfig.m_lastOpenedDir, i18n("*.chm|Compressed Help Manual (*.chm)"), this);
#else
	QString fn = QFileDialog::getOpenFileName( appConfig.m_lastOpenedDir, i18n("Compressed Help Manual (*.chm)"), this );
#endif

	if ( !fn.isEmpty() )
		loadChmFile( fn );
	else
	{
		if ( !m_chmFile )
			exit (1);
			
		statusBar()->message( i18n("Loading aborted"), 2000 );
	}
}

void KCHMMainWindow::actionPrint()
{
	currentBrowser()->printCurrentPage();
}

void KCHMMainWindow::actionEditCopy()
{
	currentBrowser()->clipCopy();
}

void KCHMMainWindow::actionEditSelectAll()
{
	currentBrowser()->clipSelectAll();
}

void KCHMMainWindow::actionFindInPage()
{
}

void KCHMMainWindow::actionChangeSettings()
{
	KCHMSetupDialog dlg ( this );
	
	// Set up the parameters
	dlg.m_radioOnBeginOpenDialog->setChecked ( !appConfig.m_LoadLatestFileOnStartup );
	dlg.m_radioOnBeginOpenLast->setChecked ( appConfig.m_LoadLatestFileOnStartup );
	dlg.m_historySize->setValue ( appConfig.m_numOfRecentFiles );
	dlg.m_rememberHistoryInfo->setChecked ( appConfig.m_HistoryStoreExtra );
	
	dlg.m_radioExtLinkOpenAlways->setChecked ( appConfig.m_onExternalLinkClick == KCHMConfig::ACTION_ALWAYS_OPEN );
	dlg.m_radioExtLinkAsk->setChecked ( appConfig.m_onExternalLinkClick == KCHMConfig::ACTION_ASK_USER );
	dlg.m_radioExtLinkOpenNever->setChecked ( appConfig.m_onExternalLinkClick == KCHMConfig::ACTION_DONT_OPEN );
	
	dlg.m_radioNewChmOpenAlways->setChecked ( appConfig.m_onNewChmClick == KCHMConfig::ACTION_ALWAYS_OPEN );
	dlg.m_radioNewChmAsk->setChecked ( appConfig.m_onNewChmClick == KCHMConfig::ACTION_ASK_USER );
	dlg.m_radioNewChmOpenNever->setChecked ( appConfig.m_onNewChmClick == KCHMConfig::ACTION_DONT_OPEN );

#if defined (USE_KDE)
	dlg.m_groupQtsettings->setEnabled ( false );
	dlg.m_groupKDEsettings->setEnabled ( true );
#else
	dlg.m_groupQtsettings->setEnabled ( true );
	dlg.m_groupKDEsettings->setEnabled ( false );
#endif

	dlg.m_qtBrowserPath->setText ( appConfig.m_QtBrowserPath );
	dlg.m_radioUseQtextBrowser->setChecked ( appConfig.m_kdeUseQTextBrowser );
	dlg.m_radioUseKHTMLPart->setChecked ( !appConfig.m_kdeUseQTextBrowser );
	
	dlg.m_enableJS->setChecked ( appConfig.m_kdeEnableJS );
	dlg.m_enablePlugins->setChecked ( appConfig.m_kdeEnablePlugins );
	dlg.m_enableJava->setChecked ( appConfig.m_kdeEnableJava );
	dlg.m_enableRefresh->setChecked ( appConfig.m_kdeEnableRefresh );
	
	dlg.m_advExternalProgramName->setText( appConfig.m_advExternalEditorPath );
	dlg.m_advViewSourceExternal->setChecked ( !appConfig.m_advUseInternalEditor );
	dlg.m_advViewSourceInternal->setChecked ( appConfig.m_advUseInternalEditor );
	
	// Search engine
	dlg.m_useSearchEngineInternal->setChecked( appConfig.m_useSearchEngine == KCHMConfig::SEARCH_USE_CHM );
	dlg.m_useSearchEngineNew->setChecked( appConfig.m_useSearchEngine == KCHMConfig::SEARCH_USE_MINE );
	
	// Connect buddies
	dlg.m_labelUseSearchEngineInternal->setBuddy( dlg.m_useSearchEngineInternal );
	dlg.m_labelUseSearchEngineNew->setBuddy( dlg.m_useSearchEngineNew );
	
	if ( dlg.exec() == QDialog::Accepted )
	{
		appConfig.m_LoadLatestFileOnStartup = dlg.m_radioOnBeginOpenLast->isChecked();
		appConfig.m_numOfRecentFiles = dlg.m_historySize->value();
		appConfig.m_HistoryStoreExtra = dlg.m_rememberHistoryInfo->isChecked();

		if ( dlg.m_radioExtLinkOpenAlways->isChecked () )
			appConfig.m_onExternalLinkClick = KCHMConfig::ACTION_ALWAYS_OPEN;
		else if ( dlg.m_radioExtLinkAsk->isChecked () )
			appConfig.m_onExternalLinkClick = KCHMConfig::ACTION_ASK_USER;
		else
			appConfig.m_onExternalLinkClick = KCHMConfig::ACTION_DONT_OPEN;

		if ( dlg.m_radioNewChmOpenAlways->isChecked () )
			appConfig.m_onNewChmClick = KCHMConfig::ACTION_ALWAYS_OPEN;
		else if ( dlg.m_radioNewChmAsk->isChecked () )
			appConfig.m_onNewChmClick = KCHMConfig::ACTION_ASK_USER;
		else
			appConfig.m_onNewChmClick = KCHMConfig::ACTION_DONT_OPEN;

		appConfig.m_QtBrowserPath = dlg.m_qtBrowserPath->text();
		
		// Check the changes
		bool need_restart = false;
		
		if ( appConfig.m_kdeEnableJS != dlg.m_enableJS->isChecked() )
		{
			need_restart = true;
			appConfig.m_kdeEnableJS = dlg.m_enableJS->isChecked();
		}
		
		if ( appConfig.m_kdeEnablePlugins != dlg.m_enablePlugins->isChecked() )
		{
			need_restart = true;
			appConfig.m_kdeEnablePlugins = dlg.m_enablePlugins->isChecked();
		}
		
		if ( appConfig.m_kdeEnableJava != dlg.m_enableJava->isChecked() )
		{
			need_restart = true;
			appConfig.m_kdeEnableJava = dlg.m_enableJava->isChecked();
		}
		
		if ( appConfig.m_kdeEnableRefresh != dlg.m_enableRefresh->isChecked() )
		{
			need_restart = true;
			appConfig.m_kdeEnableRefresh = dlg.m_enableRefresh->isChecked();
		}
		
		if ( appConfig.m_kdeUseQTextBrowser != dlg.m_radioUseQtextBrowser->isChecked() )
		{
			need_restart = true;
			appConfig.m_kdeUseQTextBrowser = dlg.m_radioUseQtextBrowser->isChecked();
		}
		
		if ( dlg.m_useSearchEngineNew->isChecked() 
				   && appConfig.m_useSearchEngine == KCHMConfig::SEARCH_USE_CHM )
		{
			appConfig.m_useSearchEngine = KCHMConfig::SEARCH_USE_MINE;
			m_searchTab->invalidate();
		}
		
		if ( dlg.m_useSearchEngineInternal->isChecked() 
				   && appConfig.m_useSearchEngine == KCHMConfig::SEARCH_USE_MINE )
		{
			appConfig.m_useSearchEngine = KCHMConfig::SEARCH_USE_CHM;
			m_searchTab->invalidate();
		}
					
		appConfig.m_advExternalEditorPath = dlg.m_advExternalProgramName->text();
		appConfig.m_advUseInternalEditor = dlg.m_advViewSourceExternal->isChecked();
		appConfig.m_advUseInternalEditor = dlg.m_advViewSourceInternal->isChecked();
		
		if ( appConfig.m_numOfRecentFiles != m_numOfRecentFiles )
			need_restart = true;
		
		appConfig.save();
		
		if ( need_restart )
			QMessageBox::information( 
			                          this,
			                          APP_NAME,
			                          i18n( "Changing browser view options, search engine used or recent "
			                                "files size requires restarting the application to take effect." )	);
	}
}

void KCHMMainWindow::actionExtractCHM()
{
	QStringList files;
	
#if defined (USE_KDE)
	QString outdir = KFileDialog::getExistingDirectory (
		QString::null,
		this,
		i18n("Choose a directory to store CHM content") );
#else
	QString outdir = QFileDialog::getExistingDirectory (
		QString::null,
		this,
		0,
		i18n("Choose a directory to store CHM content"),
		TRUE );
#endif
	
	if ( outdir.isEmpty() )
		return;
	
	outdir += "/";
	
	// Enumerate all the files in archive
	if ( !m_chmFile || !m_chmFile->enumerateFiles( &files ) )
		return;

	KQProgressModalDialog progress( i18n("Extracting CHM content"), 
	                                i18n("Extracting files..."), 
	                                i18n("Abort"), 
	                                files.size(), 
	                                this );
	
	for ( int i = 0; i < files.size(); i++ )
	{
		progress.setValue( i );
		
		if ( (i % 3) == 0 )
		{
			qApp->processEvents();

			if ( progress.wasCancelled() )
				break;
		}

		// Extract the file
		QByteArray buf;
		
		if ( m_chmFile->getFileContentAsBinary( &buf, files[i] ) )
		{
			// Split filename to get the list of subdirectories
			QStringList dirs = QStringList::split( '/', files[i] );

			// Walk through the list of subdirectories, and create them if needed
			// dirlevel is used to detect extra .. and prevent overwriting files
			// outside the directory (like creating the file images/../../../../../etc/passwd
			int i, dirlevel = 0;
			QStringList dirlist;
				
			for ( i = 0; i < dirs.size() - 1; i++ )
			{
				// Skip .. which lead too far above
				if ( dirs[i] == ".." )
				{
					if ( dirlevel > 0 )
					{
						dirlevel--;
						dirlist.pop_back();
					}
				}
				else
				{
					dirlist.push_back( dirs[i] );
					
					QDir dir ( outdir + dirlist.join( "/" ) );
					if ( !dir.exists() )
					{
						if ( !dir.mkdir( dir.path() ) )
							qWarning( "Could not create subdir %s\n", dir.path().ascii() );
					}
				}
			}
			
			QString filename = outdir + dirlist.join( "/" ) + "/" + dirs[i];
			QFile wf( filename );
			if ( !wf.open( QIODevice::WriteOnly ) )
			{
				qWarning( "Could not write file %s\n", filename.ascii() );
				continue;
			}
			
			wf. writeBlock( buf );
			wf.close();
		}
		else
			qWarning( "Could not get file %s\n", files[i].ascii() );
	}
	
	progress.setValue( files.size() );
}

void KCHMMainWindow::actionAddBookmark()
{
	m_bookmarkWindow->onAddBookmarkPressed();
}

void KCHMMainWindow::actionFontSizeIncrease()
{
	currentBrowser()->addZoomFactor( 1 );
}

void KCHMMainWindow::actionFontSizeDecrease()
{
	currentBrowser()->addZoomFactor( -1 );
}

void KCHMMainWindow::actionViewHTMLsource()
{
	QString text;

	if ( !m_chmFile->getFileContentAsString( &text, currentBrowser()->getOpenedPage() ) )
		return;

	if ( appConfig.m_advUseInternalEditor )
	{
		QTextEdit * editor = new QTextEdit ( 0 );
		editor->setTextFormat ( Qt::PlainText );
		editor->setText( text );
		editor->setCaption ( QString("HTML source of %1") .arg( currentBrowser()->getOpenedPage() ));
		editor->resize( 800, 600 );
		editor->show();
	}
	else
	{
		QFile file;
		m_tempFileKeeper.generateTempFile( file );
		
		file.writeBlock( text.utf8() );
		run_process( appConfig.m_advExternalEditorPath, file.name() );
	}
}

void KCHMMainWindow::actionToggleFullScreen()
{
	bool fullscreen = view_Toggle_fullscreen_action->isChecked();
	
	if ( fullscreen )
	{
		if ( !isFullScreen() )
		{
			showFullScreen ();
			
			// Hiding menu bar disables menu actions. Probably a bug in Qt.
			//menuBar()->hide();
			statusBar()->hide();
		}
	}
	else
	{
		if ( isFullScreen() )
		{
			showNormal();
			menuBar()->show();
			statusBar()->show();
		}
	}
}

void KCHMMainWindow::actionToggleContentsTab()
{
	bool show = view_Toggle_contents_action->isChecked();

	if ( show )
		m_tabWidget->show();
	else
		m_tabWidget->hide();
}

void KCHMMainWindow::actionLocateInContentsTab()
{
	// There may be no content tab at all
	if ( !m_contentsTab || m_tabContextPage == -1 )
		return;
	
	// Activate a content tab
	m_tabWidget->setCurrentPage( m_tabContextPage );
	
	if ( m_contentsTab )
	{
		// Open all the tree items to show current item (if needed)
		KCHMIndTocItem * treeitem = m_contentsTab->getTreeItem( currentBrowser()->getOpenedPage() );
	
		if ( treeitem )
		{
			KCHMIndTocItem * itemparent = treeitem;
			
			while ( (itemparent = (KCHMIndTocItem*) itemparent->parent()) != 0 )
				itemparent->setExpanded(true);
			
			m_contentsTab->showItem( treeitem );
		}
		else
			statusBar()->message( i18n( "Could not locate opened topic in content window"), 2000 );
	}
}

void KCHMMainWindow::actionNavigatePrevInToc()
{
	if ( !m_contentsTab )
		return;
	
	// Try to find current list item
	KCHMIndTocItem * current = m_contentsTab->getTreeItem( currentBrowser()->getOpenedPage() );
	
	if ( !current )
		return;

	QTreeWidgetItemIterator lit( current );
	lit--;
	
	if ( *lit )
		::mainWindow->openPage( ((KCHMIndTocItem *) (*lit) )->getUrl(), OPF_CONTENT_TREE | OPF_ADD2HISTORY );
}

void KCHMMainWindow::actionNavigateNextInToc()
{
	if ( !m_contentsTab )
		return;
	
	// Try to find current list item
	KCHMIndTocItem * current = m_contentsTab->getTreeItem( currentBrowser()->getOpenedPage() );

	if ( !current )
		return;
	
	QTreeWidgetItemIterator lit( current );
	lit++;
	
	if ( *lit )
		::mainWindow->openPage( ((KCHMIndTocItem *) (*lit) )->getUrl(), OPF_CONTENT_TREE | OPF_ADD2HISTORY );
}

void KCHMMainWindow::actionAboutApp()
{
	QString caption = i18n( "About %1" ) . arg(APP_NAME);
	QString text = m_aboutDlgMenuText;
	
	// It is quite funny that the argument order differs
#if defined (USE_KDE)
	KMessageBox::about( this, text, caption );
#else
	QMessageBox::about( this, caption, text );
#endif
}

void KCHMMainWindow::actionAboutQt()
{
	QMessageBox::aboutQt( this, APP_NAME);
}

void KCHMMainWindow::actionSwitchToContentTab()
{
	if ( m_tabContextPage != -1 ) 
		m_tabWidget->setCurrentPage( m_tabContextPage );
}

void KCHMMainWindow::actionSwitchToIndexTab()
{
	if ( m_tabIndexPage != -1 ) 
		m_tabWidget->setCurrentPage( m_tabIndexPage );
}

void KCHMMainWindow::actionSwitchToSearchTab()
{
	if ( m_tabSearchPage != -1 ) 
		m_tabWidget->setCurrentPage( m_tabSearchPage );
}

void KCHMMainWindow::actionSwitchToBookmarkTab()
{
	m_tabWidget->setCurrentPage( m_tabBookmarkPage );
}


void KCHMMainWindow::setupActions()
{
	// Connect actions to slots
	connect( file_Open_action, 
			 SIGNAL( activated() ),
			 this,
			 SLOT( actionOpenFile() ) );
			
	connect( file_Print_action, 
			 SIGNAL( activated() ),
			 this,
			 SLOT( actionPrint() ) );
	
	connect( edit_Copy_action,
			 SIGNAL( activated() ),
			 this,
			 SLOT( actionEditCopy() ) );
	
	connect( edit_SelectAll_action,
			 SIGNAL( activated() ),
			 this,
			 SLOT( actionEditSelectAll() ) );

	connect( edit_FindAction,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionFindInPage() ) );
	
	connect( file_ExtractCHMAction,
			 SIGNAL( activated() ),
	         this,
	         SLOT( actionExtractCHM() ) );

	connect( settings_SettingsAction,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionChangeSettings() ) );
	
	connect( bookmark_AddAction,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionAddBookmark() ) );
	
	connect( view_Increase_font_size_action,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionFontSizeIncrease() ) );
	
	connect( view_Decrease_font_size_action,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionFontSizeDecrease() ) );
	
	connect( view_View_HTML_source_action,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionViewHTMLsource() ) );
	
	connect( view_Toggle_fullscreen_action,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionToggleFullScreen() ) );
	
	connect( view_Toggle_contents_action,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionToggleContentsTab() ) );
	
	connect( view_Locate_in_contents_action,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionLocateInContentsTab() ) );
	
	connect( nav_action_Back,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionNavigateBack() ) );
	
	connect( nav_actionForward,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionNavigateForward() ) );
	
	connect( nav_actionHome,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionNavigateHome() ) );
	
	connect( nav_actionPreviousPage,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionNavigatePrevInToc() ) );
	
	connect( nav_actionNextPageToc,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionNavigateNextInToc() ) );
	
	// m_bookmarkWindow fills and maintains 'Bookmarks' menu
	m_bookmarkWindow->createMenu( this, menu_Bookmarks );
	
	// m_viewWindowMgr fills and maintains 'Window' menu
	m_viewWindowMgr->createMenu( this, menu_Windows, action_Close_window );
	
	// Close Window goes directly to the window manager
	connect( action_Close_window,
	         SIGNAL( activated() ),
	         this,
	         SLOT( actionNavigateNextInToc() ) );
	
	connect( file_exit_action, 
	         SIGNAL( activated() ),
	         qApp,
	         SLOT( closeAllWindows() ) );
	
	// Set up recent files
	recentFilesInit( menu_File );
	
	// Quit
	menu_File->addSeparator();	
	menu_File->addAction( file_exit_action );
	
#if defined(USE_KDE)
	QMenu *help = helpMenu( m_aboutDlgMenuText );
#else
	QMenu * help = new QMenu( i18n( "&Help"), this );
	help->addAction( i18n( "&About"), this, SLOT( actionAboutApp() ), QKeySequence( "F1" ) );
	help->addAction( i18n( "About &Qt"), this, SLOT( actionAboutQt() ) );
	help->addSeparator();
	
	// "What's this" action
	QAction * whatsthis = QWhatsThis::createAction( this );
	help->addAction( whatsthis );
	viewToolbar->addAction( whatsthis );
#endif
		
	menuBar()->addMenu( help );
	recentFilesUpdate();
	
	// Tab switching actions
	(void) new QShortcut( QKeySequence( i18n("Ctrl+1") ),
	                      this,
	                      SLOT( actionSwitchToContentTab() ),
	                      SLOT( actionSwitchToContentTab() ),
	                      Qt::ApplicationShortcut );
	
	(void)  new QShortcut( QKeySequence( i18n("Ctrl+2") ),
	                       this,
	                       SLOT( actionSwitchToIndexTab() ),
	                       SLOT( actionSwitchToIndexTab() ),
	                       Qt::ApplicationShortcut );
	
	(void) new QShortcut( QKeySequence( i18n("Ctrl+3") ),
	                      this,
	                      SLOT( actionSwitchToSearchTab() ),
	                      SLOT( actionSwitchToSearchTab() ),
	                      Qt::ApplicationShortcut );
	
	(void) new QShortcut( QKeySequence( i18n("Ctrl+4") ),
	                      this,
	                      SLOT( actionSwitchToBookmarkTab() ),
	                      SLOT( actionSwitchToBookmarkTab() ),
	                      Qt::ApplicationShortcut );
}


void KCHMMainWindow::navSetBackEnabled(bool enabled)
{
	nav_action_Back->setEnabled( enabled );
}

void KCHMMainWindow::navSetForwardEnabled(bool enabled)
{
	nav_actionForward->setEnabled( enabled );
}


void KCHMMainWindow::recentFilesInit( QMenu * menu )
{
	m_numOfRecentFiles = appConfig.m_numOfRecentFiles;
	
	if ( !m_recentFiles.isEmpty() )
	{
		for ( int i = 0; i < m_recentFiles.size(); i++ )
			delete m_recentFiles[i];
		
		m_recentFiles.clear();
	}
	
	m_recentFiles.resize( m_numOfRecentFiles );
	
	// Initialize the recent file actions
	for ( int i = 0; i < m_numOfRecentFiles; ++i )
	{
		m_recentFiles[i] = new QAction( this );
		m_recentFiles[i]->setVisible( false );
		connect( m_recentFiles[i], SIGNAL( triggered() ), this, SLOT( actionOpenRecentFile()) );
	}
	
	// Add the separator, and actions
	m_recentFileSeparator = menu->addSeparator();
	
	for ( int i = 0; i < m_numOfRecentFiles; ++i )
		menu->addAction( m_recentFiles[i] );
	
}

void KCHMMainWindow::recentFilesUpdate()
{
	// Set the actions
	for ( int i = 0; i < m_numOfRecentFiles; ++i )
	{
		if ( i < appConfig.m_recentFiles.size() )
		{
			QString text = tr("&%1 %2").arg(i + 1).arg( QFileInfo( appConfig.m_recentFiles[i] ).fileName() );
			m_recentFiles[i]->setText( text );
			m_recentFiles[i]->setData( appConfig.m_recentFiles[i] );
			m_recentFiles[i]->setVisible( true );
		}
		else
			m_recentFiles[i]->setVisible( false );
	}
	
	m_recentFileSeparator->setVisible( !appConfig.m_recentFiles.isEmpty() );
}

void KCHMMainWindow::actionOpenRecentFile()
{
	QAction *action = qobject_cast<QAction *>(sender());
	
	if ( action )
		loadChmFile( action->data().toString() );
}

void KCHMMainWindow::setupLangEncodingMenu()
{
	// Create the language selection menu.
	QMenu * encodings = new QMenu( this );
	
	// Create the action group
	m_encodingActions = new QActionGroup( this );
	
	// Add the codepage entries
	const LCHMTextEncoding * enctable = LCHMFileImpl::getTextEncodingTable();
	
	for ( int idx = 0; (enctable + idx)->family; idx++ )
	{
		const LCHMTextEncoding * enc = enctable + idx;
		
		QAction * action = new QAction( this );
		
		QString text = i18n("%1 ( %2 )") .arg( enc->family) .arg( enc->qtcodec );
		action->setText( text );
		action->setData( qVariantFromValue( (void*) enc ) );
		action->setCheckable( true );
		
		// Add to the action group, so only one is checkable
		m_encodingActions->addAction( action );
		
		// Add to the menu
		encodings->addAction( action );
	}
	
	// Set up the Select Codepage action
	view_Set_encoding_action->setMenu( encodings );
	
	// Connect the action group signal
	connect( m_encodingActions,
	         SIGNAL( triggered ( QAction * ) ),
	         this,
	         SLOT( actionEncodingChanged( QAction * ) ) );
}


void KCHMMainWindow::actionEncodingChanged( QAction * action )
{
	const LCHMTextEncoding * enc = (const LCHMTextEncoding *) action->data().value< void* > ();
	setTextEncoding( enc );
}
