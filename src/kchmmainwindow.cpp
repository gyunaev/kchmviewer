/***************************************************************************
 *   Copyright (C) 2004-2005 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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

#include <qaccel.h>

#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "kchmindexwindow.h"
#include "kchmsearchwindow.h"
#include "kchmbookmarkwindow.h"
#include "kchmtreeviewitem.h"
#include "kchmsearchtoolbar.h"
#include "kchmsettings.h"
#include "kchmsetupdialog.h"
#include "kqrunprocess.h"
#include "iconstorage.h"
#include "kchmviewwindow_qtextbrowser.h"

#if defined (USE_KDE)
	#include "kchmviewwindow_khtmlpart.h"
#endif

KCHMMainWindow::KCHMMainWindow()
    : KQMainWindow ( 0, "KCHMMainWindow", WDestructiveClose )
{
	const unsigned int WND_X_SIZE = 700;
	const unsigned int WND_Y_SIZE = 500;
	const unsigned int SPLT_X_SIZE = 200;

	m_FirstTimeShow = true;
	m_chmFile = 0;
	
	m_indexWindow = 0;
	m_viewWindow = 0;
	m_searchWindow = 0;
	m_contentsWindow = 0;

	m_tabContextPage = -1;
	m_tabIndexPage = -1;
	m_tabSearchPage = -1;
	m_tabBookmarkPage = -1;
	
	setupSignals();

	m_currentSettings = new KCHMSettings;
		
	// Create the initial layout - a splitter with tab window in left, and text browser in right
	m_windowSplitter = new QSplitter(this);
	m_tabWidget = new KQTabWidget (m_windowSplitter);
	
	m_bookmarkWindow = new KCHMBookmarkWindow (m_tabWidget);

	// Add the tabs
	m_tabWidget->addTab (m_bookmarkWindow, "Bookmarks");

	createViewWindow();
	setupToolbarsAndMenu();
		
	setCentralWidget( m_windowSplitter );
	
	QValueList<int> sizes;
	sizes.push_back (SPLT_X_SIZE);
	sizes.push_back (WND_X_SIZE - SPLT_X_SIZE);
	m_windowSplitter->setSizes (sizes);
	
	resize (WND_X_SIZE, WND_Y_SIZE);

#if defined (ENABLE_AUTOTEST_SUPPORT)
	m_autoteststate = STATE_OFF;
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */

	QAccel * accel = new QAccel( this );
	accel->connectItem ( accel->insertItem ( CTRL + Key_1), this, SLOT ( slotActivateContentTab() ) );
	accel->connectItem ( accel->insertItem ( CTRL + Key_2), this, SLOT ( slotActivateIndexTab() ) );
	accel->connectItem ( accel->insertItem ( CTRL + Key_3), this, SLOT ( slotActivateSearchTab() ) );
	accel->connectItem ( accel->insertItem ( CTRL + Key_4), this, SLOT ( slotActivateBookmarkTab() ) );
	accel->connectItem ( accel->insertItem ( Key_F3 ), m_searchToolbar, SLOT ( onBtnNextSearchResult() ) );

	statusBar()->show();
}


KCHMMainWindow::~KCHMMainWindow()
{
}


void KCHMMainWindow::slotOpenMenuItemActivated()
{
#if defined (USE_KDE)
    QString fn = KFileDialog::getOpenFileName( appConfig.m_lastOpenedDir, "*.chm|Compressed Help Manual (*.chm)", this);
#else
    QString fn = QFileDialog::getOpenFileName( appConfig.m_lastOpenedDir, "Compressed Help Manual (*.chm)", this);
#endif

    if ( !fn.isEmpty() )
		loadChmFile( fn );
    else
	{
		if ( !m_chmFile )
			exit (1);
			
		statusBar()->message( tr("Loading aborted"), 2000 );
	}
}


bool KCHMMainWindow::loadChmFile ( const QString &fileName, bool call_open_page )
{
	CHMFile * new_chmfile = new CHMFile (fileName);
	
	if ( new_chmfile->IsOk() )
	{
		if ( m_chmFile )
		{
			closeChmFile( );
			delete m_chmFile;
		}
	
		m_chmFile = new_chmfile;

		QDir qd;
		qd.setPath (fileName);
		m_chmFilename = qd.absPath();
		
		// Qt's 'dirname' does not work well
		QFileInfo qf ( m_chmFilename );
		appConfig.m_lastOpenedDir = qf.dirPath(true);

		// Order the tabulations
		int number_of_pages = 0;
		
		if ( m_chmFile->TopicsFile() )
			m_tabContextPage = number_of_pages++;
		else
			m_tabContextPage = -1;

		if ( m_chmFile->IndexFile() )
			m_tabIndexPage = number_of_pages++;
		else
			m_tabIndexPage = -1;

		if ( m_chmFile->isSearchAvailable() )
			m_tabSearchPage = number_of_pages++;
		else
			m_tabSearchPage = -1;

		m_tabBookmarkPage = number_of_pages;

		showOrHideContextWindow( m_tabContextPage );
		showOrHideIndexWindow( m_tabIndexPage );
		showOrHideSearchWindow( m_tabSearchPage );
		
		m_bookmarkWindow->invalidate();
		m_viewWindow->invalidate();
		updateView();

		if ( m_currentSettings->loadSettings (fileName) )
		{
			const KCHMTextEncoding::text_encoding_t * enc = KCHMTextEncoding::lookupByLCID (m_currentSettings->m_activeencodinglcid);

			m_tabWidget->setCurrentPage (m_currentSettings->m_activetab);
			
			if ( enc )
			{
				m_chmFile->setCurrentEncoding (enc);
				m_searchToolbar->setChosenEncodingInMenu (enc);
			}
			
			if ( m_searchWindow )
				m_searchWindow->restoreSettings (m_currentSettings->m_searchhistory);
				
			m_bookmarkWindow->restoreSettings (m_currentSettings->m_bookmarks);

			if ( call_open_page )
				openPage (m_currentSettings->m_activepage, true);

			m_viewWindow->setScrollbarPosition(m_currentSettings->m_scrollbarposition);
			m_viewWindow->setZoomFactor(m_currentSettings->m_chosenzoom);
		}
		else
		{
			m_tabWidget->setCurrentPage (0);
			m_searchToolbar->setChosenEncodingInMenu (m_chmFile->getCurrentEncoding());
			
			if ( call_open_page )
				openPage (m_chmFile->HomePage(), true);
		}

		m_searchToolbar->setEnabled (true);
		appConfig.addFileToHistory( m_chmFilename );
		updateHistoryMenu();
		return true;
	}
	else
	{
		if ( !m_chmFile )
		{
			QMessageBox mbox (tr("%1 - failed to load the chm file"), tr("Unable to load the chm file %2") . arg(APP_NAME) . arg(fileName), QMessageBox::Critical, QMessageBox::Ok, QMessageBox::NoButton, QMessageBox::NoButton);
			mbox.exec();
			exit (1);
		}
		
		statusBar()->message( tr("Could not load file %1").arg(fileName), 2000 );
		delete new_chmfile;	
		return false;
	}
}


void KCHMMainWindow::slotPrintMenuItemActivated()
{
	m_viewWindow->printCurrentPage();
}

void KCHMMainWindow::slotAboutMenuItemActivated()
{
	QString caption = tr("About %1") . arg(APP_NAME);
	QString text = tr("%1 version %2\n\nCopyright (C) Georgy Yunaev, tim@krasnogorsk.ru, 2005\n\n"
			"Licensed under GNU GPL license.") . arg(APP_NAME) . arg(APP_VERSION);
	
	// It is quite funny that the argument order differs
#if defined (USE_KDE)
	KMessageBox::about( this, text, caption );
#else
    QMessageBox::about( this, caption, text );
#endif
}


void KCHMMainWindow::slotAboutQtMenuItemActivated()
{
    QMessageBox::aboutQt( this, APP_NAME);
}

void KCHMMainWindow::updateView( )
{
	QString title = m_chmFile->Title();
	if ( !title )
		title = APP_NAME;
	else
		title = (QString) APP_NAME + " - " + title;

	setCaption (title);
	
	m_viewWindow->invalidate();
	
	if ( m_contentsWindow )
	{
		m_contentsWindow->clear();
		m_chmFile->ParseAndFillTopicsTree(m_contentsWindow);
		m_contentsWindow->triggerUpdate();
	}
}

void KCHMMainWindow::onTreeClicked( QListViewItem * item )
{
	if ( !item )
		return;
	
	KCHMMainTreeViewItem * treeitem = (KCHMMainTreeViewItem*) item;
	
	openPage(treeitem->getUrl(), false);
}


void KCHMMainWindow::slotLinkClicked ( const QString & link, bool& follow_link )
{
	// If the openPage failed, we do not need to follow the link.
	follow_link = openPage( link );
}

bool KCHMMainWindow::openPage( const QString & srcurl, bool set_in_tree )
{
	QString p1, p2, url = srcurl;

	if ( m_viewWindow->isRemoteURL (url, p1) )
	{
		switch ( appConfig.m_onExternalLinkClick )
		{
		case KCHMConfig::ACTION_DONT_OPEN:
			break;

		case KCHMConfig::ACTION_ASK_USER:
	   		if ( QMessageBox::question(this,
				tr ("%1 - remote link clicked - %2") . arg(APP_NAME) . arg(p1),
           		tr ("A remote link %1 will start the external program to open it.\n\nDo you want to continue?").arg( url ),
           		tr("&Yes"), tr("&No"),
           		QString::null, 0, 1 ) )
       				return false;
				// no break!

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
	if ( m_viewWindow->isJavascriptURL (url) )
	{
		QMessageBox::information(this, tr ("%1 - JavsScript link clicked") . arg(APP_NAME),
           	tr ("You have clicked a JavaScript link.\nBecause of security reasons, JavaScript links are disabled in CHM files."));
		
		return false;
	}

	if ( m_viewWindow->isNewChmURL (url, p1, p2) 
	&& p1 != m_chmFilename )
	{
   		if ( QMessageBox::question(this,
			tr ("%1 - link to a new CHM file clicked") . arg(APP_NAME),
           	tr ("You have clicked a link, which leads to a new CHM file %1.\nThe current file will be closed.\n\nDo you want to continue?").arg( p1 ),
           	tr("&Yes"), tr("&No"),
           	QString::null, 0, 1 ) )
       			return false;

		// Because chm file always contain relative link, and current filename is not changed,
		// we need to form a new path
		QFileInfo qfi (m_chmFilename);

		if ( !loadChmFile ( qfi.dirPath(true) + "/" + p1, false ) )
			return false;

		url = p2;
	}
	
	if ( m_viewWindow->openUrl (url) )
	{
		// Open all the tree items to show current item (if needed)
		KCHMMainTreeViewItem * treeitem;
		if ( set_in_tree && (treeitem = m_chmFile->getTreeItem(m_viewWindow->getOpenedPage())) != 0 )
		{
			KCHMMainTreeViewItem * itemparent = treeitem;
			while ( (itemparent = (KCHMMainTreeViewItem*) itemparent->parent()) != 0 )
				itemparent->setOpen(true);
			
			if ( m_contentsWindow )
			{
				m_contentsWindow->setCurrentItem (treeitem);
				m_contentsWindow->ensureItemVisible (treeitem);
			}
		}
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
		if ( appConfig.m_LoadLatestFileOnStartup && appConfig.m_History.size() > 0 )
		{
			if ( loadChmFile ( appConfig.m_History[0] ) )
				return;
		}
		
		emit slotOpenMenuItemActivated();
	}
}

void KCHMMainWindow::setupToolbarsAndMenu( )
{
	// Create a 'file' toolbar
    QToolBar * toolbar = new QToolBar(this);
	
	toolbar->setLabel( tr("File Operations") );

    QPixmap iconFileOpen (*gIconStorage.getToolbarPixmap(KCHMIconStorage::fileopen));
    QToolButton * fileOpen = new QToolButton (iconFileOpen, 
				tr("Open File"), 
				QString::null,
				this, 
				SLOT( slotOpenMenuItemActivated() ),
				toolbar);
	
	QString fileOpenText = tr("Click this button to open an existing chm file.");
	QWhatsThis::add( fileOpen, fileOpenText );

    QPixmap iconFilePrint (*gIconStorage.getToolbarPixmap(KCHMIconStorage::print));
    QToolButton * filePrint	= new QToolButton (iconFilePrint,
				tr("Print File"),
				QString::null,
				this,
				SLOT( slotPrintMenuItemActivated() ),
				toolbar);

	QString filePrintText = tr("Click this button to print the current page");
	QWhatsThis::add( filePrint, filePrintText );

    QToolBar * navtoolbar = new QToolBar(this);
	navtoolbar->setLabel( tr("Navigation") );
	
    QPixmap iconBackward (*gIconStorage.getToolbarPixmap(KCHMIconStorage::back));
    m_toolbarIconBackward = new QToolButton (iconBackward,
				tr("Move backward in history"),
				QString::null,
				this,
				SLOT( slotBackwardMenuItemActivated() ),
				navtoolbar);
	QWhatsThis::add( m_toolbarIconBackward, tr("Click this button to move backward in browser history") );	

    QPixmap iconForward (*gIconStorage.getToolbarPixmap(KCHMIconStorage::forward));
    m_toolbarIconForward = new QToolButton (iconForward,
				tr("Move forward in history"),
				QString::null,
				this,
				SLOT( slotForwardMenuItemActivated() ),
				navtoolbar);
	QWhatsThis::add( m_toolbarIconBackward, tr("Click this button to move forward in browser history") );	
	
    QPixmap iconHome = (*gIconStorage.getToolbarPixmap(KCHMIconStorage::gohome));
    new QToolButton (iconHome,
				tr("Go to the home page"),
				QString::null,
				this,
				SLOT( slotHomeMenuItemActivated() ),
				navtoolbar);
	QWhatsThis::add( m_toolbarIconBackward, tr("Click this button to move to the home page") );	

	// Setup the menu
	KQPopupMenu * file = new KQPopupMenu( this );
	menuBar()->insertItem( tr("&File"), file );

    int id;
	id = file->insertItem ( iconFileOpen, tr("&Open..."), this, SLOT( slotOpenMenuItemActivated() ), CTRL+Key_O );
    file->setWhatsThis( id, fileOpenText );

	id = file->insertItem( iconFilePrint, tr("&Print..."), this, SLOT( slotPrintMenuItemActivated() ), CTRL+Key_P );
    file->setWhatsThis( id, filePrintText );

    file->insertSeparator();

	m_menuHistory = new KQPopupMenu( file );
	connect ( m_menuHistory, SIGNAL( activated(int) ), this, SLOT ( slotHistoryMenuItemActivated(int) ));
	
	file->insertItem( tr("&Recent files"), m_menuHistory );
	
	file->insertSeparator();
    file->insertItem( tr("&Quit"), qApp, SLOT( closeAllWindows() ), CTRL+Key_Q );

	KQPopupMenu * menu_edit = new KQPopupMenu( this );
	menuBar()->insertItem( tr("&Edit"), menu_edit );

	id = menu_edit->insertItem ( tr("&Copy"), this, SLOT( slotBrowserCopy()), CTRL+Key_C );
	id = menu_edit->insertItem ( tr("&Select all"), this, SLOT( slotBrowserSelectAll()), CTRL+Key_A );

    menu_edit->insertSeparator();
	
	// KCHMSearchToolbar also adds 'view' menu
	m_searchToolbar = new KCHMSearchAndViewToolbar (this);

	KQPopupMenu * settings = new KQPopupMenu( this );
	menuBar()->insertItem( tr("&Setup"), settings );
	settings->insertItem( tr("&Change settings..."), this, SLOT( slotChangeSettingsMenuItemActivated() ));

    KQPopupMenu * help = new KQPopupMenu( this );
    menuBar()->insertItem( tr("&Help"), help );

	help->insertItem( tr("&About"), this, SLOT( slotAboutMenuItemActivated() ), Key_F1 );
	help->insertItem( tr("About &Qt"), this, SLOT( slotAboutQtMenuItemActivated() ));
    help->insertSeparator();
    help->insertItem( tr("What's &This"), this, SLOT(whatsThis()), SHIFT+Key_F1 );
	
	updateHistoryMenu();
}

void KCHMMainWindow::slotBackwardMenuItemActivated()
{
	m_viewWindow->navigateBack();
}

void KCHMMainWindow::slotForwardMenuItemActivated()
{
	m_viewWindow->navigateForward();
}

void KCHMMainWindow::slotHomeMenuItemActivated()
{
	openPage (m_chmFile->HomePage(), true);
}

void KCHMMainWindow::addBookmark( )
{
	emit m_bookmarkWindow->onAddBookmarkPressed ();
}

void KCHMMainWindow::setTextEncoding( const KCHMTextEncoding::text_encoding_t * enc )
{
	m_chmFile->setCurrentEncoding (enc);
	m_searchToolbar->setChosenEncodingInMenu (enc);
	
	// Because updateView() will call view->invalidate(), which clears the view->getOpenedPage(),
	// we have to make a copy of it.
	QString url = m_viewWindow->getOpenedPage();
	updateView();
	
	m_viewWindow->openUrl ( url );
}

void KCHMMainWindow::closeChmFile( )
{
	// Prepare the settings
	if ( appConfig.m_HistoryStoreExtra )
	{
		m_currentSettings->m_activeencodinglcid = m_chmFile->getCurrentEncoding()->winlcid;
		m_currentSettings->m_activetab = m_tabWidget->currentPageIndex( );
		m_currentSettings->m_chosenzoom = m_viewWindow->getZoomFactor();
			
		if ( m_searchWindow )
			m_searchWindow->saveSettings (m_currentSettings->m_searchhistory);
				
		m_bookmarkWindow->saveSettings (m_currentSettings->m_bookmarks);

		m_currentSettings->m_activepage = m_viewWindow->getOpenedPage();
		m_currentSettings->m_scrollbarposition = m_viewWindow->getScrollbarPosition();

		m_currentSettings->saveSettings( );
	}
	
	appConfig.save();
}


void KCHMMainWindow::closeEvent ( QCloseEvent * e )
{
	// Save the settings if we have something opened
	if ( m_chmFile )
		closeChmFile( );

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
/*
	search_query = args->getOption ("search");
	search_index = args->getOption ("sindex");
	search_bookmark = args->getOption ("sbook");
*/
	if ( args->count() > 0 )
		filename = args->arg(0);
#else
	// argv[0] in Qt is still a program name
	for ( int i = 1; i < qApp->argc(); i++  )
	{
		if ( !strcmp (qApp->argv()[i], "--autotestmode") )
			do_autotest = true;
		else if ( !strcmp (qApp->argv()[i], "--search") )
			search_query = qApp->argv()[++i];
		else if ( !strcmp (qApp->argv()[i], "--sindex") )
			search_index = qApp->argv()[++i];
		else if ( !strcmp (qApp->argv()[i], "--sbook") )
			search_bookmark = qApp->argv()[++i];
		else if ( !strcmp (qApp->argv()[i], "-h") || !strcmp (qApp->argv()[i], "--help") )
		{
			fprintf (stderr, "Usage: %s [chmfile]\n", qApp->argv()[0]);
			exit (1);
		}
		else
			filename = qApp->argv()[i];
	}
#endif

	if ( !filename.isEmpty() )
	{
		if ( !loadChmFile( QString::fromLocal8Bit( filename )) )
			return false;
/*
		if ( search_index.isEmpty() )
			
			
			search_query = args->getOption ("search");
		
		search_bookmark = args->getOption ("sbook");
*/
		
		if ( do_autotest )
		{
#if defined (ENABLE_AUTOTEST_SUPPORT)
			if ( !filename.isEmpty() )
				qFatal ("Could not use Auto Test mode without a chm file!");

			m_autoteststate = STATE_INITIAL;
			runAutoTest();
#else
			qFatal ("Auto Test mode support is not compiled in.");
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */
		}
		return true;
	}
	
	return false;
}

void KCHMMainWindow::slotHistoryAvailabilityChanged( bool enable_backward, bool enable_forward )
{
	m_toolbarIconBackward->setEnabled (enable_backward);
	m_toolbarIconForward->setEnabled (enable_forward);
}

void KCHMMainWindow::createViewWindow( )
{
	if ( m_viewWindow )
		delete m_viewWindow;

#if defined (USE_KDE)
	if ( !appConfig.m_kdeUseQTextBrowser )
		m_viewWindow = new KCHMViewWindow_KHTMLPart ( m_windowSplitter );
	else
#endif
		m_viewWindow = new KCHMViewWindow_QTextBrowser ( m_windowSplitter );
	
	// Handle clicking on link in browser window
	connect( m_viewWindow->getQObject(), SIGNAL( signalLinkClicked (const QString &, bool &) ), this, SLOT( slotLinkClicked(const QString &, bool &) ) );

	// Handle backward/forward buttons state change
	connect( m_viewWindow->getQObject(), SIGNAL( signalHistoryAvailabilityChanged (bool, bool) ), this, SLOT( slotHistoryAvailabilityChanged (bool, bool) ) );
}

void KCHMMainWindow::slotBrowserSelectAll( )
{
	m_viewWindow->clipSelectAll();
}

void KCHMMainWindow::slotBrowserCopy( )
{
	m_viewWindow->clipCopy();
}

void KCHMMainWindow::slotChangeSettingsMenuItemActivated()
{
	KCHMSetupDialog dlg ( this );
	
	// Set up the parameters
	dlg.m_radioOnBeginOpenDialog->setChecked ( !appConfig.m_LoadLatestFileOnStartup );
	dlg.m_radioOnBeginOpenLast->setChecked ( appConfig.m_LoadLatestFileOnStartup );
	dlg.m_historySize->setValue ( appConfig.m_HistorySize );
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
	
	if ( dlg.exec() == QDialog::Accepted )
	{
		appConfig.m_LoadLatestFileOnStartup = dlg.m_radioOnBeginOpenLast->isChecked();
		appConfig.m_HistorySize = dlg.m_historySize->value();
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
		
		appConfig.m_kdeEnableJS = dlg.m_enableJS->isChecked();
		appConfig.m_kdeEnablePlugins = dlg.m_enablePlugins->isChecked();
		appConfig.m_kdeEnableJava = dlg.m_enableJava->isChecked();
		appConfig.m_kdeEnableRefresh = dlg.m_enableRefresh->isChecked();
		appConfig.m_kdeUseQTextBrowser = dlg.m_radioUseQtextBrowser->isChecked();
		
		appConfig.m_advExternalEditorPath = dlg.m_advExternalProgramName->text();
		appConfig.m_advUseInternalEditor = dlg.m_advViewSourceExternal->isChecked();
		appConfig.m_advUseInternalEditor = dlg.m_advViewSourceInternal->isChecked();
		
		appConfig.save();
	}
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

void KCHMMainWindow::slotHistoryMenuItemActivated( int item )
{
	if ( item < 0 || item >= (signed) appConfig.m_History.size() )
		qFatal ("KCHMMainWindow::slotHistoryMenuItemActivated: bad history menu id %d", item);
	
	QString filename = appConfig.m_History[item];
	
	// remove it, so it will be added again at the history top, and will not shitf anything.
//	appConfig.m_History.remove ( appConfig.m_History.begin() + item);
	loadChmFile ( filename );
}

void KCHMMainWindow::updateHistoryMenu()
{
	m_menuHistory->clear ();
	
	for ( int i = appConfig.m_History.size() - 1; i >= 0; i-- )
		m_menuHistory->insertItem( appConfig.m_History[i], i );
}

void KCHMMainWindow::slotActivateContentTab( )
{
	if ( m_tabContextPage != -1 ) 
		m_tabWidget->setCurrentPage( m_tabContextPage );
}

void KCHMMainWindow::slotActivateIndexTab( )
{
	if ( m_tabIndexPage != -1 ) 
		m_tabWidget->setCurrentPage( m_tabIndexPage );
}

void KCHMMainWindow::slotActivateSearchTab( )
{
	if ( m_tabSearchPage != -1 ) 
		m_tabWidget->setCurrentPage( m_tabSearchPage );
}

void KCHMMainWindow::slotActivateBookmarkTab( )
{
	m_tabWidget->setCurrentPage( m_tabBookmarkPage );
}

void KCHMMainWindow::showOrHideContextWindow( int tabindex )
{
	if ( tabindex == -1 )
	{
		if ( m_contentsWindow )
		{
			m_tabWidget->removePage (m_contentsWindow);
			delete m_contentsWindow;
			m_contentsWindow = 0;
		}
	}
	else
	{
		if ( !m_contentsWindow )
		{
			m_contentsWindow = new KQListView (m_tabWidget);
			m_contentsWindow->addColumn( "Contents" );
			m_contentsWindow->setSorting(-1);
			m_contentsWindow->setFocus();
			m_contentsWindow->setRootIsDecorated(true);
			m_contentsWindow->header()->hide();
			m_contentsWindow->setShowToolTips(true);

			// Handle clicking on m_contentsWindow element
			connect( m_contentsWindow, SIGNAL( clicked( QListViewItem* ) ), this, SLOT( onTreeClicked( QListViewItem* ) ) );
			
			m_tabWidget->insertTab (m_contentsWindow, tr("Contents"), tabindex);
		}
	}
}

void KCHMMainWindow::showOrHideIndexWindow( int tabindex )
{
	// Test whether to show/invalidate the index window
	if ( tabindex == -1 )
	{
		if ( m_indexWindow )
		{
			m_tabWidget->removePage (m_indexWindow);
			delete m_indexWindow;
			m_indexWindow = 0;
		}
	}
	else
	{
		if ( !m_indexWindow )
		{
			m_indexWindow = new KCHMIndexWindow (m_tabWidget);
			m_tabWidget->insertTab (m_indexWindow, tr("Index"), tabindex);
		}
		else
			m_indexWindow->invalidate();
	}
}

void KCHMMainWindow::showOrHideSearchWindow( int tabindex )
{
	if ( tabindex == -1 )
	{
		if ( m_searchWindow )
		{
			m_tabWidget->removePage (m_searchWindow);
			delete m_searchWindow;
			m_searchWindow = 0;
		}
	}
	else
	{
		if ( !m_searchWindow )
		{
			m_searchWindow = new KCHMSearchWindow (m_tabWidget);
			m_tabWidget->insertTab (m_searchWindow, tr("Search"), tabindex);
		}
		else
			m_searchWindow->invalidate();
	}
}


#if defined (ENABLE_AUTOTEST_SUPPORT)
void KCHMMainWindow::runAutoTest()
{
	KCHMMainTreeViewItem * item;

	switch (m_autoteststate)
	{
	case STATE_INITIAL:
		if ( m_contentsWindow )
		{
			m_autotestlistiterator = QListViewItemIterator (m_contentsWindow);
			m_autoteststate = STATE_CONTENTS_OPENNEXTPAGE;
		}
		else
			m_autoteststate = STATE_OPEN_INDEX;
		
		QTimer::singleShot (500, this, SLOT(runAutoTest()) );
		break; // allow to finish the initialization sequence
		
	case STATE_CONTENTS_OPENNEXTPAGE:
		if ( (item = (KCHMMainTreeViewItem *) m_autotestlistiterator.current()) != 0 )
		{
			openPage (item->getUrl(), true);
			m_autotestlistiterator++;
		}
		else
			m_autoteststate = STATE_OPEN_INDEX;
		
		QTimer::singleShot (50, this, SLOT(runAutoTest()) );
		break;

	case STATE_OPEN_INDEX:
		if ( m_indexWindow )
			m_tabWidget->setCurrentPage (1);
		
		m_autoteststate = STATE_SHUTDOWN;
		QTimer::singleShot (500, this, SLOT(runAutoTest()) );
		break;

	case STATE_SHUTDOWN:
		qDebug ("Autotest succeed");
		qApp->quit();
		break;
		
	default:
		break;
	}
}
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */
