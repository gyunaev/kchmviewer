/**************************************************************************
 *  Kchmviewer - a CHM file viewer with broad language support            *
 *  Copyright (C) 2004-2010 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  This program is free software: you can redistribute it and/or modify  *
 *  it under the terms of the GNU General Public License as published by  *
 *  the Free Software Foundation, either version 3 of the License, or     *
 *  (at your option) any later version.                                   *
 *																	      *
 *  This program is distributed in the hope that it will be useful,       *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *  GNU General Public License for more details.                          *
 *                                                                        *
 *  You should have received a copy of the GNU General Public License     *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 **************************************************************************/

#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <QProcess>
#include <QDesktopServices>

#include "kde-qt.h"

#include "libchmfile.h"
#include "libchmfileimpl.h"
#include "libchmurlfactory.h"

#include "mainwindow.h"
#include "config.h"
#include "treeviewitem.h"
#include "settings.h"
#include "viewwindow.h"
#include "viewwindowmgr.h"
#include "keyeventfilter.h"
#include "dialog_setup.h"
#include "recentfiles.h"
#include "navigationpanel.h"
#include "version.h"


// Our implemenation of RecentFiles which uses different storage
class ConfigRecentFiles : public RecentFiles
{
	public:
		ConfigRecentFiles( QMenu * menu, QAction * before, int maxfiles = 5 )
			: RecentFiles( menu, before, maxfiles )
		{
		}

	protected:
		QStringList loadRecentFiles()
		{
			return appConfig.m_recentFilesList;
		}

		void saveRecentFiles( const QStringList& files )
		{
			appConfig.m_recentFilesList = files;
		}
};


MainWindow::MainWindow()
	: QMainWindow ( 0 ), Ui::MainWindow()
{
	const unsigned int WND_X_SIZE = 700;
	const unsigned int WND_Y_SIZE = 500;
	const unsigned int SPLT_X_SIZE = 200;

	// Delete the pointer when the window is closed
	setAttribute( Qt::WA_DeleteOnClose );
	
	// UIC stuff
	setupUi( this );
	
	// Set up layout direction
	if ( appConfig.m_advLayoutDirectionRL )
		qApp->setLayoutDirection( Qt::RightToLeft );
	else
		qApp->setLayoutDirection( Qt::LeftToRight );
	
	m_chmFile = 0;
	
	m_currentSettings = new Settings();
		
	// Create the view window, which is a central widget
	m_viewWindowMgr = new ViewWindowMgr( this );
	setCentralWidget( m_viewWindowMgr );
	
	// Create a navigation panel
	m_navPanel = new NavigationPanel( this );

	// Add navigation dock
	m_navPanel->setAllowedAreas( Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea );
	addDockWidget( Qt::LeftDockWidgetArea, m_navPanel, Qt::Vertical );

	// Set up things
	setupActions();
	updateToolbars();
	setupLangEncodingMenu();

	// Resize main window and dock
	resize( WND_X_SIZE, WND_Y_SIZE );	
	m_navPanel->resize( SPLT_X_SIZE, m_navPanel->height() );

#if defined (ENABLE_AUTOTEST_SUPPORT)
	m_autoteststate = STATE_OFF;
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */

	statusBar()->show();
	qApp->setWindowIcon( QPixmap(":/images/application.png") );

	m_aboutDlgMenuText = i18n( "<html><b>%1 version %2</b><br><br>"
			"Copyright (C) George Yunaev, 2004-2008<br>"
			"<a href=\"mailto:gyunaev@ulduzsoft.com\">gyunaev@ulduzsoft.com</a><br>"
			"<a href=\"http://www.kchmviewer.net\">http://www.kchmviewer.net</a><br><br>"
			"Licensed under GNU GPL license.</html>" )
			. arg(APP_NAME) . arg(APP_VERSION);

	m_recentFiles = new ConfigRecentFiles( menu_File, file_exit_action, appConfig.m_numOfRecentFiles );
	connect( m_recentFiles, SIGNAL(openRecentFile(QString)), this, SLOT(actionOpenRecentFile(QString)) );

	QTimer::singleShot( 0, this, SLOT( firstShow()) );
}


MainWindow::~MainWindow()
{
	// Temporary files cleanup
	while ( !m_tempFileKeeper.isEmpty() )
		delete m_tempFileKeeper.takeFirst();
}



bool MainWindow::loadFile ( const QString &loadFileName, bool call_open_page )
{
	QString fileName = loadFileName;

	// Strip file:// prefix if any
	if ( fileName.startsWith( "file://" ) )
		fileName.remove( 0, 7 );
			
	LCHMFile * new_chmfile = new LCHMFile();
	
	if ( new_chmfile->loadFile( fileName ) )
	{
		// The new file is opened, so we can close the old one
		if ( m_chmFile )
		{
			closeFile( );
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
		m_chmFilename = qd.absolutePath();
		
		// Qt's 'dirname' does not work well
		QFileInfo qf ( m_chmFilename );
		appConfig.m_lastOpenedDir = qf.dir().path();
		m_chmFileBasename = qf.fileName();

		// Apply settings to the navigation dock
		m_navPanel->updateTabs( m_chmFile );

		// and to navigation buttons
		nav_actionPreviousPage->setEnabled( m_chmFile->hasTableOfContents() );
		nav_actionNextPageToc->setEnabled( m_chmFile->hasTableOfContents() );

		navSetBackEnabled( false );
		navSetForwardEnabled( false );

		m_viewWindowMgr->invalidate();
		refreshCurrentBrowser();

		if ( m_currentSettings->loadSettings (fileName) )
		{
			const LCHMTextEncoding * encoding = 
					m_chmFile->impl()->lookupByQtCodec(  m_currentSettings->m_activeEncoding );

			if ( encoding )
				setTextEncoding( encoding );

			m_navPanel->applySettings( m_currentSettings );
			
			if ( call_open_page )
			{
				m_viewWindowMgr->restoreSettings( m_currentSettings->m_viewwindows );
				m_viewWindowMgr->setCurrentPage( m_currentSettings->m_activetabwindow );
				
				if ( m_chmFile->hasTableOfContents() )
					actionLocateInContentsTab();
			}
			
			// Restore the main window size
			resize( m_currentSettings->m_window_size_x, m_currentSettings->m_window_size_y );
			m_navPanel->resize( m_currentSettings->m_window_size_splitter, m_navPanel->height() );
		}
		else
		{
			m_navPanel->setActive( NavigationPanel::TAB_CONTENTS );
			setTextEncoding( m_chmFile->currentEncoding() );
			
			if ( call_open_page )
				openPage( m_chmFile->homeUrl() );
		}

		m_recentFiles->setCurrentFile( m_chmFilename );
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
		
		statusBar()->showMessage( 
				i18n("Could not load file %1").arg(fileName),
				2000 );
		delete new_chmfile;	
		return false;
	}
}



void MainWindow::refreshCurrentBrowser( )
{
	QString title = m_chmFile->title();
	
	if ( title.isEmpty() )
		title = APP_NAME;
	// KDE adds application name automatically, so we don't need it here	
#if !defined (USE_KDE)
	else
		title = (QString) APP_NAME + " - " + title;
#endif	
	
	setWindowTitle( title );
	
	currentBrowser()->invalidate();
	
	m_navPanel->refresh();
}



void MainWindow::activateLink ( const QString & link, bool& follow_link )
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


bool MainWindow::openPage( const QString & srcurl, unsigned int flags )
{
	QString otherlink, otherfile, url = srcurl;
	
	if ( url == "/" )
		url = m_chmFile->homeUrl();

	if ( LCHMUrlFactory::isRemoteURL (url, otherlink) )
	{
		switch ( appConfig.m_onExternalLinkClick )
		{
		case Config::ACTION_DONT_OPEN:
			break;

		case Config::ACTION_ASK_USER:
	   		if ( QMessageBox::question(this,
				 i18n("%1 - remote link clicked - %2") . arg(APP_NAME) . arg(otherlink),
				 i18n("A remote link %1 will start the external program to open it.\n\nDo you want to continue?").arg( url ),
				 i18n("&Yes"), i18n("&No"),
				 QString::null, 0, 1 ) )
					return false;
				
			// no break! should continue to open.

		case Config::ACTION_ALWAYS_OPEN:
#if defined (USE_KDE)
			new KRun ( url, 0 );
#else
			QDesktopServices::openUrl( url );
#endif
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

	if ( LCHMUrlFactory::isNewChmURL (url, otherfile, otherlink) )
	{
		// If new filename has relative path, convert it to absolute.
		QFileInfo finfo( otherfile );
		
		if ( !finfo.isAbsolute() )
		{
			QFileInfo chmfinfo( m_chmFilename );
			otherfile = chmfinfo.absolutePath() + QDir::separator() + otherfile;
		}
		
		if ( otherfile != m_chmFilename )
		{
			if ( QMessageBox::question( this,
				i18n( "%1 - link to a new CHM file clicked"). arg(APP_NAME),
				i18n( "You have clicked a link, which leads to a new CHM file %1.\nThe current file will be closed.\n\nDo you want to continue?").arg( otherfile ),
				i18n( "&Yes" ), i18n( "&No" ),
				QString::null, 0, 1 ) )
					return false;
	
			// Because chm file always contain relative link, and current filename is not changed,
			// we need to form a new path
			QStringList event_args;
			event_args.push_back( otherfile );
			event_args.push_back( otherlink ); // url
			
			qApp->postEvent( this, new UserEvent( "loadAndOpen", event_args ) );
			return false;
		}
		else
			url = otherlink;
	}
	
	ViewWindow * vwnd = currentBrowser();
	if ( flags & OPF_NEW_TAB )
		vwnd = m_viewWindowMgr->addNewTab( !(flags & OPF_BACKGROUND) );
	
	// Store current page and position to add it to history if we change it
	int hist_scrollpos = currentBrowser()->getScrollbarPosition();
	QString hist_url = currentBrowser()->getOpenedPage();
	
	if ( vwnd->openUrl (url) )
	{
		// Open all the tree items to show current item (if needed)
		if ( (flags & OPF_CONTENT_TREE) != 0 )
			m_navPanel->findUrlInContents( vwnd->getOpenedPage() );
		
		if ( flags & OPF_ADD2HISTORY )
			currentBrowser()->addNavigationHistory( hist_url, hist_scrollpos );
	}
	
	return true;
}


void MainWindow::firstShow()
{
	if ( !parseCmdLineArgs( ) )
	{
		if ( appConfig.m_LoadLatestFileOnStartup && !m_recentFiles->latestFile().isEmpty() )
		{
			if ( loadFile( m_recentFiles->latestFile() ) )
				return;
		}
		
		emit actionOpenFile();
	}
}


void MainWindow::setTextEncoding( const LCHMTextEncoding * encoding )
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

void MainWindow::closeFile( )
{
	// Prepare the settings
	if ( appConfig.m_HistoryStoreExtra )
	{
		m_currentSettings->m_activeEncoding = m_chmFile->currentEncoding()->qtcodec;
		m_currentSettings->m_activetabwindow = m_viewWindowMgr->currentPageIndex( );
		
		m_currentSettings->m_window_size_x = width();
		m_currentSettings->m_window_size_y = height();
		m_currentSettings->m_window_size_splitter = m_navPanel->width();

		m_navPanel->getSettings( m_currentSettings );

		m_viewWindowMgr->saveSettings( m_currentSettings->m_viewwindows );

		m_currentSettings->saveSettings( );
	}
	
	appConfig.save();
}


void MainWindow::closeEvent ( QCloseEvent * e )
{
	// Save the settings if we have something opened
	if ( m_chmFile )
	{
		closeFile( );
		delete m_chmFile;
		m_chmFile = 0;
	}

	QMainWindow::closeEvent ( e );
}

bool MainWindow::parseCmdLineArgs( )
{
	QString filename = QString::null, search_query = QString::null;
	QString search_index = QString::null, search_bookmark = QString::null, search_toc = QString::null;
	bool do_autotest = false;

#if defined (USE_KDE)
	KCmdLineArgs *args = KCmdLineArgs::parsedArgs();

	if ( args->isSet("autotestmode") || args->isSet("shortautotestmode") )
		do_autotest = true;

	search_query = args->getOption ("search");
	search_index = args->getOption ("sindex");
	search_toc = args->getOption ("stoc");
	
	if ( args->count() > 0 )
		filename = args->arg(0);
#else
	// argv[0] in Qt is still a program name
	for ( int i = 1; i < qApp->argc(); i++  )
	{
		if ( !strcmp (qApp->argv()[i], "-h") || !strcmp (qApp->argv()[i], "--help") )
		{
			fprintf (stderr, "Usage: %s [options] [chmfile]\n"
					"    The following options supported:\n"
					"  --search <query> specifies the search query to search, and activate the first entry if found\n"
					"  --sindex <word>  specifies the word to find in index, and activate if found\n"
					"  --stoc <word(s)> specifies the word(s) to find in TOC, and activate if found. Wildcards allowed\n",
	 				qApp->argv()[0] );
			
			exit (1);
		}
#if defined (ENABLE_AUTOTEST_SUPPORT)
		else if ( !strcmp (qApp->argv()[i], "--autotestmode") || !strcmp (qApp->argv()[i], "--shortautotestmode") )
			do_autotest = true;
#endif		
		else if ( !strcmp (qApp->argv()[i], "--search") )
			search_query = qApp->argv()[++i];
		else if ( !strcmp (qApp->argv()[i], "--sindex") )
			search_index = qApp->argv()[++i];
		else if ( !strcmp (qApp->argv()[i], "--stoc") )
			search_toc = qApp->argv()[++i];
		else
			filename = QString::fromLocal8Bit( qApp->argv()[i] );
	}
#endif

	if ( !filename.isEmpty() )
	{
		if ( !loadFile( filename ) )
			return true; // skip the latest checks, but do not exit from the program

		if ( !search_index.isEmpty() )
		{
			QStringList event_args;
			event_args.push_back( search_index );
			qApp->postEvent( this, new UserEvent( "findInIndex", event_args ) );
		}
		
		if ( !search_query.isEmpty() )	
		{
			QStringList event_args;
			event_args.push_back( search_query );
			qApp->postEvent( this, new UserEvent( "searchQuery", event_args ) );
		}
		
		if ( !search_toc.isEmpty() )	
		{
			QStringList event_args;
			event_args.push_back( search_toc );
			qApp->postEvent( this, new UserEvent( "findInToc", event_args ) );
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

ViewWindow * MainWindow::currentBrowser( ) const
{
	return m_viewWindowMgr->current();
}

void MainWindow::onOpenPageInNewTab( )
{
	openPage( currentBrowser()->getNewTabLink(), OPF_NEW_TAB | OPF_CONTENT_TREE );
}

void MainWindow::onOpenPageInNewBackgroundTab( )
{
	openPage( currentBrowser()->getNewTabLink(), OPF_NEW_TAB | OPF_BACKGROUND );
}

void MainWindow::browserChanged( ViewWindow * newbrowser )
{
	m_navPanel->findUrlInContents( newbrowser->getOpenedPage() );
}

bool MainWindow::event( QEvent * e )
{
	if ( e->type() == QEvent::User )
		return handleUserEvent( (UserEvent*) e );
	
	return QMainWindow::event( e );
}

bool MainWindow::handleUserEvent( const UserEvent * event )
{
	if ( event->m_action == "loadAndOpen" )
	{
		if ( event->m_args.size() != 1 && event->m_args.size() != 2 )
			qFatal("handleUserEvent: event loadAndOpen must receive 1 or 2 args");
		
		QString chmfile = event->m_args[0];
		QString openurl = event->m_args.size() > 1 ? event->m_args[1] : "/";
				
		return loadFile( chmfile, false ) && openPage( openurl );
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
			qFatal( "handleUserEvent: event findInIndex must receive 1 arg" );
		
		if ( !hasIndex() )
			return false;

		actionSwitchToIndexTab();
		m_navPanel->findInIndex( event->m_args[0] );
		return true;
	}
	else if ( event->m_action == "findInToc" )
	{
		if ( event->m_args.size() != 1 )
			qFatal( "handleUserEvent: event findInToc must receive 1 arg" );
		
		if ( !hasTableOfContents() )
			return false;

		actionSwitchToContentTab();
		m_navPanel->findTextInContents( event->m_args[0] );
		return true;
	}
	else if ( event->m_action == "searchQuery" )
	{
		if ( event->m_args.size() != 1 )
			qFatal( "handleUserEvent: event searchQuery must receive 1 arg" );
		
		actionSwitchToSearchTab();
		m_navPanel->executeQueryInSearch( event->m_args[0] );
		return true;
	}
	else
		qWarning( "Unknown user event received: %s", qPrintable( event->m_action ) );
	
	return false;
}


#if defined (ENABLE_AUTOTEST_SUPPORT)
void MainWindow::runAutoTest()
{
	switch (m_autoteststate)
	{
	case STATE_INITIAL:
		m_autoteststate = STATE_OPEN_INDEX;
		
		QTimer::singleShot (500, this, SLOT(runAutoTest()) );
		break; // allow to finish the initialization sequence
		
	case STATE_OPEN_INDEX:
		if ( hasIndex() )
			m_navPanel->setActive( NavigationPanel::TAB_INDEX );
		
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


void MainWindow::showInStatusBar(const QString & text)
{
	statusBar()->showMessage( text, 2000 );
}

void MainWindow::actionNavigateBack()
{
	currentBrowser()->navigateBack();
}

void MainWindow::actionNavigateForward()
{
	currentBrowser()->navigateForward();
}

void MainWindow::actionNavigateHome()
{
	currentBrowser()->navigateHome();
}

void MainWindow::actionOpenFile()
{
#if defined (USE_KDE)
	QString fn = KFileDialog::getOpenFileName( appConfig.m_lastOpenedDir, i18n("*.chm|Compressed Help Manual (*.chm)"), this);
#else
	QString fn = QFileDialog::getOpenFileName( this, 
	                                           i18n( "Open a chm file"), 
	                                           appConfig.m_lastOpenedDir, 
	                                           i18n("Compressed Help Manual (*.chm)"),
	                                           0,
	                                           QFileDialog::DontResolveSymlinks );
#endif

	if ( !fn.isEmpty() )
		loadFile( fn );
	else
	{
		if ( !m_chmFile )
			exit (1);
			
		statusBar()->showMessage( i18n("Loading aborted"), 2000 );
	}
}

void MainWindow::actionPrint()
{
	currentBrowser()->printCurrentPage();
}

void MainWindow::actionEditCopy()
{
	currentBrowser()->clipCopy();
}

void MainWindow::actionEditSelectAll()
{
	currentBrowser()->clipSelectAll();
}

void MainWindow::actionFindInPage()
{
	m_viewWindowMgr->onActivateFind();
}

void MainWindow::actionChangeSettings()
{
	DialogSetup dlg ( this );
	
	dlg.exec();
}


void MainWindow::actionExtractCHM()
{
	QStringList files;
	
#if defined (USE_KDE)
	QString outdir = KFileDialog::getExistingDirectory (
		KUrl(),
		this,
		i18n("Choose a directory to store CHM content") );
#else
	QString outdir = QFileDialog::getExistingDirectory (
		this,
		i18n("Choose a directory to store CHM content"),
		QString::null,
		QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks );
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
			QStringList dirs = files[i].split( '/' );

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
							qWarning( "Could not create subdir %s\n", qPrintable( dir.path() ) );
					}
				}
			}
			
			QString filename = outdir + dirlist.join( "/" ) + "/" + dirs[i];
			QFile wf( filename );
			if ( !wf.open( QIODevice::WriteOnly ) )
			{
				qWarning( "Could not write file %s\n", qPrintable( filename ) );
				continue;
			}
			
			wf. write( buf );
			wf.close();
		}
		else
			qWarning( "Could not get file %s\n", qPrintable( files[i] ) );
	}
	
	progress.setValue( files.size() );
}

void MainWindow::actionFontSizeIncrease()
{
	currentBrowser()->addZoomFactor( 1 );
}

void MainWindow::actionFontSizeDecrease()
{
	currentBrowser()->addZoomFactor( -1 );
}

void MainWindow::actionViewHTMLsource()
{
	QString text;

	if ( !m_chmFile->getFileContentAsString( &text, currentBrowser()->getOpenedPage() ) || text.isEmpty() )
		return;

	if ( appConfig.m_advUseInternalEditor )
	{
		QTextEdit * editor = new QTextEdit ( 0 );
		editor->setPlainText( text );
		editor->setWindowTitle( QString("HTML source of %1") .arg( currentBrowser()->getOpenedPage() ));
		editor->resize( 800, 600 );
		editor->show();
	}
	else
	{
		QTemporaryFile * tf = new QTemporaryFile();
		m_tempFileKeeper.append( tf );

		if ( !tf->open() )
		{
			qWarning("Cannot open created QTemporaryFile: something is wrong with your system");
			return;
		}
		
		tf->write( text.toUtf8() );
		tf->seek( 0 );
		
		// Run the external editor
		QStringList arguments;
		arguments.push_back( tf->fileName() );
		
		if ( !QProcess::startDetached( appConfig.m_advExternalEditorPath, arguments, "." ) )
		{
			QMessageBox::warning( 0,
								  "Cannot start external editor", 
		  						  tr("Cannot start external editor %1.\nMake sure the path is absolute!") .arg( appConfig.m_advExternalEditorPath ) );
			delete m_tempFileKeeper.takeLast();
		}
	}
}

void MainWindow::actionToggleFullScreen()
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

void MainWindow::actionShowHideNavigator( bool toggle )
{
	if ( toggle )
		m_navPanel->show();
	else
		m_navPanel->hide();
}

void MainWindow::navigatorVisibilityChanged( bool visible )
{
	view_Show_navigator_window->setChecked( visible );
}

void MainWindow::actionLocateInContentsTab()
{
	if ( m_navPanel->findUrlInContents( currentBrowser()->getOpenedPage() ) )
		m_navPanel->setActive( NavigationPanel::TAB_CONTENTS );
	else
		statusBar()->showMessage( i18n( "Could not locate opened topic in content window"), 2000 );
}


void MainWindow::actionAboutApp()
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

void MainWindow::actionAboutQt()
{
	QMessageBox::aboutQt( this, APP_NAME);
}

void MainWindow::actionSwitchToContentTab()
{
	m_navPanel->setActive( NavigationPanel::TAB_CONTENTS );
}

void MainWindow::actionSwitchToIndexTab()
{
	m_navPanel->setActive( NavigationPanel::TAB_INDEX );
}

void MainWindow::actionSwitchToSearchTab()
{
	m_navPanel->setActive( NavigationPanel::TAB_SEARCH );
}

void MainWindow::actionSwitchToBookmarkTab()
{
	m_navPanel->setActive( NavigationPanel::TAB_BOOKMARK );
}


void MainWindow::setupActions()
{
	// Connect actions to slots
	connect( file_Open_action, 
			 SIGNAL( triggered() ),
			 this,
			 SLOT( actionOpenFile() ) );
			
	connect( file_Print_action, 
			 SIGNAL( triggered() ),
			 this,
			 SLOT( actionPrint() ) );
	
	connect( edit_Copy_action,
			 SIGNAL( triggered() ),
			 this,
			 SLOT( actionEditCopy() ) );
	
	connect( edit_SelectAll_action,
			 SIGNAL( triggered() ),
			 this,
			 SLOT( actionEditSelectAll() ) );

	connect( edit_FindAction,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionFindInPage() ) );
	
	connect( file_ExtractCHMAction,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionExtractCHM() ) );

	connect( settings_SettingsAction,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionChangeSettings() ) );
	
	connect( bookmark_AddAction,
			 SIGNAL( triggered() ),
			 m_navPanel,
			 SLOT( addBookmark()) );
	
	connect( view_Increase_font_size_action,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionFontSizeIncrease() ) );
	
	connect( view_Decrease_font_size_action,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionFontSizeDecrease() ) );
	
	connect( view_View_HTML_source_action,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionViewHTMLsource() ) );
	
	connect( view_Toggle_fullscreen_action,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionToggleFullScreen() ) );
	
	connect( view_Show_navigator_window,
			 SIGNAL( triggered(bool) ),
			 this,
			 SLOT( actionShowHideNavigator(bool) ) );
	
	connect( view_Locate_in_contents_action,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionLocateInContentsTab() ) );
	
	connect( nav_action_Back,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionNavigateBack() ) );
	
	connect( nav_actionForward,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionNavigateForward() ) );
	
	connect( nav_actionHome,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( actionNavigateHome() ) );
	
	connect( nav_actionPreviousPage,
			 SIGNAL( triggered() ),
			 m_navPanel,
			 SLOT( showPrevInToc() ) );
	
	connect( nav_actionNextPageToc,
			 SIGNAL( triggered() ),
			 m_navPanel,
			 SLOT( showNextInToc() ) );
	
	// m_viewWindowMgr fills and maintains 'Window' menu
	m_viewWindowMgr->createMenu( this, menu_Windows, action_Close_window );

	m_navPanel->setBookmarkMenu( menu_Bookmarks );
	
	// Close Window goes directly to the window manager
	connect( action_Close_window,
			 SIGNAL( triggered() ),
			 m_viewWindowMgr,
			 SLOT( onCloseCurrentWindow() ) );
	
	connect( file_exit_action, 
			 SIGNAL( triggered() ),
	         qApp,
	         SLOT( closeAllWindows() ) );
	
	connect( m_navPanel,
			 SIGNAL(visibilityChanged(bool)),
			 this,
			 SLOT( navigatorVisibilityChanged(bool) ) );

	QMenu * help = new QMenu( i18n( "&Help"), this );
	help->addAction( i18n( "&About"), this, SLOT( actionAboutApp() ), QKeySequence( "F1" ) );
	help->addAction( i18n( "About &Qt"), this, SLOT( actionAboutQt() ) );
	help->addSeparator();
	
	// "What's this" action
	QAction * whatsthis = QWhatsThis::createAction( this );
	help->addAction( whatsthis );
	viewToolbar->addAction( whatsthis );
		
	menuBar()->addMenu( help );
	
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

	// Find (/) global shortcut
	(void) new QShortcut( QKeySequence( i18n("/") ),
	                      m_viewWindowMgr,
	                      SLOT( onActivateFind() ),
	                      SLOT( onActivateFind() ),
	                      Qt::ApplicationShortcut );
	
	// Find next global shortcut
	(void) new QShortcut( QKeySequence( i18n("F3") ),
	                      m_viewWindowMgr,
	                      SLOT( onFindNext() ),
	                      SLOT( onFindNext() ),
	                      Qt::ApplicationShortcut );

	// Open next page in TOC global shortcut
	(void) new QShortcut( QKeySequence( i18n("Ctrl+Right") ),
						  m_navPanel,
						  SLOT( showNextInToc() ),
						  SLOT( showNextInToc() ),
	                      Qt::ApplicationShortcut );
	
	// Open next page in TOC global shortcut
	(void) new QShortcut( QKeySequence( i18n("Ctrl+Left") ),
						  m_navPanel,
						  SLOT( showPrevInToc() ),
						  SLOT( showPrevInToc() ),
	                      Qt::ApplicationShortcut );
	
	// Context menu
	m_contextMenu = new QMenu( this );
	
	m_contextMenu->addAction ( "&Open this link in a new tab",
	                          this, 
	                          SLOT( onOpenPageInNewTab() ), 
	                          QKeySequence( "Shift+Enter" ) );
	
	m_contextMenu->addAction ( "&Open this link in a new background tab", 
	                          this, 
	                          SLOT( onOpenPageInNewBackgroundTab() ),
	                          QKeySequence( "Ctrl+Enter" ) );
}

void MainWindow::updateToolbars()
{
	// Toolbars configuration
	Qt::ToolButtonStyle buttonstyle = Qt::ToolButtonIconOnly;
	QSize iconsize = QSize( 32, 32 );

	switch ( appConfig.m_toolbarMode )
	{
		case Config::TOOLBAR_SMALLICONS:
			iconsize = QSize( 16, 16 );
			break;

		case Config::TOOLBAR_LARGEICONS:
			break;

		case Config::TOOLBAR_LARGEICONSTEXT:
			buttonstyle = Qt::ToolButtonTextUnderIcon;
			break;

		case Config::TOOLBAR_TEXTONLY:
			buttonstyle = Qt::ToolButtonTextOnly;
			break;
	}

	mainToolbar->setIconSize( iconsize );
	mainToolbar->setToolButtonStyle( buttonstyle );
	navToolbar->setIconSize( iconsize );
	navToolbar->setToolButtonStyle( buttonstyle );
	viewToolbar->setIconSize( iconsize );
	viewToolbar->setToolButtonStyle( buttonstyle );
}


void MainWindow::navSetBackEnabled(bool enabled)
{
	nav_action_Back->setEnabled( enabled );
}

void MainWindow::navSetForwardEnabled(bool enabled)
{
	nav_actionForward->setEnabled( enabled );
}

void MainWindow::actionOpenRecentFile( const QString& file )
{
	loadFile( file );
}

void MainWindow::setupLangEncodingMenu()
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


void MainWindow::actionEncodingChanged( QAction * action )
{
	const LCHMTextEncoding * enc = (const LCHMTextEncoding *) action->data().value< void* > ();
	setTextEncoding( enc );
}


QMenu * MainWindow::tabItemsContextMenu()
{
	return m_contextMenu;
}

void MainWindow::setupPopupMenu( QMenu * menu )
{
	menu->addAction( action_Close_window );
	menu->addSeparator();
	menu->addAction( nav_action_Back );
	menu->addAction( nav_actionForward );
	menu->addAction( nav_actionHome );
	menu->addSeparator();
	menu->addAction( nav_actionPreviousPage );
	menu->addAction( nav_actionNextPageToc );
	menu->addSeparator();
	menu->addAction( view_Increase_font_size_action );
	menu->addAction( view_Decrease_font_size_action );
	menu->addSeparator();
	menu->addAction( edit_Copy_action );
	menu->addAction( edit_FindAction );
}

bool MainWindow::hasTableOfContents() const
{
	return m_chmFile && m_chmFile->hasTableOfContents();
}

bool MainWindow::hasIndex() const
{
	return m_chmFile && m_chmFile->hasIndexTable();
}
