/***************************************************************************
 *   Copyright (C) 2005 by Georgy Yunaev                                   *
 *   tim@krasnogorsk.ru                                                    *
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

#include "kde-qt.h"

#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "kchmindexwindow.h"
#include "kchmsearchwindow.h"
#include "kchmbookmarkwindow.h"
#include "kchmtreeviewitem.h"
#include "kchmsearchtoolbar.h"
#include "kchmsettings.h"

#include "iconstorage.h"
#include "froglogic_getopt.h"

#include "kchmviewwindow_qtextbrowser.h"


KCHMMainWindow::KCHMMainWindow()
    : KQMainWindow ( 0, "KCHMMainWindow", WDestructiveClose )
{
	const unsigned int WND_X_SIZE = 700;
	const unsigned int WND_Y_SIZE = 500;
	const unsigned int SPLT_X_SIZE = 200;
	
	m_FirstTimeShow = true;
	chmfile = 0;
	indexWindow = 0;

	m_currentSettings = new KCHMSettings;
		
	// Create the initial layout - a splitter with tab window in left, and text browser in right
	QSplitter * splitter = new QSplitter(this);
	m_tabWidget = new QTabWidget (splitter);
	
	contentsWindow = new KQListView (m_tabWidget, "contents", 0);
	contentsWindow->addColumn( "Contents" );
	contentsWindow->setSorting(-1);
	contentsWindow->setFocus();
	contentsWindow->setRootIsDecorated(true);
	contentsWindow->header()->hide();
	contentsWindow->setShowToolTips(true);

	bookmarkWindow = new KCHMBookmarkWindow (m_tabWidget);
	searchWindow = new KCHMSearchWindow (m_tabWidget);

	// Add the tabs
	m_tabWidget->addTab (contentsWindow, "Contents");
	m_tabWidget->addTab (searchWindow, "Search");
	m_tabWidget->addTab (bookmarkWindow, "Bookmarks");

	viewWindow = new KCHMViewWindow_QTextBrowser ( splitter );

	// Handle clicking on contentsWindow element
	connect( contentsWindow, SIGNAL( clicked( QListViewItem* ) ), this, SLOT( onTreeClicked( QListViewItem* ) ) );

	// Handle clicking on link in browser window
	connect( viewWindow->getQObject(), SIGNAL( signalLinkClicked (const QString &, bool &) ), this, SLOT( slotLinkClicked(const QString &, bool &) ) );

	// Handle backward/forward buttons state change
	connect( viewWindow->getQObject(), SIGNAL( signalHistoryAvailabilityChanged (bool, bool) ), this, SLOT( slotHistoryAvailabilityChanged (bool, bool) ) );

	setupToolbarsAndMenu();
		
	setCentralWidget( splitter );
	
	QValueList<int> sizes;
	sizes.push_back (SPLT_X_SIZE);
	sizes.push_back (WND_X_SIZE - SPLT_X_SIZE);
	splitter->setSizes (sizes);
	
	resize (WND_X_SIZE, WND_Y_SIZE);

#if defined (ENABLE_AUTOTEST_SUPPORT)
	m_autoteststate = STATE_OFF;
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */
}


KCHMMainWindow::~KCHMMainWindow()
{
}


void KCHMMainWindow::choose()
{
#if defined (USE_KDE)
    QString fn = KFileDialog::getOpenFileName( QString::null, "*.chm|Compressed Help Manual (*.chm)",
					       this);
#else
    QString fn = QFileDialog::getOpenFileName( QString::null, "Compressed Help Manual (*.chm)",
					       this);
#endif

    if ( !fn.isEmpty() )
		loadChmFile( fn );
    else
	{
		if ( !chmfile )
			exit (1);
			
		statusBar()->message( tr("Loading aborted"), 2000 );
	}
}


void KCHMMainWindow::loadChmFile ( const QString &fileName )
{
	CHMFile * new_chmfile = new CHMFile (fileName);
	
	if ( new_chmfile->IsOk() )
	{
		if ( chmfile )
		{
			CloseChmFile( );
			delete chmfile;
		}
	
		chmfile = new_chmfile;

		QDir qd;
		qd.setPath (fileName);
		m_chmFilename = qd.absPath();
		
		// Test whether to show/invalidate the index window
		if ( chmfile->IndexFile().isEmpty() )
		{
			if ( indexWindow )
			{
				m_tabWidget->removePage (indexWindow);
				delete indexWindow;
				indexWindow = 0;
			}
		}
		else
		{
			if ( !indexWindow )
			{
				indexWindow = new KCHMIndexWindow (m_tabWidget);
				m_tabWidget->insertTab (indexWindow, "Index", 1);
			}
			else
				indexWindow->invalidate();
		}

		searchWindow->invalidate();
		bookmarkWindow->invalidate();
		viewWindow->invalidate();
		updateView();

		if ( m_currentSettings->loadSettings (fileName) )
		{
			const KCHMTextEncoding::text_encoding_t * enc = KCHMTextEncoding::lookupByLCID (m_currentSettings->m_activeencodinglcid);
			
			m_tabWidget->setCurrentPage (m_currentSettings->m_activetab);
			
			if ( enc )
			{
				chmfile->setCurrentEncoding (enc);
				m_searchToolbar->setChosenEncodingInMenu (enc);
			}
			
			if ( searchWindow )
				searchWindow->restoreSettings (m_currentSettings->m_searchhistory);
				
			bookmarkWindow->restoreSettings (m_currentSettings->m_bookmarks);

			openPage (m_currentSettings->m_activepage, true);
			viewWindow->setScrollbarPosition(m_currentSettings->m_scrollbarposition);
			viewWindow->setZoomFactor(m_currentSettings->m_chosenzoom);
		}
		else
		{
			m_tabWidget->setCurrentPage (0);
			m_searchToolbar->setChosenEncodingInMenu (chmfile->getCurrentEncoding());
			openPage (chmfile->HomePage(), true);
		}

		m_searchToolbar->setEnabled (true);
	}
	else
	{
		if ( !chmfile )
		{
			QMessageBox mbox (tr("%1 - failed to load the chm file"), tr("Unable to load the chm file %2") . arg(APP_NAME) . arg(fileName), QMessageBox::Critical, QMessageBox::Ok, QMessageBox::NoButton, QMessageBox::NoButton);
			mbox.exec();
			exit (1);
		}
		
		statusBar()->message( tr("Could not load file %1").arg(fileName), 2000 );
		delete new_chmfile;	
	}
}


void KCHMMainWindow::print()
{
#if !defined (QT_NO_PRINTER) && !defined (USE_KDE)
    QPrinter printer( QPrinter::HighResolution );
    printer.setFullPage(TRUE);
	
	if ( printer.setup( this ) )
	{
		QPainter p( &printer );
		
		if( !p.isActive() ) // starting printing failed
			return;
		
		QPaintDeviceMetrics metrics(p.device());
		int dpiy = metrics.logicalDpiY();
		int margin = (int) ( (2/2.54)*dpiy ); // 2 cm margins
		QRect body( margin, margin, metrics.width() - 2*margin, metrics.height() - 2*margin );
		QSimpleRichText richText( viewWindow->text(),
								  QFont(),
								  viewWindow->context(),
								  viewWindow->styleSheet(),
								  viewWindow->mimeSourceFactory(),
								  body.height() );
		richText.setWidth( &p, body.width() );
		QRect view( body );
		
		int page = 1;
		
		do
		{
			richText.draw( &p, body.left(), body.top(), view, colorGroup() );
			view.moveBy( 0, body.height() );
			p.translate( 0 , -body.height() );
			p.drawText( view.right() - p.fontMetrics().width( QString::number(page) ),
						view.bottom() + p.fontMetrics().ascent() + 5, QString::number(page) );
			
			if ( view.top()  >= richText.height() )
				break;
			
			QString msg = tr ("Printing (page ") + QString::number( page ) + tr (")...");
			statusBar()->message( msg );
			
			printer.newPage();
			page++;
		}
		while (TRUE);
	
		statusBar()->message( tr("Printing completed"), 2000 );
	}
	else
		statusBar()->message( tr("Printing aborted"), 2000 );
#else
	QMessageBox::warning (this, tr("%1 - could not print") . arg(APP_NAME), "Could not print.\nYour Qt library has been compiled without printing support");
#endif
}

void KCHMMainWindow::about()
{
    QMessageBox::about( this, APP_NAME,
			tr("%1 version %2\n\nCopyright (C) Georgy Yunaev, tim@krasnogorsk.ru, 2005\n\n"
				"Licensed under GNU GPL license.") . arg(APP_NAME) . arg(APP_VERSION));
}


void KCHMMainWindow::aboutQt()
{
    QMessageBox::aboutQt( this, APP_NAME);
}

void KCHMMainWindow::updateView( )
{
	QString title = chmfile->Title();
	if ( !title )
		title = APP_NAME;
	else
		title = (QString) APP_NAME + " - " + title;

	setCaption (title);
	
	contentsWindow->clear();
	viewWindow->invalidate();
	
	chmfile->ParseAndFillTopicsTree(contentsWindow);
	contentsWindow->triggerUpdate();
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

bool KCHMMainWindow::openPage( const QString & url, bool set_in_tree )
{
	QString p1, p2;

	if ( viewWindow->isRemoteURL (url, p1) )
	{
   		if ( QMessageBox::question(this,
			tr ("%1 - remote link clicked - %2") . arg(APP_NAME) . arg(p1),
           	tr ("A remote link <a href=\"%1\"i>%2</a>\nwill start the external program to open it.\n\nDo you want to continue?").arg( url ).arg( url ),
           	tr("&Yes"), tr("&No"),
           	QString::null, 0, 1 ) )
       			return false;
		
		//FIXME: run the browser/mailer/etc.
		return false;
	}
		
	// Filter the URLs which do not need to be opened at all by Qt version
	if ( viewWindow->isJavascriptURL (url) )
	{
		QMessageBox::information(this, tr ("%1 - JavsScript link clicked") . arg(APP_NAME),
           	tr ("You have clicked a JavaScript link. Unfortunately, JavaScript links are not supported."));
		
		return false;
	}

	if ( viewWindow->isNewChmURL (url, p1, p2) )
	{
   		if ( QMessageBox::question(this,
			tr ("%1 - link to a new CHM file clicked") . arg(APP_NAME),
           	tr ("You have clicked a link, which leads to a new CHM file %1.\nThe current file will be closed.\n\nDo you want to continue?").arg( p1 ),
           	tr("&Yes"), tr("&No"),
           	QString::null, 0, 1 ) )
       			return false;
		
		//FIXME: open new CHM file
		return false;
	}
	
	if ( viewWindow->openUrl (url) )
	{
		// Open all the tree items to show current item (if needed)
		KCHMMainTreeViewItem * treeitem;
		if ( set_in_tree && (treeitem = chmfile->getTreeItem(viewWindow->getOpenedPage())) != 0 )
		{
			KCHMMainTreeViewItem * itemparent = treeitem;
			while ( (itemparent = (KCHMMainTreeViewItem*) itemparent->parent()) != 0 )
				itemparent->setOpen(true);
			
			contentsWindow->setCurrentItem (treeitem);
			contentsWindow->ensureItemVisible (treeitem);
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
		choose();
}

//FIXME: add whats'is to every menu
//FIXME: fix Chineze encoding issues
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
				SLOT(choose()), 
				toolbar);

    QPixmap iconFilePrint (*gIconStorage.getToolbarPixmap(KCHMIconStorage::print));
    QToolButton * filePrint	= new QToolButton (iconFilePrint,
				tr("Print File"),
				QString::null,
				this,
				SLOT(print()),
				toolbar);

    QToolBar * navtoolbar = new QToolBar(this);
	navtoolbar->setLabel( tr("Navigation") );
	
    QPixmap iconBackward (*gIconStorage.getToolbarPixmap(KCHMIconStorage::back));
    m_toolbarIconBackward	= new QToolButton (iconBackward,
				tr("Move backward in history"),
				QString::null,
				this,
				SLOT(backward()),
				navtoolbar);

    QPixmap iconForward (*gIconStorage.getToolbarPixmap(KCHMIconStorage::forward));
    m_toolbarIconForward	= new QToolButton (iconForward,
				tr("Move forward in history"),
				QString::null,
				this,
				SLOT(forward()),
				navtoolbar);

    QPixmap iconHome = (*gIconStorage.getToolbarPixmap(KCHMIconStorage::gohome));
    new QToolButton (iconHome,
				tr("Go to the home page"),
				QString::null,
				this,
				SLOT(gohome()),
				navtoolbar);

	// And helpers
    QWhatsThis::whatsThisButton( toolbar );
    
	QString fileOpenText = tr("Click this button to open a <em>chm file</em>.");
    QWhatsThis::add( fileOpen, fileOpenText );

    QString filePrintText = tr("Click this button to print the current page");
    QWhatsThis::add( filePrint, filePrintText );

	// Setup the menu
	QPopupMenu * file = new QPopupMenu( this );
	menuBar()->insertItem( tr("&File"), file );

    int id;
    id = file->insertItem ( iconFileOpen, tr("&Open..."), this, SLOT(choose()), CTRL+Key_O );
    file->setWhatsThis( id, fileOpenText );

    id = file->insertItem( iconFilePrint, tr("&Print..."), this, SLOT(print()), CTRL+Key_P );
    file->setWhatsThis( id, filePrintText );

    file->insertSeparator();

    file->insertItem( tr("&Quit"), qApp, SLOT( closeAllWindows() ), CTRL+Key_Q );

	QPopupMenu * menu_edit = new QPopupMenu( this );
	menuBar()->insertItem( tr("&Edit"), menu_edit );
#if defined (FIXME_KDE)
//    id = menu_edit->insertItem ( tr("&Copy"), viewWindow, SLOT(copy()), CTRL+Key_C );
//	id = menu_edit->insertItem ( tr("&Select all"), viewWindow, SLOT(selectAll()), CTRL+Key_A );
#endif
    menu_edit->insertSeparator();
	
	// KCHMSearchToolbar also adds 'view' menu
	m_searchToolbar = new KCHMSearchAndViewToolbar (this);
		
    QPopupMenu * help = new QPopupMenu( this );
    menuBar()->insertItem( tr("&Help"), help );

    help->insertItem( tr("&About"), this, SLOT(about()), Key_F1 );
    help->insertItem( tr("About &Qt"), this, SLOT(aboutQt()) );
    help->insertSeparator();
    help->insertItem( tr("What's &This"), this, SLOT(whatsThis()), SHIFT+Key_F1 );
}

void KCHMMainWindow::backward( )
{
	viewWindow->navigateBack();
}

void KCHMMainWindow::forward( )
{
	viewWindow->navigateForward();
}

void KCHMMainWindow::gohome( )
{
	openPage (chmfile->HomePage(), true);
}

void KCHMMainWindow::addBookmark( )
{
	emit bookmarkWindow->onAddBookmarkPressed ();
}

void KCHMMainWindow::setTextEncoding( const KCHMTextEncoding::text_encoding_t * enc )
{
	chmfile->setCurrentEncoding (enc);
	m_searchToolbar->setChosenEncodingInMenu (enc);
	updateView();
}

void KCHMMainWindow::CloseChmFile( )
{
	// Prepare the settings
	m_currentSettings->m_activeencodinglcid = chmfile->getCurrentEncoding()->winlcid;
	m_currentSettings->m_activetab = m_tabWidget->currentPageIndex( );
	m_currentSettings->m_chosenzoom = viewWindow->getZoomFactor();
			
	if ( searchWindow )
		searchWindow->saveSettings (m_currentSettings->m_searchhistory);
				
	bookmarkWindow->saveSettings (m_currentSettings->m_bookmarks);

	m_currentSettings->m_activepage = viewWindow->getOpenedPage();
	m_currentSettings->m_scrollbarposition = viewWindow->getScrollbarPosition();

	m_currentSettings->saveSettings( );
}


void KCHMMainWindow::closeEvent ( QCloseEvent * e )
{
	// Save the settings if we have something opened
	if ( chmfile )
		CloseChmFile( );

	QMainWindow::closeEvent ( e );
}

bool KCHMMainWindow::parseCmdLineArgs( )
{
	QString filename;

	GetOpt opts(qApp->argc(), qApp->argv());
	
#if defined (ENABLE_AUTOTEST_SUPPORT)
	bool do_autotest = false;
	opts.addSwitch("autotestmode", &do_autotest);
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */

	opts.addOptionalArgument ("file", &filename);
	
	if ( opts.parse() && !filename.isEmpty() )
	{
		loadChmFile( filename );
		
#if defined (ENABLE_AUTOTEST_SUPPORT)
		if ( do_autotest )
		{
			m_autoteststate = STATE_INITIAL;
			runAutoTest();
		}
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */

		return true;
	}
	
	return false;
}

void KCHMMainWindow::slotHistoryAvailabilityChanged( bool enable_backward, bool enable_forward )
{
	m_toolbarIconBackward->setEnabled (enable_backward);
	m_toolbarIconForward->setEnabled (enable_forward);
}

#if defined (ENABLE_AUTOTEST_SUPPORT)
void KCHMMainWindow::runAutoTest()
{
	KCHMMainTreeViewItem * item;

	switch (m_autoteststate)
	{
	case STATE_INITIAL:
		m_autotestlistiterator = QListViewItemIterator (contentsWindow);
		m_autoteststate = STATE_CONTENTS_OPENNEXTPAGE;
		//m_autoteststate = STATE_OPEN_INDEX;
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
		if ( indexWindow )
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
