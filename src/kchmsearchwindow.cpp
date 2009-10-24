/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
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
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.         *
 ***************************************************************************/

#include <QHeaderView>

#include "libchmfile.h"

#include "kchmsearchwindow.h"
#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "kchmtreeviewitem.h"


class KCMSearchTreeViewItem : public QTreeWidgetItem
{
	public:
		KCMSearchTreeViewItem( QTreeWidget * tree, const QString& name, const QString& url )
			:	QTreeWidgetItem( tree ), m_name( name ), m_url( url ) {};
	
		QString		getUrl() const { return m_url; }
	
	protected:
		// Overriden members
	int columnCount () const	{ return 2; }
	
		// Overriden member
		QVariant data ( int column, int role ) const
		{
			switch( role )
			{
				// Item name
				case Qt::DisplayRole:
				case Qt::ToolTipRole:
				case Qt::WhatsThisRole:
				if ( column == 0 )
					return m_name;
				else
					return m_url;
			}
			
			return QVariant();
		}
	
	private:
		QString		m_name;		
		QString		m_url;
};



KCHMSearchWindow::KCHMSearchWindow( QWidget * parent )
	: QWidget( parent ), Ui::TabSearch()
{
	// UIC stuff
	setupUi( this );
	
	// Clickable Help label
	connect( lblHelp, 
	         SIGNAL( linkActivated( const QString & ) ), 
	         this, 
	         SLOT( onHelpClicked(const QString & ) ) );
	
	// Go Button
	connect( btnGo, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onReturnPressed() ) );

	// Pressing 'Return' in the combo box line edit
	connect( searchBox->lineEdit(), 
			 SIGNAL( returnPressed() ), 
			 this, 
			 SLOT( onReturnPressed() ) );
	
	// Clicking on tree element
	connect( tree, 
	         SIGNAL( itemDoubleClicked( QTreeWidgetItem *, int ) ), 
			 this, 
	         SLOT( onDoubleClicked( QTreeWidgetItem *, int ) ) );

	// Activate custom context menu, and connect it
	tree->setContextMenuPolicy( Qt::CustomContextMenu );
	connect( tree, 
			 SIGNAL( customContextMenuRequested ( const QPoint & ) ),
			 this, 
			 SLOT( onContextMenuRequested( const QPoint & ) ) );

	searchBox->setFocus();
	
	m_contextMenu = 0;
	m_genIndexProgress = 0;
	m_searchEngineInitDone = false;
	
	m_searchEngine = new LCHMSearchEngine();
	connect( m_searchEngine, SIGNAL( progressStep( int, const QString& ) ), this, SLOT( onProgressStep( int, const QString& ) ) );
}


void KCHMSearchWindow::invalidate( )
{
	tree->clear();
	searchBox->clear();
	searchBox->lineEdit()->clear();
	
	delete m_genIndexProgress;
	m_genIndexProgress = 0;
	
	m_searchEngineInitDone = false;
}


void KCHMSearchWindow::onReturnPressed( )
{
	QStringList results;
	QString text = searchBox->lineEdit()->text();
	
	if ( text.isEmpty() )
		return;
	
	tree->clear();
	
	if ( searchQuery( text, &results ) )
	{
		if ( !results.empty() )
		{
			for ( int i = 0; i < results.size(); i++ )
			{
				new KCMSearchTreeViewItem ( tree,
				                            ::mainWindow->chmFile()->getTopicByUrl( results[i] ),
										 	results[i] );
			}

			::mainWindow->showInStatusBar( i18n( "Search returned %1 result(s)" ) . arg(results.size()) );
		}
		else
			::mainWindow->showInStatusBar( i18n( "Search returned no results") );
	}
	else
		::mainWindow->showInStatusBar( i18n( "Search failed") );
}


void KCHMSearchWindow::onDoubleClicked( QTreeWidgetItem * item, int )
{
	if ( !item )
		return;
	
	KCMSearchTreeViewItem * treeitem = (KCMSearchTreeViewItem *) item;
	::mainWindow->openPage( treeitem->getUrl(), KCHMMainWindow::OPF_ADD2HISTORY );
}


void KCHMSearchWindow::restoreSettings( const KCHMSettings::search_saved_settings_t & settings )
{
	for ( int i = 0; i < settings.size(); i++ )
		searchBox->addItem (settings[i]);
}


void KCHMSearchWindow::saveSettings( KCHMSettings::search_saved_settings_t & settings )
{
	settings.clear();

	for ( int i = 0; i < searchBox->count(); i++ )
		settings.push_back( searchBox->itemText(i) );
}


void KCHMSearchWindow::onHelpClicked( const QString & )
{
	QWhatsThis::showText ( mapToGlobal( lblHelp->pos() ),
		i18n( "<html><p>The improved search engine allows you to search for a word, symbol or phrase, which is set of words and symbols included in quotes. Only the documents which include all the terms speficide in th search query are shown; no prefixes needed.<p>Unlike MS CHM internal search index, my improved search engine indexes everything, including special symbols. Therefore it is possible to search (and find!) for something like <i>$q = new ChmFile();</i>. This search also fully supports Unicode, which means that you can search in non-English documents.<p>If you want to search for a quote symbol, use quotation mark instead. The engine treats a quote and a quotation mark as the same symbol, which allows to use them in phrases.</html>") );
}


bool KCHMSearchWindow::initSearchEngine( )
{
	KCHMShowWaitCursor waitcursor;
	
	QString indexfile = ::mainWindow->currentSettings()->searchIndexFile();
	
	// First try to read the index if exists
	QFile file( indexfile );
	
	if ( file.open( QIODevice::ReadOnly ) )
	{
		QDataStream stream( &file );
		
		::mainWindow->statusBar()->showMessage( i18n( "Reading dictionary..." ) );
		qApp->processEvents( QEventLoop::ExcludeUserInputEvents );
		
		if ( m_searchEngine->loadIndex( stream ) )
		{
			m_searchEngineInitDone = true;
			return true;
		}
	}
	
	// So the index cannot be read or does not exist. Create a new one.
	
	// Show the user what we gonna do
	m_genIndexProgress = new QProgressDialog( this );
	m_genIndexProgress->setWindowTitle( i18n( "Generating search index..." ) );
	m_genIndexProgress->setLabelText( i18n( "Generating search index..." ) );
	m_genIndexProgress->setMaximum( 100 );
	m_genIndexProgress->reset();
	m_genIndexProgress->show();
	
	::mainWindow->statusBar()->showMessage( tr( "Generating search index..." ) );
	
	// Show 'em
	qApp->processEvents( QEventLoop::ExcludeUserInputEvents );
		
	// Since we gonna save it, reopen the file
	file.close();
	
	if ( !file.open( QIODevice::WriteOnly ) )
	{
		QMessageBox::critical( 0, "Cannot save index", tr("The index cannot be saved into file %1") .arg( file.fileName() ) );
		return false;
	}
	
	// Run the generation
	QDataStream stream( &file );
	
	m_searchEngine->generateIndex( ::mainWindow->chmFile(), stream );
	
	delete m_genIndexProgress;
	m_genIndexProgress = 0;
	
	if ( m_searchEngine->hasIndex() )
	{
		m_searchEngineInitDone = true;
		return true;
	}
	
	m_searchEngineInitDone = false;
	return false;
}


void KCHMSearchWindow::execSearchQueryInGui( const QString & query )
{
	searchBox->lineEdit()->setText( query );
	onReturnPressed();
}


bool KCHMSearchWindow::searchQuery( const QString & query, QStringList * results )
{
	if ( !m_searchEngineInitDone )
	{
		if ( !initSearchEngine() )
			return false;
	}
	
	if ( !m_searchEngine->hasIndex() )
	{
		QMessageBox::information ( this, "No index present", "The index is not present" );
		return false;
	}
		
	if ( query.isEmpty() )
		return false;

	KCHMShowWaitCursor waitcursor;
	bool result;
	
	result = m_searchEngine->searchQuery( query, results, ::mainWindow->chmFile() );
	return result;
}


void KCHMSearchWindow::onContextMenuRequested( const QPoint & point )
{
	KCMSearchTreeViewItem * treeitem = (KCMSearchTreeViewItem *) tree->itemAt( point );
	
	if( treeitem )
	{
		::mainWindow->currentBrowser()->setTabKeeper( treeitem->getUrl() );
		::mainWindow->tabItemsContextMenu()->popup( tree->viewport()->mapToGlobal( point ) );
	}
}


void KCHMSearchWindow::onProgressStep(int value, const QString & stepName)
{
	if ( m_genIndexProgress )
	{
		m_genIndexProgress->setLabelText( stepName );
		m_genIndexProgress->setValue( value );
	}
}
