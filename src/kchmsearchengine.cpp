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

#include <qapplication.h>

#include "kchmmainwindow.h"
#include "kchmsearchengine.h"
#include "kchmconfig.h"
#include "kchmsettings.h"
#include "libchmurlfactory.h"

#include "qassistant_index.h"

#include "kchmsearchengine.moc"



KCHMSearchEngine::KCHMSearchEngine()
{
	m_Index = 0;
	m_progressDlg = 0;
}


KCHMSearchEngine::~KCHMSearchEngine()
{
	delete m_Index;
	delete m_progressDlg;
}

void KCHMSearchEngine::processEvents( )
{
	qApp->eventLoop()->processEvents( QEventLoop::ExcludeUserInput );
}


void KCHMSearchEngine::cancelButtonPressed( )
{
	m_Index->setLastWinClosed();
}


bool KCHMSearchEngine::loadOrGenerateIndex( )
{
	if ( m_Index )
		return true;

	QString settingspath = ::mainWindow->currentSettings()->getSettingsFilename();
	QString indexfiledict = settingspath + ".indexdb-dict";
	QString indexfiledoc = settingspath + ".indexdb-doc";
	QString indexfile = settingspath + ".indexdb";
	QStringList documents;
	
	m_Index = new QtAs::Index( documents, appConfig.m_datapath );
	m_Index->setDictionaryFile( indexfiledict );
	m_Index->setDocListFile( indexfiledoc );

	m_progressDlg = new QProgressDialog( 0 );
	connect( m_progressDlg, SIGNAL( canceled() ), this, SLOT( cancelButtonPressed() ) );
	
	connect( m_Index, SIGNAL( indexingProgress( int ) ),  this, SLOT( setIndexingProgress( int ) ) );
	KCHMShowWaitCursor waitcursor;
		
	QFile f( indexfiledict );
	if ( !f.exists() )
	{
		::mainWindow->statusBar()->message( tr( "Generating search index..." ) );
		
		// Get the list of files in CHM archive
		QStringList alldocuments;
		
		if ( !::mainWindow->chmFile()->enumerateFiles( &alldocuments ) )
			return false;
		
		// Process the list keeping only HTML documents there
		for ( unsigned int i = 0; i < alldocuments.size(); i++ )
			if ( alldocuments[i].endsWith( ".html", false ) || alldocuments[i].endsWith( ".htm", false ) )
				documents.push_back( LCHMUrlFactory::makeURLabsoluteIfNeeded( alldocuments[i] ) );

//		if ( !loadIndexFile( indexfile, &progressdlg ) )
//			return false;

		m_Index->setDocList( documents );

		m_progressDlg->setLabelText( tr( "Indexing files..." ) );
		m_progressDlg->setTotalSteps( 100 );
		m_progressDlg->reset();
		m_progressDlg->show();
		processEvents();
		
		if ( m_Index->makeIndex() != -1 )
		{
			m_Index->writeDict();
			m_progressDlg->setProgress( 100 );

			m_keywordDocuments.clear();
		}
		else
			return false;
	}
	else
	{
		::mainWindow->statusBar()->message( tr( "Reading dictionary..." ) );
		processEvents();
		
		m_Index->readDict();
	}
	
	::mainWindow->statusBar()->message( tr( "Done" ), 3000 );
	delete m_progressDlg;
	m_progressDlg = 0;
	
	return true;
}

void KCHMSearchEngine::setIndexingProgress( int progress )
{
	m_progressDlg->setProgress( progress );
	processEvents();
}

bool KCHMSearchEngine::searchQuery( const QString & query, QValueVector< LCHMSearchResult > * results, unsigned int limit )
{
	QString str = query;
	str = str.replace( "\'", "\"" );
	str = str.replace( "`", "\"" );
	QString buf = str;
	str = str.replace( "-", " " );
	str = str.replace( QRegExp( "\\s[\\S]?\\s" ), " " );
	QStringList terms = QStringList::split( " ", str );
	QStringList termSeq;
	QStringList seqWords;
	QStringList::iterator it = terms.begin();
	for ( ; it != terms.end(); ++it ) {
		(*it) = (*it).simplifyWhiteSpace();
		(*it) = (*it).lower();
		(*it) = (*it).replace( "\"", "" );
	}
	if ( str.contains( '\"' ) ) {
		if ( (str.contains( '\"' ))%2 == 0 ) {
			int beg = 0;
			int end = 0;
			QString s;
			beg = str.find( '\"', beg );
			while ( beg != -1 ) {
				beg++;
				end = str.find( '\"', beg );
				s = str.mid( beg, end - beg );
				s = s.lower();
				s = s.simplifyWhiteSpace();
				if ( s.contains( '*' ) )
				{
					QMessageBox::warning( 0, 
										  tr( "Full Text Search" ),
										  tr( "Using a wildcard within phrases is not allowed." ) );
					return false;
				}
				seqWords += QStringList::split( ' ', s );
				termSeq << s;
				beg = str.find( '\"', end + 1);
			}
		}
		else
		{
			QMessageBox::warning( 0,
								  tr( "Full Text Search" ),
								  tr( "The closing quotation mark is missing." ) );
			return false;
		}
	}
	
	KCHMShowWaitCursor waitcursor;
	QStringList foundDocs;
	
	foundDocs = m_Index->query( terms, termSeq, seqWords );
	
	for ( it = foundDocs.begin(); it != foundDocs.end() && limit > 0; ++it, limit-- )
	{
		LCHMSearchResult res;
		
		res.url = *it;
		res.title = ::mainWindow->chmFile()->getTopicByUrl( res.url );
		results->push_back( res );
	}

	terms.clear();
	bool isPhrase = FALSE;
	QString s = "";
	for ( int i = 0; i < (int)buf.length(); ++i ) {
		if ( buf[i] == '\"' ) {
			isPhrase = !isPhrase;
			s = s.simplifyWhiteSpace();
			if ( !s.isEmpty() )
				terms << s;
			s = "";
		} else if ( buf[i] == ' ' && !isPhrase ) {
			s = s.simplifyWhiteSpace();
			if ( !s.isEmpty() )
				terms << s;
			s = "";
		} else
			s += buf[i];
	}
	if ( !s.isEmpty() )
		terms << s;
	
	return true;
}


/*
bool KCHMSearchEngine::loadIndexFile( const QString& filename, QProgressDialog * progressdlg )
{
//	setCursor( waitCursor );

	progressdlg->setLabel( tr( "Prepare..." ) );
	progressdlg->setTotalSteps( 100 );
	progressdlg->reset();
	progressdlg->show();
	processEvents();	
	
	keywordDocuments.clear();
	
	QValueList<IndexKeyword> lst;
	QFile indexFile( filename );
	
	if ( !indexFile.open( IO_ReadOnly ) )
	{
		buildKeywordDB();
		processEvents();
		
		if( m_progressCancelled )
			return false;
		
		if ( !indexFile.open(IO_ReadOnly) )
		{
			qWarning( "Failed to load keyword index file, custom search/index disabled for this file.\n" );
			return false;
		}
	}

	QDataStream ds( &indexFile );
	Q_UINT32 fileAges;
	ds >> fileAges;
	if ( fileAges != getFileAges() )
	{
		indexFile.close();
		buildKeywordDB();
		
		if ( !indexFile.open( IO_ReadOnly ) )
		{
			qWarning( "Cannot open the index file %s", QFileInfo( indexFile ).absFilePath().ascii() );
			return false;
		}
		
		ds.setDevice( &indexFile );
		ds >> fileAges;
	}
	
	ds >> lst;
	indexFile.close();

	progressdlg->setProgress( progressdlg->totalSteps() );
	processEvents();

	listIndex->clear();
	HelpNavigationListItem *lastItem = 0;
	QString lastKeyword = QString::null;
	QValueList<IndexKeyword>::ConstIterator it = lst.begin();
	for ( ; it != lst.end(); ++it ) {
		if ( lastKeyword.lower() != (*it).keyword.lower() )
			lastItem = new HelpNavigationListItem( listIndex, (*it).keyword );
		lastItem->addLink( (*it).link );
		lastKeyword = (*it).keyword;

		QString lnk = (*it).link;
		int i = lnk.findRev('#');
		if ( i > -1 )
			lnk = lnk.left( i );
		if (!keywordDocuments.contains(lnk))
			keywordDocuments.append(lnk);
	}
	framePrepare->hide();
	showInitDoneMessage();
	setCursor( arrowCursor );
	editIndex->setEnabled(TRUE);
}
*/

