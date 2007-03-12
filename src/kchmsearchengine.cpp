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

#include <qapplication.h>

#include "kchmmainwindow.h"
#include "kchmsearchengine.h"
#include "kchmconfig.h"
#include "kchmsettings.h"
#include "libchmurlfactory.h"

#include "kchmsearchengine_impl.h"

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
		
		m_progressDlg->setCaption( tr( "Generating search index..." ) );
		m_progressDlg->setLabelText( tr( "Generating search index..." ) );
		m_progressDlg->setTotalSteps( 100 );
		m_progressDlg->reset();
		m_progressDlg->show();
		processEvents();
		
		if ( !::mainWindow->chmFile()->enumerateFiles( &alldocuments ) )
		{
			delete m_progressDlg;
			m_progressDlg = 0;
			return false;
		}
		
		// Process the list keeping only HTML documents there
		for ( unsigned int i = 0; i < alldocuments.size(); i++ )
			if ( alldocuments[i].endsWith( ".html", false ) || alldocuments[i].endsWith( ".htm", false ) )
				documents.push_back( LCHMUrlFactory::makeURLabsoluteIfNeeded( alldocuments[i] ) );

		m_Index->setDocList( documents );

		if ( m_Index->makeIndex() != -1 )
		{
			m_Index->writeDict();
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
	if ( progress <= 100 )
		m_progressDlg->setProgress( progress );
	
	processEvents();
}

// Helper class to simplity state management and data keeping
class SearchDataKeeper
{
	public:
		SearchDataKeeper() { m_inPhrase = false; }
				
		void beginPhrase()
		{
			phrase_terms.clear();
			m_inPhrase = true;
		}
		
		void endPhrase()
		{
			m_inPhrase = false;
			phrasewords += phrase_terms;
			phrases.push_back( phrase_terms.join(" ") );
		}
		
		bool isInPhrase() const { return m_inPhrase; }
		
		void addTerm( const QString& term )
		{
			if ( !term.isEmpty() )
			{
				terms.push_back( term );
				
				if ( m_inPhrase )
					phrase_terms.push_back( term );
			}
		}
		
		// Should contain all the search terms present in query, includind those from phrases. One element - one term .
		QStringList terms;
	
		// Should contain phrases present in query without quotes. One element - one phrase.
		QStringList phrases;
	
		// Should contain all the terms present in all the phrases (but not outside).
		QStringList phrasewords;

	private:		
		bool		m_inPhrase;
		QStringList phrase_terms;
};


bool KCHMSearchEngine::searchQuery( const QString & query, QStringList * results, unsigned int limit )
{
	// Characters which split the words. We need to make them separate tokens
	QString splitChars = m_Index->getCharsSplit();
	
	// Characters which are part of the word. We should keep them apart.
	QString partOfWordChars = m_Index->getCharsPartOfWord();
	
	SearchDataKeeper keeper;
	
	// State machine variables
	QString term;

	for ( unsigned int i = 0; i < query.length(); i++ )
	{
		QChar ch = query[i].lower();
		
		// a quote either begins or ends the phrase
		if ( ch == '"' )
		{
			keeper.addTerm( term );
			
			if ( keeper.isInPhrase() )
				keeper.endPhrase();
			else
				keeper.beginPhrase();

			continue;
		}
		
		// If new char does not stop the word, add ot and continue
		if ( ch.isLetterOrNumber() || partOfWordChars.find( ch ) != -1 )
		{
			term.append( ch );
			continue;
		}
		
		// If it is a split char, add this term and split char as separate term
		if ( splitChars.find( ch ) != -1 )
		{
			// Add existing term if present
			keeper.addTerm( term );
			
			// Change the term variable, so it will be added when we exit this block
			term = ch;
		}

		// Just add the word; it is most likely a space or terminated by tokenizer.
		keeper.addTerm( term );
		term = QString::null;			
	}
	
	keeper.addTerm( term );
	
	if ( keeper.isInPhrase() )
	{
		QMessageBox::warning( 0, i18n( "Search" ), i18n( "A closing quote character is missing." ) );
		return false;
	}
	
	KCHMShowWaitCursor waitcursor;
	QStringList foundDocs = m_Index->query( keeper.terms, keeper.phrases, keeper.phrasewords );
	
	for ( QStringList::iterator it = foundDocs.begin(); it != foundDocs.end() && limit > 0; ++it, limit-- )
		results->push_back( *it );

	return true;
}
