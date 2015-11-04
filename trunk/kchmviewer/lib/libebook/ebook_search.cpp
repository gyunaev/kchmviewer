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

#include <QApplication>

#include "ebook.h"
#include "ebook_search.h"

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



EBookSearch::EBookSearch()
{
	m_Index = 0;
}


EBookSearch::~ EBookSearch()
{
	delete m_Index;
}


bool EBookSearch::loadIndex( QDataStream & stream )
{
	delete m_Index;

	m_Index = new QtAs::Index();
	return m_Index->readDict( stream );
}


bool EBookSearch::generateIndex( EBook * ebookFile, QDataStream & stream )
{
	QList< QUrl > documents;
	QList< QUrl > alldocuments;
	
	emit progressStep( 0, "Generating the list of documents" );
	processEvents();

	// Enumerate the documents
	if ( !ebookFile->enumerateFiles( alldocuments ) )
		return false;
			
	if ( m_Index )
		delete m_Index;

	m_Index = new QtAs::Index();
	connect( m_Index, SIGNAL( indexingProgress( int, const QString& ) ), this, SLOT( updateProgress( int, const QString& ) ) );
	
	// Process the list of files in CHM archive and keep only HTML document files from there
	for ( int i = 0; i < alldocuments.size(); i++ )
	{
		QString docpath = alldocuments[i].path();

		if ( docpath.endsWith( ".html", Qt::CaseInsensitive )
		|| docpath.endsWith( ".htm", Qt::CaseInsensitive )
		|| docpath.endsWith( ".xhtml", Qt::CaseInsensitive ) )
			documents.push_back( alldocuments[i] );
	}

    if ( !m_Index->makeIndex( documents, ebookFile ) )
	{
		delete m_Index;
		m_Index = 0;
		return false;
	}
	
	m_Index->writeDict( stream );
	m_keywordDocuments.clear();
	
	return true;
}


void EBookSearch::cancelIndexGeneration()
{
	m_Index->setLastWinClosed();
}


void EBookSearch::updateProgress(int value, const QString & stepName)
{
	emit progressStep( value, stepName );
}

void EBookSearch::processEvents()
{
	// Do it up to ten times; some events generate other events
	for ( int i = 0; i < 10; i++ )
		qApp->processEvents( QEventLoop::ExcludeUserInputEvents );
}

bool EBookSearch::searchQuery(const QString & query, QList< QUrl > * results, EBook *ebookFile, unsigned int limit)
{
	// We should have index
	if ( !m_Index )
		return false;
	
	// Characters which split the words. We need to make them separate tokens
	QString splitChars = m_Index->getCharsSplit();
	
	// Characters which are part of the word. We should keep them apart.
	QString partOfWordChars = m_Index->getCharsPartOfWord();
	
	// Variables to store current state
	SearchDataKeeper keeper;	
	QString term;

	for ( int i = 0; i < query.length(); i++ )
	{
		QChar ch = query[i].toLower();
		
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
		if ( ch.isLetterOrNumber() || partOfWordChars.indexOf( ch ) != -1 )
		{
			term.append( ch );
			continue;
		}
		
		// If it is a split char, add this term and split char as separate term
		if ( splitChars.indexOf( ch ) != -1 )
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
		return false;
	
	QList< QUrl > foundDocs = m_Index->query( keeper.terms, keeper.phrases, keeper.phrasewords, ebookFile );
	
	for ( QList< QUrl >::iterator it = foundDocs.begin(); it != foundDocs.end() && limit > 0; ++it, limit-- )
		results->push_back( *it );

	return true;
}

bool EBookSearch::hasIndex() const
{
	return m_Index != 0;
}
