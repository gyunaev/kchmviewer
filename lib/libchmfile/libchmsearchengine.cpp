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

#include "libchmfile.h"
#include "libchmurlfactory.h"
#include "libchmsearchengine.h"
#include "libchmsearchengine_impl.h"
#include "libchmsearchengine_indexing.h"


LCHMSearchEngine::LCHMSearchEngine()
{
	impl = new LCHMSearchEngineImpl();
}


LCHMSearchEngine::~ LCHMSearchEngine()
{
	delete impl;
}


bool LCHMSearchEngine::loadIndex( QDataStream & stream )
{
	if ( impl->m_Index )
		delete impl->m_Index;

	impl->m_Index = new QtAs::Index();
	return impl->m_Index->readDict( stream );
}


bool LCHMSearchEngine::generateIndex( LCHMFile * chmFile, QDataStream & stream )
{
	QStringList documents;
	QStringList alldocuments;
	
	emit progressStep( 0, "Generating the list of documents" );
	impl->processEvents();

	// Enumerate the documents
	if ( !chmFile->enumerateFiles( &alldocuments ) )
		return false;
			
	if ( impl->m_Index )
		delete impl->m_Index;

	impl->m_Index = new QtAs::Index();
	connect( impl->m_Index, SIGNAL( indexingProgress( int, const QString& ) ), this, SLOT( updateProgress( int, const QString& ) ) );
	
	// Process the list of files in CHM archive and keep only HTML document files from there
	for ( int i = 0; i < alldocuments.size(); i++ )
		if ( alldocuments[i].endsWith( ".html", Qt::CaseInsensitive )
		|| alldocuments[i].endsWith( ".htm", Qt::CaseInsensitive ) )
			documents.push_back( LCHMUrlFactory::makeURLabsoluteIfNeeded( alldocuments[i] ) );

	if ( impl->m_Index->makeIndex( documents, chmFile ) == -1 )
	{
		delete impl->m_Index;
		impl->m_Index = 0;
		return false;
	}
	
	impl->m_Index->writeDict( stream );
	impl->m_keywordDocuments.clear();
	
	return true;
}


void LCHMSearchEngine::cancelIndexGeneration()
{
	impl->m_Index->setLastWinClosed();
}


void LCHMSearchEngine::updateProgress(int value, const QString & stepName)
{
	emit progressStep( value, stepName );
}


bool LCHMSearchEngine::searchQuery(const QString & query, QStringList * results, LCHMFile * chmFile, unsigned int limit)
{
	// We should have index
	if ( !impl->m_Index )
		return false;
	
	// Characters which split the words. We need to make them separate tokens
	QString splitChars = impl->m_Index->getCharsSplit();
	
	// Characters which are part of the word. We should keep them apart.
	QString partOfWordChars = impl->m_Index->getCharsPartOfWord();
	
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
	
	QStringList foundDocs = impl->m_Index->query( keeper.terms, keeper.phrases, keeper.phrasewords, chmFile );
	
	for ( QStringList::iterator it = foundDocs.begin(); it != foundDocs.end() && limit > 0; ++it, limit-- )
		results->push_back( *it );

	return true;
}

bool LCHMSearchEngine::hasIndex() const
{
	return impl->m_Index != 0;
}
