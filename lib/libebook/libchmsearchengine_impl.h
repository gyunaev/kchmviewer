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

#ifndef LCHMSEARCHENGINE_IMPL_H
#define LCHMSEARCHENGINE_IMPL_H

#include "libchmfile.h"


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



namespace QtAs { class Index; };


class LCHMSearchEngineImpl
{
	public:
		LCHMSearchEngineImpl();
		~LCHMSearchEngineImpl();
		void	processEvents();
		
	public:
		QStringList 				m_keywordDocuments;
		QtAs::Index 			*	m_Index;
};


#endif
