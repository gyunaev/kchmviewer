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

#ifndef KCHMEXTERNALSEARCHENGINE_H
#define KCHMEXTERNALSEARCHENGINE_H

#include <qmap.h>
#include <qvaluevector.h>

#include "kchmexternalsearch.h"

/**
@author Georgy Yunaev
*/
class KCHMExternalSearchEngine : public KCHMExternalSearchBackend
{
public:
    KCHMExternalSearchEngine();
    ~KCHMExternalSearchEngine();

	virtual bool	loadIndexFile (const QString& filename);
	virtual bool	saveIndexFile (const QString& filename);

	virtual void	invalidate();
	virtual bool	parseFile (const QString& filename);
	virtual bool	doSearch (const QString& query, search_results_t& results);

private:
	
	class IndexEntry
	{
		public:
			IndexEntry() : page(0), word(0), offset(0) {};
			IndexEntry(unsigned short p, unsigned int w, unsigned int o) : page(p), word(w), offset(o) {};
			unsigned short	page;
			unsigned int	word;
			unsigned int	offset;
	};
	
	class SearchIndexBuild
	{
	public:
		SearchIndexBuild() { m_pageid = m_wordid = m_indexmapid = 1;}
		
		QMap< QString, int >		m_pagesmap;
		QMap< QString, int >		m_wordsmap;
		QValueList< IndexEntry >	m_indexmap;
		
		unsigned short	m_pageid;
		unsigned int	m_wordid;
		unsigned int	m_indexmapid;
	};

	// text allowed to be changed just to remove need for extra copying
	void	addPageToIndex (unsigned short pageurl, SearchIndexBuild& build, QString& text);	
	bool	addToIndex (const QString& url);

	QMap<int, QString>			m_pagesmap;
	QMap<int, QString>			m_wordsmap;
	QValueList< IndexEntry >	m_indexmap;

	SearchIndexBuild		*	m_buildindex;
};

#endif
