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
class KCHMSearchIndexBuilder;

class KCHMSearchEngineGeorge : public KCHMSearchBackend
{
public:
	class IndexEntry
	{
		public:
			IndexEntry() : page(0), word(0), offset(0) {};
			IndexEntry(unsigned short p, unsigned int w, unsigned int o) : page(p), word(w), offset(o) {};
			unsigned short	page;
			unsigned int	word;
			unsigned int	offset;
	};

public:
    KCHMSearchEngineGeorge();
    ~KCHMSearchEngineGeorge();

	virtual bool	loadIndexFile (const QString& filename);
	virtual bool	saveIndexFile (const QString& filename);

	virtual void	invalidate();
<<<<<<< kchmexternalsearchengine.h

	virtual bool	hasValidIndex ();
	virtual bool	canGenerateIndex()	{	return true; }

	virtual bool	doSearch (const QString& query, KCHMSearchEngine::searchResults& results, unsigned int limit);
=======

	virtual bool	hasValidIndex ();
	virtual bool	doSearch (const QString& query, KCHMSearchEngine::searchResults& results, unsigned int limit);
>>>>>>> 1.3

	/*
	 * Index creation routines.
	 * Before creating indexes, indexInit() is called once (allocate structures, etc)
	 * Then indexAddFile() is called several times. 
	 * And then indexDone() is called (do index creation cleanup).
	 */
	virtual void	indexInit ();
	virtual bool	indexAddFile (const QString& filename);
	virtual void	indexDone ();

private:
	QMap<int, QString>			m_pagesmap;
	QMap<QString, int>			m_wordsmap;
	QValueList< IndexEntry >	m_indexmap;

	KCHMSearchIndexBuilder	*	m_indexbuilder;
};

#endif
