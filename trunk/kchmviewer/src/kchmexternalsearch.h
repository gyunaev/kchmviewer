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
#ifndef KCHMEXTERNALSEARCH_H
#define KCHMEXTERNALSEARCH_H

#include <qmap.h>
#include <qstring.h>


class KCHMSearchBackend;

//! Search engine manager
class KCHMSearchEngine
{
public:
	// map <url, name>
	typedef QMap<QString, QString> searchResults;

    KCHMSearchEngine ();
    ~KCHMSearchEngine ();

	void	setSearchBackend (KCHMSearchBackend * backend);
	bool	hasValidIndex ();
	bool	createIndex ();
	bool	doSearch (const QString& query, searchResults& results, unsigned int limit_results = 100);

private:
	KCHMSearchBackend 	*	m_searchBackend;
	bool					m_abortButtonPressed;
};


/*
 * Abstract class, represents specific search engine
 */
class KCHMSearchBackend
{
public:
    KCHMSearchBackend();
    virtual ~KCHMSearchBackend();

	virtual bool	loadIndexFile (const QString& filename) = 0;
	virtual bool	saveIndexFile (const QString& filename) = 0;

	virtual void	invalidate() = 0;

	virtual void	indexInit () = 0;
	virtual bool	indexAddFile (const QString& filename) = 0;
	virtual void	indexDone () = 0;

	virtual bool	hasValidIndex () = 0;
	virtual bool	doSearch (const QString& word, KCHMSearchEngine::searchResults& results, unsigned int limit) = 0;
};

#endif
