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


/*
 * Abstract class, represents specific search engine
 */

class KCHMExternalSearchBackend
{
public:
	typedef QMap<QString, QString> search_results_t;

    KCHMExternalSearchBackend();
    virtual ~KCHMExternalSearchBackend();

	virtual bool	loadIndexFile (const QString& filename) = 0;
	virtual bool	saveIndexFile (const QString& filename) = 0;

	virtual void	invalidate() = 0;

	virtual void	indexInit () = 0;
	virtual bool	indexAddFile (const QString& filename) = 0;
	virtual void	indexDone () = 0;

	virtual bool	doSearch (const QString& query, search_results_t& results) = 0;
};


class KCHMExternalSearch
{
public:
    KCHMExternalSearch (KCHMExternalSearchBackend * backend);
    ~KCHMExternalSearch();

	bool	hasSearchIndex ();
	bool	createSearchIndex ();
	bool	doSearch (const QString& query, KCHMExternalSearchBackend::search_results_t& results);

private:
	KCHMExternalSearchBackend 	*	m_searchBackend;
	bool							m_abortButtonPressed;
};

#endif
