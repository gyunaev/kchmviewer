/***************************************************************************
 *   Copyright (C) 2005 by tim   *
 *   tim@krasnogorsk.ru   *
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
#ifndef KCHMSEARCHENGINECHM_H
#define KCHMSEARCHENGINECHM_H

#include <kchmexternalsearch.h>

/**
@author tim
*/
class KCHMSearchEngineChm : public KCHMSearchBackend
{
public:
    KCHMSearchEngineChm();

    ~KCHMSearchEngineChm();

    virtual bool doSearch(const QString& word, KCHMSearchEngine::searchResults& results, unsigned int limit);
    virtual bool hasValidIndex();
	virtual bool canGenerateIndex()	{	return false; }
    virtual bool indexAddFile(const QString& filename);
    virtual bool loadIndexFile(const QString& filename);
    virtual bool saveIndexFile(const QString& filename);
    virtual void indexDone();
    virtual void indexInit();
    virtual void invalidate();

private:
};

#endif
