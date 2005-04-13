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

#include "kchmsearchenginechm.h"
#include "kchmmainwindow.h"
#include "xchmfile.h"

KCHMSearchEngineChm::KCHMSearchEngineChm()
 : KCHMSearchBackend()
{
}


KCHMSearchEngineChm::~KCHMSearchEngineChm()
{
}

bool KCHMSearchEngineChm::hasValidIndex()
{
}

bool KCHMSearchEngineChm::indexAddFile(const QString& filename)
{
}

bool KCHMSearchEngineChm::loadIndexFile(const QString& filename)
{
}

bool KCHMSearchEngineChm::saveIndexFile(const QString& filename)
{
}

void KCHMSearchEngineChm::indexDone()
{
}

void KCHMSearchEngineChm::indexInit()
{
}

void KCHMSearchEngineChm::invalidate()
{
}

bool KCHMSearchEngineChm::doSearch(const QString& word, KCHMSearchEngine::searchResults& results, unsigned int limit)
{
	KCHMSearchBackend::searchResults mresults;
	if ( !::mainWindow->getChmFile()->IndexSearch (word, true, false, mresults) )
		return false;

	for ( int i = 0; i < mresults.size(); i++ )
		printf ("RES: %s -> %s\n", mresults[i].url.ascii(), mresults[i].title.ascii());

	return false;
}
