
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

#include <qapplication.h>
#include <qprogressdialog.h>

#include "xchmfile.h"
#include "kchmexternalsearch.h"
#include "kchmmainwindow.h"
#include "kchmexternalsearchengine.h"


KCHMSearchBackend::KCHMSearchBackend( )
{
}

KCHMSearchBackend::~ KCHMSearchBackend( )
{
}


KCHMSearchEngine::KCHMSearchEngine ( )
{
	m_searchBackend = 0;
}

KCHMSearchEngine::~KCHMSearchEngine()
{
	delete m_searchBackend;
}

bool KCHMSearchEngine::createIndex( )
{
	QValueVector<QString> files;
	QString data;

	Q_ASSERT (m_searchBackend);

	if ( !::mainWindow->getChmFile()->enumerateArchive (files) )
	{
		qWarning ("KCHMExternalSearch::createSearchIndex: failed to enumerate CHM file content.");
		return false;
	}

	m_searchBackend->indexInit();

	// Create a progress dialog
	QProgressDialog progress( "Building the index...", "Abort", files.size(),
                          ::mainWindow, "progress", TRUE );

	progress.setMinimumDuration (1000);

	for ( unsigned int i = 0; i < files.size(); i++ )
	{
    	progress.setProgress( i );
		QString label = "Parsing file " + QString::number(i) + " of " + QString::number(files.size());
    	progress.setLabelText (label);

    	qApp->processEvents();

    	if ( progress.wasCanceled() )
		{
			m_searchBackend->indexDone();
			m_searchBackend->invalidate();
			return false;
		}

		if ( !files[i].endsWith (".htm", FALSE) && !files[i].endsWith (".html", FALSE) )
			continue;

		m_searchBackend->indexAddFile(files[i]);
	}

	progress.setProgress( files.size() ); // hide the dialog
	m_searchBackend->indexDone();
	return true;
}

bool KCHMSearchEngine::doSearch (const QString& query, searchResults& results, unsigned int limit_results)
{
	Q_ASSERT (m_searchBackend);
	return false;
}

bool KCHMSearchEngine::hasValidIndex( )
{
	Q_ASSERT (m_searchBackend);
	return m_searchBackend->hasValidIndex();
}

void KCHMSearchEngine::setSearchBackend( KCHMSearchBackend * backend )
{
	m_searchBackend = backend;
}
