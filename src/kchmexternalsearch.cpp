
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


KCHMExternalSearchBackend::KCHMExternalSearchBackend( )
{
}

KCHMExternalSearchBackend::~ KCHMExternalSearchBackend( )
{
}


KCHMExternalSearch::KCHMExternalSearch( KCHMExternalSearchBackend * backend )
{
	m_searchBackend = backend;
}

KCHMExternalSearch::~KCHMExternalSearch()
{
	delete m_searchBackend;
}

bool KCHMExternalSearch::createSearchIndex( )
{
	QValueVector<QString> files;
	QString data;

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
		QString label = "Parsing file " + files[i];
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

bool KCHMExternalSearch::doSearch( const QString & query, KCHMExternalSearchBackend::search_results_t & results )
{
	return false;
}

bool KCHMExternalSearch::hasSearchIndex( )
{
	return false;
}


