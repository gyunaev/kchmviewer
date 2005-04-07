
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
			return false;

		if ( !files[i].endsWith (".htm", FALSE) && !files[i].endsWith (".html", FALSE) )
			continue;

		if ( ::mainWindow->getChmFile()->GetFileContentAsString (data, files[i]) == 0 )
		{
			qWarning ("KCHMExternalSearch::createSearchIndex: Could not get file content of %s", files[i].ascii());
			continue;
		}

//		if ( !m_searchBackend->parseFileContent (files[i], data) )
        	//return false;
	}

	progress.setProgress( files.size() ); // hide the dialog
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


