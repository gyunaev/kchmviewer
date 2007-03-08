/***************************************************************************
 *   Copyright (C) 2004-2005 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
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

#include "kde-qt.h"

#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "kchmkeyeventfilter.h"

#if defined (USE_KDE)
	#include <kaboutdata.h>
#endif

KCHMMainWindow * mainWindow;


int main( int argc, char ** argv )
{
#if defined (USE_KDE)
 	static KCmdLineOptions options[] =
 	{
    	{ "autotestmode", "Perform auto testing", 0 },
		{ "shortautotestmode", "Perform short auto testing", 0 },
		{ "+[chmfile]", "A CHM file to show", 0 },
/*		{ "search <query>", I18N_NOOP("'--search <query>' specifies the search query to search, and activate the first entry if found"), 0 },
		{ "sindex <word>", I18N_NOOP("'--sindex <word>' specifies the word to find in index, and activate if found"), 0 },
		{ "sbook <word>", I18N_NOOP("'--sbook <text>' specifies the word to find in bookmarks, and activate if found"), 0 },
*/		KCmdLineLastOption
 	};

	KAboutData aboutdata ( "kchmviewer",
				APP_NAME,
				APP_VERSION,
				I18N_NOOP("CHM file viewer"),
				KAboutData::License_GPL,
				"(c) 2005 George Yunaev, gyunaev@sourceforge.net",
				0,
				"http://kchmviewer.sourceforge.net",
				"gyunaev@sourceforge.net");

	KLocale::setMainCatalogue( "kchmviewer" );
	KCmdLineArgs::init (argc, argv, &aboutdata);
	KCmdLineArgs::addCmdLineOptions( options );

	KApplication app;
#else
	QApplication app( argc, argv );
#endif
	
	appConfig.load();
	app.installEventFilter( &gKeyEventFilter );
	
	mainWindow = new KCHMMainWindow();
	mainWindow->show();
	
#if !defined(USE_KDE)
	app.connect( &app, SIGNAL(lastWindowClosed()), &app, SLOT(quit()) );
#else
	app.setMainWidget( mainWindow );
#endif
	
	return app.exec();
}
