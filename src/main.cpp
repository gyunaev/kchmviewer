/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.         *
 ***************************************************************************/

#include "kde-qt.h"

#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "kchmkeyeventfilter.h"
#include "version.h"


#if defined (USE_KDE)
	#include <kaboutdata.h>
	
	#include "kde/kchmdbusiface.h"
#endif

KCHMMainWindow * mainWindow;


int main( int argc, char ** argv )
{
#if defined (USE_KDE)
 	KCmdLineOptions options;
	options.add( "autotestmode", ki18n("Perform auto testing") );
	options.add( "shortautotestmode", ki18n("Perform short auto testing") );
	options.add( "+[chmfile]", ki18n("A CHM file to show") );
	options.add( "search <query>", ki18n("'--search <query>' specifies the search query to search, and activate the first entry if found") );
	options.add( "sindex <word>", ki18n("'--sindex <word>' specifies the word to find in index, and activate if found") );
	options.add( "stoc <word>", ki18n("'--stoc <word(s)>' specifies the word(s) to find in TOC, and activate if found. Wildcards allowed.") );

	KAboutData aboutdata ( "kchmviewer",
				QByteArray(),
				ki18n(APP_NAME),
				APP_VERSION,
				ki18n("CHM file viewer"),
				KAboutData::License_GPL,
				ki18n("(c) 2004-2008 George Yunaev, gyunaev@ulduzsoft.com"),
				ki18n("Please report bugs to kchmviewer@ulduzsoft.com"),
				"http://www.kchmviewer.net",
				"kchmviewer@ulduzsoft.com");

	KCmdLineArgs::init (argc, argv, &aboutdata);
	KCmdLineArgs::addCmdLineOptions( options );

	KApplication app;
#else
	QApplication app( argc, argv );
#endif
	
	appConfig.load();
	app.installEventFilter( &gKeyEventFilter );
	
#if defined(USE_KDE)	
	// DBus stuff
	KCHMDBusIface iface;
#endif
	mainWindow = new KCHMMainWindow();
	mainWindow->show();
	
	app.connect( &app, SIGNAL(lastWindowClosed()), &app, SLOT(quit()) );
	
	return app.exec();
}

