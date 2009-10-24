/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
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
#include "kchmdbusiface.h"
#include "version.h"

#if !defined (WIN32)
	#include <QtDBus/QtDBus>
#endif

#if defined (USE_KDE)
	#include <kaboutdata.h>
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
	
#if !defined (WIN32)	
	if ( QDBusConnection::sessionBus().isConnected() )
	{
		if ( QDBusConnection::sessionBus().registerService(SERVICE_NAME) )
		{
			KCHMDBusIface * dbusiface = new KCHMDBusIface();
			QDBusConnection::sessionBus().registerObject( "/", dbusiface, QDBusConnection::ExportAllSlots );
		}
		else
			qWarning( "Cannot register service %s on session bus. Going without D-BUS support.", SERVICE_NAME );
	}
	else
		qWarning( "Cannot connect to the D-BUS session bus. Going without D-BUS support." );
#endif

	mainWindow = new KCHMMainWindow();
	mainWindow->show();
	
	app.connect( &app, SIGNAL(lastWindowClosed()), &app, SLOT(quit()) );
	
	return app.exec();
}

