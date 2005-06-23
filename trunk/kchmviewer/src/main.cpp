

#include "kde-qt.h"

#include "kchmmainwindow.h"
#include "kchmconfig.h"

#if defined (USE_KDE)
	#include <kaboutdata.h>
#endif

KCHMMainWindow * mainWindow;

int main( int argc, char ** argv )
{
#if defined (USE_KDE)
 	static KCmdLineOptions options[] =
 	{
    	{ "autotestmode", I18N_NOOP("Perform auto testing"), 0 },
		{ "+[chmfile]", I18N_NOOP("A CHM file to show"), 0 },
/*		{ "search <query>", I18N_NOOP("'--search <query>' specifies the search query to search, and activate the first entry if found"), 0 },
		{ "sindex <word>", I18N_NOOP("'--sindex <word>' specifies the word to find in index, and activate if found"), 0 },
		{ "sbook <word>", I18N_NOOP("'--sbook <text>' specifies the word to find in bookmarks, and activate if found"), 0 },
*/		KCmdLineLastOption
 	};

	KAboutData aboutdata ( APP_NAME,
				I18N_NOOP(APP_NAME),
				APP_VERSION,
				I18N_NOOP("CHM file viewer"),
				KAboutData::License_GPL,
				"(c) 2005 Georgy Yunaev, gyunaev@sourceforge.net",
				0,
				"http://kchmviewer.sourceforge.net",
				"gyunaev@sourceforge.net");

	KCmdLineArgs::init (argc, argv, &aboutdata);
	KCmdLineArgs::addCmdLineOptions( options );

	KApplication app;
#else
	QApplication app( argc, argv );
#endif

	appConfig.load();
	
	mainWindow = new KCHMMainWindow();
	mainWindow->show();
	app.connect( &app, SIGNAL(lastWindowClosed()), &app, SLOT(quit()) );
	return app.exec();
}
