

#include "kde-qt.h"

#include "kchmmainwindow.h"
#include "kchmconfig.h"

KCHMMainWindow * mainWindow;

int main( int argc, char ** argv )
{
#if defined (USE_KDE)
	KCmdLineArgs::init (argc, argv, argv[0], I18N_NOOP(APP_NAME), I18N_NOOP("CHM files viewer"), APP_VERSION);
	KApplication app;
#else
	KQApplication app( argc, argv );
#endif

	appConfig = new KCHMConfig();
	appConfig->load();
	
	mainWindow = new KCHMMainWindow();
	mainWindow->setCaption( "kchmview" );
	mainWindow->show();
	app.connect( &app, SIGNAL(lastWindowClosed()), &app, SLOT(quit()) );
	return app.exec();
}
