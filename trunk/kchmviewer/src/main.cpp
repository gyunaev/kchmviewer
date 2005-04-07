
#if defined (ENABLE_KDE)

#else
	#include <qapplication.h>
#endif

#include "kchmmainwindow.h"
#include "kchmconfig.h"

KCHMMainWindow * mainWindow;

int main( int argc, char ** argv )
{
#if defined (ENABLE_KDE)
	KApplication app();
#else
	QApplication app( argc, argv );
#endif

	appConfig = new KCHMConfig();
	appConfig->load();
	
	mainWindow = new KCHMMainWindow();
	mainWindow->setCaption( "kchmview" );
	mainWindow->show();
	app.connect( &app, SIGNAL(lastWindowClosed()), &app, SLOT(quit()) );
	return app.exec();
}
