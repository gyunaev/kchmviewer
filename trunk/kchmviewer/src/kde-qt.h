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

#ifndef KDE_QT_H
#define KDE_QT_H

#if defined (USE_KDE)
	
	#define KQ_CLASSNAME(name)			K##name
	#define KQ_DECLARECLASS(name)		class KQ##name : public K##name

	#include <kapplication.h>
	#include <kmainwindow.h>
	#include <kstatusbar.h>
	#include <kmenubar.h>
	#include <kcmdlineargs.h>
	#include <klocale.h>
	#include <kfiledialog.h>
	#include <khtml_part.h>
	#include <ktabwidget.h>
	#include <kmenu.h>
	#include <kmessagebox.h>
	#include <kprogressdialog.h>
	#include <krun.h>

	#include <QProgressDialog>

#else /* !USE_KDE */

	#define KQ_CLASSNAME(name)			Q##name

	#include <QApplication>
	#include <QMainWindow>
	#include <QStatusBar>
	#include <QFileDialog>
	#include <QMenuBar>
	#include <QMenu>
	#include <QTabWidget>
	#include <QMessageBox>
	#include <QProgressDialog>
	#include <QPrinter>
	#include <QPrintDialog>

	#define i18n(A)		tr(A)

#endif /* USE_KDE */

// common non-wrapped UI classes
#include <QSplitter>
#include <QToolButton>
#include <QHeaderView>
#include <QTextBrowser>
#include <QLayout>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QScrollBar>


// common utility classes
#include <QWhatsThis>
#include <QString>
#include <QTextEdit>
#include <QFile>
#include <QTemporaryFile>
#include <QDir>
#include <QRegExp>
#include <QTimer>
#include <QMap>
#include <QShortcut>

// events
#include <QEventLoop>
#include <QCloseEvent>
#include <QShowEvent>
#include <QEvent>


class KQMainWindow : public KQ_CLASSNAME(MainWindow)
{
public:
	KQMainWindow ( QWidget * parent, Qt::WFlags f )
		: KQ_CLASSNAME(MainWindow) (parent, f) {};
};


class KQProgressModalDialog : public KQ_CLASSNAME(ProgressDialog)
{
	public:
		KQProgressModalDialog ( const QString & captionText, const QString & labelText, const QString & cancelButtonText, int totalSteps, QWidget * creator = 0 );
		
		// Seems like people have fun making classes incompatible
#if defined (USE_KDE)		
		void   setValue( int value ) { progressBar()->setValue( value ); }
#else
		bool   wasCancelled() { return wasCanceled(); }
#endif

};

class KQTabWidget : public KQ_CLASSNAME(TabWidget)
{
public:
	KQTabWidget (QWidget *parent = 0 )
		: KQ_CLASSNAME(TabWidget) (parent) {};
};


#include <QInputDialog>
#include <QCheckBox>
#include <QTextEdit>
#include <QRadioButton>
#include <QSpinBox>
#include <QGroupBox>
#include <QToolBar>
#include <QToolTip>
#include <QListWidget>
#include <QTreeWidget>
#include <QPixmap>
				 				 

class KCHMShowWaitCursor
{
	public:
		KCHMShowWaitCursor() { QApplication::setOverrideCursor( QCursor(Qt::WaitCursor) ); }
		~KCHMShowWaitCursor() { QApplication::restoreOverrideCursor(); }
};


// Forward declarations
class KCHMMainWindow;
class KCHMViewWindow;
class KCHMIndexWindow;
class KCHMSearchWindow;
class KCHMBookmarkWindow;
class KCHMSettings;
class KCHMSearchAndViewToolbar;
class KCHMViewWindow;
class KCHMViewWindowMgr;
class KCHMContentsWindow;

				 
#endif /* KDE_QT_H */
