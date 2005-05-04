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

#ifndef KDE_QT_H
#define KDE_QT_H

#include "config.h"

#if defined (USE_KDE)
	
	#define KQ_CLASSNAME(name)			K##name
	#define KQ_DECLARECLASS(name)		class KQ##name : public K##name

	#include <kapplication.h>
	#include <kmainwindow.h>
	#include <kstatusbar.h>
	#include <kmenubar.h>
	#include <kcmdlineargs.h>
	#include <klocale.h>
	#include <klistview.h>
	#include <kfiledialog.h>
	#include <khtml_part.h>

#else /* !USE_KDE */

	#define KQ_CLASSNAME(name)			Q##name

	#include <qapplication.h>
	#include <qmainwindow.h>
	#include <qstring.h>
	#include <qstatusbar.h>
	#include <qlistview.h>
	#include <qfiledialog.h>
	#include <qmenubar.h>

#endif /* USE_KDE */

/* common non-wrapped UI classes */
#include <qsplitter.h>
#include <qtabwidget.h>
#include <qtoolbutton.h>
#include <qheader.h>
#include <qtextbrowser.h>

/* common utility classes */
#include <qstring.h>
#include <qtextedit.h>
#include <qfile.h>
#include <qregexp.h>
#include <qtimer.h>

class KQMainWindow : public KQ_CLASSNAME(MainWindow)
{
public:
	KQMainWindow ( QWidget * parent, const char * name, WFlags f )
		: KQ_CLASSNAME(MainWindow) (parent, name, f) {};
};


class KQListView : public KQ_CLASSNAME(ListView)
{
public:
	KQListView(QWidget *parent = 0, const char *name = 0, int f = 0);
};

class KQFileDialog
{
public:
	static QString getOpenFileName ( const QString & startWith = QString::null, const QString & filter = QString::null, QWidget * parent = 0 );
};

#include <qmessagebox.h>
#include <qprinter.h>
#include <qpainter.h>
#include <qsimplerichtext.h>
#include <qpaintdevicemetrics.h>
#include <qwhatsthis.h>

#endif /* KDE_QT_H */
