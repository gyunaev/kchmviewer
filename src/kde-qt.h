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

#if !defined (KDE_QT_H)
#define KDE_QT_H

#if defined (ENABLE_KDE)
	
	#define KCHM_APPLICATION_CLASS		KApplication
	#define KCHM_MAINWINDOW_CLASS		KMainWindow

	#include <kapplication.h>

#else /* !ENABLE_KDE */

	#define KCHM_APPLICATION_CLASS		QApplication
	#define KCHM_MAINWINDOW_CLASS		QMainWindow

#endif /* ENABLE_KDE */


#include <qmainwindow.h>
#include <qstring.h>
#include <qstatusbar.h>
#include <qlistview.h>


#endif /* KDE_QT_H */
