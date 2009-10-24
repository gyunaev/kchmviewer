/***************************************************************************
 *   Copyright (C) 2004-2005 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <QtDBus/QtDBus>

#include "kchmdbusiface.h"
#include "kchmmainwindow.h"
#include "kchmsearchwindow.h"


KCHMDBusIface::KCHMDBusIface( QObject *parent )
	: QObject( parent )
{
	QDBusConnection::sessionBus().registerObject( "/application",
												  this,
												  QDBusConnection::ExportScriptableSlots );
}


KCHMDBusIface::~KCHMDBusIface()
{
}


void KCHMDBusIface::loadHelpFile( const QString & filename, const QString & page2open )
{
	QStringList args;
	
	args.push_back( filename );
	args.push_back( page2open );
	
	qApp->postEvent( ::mainWindow, new KCHMUserEvent( "loadAndOpen", args ) );
}


void KCHMDBusIface::openPage( const QString & page2open )
{
	QStringList args;
	
	args.push_back( page2open );
	qApp->postEvent( ::mainWindow, new KCHMUserEvent( "openPage", args ) );
}


void KCHMDBusIface::guiFindInIndex( const QString & word )
{
	QStringList args;
	
	args.push_back( word );
	qApp->postEvent( ::mainWindow, new KCHMUserEvent( "findInIndex", args ) );
}


void KCHMDBusIface::guiSearchQuery( const QString & query )
{
	QStringList args;
	
	args.push_back( query );
	qApp->postEvent( ::mainWindow, new KCHMUserEvent( "searchQuery", args ) );
}

QStringList KCHMDBusIface::searchQuery( const QString & query )
{
	QStringList results;
	
	if ( ::mainWindow->searchWindow()->searchQuery( query, &results ) )
		return results;
	else
		return QStringList();
}
