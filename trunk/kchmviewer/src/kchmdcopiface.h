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

#ifndef KCHMDCOPIFACE_H
#define KCHMDCOPIFACE_H

#include <qobject.h>
#include <dcopobject.h>
#include <qstring.h>
#include <qstringlist.h>

class KCHMDCOPIface : public QObject, public DCOPObject
{
	Q_OBJECT
	K_DCOP
			
	public:
    	KCHMDCOPIface( QObject *parent = 0, const char *name = 0 );
		~KCHMDCOPIface();
		
	k_dcop:
		//! Loads a CHM file \a filename , and opens the URL \a url. Use URL "/" to open default homepage
		void		loadHelpFile( const QString& filename, const QString& url );
	
		//! Opens a specific \a url inside the loaded CHM file
		void		openPage( const QString& url );
		
		//! Tries to find word in index, opening the index window and scrolling it there
		void		guiFindInIndex( const QString& word );
		
		//! Executes a search in GUI. \a query contains the complete search query.
		void		guiSearchQuery( const QString& query );
		
		//! Executes a search; GUI is not involved and user sees nothing.
		//! \a query contains the complete search query.
		//! Returns a list of URLs, or empty array if nothing os
		QStringList	searchQuery( const QString& query );
};

#endif
