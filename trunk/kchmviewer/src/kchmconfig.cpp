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

#include <qdir.h>

#include "kchmconfig.h"

KCHMConfig * appConfig;
const char * APP_NAME = "KchmViewer";
const char * APP_VERSION = "0.1";
const char * APP_PATHINUSERDIR = ".kchmviewer";


KCHMConfig::KCHMConfig()
{
	QDir dir;
	m_datapath = QDir::homeDirPath() + "/" + APP_PATHINUSERDIR;
	 
	dir.setPath (m_datapath);
	
	if ( !dir.exists() && !dir.mkdir(m_datapath) )
		qWarning ("Could not create directory %s", m_datapath.ascii());
}


KCHMConfig::~KCHMConfig()
{
}

bool KCHMConfig::load()
{
	return true;
}
