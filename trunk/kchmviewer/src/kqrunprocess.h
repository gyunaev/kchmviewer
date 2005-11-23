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


static bool run_process( const QString& command, const QString& filename )
{
	QString safefilename = filename;
	QString preparedcommand = command;
	
	// To be safe, URL should contain no quotes, apostrofes and \0 symbols
	safefilename.remove (QRegExp ("['\"\0]"));
	preparedcommand.replace( "%s", safefilename );

	// And run an external command with fork()s
	switch ( fork() )
	{
	case -1:
		return false;
				
	case 0: // child
		if ( fork() != 0 )
			exit(0); // exit immediately - our child is now has init as his parent
				
		system( preparedcommand.ascii() );
		exit (0);
				
	default: // parent
		break;
	}
	
	return true;
}
