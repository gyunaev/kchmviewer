/**************************************************************************
 *  Kchmviewer - a CHM file viewer with broad language support            *
 *  Copyright (C) 2004-2010 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  This program is free software: you can redistribute it and/or modify  *
 *  it under the terms of the GNU General Public License as published by  *
 *  the Free Software Foundation, either version 3 of the License, or     *
 *  (at your option) any later version.                                   *
 *																	      *
 *  This program is distributed in the hope that it will be useful,       *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *  GNU General Public License for more details.                          *
 *                                                                        *
 *  You should have received a copy of the GNU General Public License     *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 **************************************************************************/

#ifndef LIBCHMTEXTENCODING_H
#define LIBCHMTEXTENCODING_H


/*!
 * Represents a text encoding of CHM file; also has some useful routines.
 */
typedef struct 
{
	const char	*	family;			//! Cyrillic, Western, Greek... NULL pointer represents the end of table.
	const char	*	qtcodec;		//! Qt text codec to use
	const short	*	lcids;			//! List of LCIDs to use for this codepage. Ends with LCID 0.
} LCHMTextEncoding;


#endif /* LIBCHMTEXTENCODING_H */
