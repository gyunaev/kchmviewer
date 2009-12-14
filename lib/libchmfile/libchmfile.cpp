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

#include "libchmfile.h"
#include "libchmfileimpl.h"

#include <QPixmap>


LCHMFile::LCHMFile( )
{
	m_impl = new LCHMFileImpl();
}

LCHMFile::~ LCHMFile( )
{
	delete m_impl;
}

bool LCHMFile::loadFile( const QString & archiveName )
{
	return m_impl->loadFile( archiveName );
}

void LCHMFile::closeAll( )
{
	m_impl->closeAll();
}

QString LCHMFile::title( ) const
{
	return m_impl->title();
}

QString LCHMFile::homeUrl( ) const
{
	QString url = m_impl->homeUrl();
	return url.isNull() ? "/" : url;
}

bool LCHMFile::hasTableOfContents( ) const
{
	return m_impl->m_tocAvailable;
}

bool LCHMFile::hasIndexTable( ) const
{
	return m_impl->m_indexAvailable;
}

bool LCHMFile::hasSearchTable( ) const
{
	return m_impl->m_searchAvailable;
}

bool LCHMFile::parseTableOfContents( QVector< LCHMParsedEntry > * topics ) const
{
	return m_impl->parseBinaryTOC( topics )
	|| m_impl->parseFileAndFillArray( m_impl->m_topicsFile, topics, false );
}

bool LCHMFile::parseIndex( QVector< LCHMParsedEntry > * indexes ) const
{
	//return m_impl->parseBinaryIndex( indexes )
	return m_impl->parseFileAndFillArray( m_impl->m_indexFile, indexes, true );
}

bool LCHMFile::getFileContentAsString( QString * str, const QString & url )
{
	return m_impl->getFileContentAsString( str, url );
}

bool LCHMFile::getFileContentAsBinary( QByteArray * data, const QString & url )
{
	return m_impl->getFileContentAsBinary( data, url );
}

bool LCHMFile::enumerateFiles( QStringList * files )
{
	return m_impl->enumerateFiles( files );
}

QString LCHMFile::getTopicByUrl( const QString & url )
{
	return m_impl->getTopicByUrl( url );
}

const QPixmap * LCHMFile::getBookIconPixmap( unsigned int imagenum )
{
	return m_impl->getBookIconPixmap( imagenum );
}

const LCHMTextEncoding * LCHMFile::currentEncoding( ) const
{
	return m_impl->m_currentEncoding;
}

bool LCHMFile::setCurrentEncoding( const LCHMTextEncoding * encoding )
{
	return m_impl->setCurrentEncoding( encoding );
}

QString LCHMFile::normalizeUrl( const QString & url ) const
{
	return m_impl->normalizeUrl( url );
}

bool LCHMFile::getFileSize(unsigned int * size, const QString & url)
{
	return m_impl->getFileSize( size, url );
}
