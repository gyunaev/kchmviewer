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

#ifndef QASSISTANTINDEX_H
#define QASSISTANTINDEX_H

#include <QHash>
#include <QVector>
#include <QDataStream>
#include <QStringList>

//#include "libchmurlfactory.h"

class LCHMFile;

namespace QtAs
{

struct Document
{
	Document( int d, int f ) : docNumber( d ), frequency( f ) {}
	Document() : docNumber( -1 ), frequency( 0 ) {}
	bool operator==( const Document &doc ) const
	{
		return docNumber == doc.docNumber;
	}
	
	bool operator<( const Document &doc ) const
	{
		return frequency > doc.frequency;
	}
	
	bool operator<=( const Document &doc ) const
	{
		return frequency >= doc.frequency;
	}
	
	bool operator>( const Document &doc ) const
	{
		return frequency < doc.frequency;
	}
	
	qint16	docNumber;
	qint16	frequency;
};

QDataStream &operator>>( QDataStream &s, Document &l );
QDataStream &operator<<( QDataStream &s, const Document &l );

class Index : public QObject
{
    Q_OBJECT
	public:

		Index();
		
		void 		writeDict( QDataStream& stream );
		bool 		readDict( QDataStream& stream );
		bool 		makeIndex( const QStringList& docs, LCHMFile * chmFile );
		QStringList query( const QStringList&, const QStringList&, const QStringList&, LCHMFile * chmFile );
		QString 	getCharsSplit() const { return m_charssplit; }
		QString 	getCharsPartOfWord() const { return m_charsword; }

	signals:
		void indexingProgress( int, const QString& );

	public slots:
		void setLastWinClosed();

	private:
		struct Entry
		{
			Entry( int d ) { documents.append( Document( d, 1 ) ); }
			Entry( QVector<Document> l ) : documents( l ) {}
			QVector<Document> documents;
		};
		
		struct PosEntry
		{
			PosEntry( int p ) { positions.append( p ); }
			QList<uint> positions;
		};
		
		bool	parseDocumentToStringlist( LCHMFile * chmFile, const QString& filename, QStringList& tokenlist );
		void	insertInDict( const QString&, int );
		
		QStringList				getWildcardTerms( const QString& );
		QStringList				split( const QString& );
		QList<Document> 		setupDummyTerm( const QStringList& );
		bool 					searchForPhrases( const QStringList &phrases, const QStringList &words, const QString &filename, LCHMFile * chmFile );
		
		QStringList 			docList;
		QHash<QString, Entry*> 	dict;
		QHash<QString,PosEntry*>miniDict;
		bool 					lastWindowClosed;
	
		// Those characters are splitters (i.e. split the word), but added themselves into dictionary too.
		// This makes the dictionary MUCH larger, but ensure that for the piece of "window->print" both 
		// search for "print" and "->print" will find it.
		QString 				m_charssplit;

		// Those characters are parts of word - for example, '_' is here, and search for _debug will find only _debug.
		QString 				m_charsword;
};

};

#endif /* QASSISTANTINDEX_H */
