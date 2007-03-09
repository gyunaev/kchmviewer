/**********************************************************************
** Copyright (C) 2000-2005 Trolltech AS.  All rights reserved.
**
** This file is part of the Qt Assistant.
**
** This file may be distributed and/or modified under the terms of the
** GNU General Public License version 2 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.
**
** Licensees holding valid Qt Enterprise Edition or Qt Professional Edition
** licenses may use this file in accordance with the Qt Commercial License
** Agreement provided with the Software.
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** See http://www.trolltech.com/gpl/ for GPL licensing information.
** See http://www.trolltech.com/pricing.html or email sales@trolltech.com for
**   information about Qt Commercial License Agreements.
**
** Contact info@trolltech.com if any conditions of this licensing are
** not clear to you.
**
**********************************************************************/

#ifndef QASSISTANTINDEX_H
#define QASSISTANTINDEX_H

#include <qstringlist.h>
#include <qdict.h>
#include <qdatastream.h>
#include <qobject.h>

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
	
	Q_INT16 docNumber;
	Q_INT16 frequency;
};

QDataStream &operator>>( QDataStream &s, Document &l );
QDataStream &operator<<( QDataStream &s, const Document &l );

class Index : public QObject
{
    Q_OBJECT
	public:
		struct Entry
		{
			Entry( int d ) { documents.append( Document( d, 1 ) ); }
			Entry( QValueList<Document> l ) : documents( l ) {}
			QValueList<Document> documents;
		};
		
		struct PosEntry
		{
			PosEntry( int p ) { positions.append( p ); }
			QValueList<uint> positions;
		};

		Index( const QString &dp, const QString &hp );
		Index( const QStringList &dl, const QString &hp );
		
		void 		writeDict();
		bool 		readDict();
		bool 		makeIndex();
		QStringList query( const QStringList&, const QStringList&, const QStringList& );
		
		void 		setDictionaryFile( const QString& );
		void 		setDocListFile( const QString& );
		void 		setDocList( const QStringList & );
		QString 	getCharsSplit() const { return m_charssplit; }
		QString 	getCharsPartOfWord() const { return m_charsword; }

	signals:
		void indexingProgress( int );

	public slots:
		void setLastWinClosed();

	private:
		void	setupDocumentList();
		bool	parseDocumentToStringlist( const QString& filename, QStringList& tokenlist );
		void	parseDocument( const QString& filename, int docnum );
		void	insertInDict( const QString&, int );
		
		void	writeDocumentList();
		bool	readDocumentList();
		
		QStringList				getWildcardTerms( const QString& );
		QStringList				split( const QString& );
		QValueList<Document> 	setupDummyTerm( const QStringList& );
		bool 					searchForPattern( const QStringList&, const QStringList&, const QString& );
		void 					buildMiniDict( const QString& );
		
		QStringList 		docList;
		QDict<Entry> 		dict;
		QDict<PosEntry>		miniDict;
		uint 				wordNum;
		QString 			docPath;
		QString 			dictFile;
		QString 			docListFile;
		bool 				lastWindowClosed;
	
		// Those characters are splitters (i.e. split the word), but added themselves into dictionary too.
		// This makes the dictionary MUCH larger, but ensure that for the piece of "window->print" both 
		// search for "print" and "->print" will find it.
		QString m_charssplit;

		// Those characters are parts of word - for example, '_' is here, and search for _debug will find only _debug.
		QString m_charsword;
};

struct Term
{
	Term( const QString &t, int f, QValueList<Document> l ) : term( t ), frequency( f ), documents( l ) {}
	
	QString 				term;
	int 					frequency;
	QValueList<Document>	documents;
};

class TermList : public QPtrList<Term>
{
	public:
		TermList() : QPtrList<Term>() {}
		int compareItems( QPtrCollection::Item i1, QPtrCollection::Item i2 );
};

};

#endif /* QASSISTANTINDEX_H */
