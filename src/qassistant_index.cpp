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

#include <qfile.h>
#include <qdir.h>
#include <qstringlist.h>
#include <qdict.h>
#include <qapplication.h>

#include <ctype.h>

#include "qassistant_index.h"
#include "kchmmainwindow.h"
#include "libchmfileimpl.h"


namespace QtAs {

// Those characters are splitters (i.e. split the word), but added themselves into dictionary too.
// This makes the dictionary MUCH larger, but ensure that for the piece of "window->print" both 
// search for "print" and "->print" will find it.
static const char SPLIT_CHARACTERS[] = "!()*&^%#@[]{}':;,.?/|/?<>\\-+=~`";
	
// Those characters are parts of word - for example, '_' is here, and search for _debug will find only _debug.
static const char WORD_CHARACTERS[] = "$_";

	
int TermList::compareItems( QPtrCollection::Item i1, QPtrCollection::Item i2 )
{
	if( ( (Term*)i1 )->frequency == ( (Term*)i2 )->frequency )
		return 0;
	if( ( (Term*)i1 )->frequency < ( (Term*)i2 )->frequency )
		return -1;
	return 1;
}

QDataStream &operator>>( QDataStream &s, Document &l )
{
	s >> l.docNumber;
	s >> l.frequency;
	return s;
}

QDataStream &operator<<( QDataStream &s, const Document &l )
{
	s << (Q_INT16)l.docNumber;
	s << (Q_INT16)l.frequency;
	return s;
}

Index::Index( const QString &dp, const QString & )
	: QObject( 0, 0 ), dict( 8999 ), docPath( dp )
{
	lastWindowClosed = FALSE;
	connect( qApp, SIGNAL( lastWindowClosed() ),
			 this, SLOT( setLastWinClosed() ) );
}

Index::Index( const QStringList &dl, const QString & )
	: QObject( 0, 0 ), dict( 20011 )
{
	docList = dl;
	lastWindowClosed = FALSE;
	connect( qApp, SIGNAL( lastWindowClosed() ),
			 this, SLOT( setLastWinClosed() ) );
}

void Index::setLastWinClosed()
{
	lastWindowClosed = TRUE;
}

void Index::setDictionaryFile( const QString &f )
{
	dictFile = f;
}

void Index::setDocListFile( const QString &f )
{
	docListFile = f;
}

void Index::setDocList( const QStringList &lst )
{
	docList = lst;
}

int Index::makeIndex()
{
	if ( docList.isEmpty() )
		return 1;
	QStringList::Iterator it = docList.begin();
	int steps = docList.count() / 100;
	if ( !steps )
		steps++;
	int prog = 0;
	for ( int i = 0; it != docList.end(); ++it, ++i ) {
		if ( lastWindowClosed ) {
			return -1;
		}
		parseDocument( *it, i );
		if ( i%steps == 0 ) {
			prog++;
			emit indexingProgress( prog );
		}
	}
	return 0;
}


void Index::insertInDict( const QString &str, int docNum )
{
	Entry *e = 0;
	if ( dict.count() )
		e = dict[ str.lower() ];
	
	if ( e )
	{
		if ( e->documents.first().docNumber != docNum )
			e->documents.prepend( Document( docNum, 1 ) );
		else
			e->documents.first().frequency++;
	}
	else
	{
		dict.insert( str.lower(), new Entry( docNum ) );
	}
}


bool Index::parseDocumentToStringlist( const QString & filename, QStringList & tokenlist )
{
	QString text;
	
	if ( !::mainWindow->chmFile()->getFileContentAsString( &text, filename ) )
	{
		qWarning( "Index::parseDocument: Could not retrieve the content at %s", filename.ascii() );
		return false;
	}
	
	if ( text.isNull() )
	{
		qWarning( "Index::parseDocument: Retrieved content for %s is empty", filename.ascii() );
		return false;
	}

	m_charssplit = SPLIT_CHARACTERS;
	m_charsword = WORD_CHARACTERS;
	
	tokenlist.clear();
	
	const QChar *buf = text.unicode();
	QString parsedbuf;
	
	// true if we are inside HTML tag (i.e. ignore everything)
	bool in_html_tag = false;
	
	// true if we are inside HTML entity (like &nbsp;) - unlike Qt assistant, we decode it
	bool in_html_entiry = false;
	
	for ( unsigned int j = 0; j < text.length(); j++ )
	{
		QChar ch = buf[j];
		
		// State 1: we are inside HTML tag. Ignore everything until we see '>'
		if ( in_html_tag )
		{
			if ( ch == '>' )
				in_html_tag = false;
			
			continue;
		}
		
		// State 2: The HTML tag is about to start.
		// Must be here, as '<' could be a decoded entity at state 4.
		if ( ch == '<' )
		{
			in_html_tag = true;
			goto tokenize_buf;
		}
		
		// State 3: The HTML entity is about to start.
		// Must be here, as '&' could be a decoded entity at state 4.
		if ( ch == '&' )
		{
			in_html_entiry = true;
			goto tokenize_buf;
		}
		
		// State 4: we're in HTML entity
		if ( in_html_entiry )
		{
			if ( ch != ';' )
			{
				// get next character of this entity
				parsedbuf.append( ch );
				continue;
			}
			
			// The entity ended
			in_html_entiry = false;
			QString entity = ::mainWindow->chmFile()->impl()->decodeEntity( parsedbuf.lower() );
			
			if ( entity.isNull() )
			{
				qWarning( "Index::parseDocument: failed to decode entity &%s;", parsedbuf.ascii() );
				parsedbuf = QString::null;
				continue;
			}
			
			parsedbuf = entity;
			
			// No continue! this is valid character, and we go to state 5.
		}
		
		// State 5: we have a valid character outside HTML tags, and probably some in buffer already.
		// If it is char or letter, add it and continue
		if ( ch.isLetterOrNumber() || m_charsword.find( ch ) != -1 )
		{
			parsedbuf.append( ch );
			continue;
		}
		
		// If it is a split char, add the word to the dictionary, and then add the char itself.
		if ( m_charssplit.find( ch ) != -1 )
		{
			if ( !parsedbuf.isEmpty() )
				tokenlist.push_back( parsedbuf );
			
			tokenlist.push_back( ch );
			parsedbuf = QString::null;
			continue;
		}
		
tokenize_buf:		
		// Just add the word; it is most likely a space or terminated by tokenizer.
		if ( !parsedbuf.isEmpty() )
		{
			tokenlist.push_back( parsedbuf );
			parsedbuf = QString::null;
		}
	}
	
	// Add the last word if still here - for broken htmls.
	if ( !parsedbuf.isEmpty() )
		tokenlist.push_back( parsedbuf );
	
	return true;
}


void Index::parseDocument( const QString &filename, int docNum )
{
	/*
	QString text;
	
	if ( !::mainWindow->chmFile()->getFileContentAsString( &text, filename ) )
	{
		qWarning( "Index::parseDocument: Could not retrieve the content at %s", filename.ascii() );
		return;
	}
	
	if ( text.isNull() )
	{
		qWarning( "Index::parseDocument: Retrieved content for %s is empty", filename.ascii() );
		return;
	}

	m_charssplit = SPLIT_CHARACTERS;
	m_charsword = WORD_CHARACTERS;
	
	const QChar *buf = text.unicode();
	QString parsedbuf;
	
	// true if we are inside HTML tag (i.e. ignore everything)
	bool in_html_tag = false;
	
	// true if we are inside HTML entity (like &nbsp;) - unlike Qt assistant, we decode it
	bool in_html_entiry = false;
	
	for ( unsigned int j = 0; j < text.length(); j++ )
	{
		QChar ch = buf[j];
		
		// State 1: we are inside HTML tag. Ignore everything until we see '>'
		if ( in_html_tag )
		{
			if ( ch == '>' )
				in_html_tag = false;
			
			continue;
		}
		
		// State 2: The HTML tag is about to start.
		// Must be here, as '<' could be a decoded entity at state 4.
		if ( ch == '<' )
		{
			in_html_tag = true;
			goto tokenize_buf;
		}
		
		// State 3: The HTML entity is about to start.
		// Must be here, as '&' could be a decoded entity at state 4.
		if ( ch == '&' )
		{
			in_html_entiry = true;
			goto tokenize_buf;
		}
		
		// State 4: we're in HTML entity
		if ( in_html_entiry )
		{
			if ( ch != ';' )
			{
				// get next character of this entity
				parsedbuf.append( ch );
				continue;
			}
			
			// The entity ended
			in_html_entiry = false;
			QString entity = ::mainWindow->chmFile()->impl()->decodeEntity( parsedbuf.lower() );
			
			if ( entity.isNull() )
			{
				qWarning( "Index::parseDocument: failed to decode entity &%s;", parsedbuf.ascii() );
				parsedbuf = QString::null;
				continue;
			}
			
			parsedbuf = entity;
			
			// No continue! this is valid character, and we go to state 5.
		}
		
		// State 5: we have a valid character outside HTML tags, and probably some in buffer already.
		// If it is char or letter, add it and continue
		if ( ch.isLetterOrNumber() || m_charsword.find( ch ) != -1 )
		{
			parsedbuf.append( ch );
			continue;
		}
		
		// If it is a split char, add the word to the dictionary, and then add the char itself.
		if ( m_charssplit.find( ch ) != -1 )
		{
			if ( !parsedbuf.isEmpty() )
				insertInDict( parsedbuf, docNum );
			
			insertInDict( ch, docNum );
			parsedbuf = QString::null;
			continue;
		}
		
tokenize_buf:		
		// Just add the word; it is most likely a space or terminated by tokenizer.
		if ( !parsedbuf.isEmpty() )
		{
			insertInDict( parsedbuf, docNum );
			parsedbuf = QString::null;
		}
	}
	
	// Add the last word if still here - for broken htmls.
	if ( !parsedbuf.isEmpty() )
		insertInDict( parsedbuf, docNum );
	*/
	QStringList terms;
	
	if ( !parseDocumentToStringlist( filename, terms ) )
		return;
	
	for ( unsigned int i = 0; i < terms.size(); i++ )
		insertInDict( terms[i], docNum );
}


bool Index::searchForPattern( const QStringList &patterns, const QStringList &words, const QString &filename )
{
	QStringList terms;
		
	if ( !parseDocumentToStringlist( filename, terms ) )
		return false;
/*
	
	QFile file( fileName );
	if ( !file.open( IO_ReadOnly ) ) {
		qWarning( "cannot open file %s", fileName.ascii() );
		return FALSE;
	}
*/

	wordNum = 3;
	miniDict.clear();
	QStringList::ConstIterator cIt = words.begin();
	
	for ( ; cIt != words.end(); ++cIt )
		miniDict.insert( *cIt, new PosEntry( 0 ) );

	for ( unsigned int i = 0; i < terms.size(); i++ )
		buildMiniDict( terms[i] );
	
/*	
	QTextStream s( &file );
	QString text = s.read();
	bool valid = TRUE;
	const QChar *buf = text.unicode();
	QChar str[64];
	QChar c = buf[0];
	int j = 0;
	int i = 0;
	while ( (uint)j < text.length() ) {
		if ( c == '<' || c == '&' ) {
			valid = FALSE;
			if ( i > 1 )
				buildMiniDict( QString(str,i) );
			i = 0;
			c = buf[++j];
			continue;
		}
		if ( ( c == '>' || c == ';' ) && !valid ) {
			valid = TRUE;
			c = buf[++j];
			continue;
		}
		if ( !valid ) {
			c = buf[++j];
			continue;
		}
		if ( ( c.isLetterOrNumber() || c == '_' ) && i < 63 ) {
			str[i] = c.lower();
			++i;
		} else {
			if ( i > 1 )
				buildMiniDict( QString(str,i) );
			i = 0;
		}
		c = buf[++j];
	}
	if ( i > 1 )
		buildMiniDict( QString(str,i) );
	file.close();
*/
	
	QStringList::ConstIterator patIt = patterns.begin();
	QStringList wordLst;
	QValueList<uint> a, b;
	QValueList<uint>::iterator aIt;
	for ( ; patIt != patterns.end(); ++patIt ) {
		wordLst = QStringList::split( ' ', *patIt );
		a = miniDict[ wordLst[0] ]->positions;
		for ( int j = 1; j < (int)wordLst.count(); ++j ) {
			b = miniDict[ wordLst[j] ]->positions;
			aIt = a.begin();
			while ( aIt != a.end() ) {
				if ( b.find( *aIt + 1 ) != b.end() ) {
					(*aIt)++;
					++aIt;
				} else {
					aIt = a.remove( aIt );
				}
			}
		}
	}
	if ( a.count() )
		return TRUE;
	return FALSE;
}


void Index::writeDict()
{
	QDictIterator<Entry> it( dict );
	QFile f( dictFile );
	if ( !f.open( IO_WriteOnly ) )
	{
		qWarning( "Index::writeDict: could not write dictionary file %s", dictFile.ascii() );
		return;
	}
	
	QDataStream s( &f );
	s << (int) 1; // version
	s << m_charssplit;
	s << m_charsword;
	
	for( ; it.current(); ++it ) {
		Entry *e = it.current();
		s << it.currentKey();
		s << e->documents;
	}
	f.close();
	writeDocumentList();
}

void Index::writeDocumentList()
{
	QFile f( docListFile );
	if ( !f.open( IO_WriteOnly ) )
	{
		qWarning( "Index::writeDocumentList: could not write dictionary file %s", docListFile.ascii() );
		return;
	}
	QDataStream s( &f );
	s << docList;
}

bool Index::readDict()
{
	QFile f( dictFile );
	if ( !f.open( IO_ReadOnly ) )
		return false;

	dict.clear();
	QDataStream s( &f );
	QString key;
	int version;
	QValueList<Document> docs;
	
	s >> version;
	s >> m_charssplit;
	s >> m_charsword;
	
	while ( !s.atEnd() ) {
		s >> key;
		s >> docs;
		dict.insert( key, new Entry( docs ) );
	}
	f.close();
	return dict.size() > 0 && readDocumentList();
}

bool Index::readDocumentList()
{
	QFile f( docListFile );
	if ( !f.open( IO_ReadOnly ) )
		return false;
	QDataStream s( &f );
	s >> docList;
	return true;
}

QStringList Index::query( const QStringList &terms, const QStringList &termSeq, const QStringList &seqWords )
{
	TermList termList;

	QStringList::ConstIterator it = terms.begin();
	for ( it = terms.begin(); it != terms.end(); ++it ) {
		Entry *e = 0;
		if ( (*it).contains( '*' ) ) {
			QValueList<Document> wcts = setupDummyTerm( getWildcardTerms( *it ) );
			termList.append( new Term( "dummy", wcts.count(), wcts ) );
		} else if ( dict[ *it ] ) {
			e = dict[ *it ];
			termList.append( new Term( *it, e->documents.count(), e->documents ) );
		} else {
			return QStringList();
		}
	}
	termList.sort();

	Term *minTerm = termList.first();
	if ( !termList.count() )
		return QStringList();
	termList.removeFirst();

	QValueList<Document> minDocs = minTerm->documents;
	QValueList<Document>::iterator C;
	QValueList<Document>::ConstIterator It;
	Term *t = termList.first();
	for ( ; t; t = termList.next() ) {
		QValueList<Document> docs = t->documents;
		C = minDocs.begin();
		while ( C != minDocs.end() ) {
			bool found = FALSE;
			for ( It = docs.begin(); It != docs.end(); ++It ) {
				if ( (*C).docNumber == (*It).docNumber ) {
					(*C).frequency += (*It).frequency;
					found = TRUE;
					break;
				}
			}
			if ( !found )
				C = minDocs.remove( C );
			else
				++C;
		}
	}

	QStringList results;
	qHeapSort( minDocs );
	if ( termSeq.isEmpty() ) {
		for ( C = minDocs.begin(); C != minDocs.end(); ++C )
			results << docList[ (int)(*C).docNumber ];
		return results;
	}

	QString fileName;
	for ( C = minDocs.begin(); C != minDocs.end(); ++C ) {
		fileName =  docList[ (int)(*C).docNumber ];
		if ( searchForPattern( termSeq, seqWords, fileName ) )
			results << fileName;
	}
	return results;
}


QStringList Index::getWildcardTerms( const QString &term )
{
	QStringList lst;
	QStringList terms = split( term );
	QValueList<QString>::iterator iter;

	QDictIterator<Entry> it( dict );
	for( ; it.current(); ++it ) {
		int index = 0;
		bool found = FALSE;
		QString text( it.currentKey() );
		for ( iter = terms.begin(); iter != terms.end(); ++iter ) {
			if ( *iter == "*" ) {
				found = TRUE;
				continue;
			}
			if ( iter == terms.begin() && (*iter)[0] != text[0] ) {
				found = FALSE;
				break;
			}
			index = text.find( *iter, index );
			if ( *iter == terms.last() && index != (int)text.length()-1 ) {
				index = text.findRev( *iter );
				if ( index != (int)text.length() - (int)(*iter).length() ) {
					found = FALSE;
					break;
				}
			}
			if ( index != -1 ) {
				found = TRUE;
				index += (*iter).length();
				continue;
			} else {
				found = FALSE;
				break;
			}
		}
		if ( found )
			lst << text;
	}

	return lst;
}

QStringList Index::split( const QString &str )
{
	QStringList lst;
	int j = 0;
	int i = str.find( '*', j );

	while ( i != -1 ) {
		if ( i > j && i <= (int)str.length() ) {
			lst << str.mid( j, i - j );
			lst << "*";
		}
		j = i + 1;
		i = str.find( '*', j );
	}

	int l = str.length() - 1;
	if ( str.mid( j, l - j + 1 ).length() > 0 )
		lst << str.mid( j, l - j + 1 );

	return lst;
}

QValueList<Document> Index::setupDummyTerm( const QStringList &terms )
{
	TermList termList;
	QStringList::ConstIterator it = terms.begin();
	for ( ; it != terms.end(); ++it ) {
		Entry *e = 0;
		if ( dict[ *it ] ) {
			e = dict[ *it ];
			termList.append( new Term( *it, e->documents.count(), e->documents ) );
		}
	}
	termList.sort();

	QValueList<Document> maxList;

	if ( !termList.count() )
		return maxList;
	maxList = termList.last()->documents;
	termList.removeLast();

	QValueList<Document>::iterator docIt;
	Term *t = termList.first();
	while ( t ) {
		QValueList<Document> docs = t->documents;
		for ( docIt = docs.begin(); docIt != docs.end(); ++docIt ) {
			if ( maxList.findIndex( *docIt ) == -1 )
				maxList.append( *docIt );
		}
		t = termList.next();
	}
	return maxList;
}

void Index::buildMiniDict( const QString &str )
{
	if ( miniDict[ str ] )
		miniDict[ str ]->positions.append( wordNum );
	++wordNum;
}


};
