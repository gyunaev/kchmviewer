/***************************************************************************
 *  Copyright (C) 2000-2005 Trolltech AS.                                  *
 *  Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com        *
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


#include <qfile.h>
#include <qdir.h>
#include <qstringlist.h>
#include <qdict.h>
#include <qapplication.h>

#include <ctype.h>

#include "kchmsearchengine_impl.h"
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
	lastWindowClosed = false;
	connect( qApp, SIGNAL( lastWindowClosed() ),
			 this, SLOT( setLastWinClosed() ) );
}

Index::Index( const QStringList &dl, const QString & )
	: QObject( 0, 0 ), dict( 20011 )
{
	docList = dl;
	lastWindowClosed = false;
	connect( qApp, SIGNAL( lastWindowClosed() ),
			 this, SLOT( setLastWinClosed() ) );
}

void Index::setLastWinClosed()
{
	lastWindowClosed = true;
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

bool Index::makeIndex()
{
	if ( docList.isEmpty() )
		return false;
	
	QStringList::Iterator it = docList.begin();
	int steps = docList.count() / 100;
	
	if ( !steps )
		steps++;
	
	int prog = 0;
	
	for ( int i = 0; it != docList.end(); ++it, ++i )
	{
		if ( lastWindowClosed )
			return false;

		parseDocument( *it, i );
		
		if ( i%steps == 0 )
		{
			prog++;
			emit indexingProgress( prog );
		}
	}
	
	return true;
}


void Index::insertInDict( const QString &str, int docNum )
{
	Entry *e = 0;
	if ( dict.count() )
		e = dict[ str ];
	
	if ( e )
	{
		if ( e->documents.first().docNumber != docNum )
			e->documents.prepend( Document( docNum, 1 ) );
		else
			e->documents.first().frequency++;
	}
	else
	{
		dict.insert( str, new Entry( docNum ) );
	}
}


bool Index::parseDocumentToStringlist( const QString & filename, QStringList & tokenlist )
{
	QString parsedbuf, parseentity;
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
	
	// State machine states
	enum state_t
	{
		STATE_OUTSIDE_TAGS,		// outside HTML tags; parse text
		STATE_IN_HTML_TAG,		// inside HTML tags; wait for end tag
		STATE_IN_QUOTES,		// inside HTML tags and inside quotes; wait for end quote (in var QuoteChar)
		STATE_IN_HTML_ENTITY,	// inside HTML entity; parse the entity
	};
	
	state_t state = STATE_OUTSIDE_TAGS;
	QChar QuoteChar; // used in STATE_IN_QUOTES
	
	for ( unsigned int j = 0; j < text.length(); j++ )
	{
		QChar ch = text[j];
		
		if ( state == STATE_IN_HTML_TAG )
		{
			// We are inside HTML tag.
			// Ignore everything until we see '>' (end of HTML tag) or quote char (quote start)
			if ( ch == '"' || ch == '\'' )
			{
				state = STATE_IN_QUOTES;
				QuoteChar = ch;
			}
			else if ( ch == '>' )
				state = STATE_OUTSIDE_TAGS;
				
			continue;
		}
		else if ( state == STATE_IN_QUOTES )
		{
			// We are inside quoted text inside HTML tag. 
			// Ignore everything until we see the quote character again
			if ( ch == QuoteChar )
				state = STATE_IN_HTML_TAG;
				
			continue;
		}
		else if ( state == STATE_IN_HTML_ENTITY )
		{
			// We are inside encoded HTML entity (like &nbsp;).
			// Collect to parsedbuf everything until we see ;
			if ( ch != ';' )
			{
				// get next character of this entity
				parseentity.append( ch );
				continue;
			}
			
			// The entity ended
			state = STATE_OUTSIDE_TAGS;
			
			// Don't we have a space?
			if ( parseentity.lower() != "nbsp" )
			{
				QString entity = ::mainWindow->chmFile()->impl()->decodeEntity( parseentity.lower() );
			
				if ( entity.isNull() )
				{
					qWarning( "Index::parseDocument: failed to decode entity &%s;", parsedbuf.ascii() );
					parsedbuf = QString::null;
					continue;
				}
			
				parsedbuf += entity;
				continue;
			}
			else
				ch = ' '; // We got a space, so treat it like it, and not add it to parsebuf
		}
		
		// 
		// Now process STATE_OUTSIDE_TAGS
		//
		
		// Check for start of HTML tag, and switch to STATE_IN_HTML_TAG if it is
		if ( ch == '<' )
		{
			state = STATE_IN_HTML_TAG;
			goto tokenize_buf;
		}
		
		// Check for start of HTML entity
		if ( ch == '&' )
		{
			state = STATE_IN_HTML_ENTITY;
			parseentity = QString::null;
			continue;
		}
		
		// Replace quote by ' - quotes are used in search window to set the phrase
		if ( ch == '"' )
			ch = '\'';
		
		// Ok, we have a valid character outside HTML tags, and probably some in buffer already.
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
				tokenlist.push_back( parsedbuf.lower() );
			
			tokenlist.push_back( ch.lower() );
			parsedbuf = QString::null;
			continue;
		}
		
tokenize_buf:		
		// Just add the word; it is most likely a space or terminated by tokenizer.
		if ( !parsedbuf.isEmpty() )
		{
			tokenlist.push_back( parsedbuf.lower() );
			parsedbuf = QString::null;
		}
	}
	
	// Add the last word if still here - for broken htmls.
	if ( !parsedbuf.isEmpty() )
		tokenlist.push_back( parsedbuf.lower() );
	
	return true;
}


void Index::parseDocument( const QString &filename, int docNum )
{
	QStringList terms;
	
	if ( !parseDocumentToStringlist( filename, terms ) )
		return;
	
	for ( unsigned int i = 0; i < terms.size(); i++ )
		insertInDict( terms[i], docNum );
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
	
	for( ; it.current(); ++it )
	{
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
	
	while ( !s.atEnd() )
	{
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
	for ( it = terms.begin(); it != terms.end(); ++it )
	{
		Entry *e = 0;
		
		if ( dict[ *it ] )
		{
			e = dict[ *it ];
			termList.append( new Term( *it, e->documents.count(), e->documents ) );
		}
		else
		{
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
	
	for ( ; t; t = termList.next() )
	{
		QValueList<Document> docs = t->documents;
		C = minDocs.begin();
		
		while ( C != minDocs.end() )
		{
			bool found = false;
			
			for ( It = docs.begin(); It != docs.end(); ++It )
			{
				if ( (*C).docNumber == (*It).docNumber )
				{
					(*C).frequency += (*It).frequency;
					found = true;
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
	
	if ( termSeq.isEmpty() )
	{
		for ( C = minDocs.begin(); C != minDocs.end(); ++C )
			results << docList[ (int)(*C).docNumber ];
		
		return results;
	}

	QString fileName;
	
	for ( C = minDocs.begin(); C != minDocs.end(); ++C )
	{
		fileName =  docList[ (int)(*C).docNumber ];
		
		if ( searchForPhrases( termSeq, seqWords, fileName ) )
			results << fileName;
	}
	
	return results;
}


bool Index::searchForPhrases( const QStringList &phrases, const QStringList &words, const QString &filename )
{
	QStringList parsed_document;
	
	if ( !parseDocumentToStringlist( filename, parsed_document ) )
		return false;

	miniDict.clear();
	
	// Initialize the dictionary with the words in phrase(s)
	for ( QStringList::ConstIterator cIt = words.begin(); cIt != words.end(); ++cIt )
		miniDict.insert( *cIt, new PosEntry( 0 ) );

	// Fill the dictionary with the words from the document
	unsigned int word_offset = 3;
	for ( QStringList::ConstIterator it = parsed_document.begin(); it != parsed_document.end(); it++, word_offset++ )
	{
		PosEntry * entry = miniDict[ *it ];
		
		if ( entry )
			entry->positions.append( word_offset );
	}
	
	// Dump it
/*	
	QDictIterator<PosEntry> it( miniDict );
	for( ; it.current(); ++it )
	{
		QString text( it.currentKey() );
		QValueList<uint> pos = miniDict[text]->positions;
		for ( unsigned int i = 1; i < pos.size(); i++ )
			text += " " + QString::number( pos[i] );
		
		qDebug( "%s", text.ascii());
	}
*/				
	
	QValueList<uint> first_word_positions;
	
	for ( QStringList::ConstIterator phrase_it = phrases.begin(); phrase_it != phrases.end(); phrase_it++ )
	{
		QStringList phrasewords = QStringList::split( ' ', *phrase_it );
		first_word_positions = miniDict[ phrasewords[0] ]->positions;
		
		for ( unsigned int j = 1; j < phrasewords.count(); ++j )
		{
			QValueList<uint> next_word_it = miniDict[ phrasewords[j] ]->positions;
			QValueList<uint>::iterator dict_it = first_word_positions.begin();
			
			while ( dict_it != first_word_positions.end() )
			{
				if ( next_word_it.find( *dict_it + 1 ) != next_word_it.end() )
				{
					(*dict_it)++;
					++dict_it;
				}
				else
					dict_it = first_word_positions.remove( dict_it );
			}
		}
	}
	
	if ( first_word_positions.count() )
		return true;
	
	return false;
}


};
