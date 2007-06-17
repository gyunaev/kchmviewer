/***************************************************************************
 *   Copyright (C) 2007 by Albert Astals Cid, aacid@kde.org                *
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

#ifndef INCLUDE_QT34_H
#define INCLUDE_QT34_H

#include <qregexp.h>
#include <qstring.h>

// Qt3/Qt4 compatibility: in Qt3 QVector stores pointers, not values - so QValueVector should be used. 
// In Qt4 QVector stores values, so we can use QVector
#if defined (USE_QT_4)
	#define	LIBCHMVector	QVector
#else
#include <qvaluevector.h>
	#define	LIBCHMVector	QValueVector
#endif

#if defined (USE_QT_4)
	#define	LIBCHMMemArray	QVector
#else
	#define	LIBCHMMemArray	QMemArray
#endif

class LIBCHMCString
{
	public:
		LIBCHMCString();
		LIBCHMCString(const char *string);
		
		const char *toCString() const;
		
		void clear();
		
		bool operator==(const QString &string) const;
		uint length() const;
		bool isEmpty() const;
		void prepend(char c);
		char at(uint i) const;
		void replace(uint index, uint len, const char *str);
		void remove(uint index, uint len);
		LIBCHMCString lower();
	
	private:
#if defined (USE_QT_4)
		QByteArray cs;
#else
		QCString cs;
#endif
};

class LIBCHMRegExp
{
	public:
		LIBCHMRegExp(const QString &regexp);
		
		int search(const QString &str, int offset = 0);
		QString cap(int nth);
		void setMinimal(bool minimal);
		int matchedLength() const;
	
	private:
		QRegExp re;
};

class LIBCHMString
{
	public:
		LIBCHMString();
		LIBCHMString(const QString &string);
		LIBCHMString(const char *string);
		
		QString lower() const;
		const char *ascii() const;
		int find(char c, int index = -1) const;
		int find(const QChar &c, int index) const;
		int find(const QString &string, int index, bool cs) const;
		int findRev(char c) const;
		QChar at(uint i) const;
		QString left(uint len) const;
		LIBCHMString mid(uint index, uint len = 0xffffffff) const;
		bool isEmpty() const;
		
		QString toString() const;
		
		bool operator==(const QString &string) const;
	
	private:
		QString s;
};

class LIBCHMDir
{
	public:
		static QString cleanDirPath(const QString &dir);
};

class LIBCHMStringList
{
	public:
		static bool contains(const QStringList &list, const QString &string);
		static QStringList split(const QRegExp &regexp, const QString &string);
};

#endif
