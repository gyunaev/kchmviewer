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

#include <qdir.h>

#include "qt34.h"

LIBCHMCString::LIBCHMCString()
{
}

LIBCHMCString::LIBCHMCString(const char *string)
{
#if defined (USE_QT_4)
	cs = QByteArray(string);
#else
	cs = QCString(string);
#endif
}


const char *LIBCHMCString::toCString() const
{
	return cs.data();
}


void LIBCHMCString::clear()
{
#if defined (USE_QT_4)
	cs = QByteArray();
#else
	cs = QCString();
#endif
}

bool LIBCHMCString::operator==(const QString &string) const
{
	return QString(cs) == string;
}

uint LIBCHMCString::length() const
{
	return cs.length();
}

bool LIBCHMCString::isEmpty() const
{
	return cs.isEmpty();
}

void LIBCHMCString::prepend(char c)
{
	cs = c + cs;
}

char LIBCHMCString::at(uint i) const
{
	return cs.at(i);
}

void LIBCHMCString::replace(uint index, uint len, const char *str)
{
	cs.replace(index, len, str);
}

void LIBCHMCString::remove(uint index, uint len)
{
	cs.remove(index, len);
}

LIBCHMCString LIBCHMCString::lower()
{
#if defined (USE_QT_4)
	return cs.toLower().data();
#else
	return cs.lower().data();
#endif
}



LIBCHMRegExp::LIBCHMRegExp(const QString &regexp)
{
	re = QRegExp(regexp);
}

int LIBCHMRegExp::search(const QString &str, int offset)
{
#if defined (USE_QT_4)
	return re.indexIn(str, offset);
#else
	return re.search(str, offset);
#endif
}

QString LIBCHMRegExp::cap(int nth)
{
	return re.cap(nth);
}

void LIBCHMRegExp::setMinimal(bool minimal)
{
	return re.setMinimal(minimal);
}

int LIBCHMRegExp::matchedLength() const
{
	return re.matchedLength();
}




LIBCHMString::LIBCHMString()
{
}

LIBCHMString::LIBCHMString(const QString &string)
{
	s = string;
}

LIBCHMString::LIBCHMString(const char *string)
{
	s = QString(string);
}

QString LIBCHMString::lower() const
{
#if defined (USE_QT_4)
	return s.toLower();
#else
	return s.lower();
#endif
}

const char *LIBCHMString::ascii() const
{
#if defined (USE_QT_4)
	return s.toAscii();
#else
	return s.ascii();
#endif
}

int LIBCHMString::find(char c, int index) const
{
#if defined (USE_QT_4)
	return s.indexOf(c, index);
#else
	return s.find(c, index);
#endif
}

int LIBCHMString::find(const QChar &c, int index) const
{
#if defined (USE_QT_4)
	return s.indexOf(c, index);
#else
	return s.find(c, index);
#endif
}

int LIBCHMString::find(const QString &string, int index, bool cs) const
{
#if defined (USE_QT_4)
	Qt::CaseSensitivity cse;
	if (cs) cse = Qt::CaseSensitive;
	else cse = Qt::CaseInsensitive;
	return s.indexOf(string, index, cse);
#else
	return s.find(string, index, cs);
#endif
}

int LIBCHMString::findRev(char c) const
{
#if defined (USE_QT_4)
	return s.lastIndexOf(c);
#else
	return s.findRev(c);
#endif
}

QChar LIBCHMString::at(uint i) const
{
	return s.at(i);
}

QString LIBCHMString::left(uint len) const
{
	return s.left(len);
}

LIBCHMString LIBCHMString::mid(uint index, uint len) const
{
	return s.mid(index, len);
}

bool LIBCHMString::isEmpty() const
{
	return s.isEmpty();
}

QString LIBCHMString::toString() const
{
	return s;
}

bool LIBCHMString::operator==(const QString &string) const
{
	return s == string;
}



QString LIBCHMDir::cleanDirPath(const QString &dir)
{
#if defined (USE_QT_4)
	return QDir::cleanPath(dir);
#else
	return QDir::cleanDirPath(dir);
#endif
}



bool LIBCHMStringList::contains(const QStringList &list, const QString &string)
{
	return list.contains(string);
}

QStringList LIBCHMStringList::split(const QRegExp &regexp, const QString &string)
{
#if defined (USE_QT_4)
	return string.split(regexp, QString::SkipEmptyParts);
#else
	return QStringList::split(regexp, string);
#endif
}
