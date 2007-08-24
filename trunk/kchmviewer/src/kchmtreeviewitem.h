/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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

#ifndef CTREEVIEWITEM_H
#define CTREEVIEWITEM_H

#include <q3listview.h>
#include <q3valuevector.h>
//Added by qt3to4:
#include <QPixmap>

#include "libchmfile.h"

/**
@author Georgy Yunaev
*/
//! This is a list item used both in Index and Table Of Content trees
class KCHMIndTocItem : public Q3ListViewItem
{
	public:
		KCHMIndTocItem( Q3ListViewItem* parent, Q3ListViewItem* after, QString name, QString aurl, int image); 
		KCHMIndTocItem( Q3ListView* parent, Q3ListViewItem* after, QString name, QString url, int image);
		
		QString		getUrl() const;
		virtual void setOpen ( bool open );
		
	private:
		virtual void paintBranches ( QPainter * p, const QColorGroup & cg, int w, int y, int h );
		virtual void paintCell ( QPainter * p, const QColorGroup & cg, int column, int width, int align );
		virtual const QPixmap * pixmap( int i ) const;
		
		QString		url;
		int 		image_number;
};


class KCMSearchTreeViewItem : public Q3ListViewItem
{
	public:
		KCMSearchTreeViewItem (Q3ListView* parent, QString name, QString loc, QString url)
			: Q3ListViewItem (parent, name, loc)
		{
			this->url = url;
		}
	
		QString		getUrl() const	{ return url; }
		
	private:
		QString		url;
};


class KCHMSingleTreeViewItem : public Q3ListViewItem
{
	public:
		KCHMSingleTreeViewItem (Q3ListView* parent, QString name, QString url)
			: Q3ListViewItem (parent, name)
		{
			this->url = url;
		}
	
		QString		getUrl() const	{ return url; }
		
	private:
		QString		url;
};



void kchmFillListViewWithParsedData( Q3ListView * list, const Q3ValueVector< LCHMParsedEntry >& data, QMap<QString, KCHMIndTocItem*> * map );

#endif
