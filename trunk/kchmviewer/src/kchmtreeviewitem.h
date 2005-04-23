/***************************************************************************
 *   Copyright (C) 2005 by Georgy Yunaev                                   *
 *   tim@krasnogorsk.ru                                                    *
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

#include <qlistview.h>

namespace KCHMImageType
{
	const int IMAGE_NONE = -1;
	const int IMAGE_AUTO = -2;
	const int IMAGE_INDEX = -3;
};

/**
@author Georgy Yunaev
*/
class KCHMMainTreeViewItem : public QListViewItem
{
public:
    KCHMMainTreeViewItem(QListViewItem* parent, QListViewItem* after, QString name, QString aurl, int image); 
	KCHMMainTreeViewItem(QListView* parent, QListViewItem* after, QString name, QString url, int image);
	
	QString		getUrl() const;
	virtual void setOpen ( bool open );
	
private:
//	virtual int width ( const QFontMetrics & fm, const QListView * lv, int c ) const;
	virtual void paintBranches ( QPainter * p, const QColorGroup & cg, int w, int y, int h );
	virtual void paintCell ( QPainter * p, const QColorGroup & cg, int column, int width, int align );
	virtual const QPixmap * pixmap( int i ) const;
	
	QString		url;
	int 		image_number;
};


class KCMSearchTreeViewItem : public QListViewItem
{
public:
	KCMSearchTreeViewItem (QListView* parent, QString name, QString loc, QString url)
		 : QListViewItem (parent, name, loc)
	{
		this->url = url;
	}

	QString		getUrl() const	{ return url; }
	
private:
	QString		url;
};


class KCHMSingleTreeViewItem : public QListViewItem
{
public:
	KCHMSingleTreeViewItem (QListView* parent, QString name, QString url)
		 : QListViewItem (parent, name)
	{
		this->url = url;
	}

	QString		getUrl() const	{ return url; }
	
private:
	QString		url;
};


class KCMBookmarkTreeViewItem : public QListViewItem
{
public:
	KCMBookmarkTreeViewItem (QListView* parent, QString name, QString url, int scroll_y)
		 : QListViewItem (parent, name), m_url(url), m_name(name), m_scroll_y(scroll_y) {};

	QString		m_url;
	QString		m_name;
	int			m_scroll_y;
};

#endif
