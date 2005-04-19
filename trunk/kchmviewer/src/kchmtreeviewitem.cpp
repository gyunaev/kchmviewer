
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

#include "kchmtreeviewitem.h"
#include "kchmconfig.h"

#include "iconstorage.h"

// This GREATLY reduces the overhead of creating the image set for every list
static QPixmap	* m_imageFolder;
static QPixmap	* m_imageFolderOpened;
static QPixmap	* m_imageHtmlPage;

KCHMMainTreeViewItem::KCHMMainTreeViewItem( QListViewItem * parent, QListViewItem * after, QString name, QString aurl, int image) : QListViewItem(parent, after, name), url(aurl), image_number(image)
{
}

KCHMMainTreeViewItem::KCHMMainTreeViewItem( QListView * parent, QListViewItem * after, QString name, QString aurl, int image) : QListViewItem(parent, after, name), url(aurl), image_number(image)
{
}

const QPixmap * KCHMMainTreeViewItem::pixmap( int i ) const
{
    if ( i || image_number == KCHMImageType::IMAGE_NONE )
        return 0;

	if ( firstChild () )
	{
		if ( isOpen() )
			return (image_number == KCHMImageType::IMAGE_AUTO) ? 
				gIconStorage.getBookIconPixmap(1) : gIconStorage.getBookIconPixmap(image_number + 1);
		else
			return (image_number == KCHMImageType::IMAGE_AUTO) ? 
				gIconStorage.getBookIconPixmap(0) : gIconStorage.getBookIconPixmap(image_number);
	}
	
	return (image_number == KCHMImageType::IMAGE_AUTO) ? 
		gIconStorage.getBookIconPixmap(10) : gIconStorage.getBookIconPixmap(image_number);
}
