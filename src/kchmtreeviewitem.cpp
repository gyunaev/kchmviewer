
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

KCHMMainTreeViewItem::KCHMMainTreeViewItem( QListViewItem * parent, QListViewItem * after, QString name, QString aurl, bool hideimage) : QListViewItem(parent, after, name), url(aurl), do_not_show_image(hideimage)
{
	if ( !m_imageFolder )
		initImages();}


KCHMMainTreeViewItem::KCHMMainTreeViewItem( QListView * parent, QListViewItem * after, QString name, QString aurl, bool hideimage) : QListViewItem(parent, after, name), url(aurl), do_not_show_image(hideimage)
{
	if ( !m_imageFolder )
		initImages();
}

const QPixmap * KCHMMainTreeViewItem::pixmap( int i ) const
{
    if ( i || do_not_show_image )
        return 0;

	if ( firstChild () )
	{
		if ( isOpen() )
			return m_imageFolderOpened;
		else
			return m_imageFolder;
	}
	
	return m_imageHtmlPage;
}

void KCHMMainTreeViewItem::initImages( )
{
	m_imageFolder = new QPixmap (kchmicons::xpm_icon_folder);
	m_imageFolderOpened = new QPixmap (kchmicons::xpm_icon_folder_open);
	m_imageHtmlPage = new QPixmap (kchmicons::xpm_icon_htmlfile);
}
