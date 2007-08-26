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

#include <qstringlist.h>
#include <qstyle.h>
#include <QPixmap>

#include "kchmtreeviewitem.h"
#include "kchmmainwindow.h"
#include "kchmdialogchooseurlfromlist.h"


KCHMIndTocItem::KCHMIndTocItem( QTreeWidgetItem * parent, QTreeWidgetItem * after, QString name, QString aurl, int image) 
	: QTreeWidgetItem( parent, after ), m_name(name), m_url(aurl), m_image_number(image)
{
}

KCHMIndTocItem::KCHMIndTocItem( QTreeWidget * parent, QTreeWidgetItem * after, QString name, QString aurl, int image) 
	: QTreeWidgetItem( parent, after ), m_name(name), m_url(aurl), m_image_number(image)
{
}

/*
const QPixmap * KCHMIndTocItem::pixmap( int i ) const
{
	int imagenum;

	if ( i || image_number == LCHMBookIcons::IMAGE_NONE || image_number == LCHMBookIcons::IMAGE_INDEX )
        return 0;

	// If the item has children, we change the book image to "open book", or next image automatically
	if ( childCount() )
	{
		if ( isExpanded() )
			imagenum = (image_number == LCHMBookIcons::IMAGE_AUTO) ? 1 : image_number;
		else
			imagenum = (image_number == LCHMBookIcons::IMAGE_AUTO) ? 0 : image_number + 1;
	}
	else
		imagenum = (image_number == LCHMBookIcons::IMAGE_AUTO) ? 10 : image_number;

	return ::mainWindow->chmFile()->getBookIconPixmap( imagenum );
}
*/

QString KCHMIndTocItem::getUrl( ) const
{
	if ( m_url.find ('|') == -1 )
		return m_url;

	// Create a dialog with URLs, and show it, so user can select an URL he/she wants.
	QStringList urls = QStringList::split ('|', m_url);
	QStringList titles;
	LCHMFile * xchm = ::mainWindow->chmFile();

	for ( int i = 0; i < urls.size(); i++ )
	{
		QString title = xchm->getTopicByUrl (urls[i]);
		
		if ( title.isEmpty() )
		{
			qWarning ("Could not get item name for url '%s'", urls[i].ascii());
			titles.push_back(QString::null);
		}
		else
			titles.push_back(title);
	}

	KCHMDialogChooseUrlFromList dlg( ::mainWindow );
	return dlg.getSelectedItemUrl( urls, titles );
}

/*
void KCHMIndTocItem::paintBranches( QPainter * p, const QColorGroup & cg, int w, int y, int h )
{
	if ( image_number != LCHMBookIcons::IMAGE_INDEX )
		Q3ListViewItem::paintBranches(p, cg, w, y, h);
	else
	{
		// Too bad that listView()->paintEmptyArea( p, QRect( 0, 0, w, h ) ) is protected. 
		// Taken from qt-x11-free-3.0.4/src/widgets/qlistview.cpp
    	QStyleOption opt( 0, 0 );
    	QStyle::SFlags how = QStyle::Style_Default | QStyle::Style_Enabled;

    	listView()->style().drawComplexControl( QStyle::CC_ListView,
				p, listView(), QRect( 0, 0, w, h ), cg,
				how, QStyle::SC_ListView, QStyle::SC_None,
				opt );
	}
}


void KCHMIndTocItem::paintCell( QPainter * p, const QColorGroup & cg, int column, int width, int align )
{
    QColorGroup newcg ( cg );
    QColor c = newcg.text();

	if ( url.find ('|') != -1 )
        newcg.setColor( QColorGroup::Text, Qt::red );
	else if ( url[0] == ':' )
        newcg.setColor( QColorGroup::Text, Qt::lightGray );
	else
	{
		Q3ListViewItem::paintCell( p, cg, column, width, align );
		return;
	}

    Q3ListViewItem::paintCell( p, newcg, column, width, align );
	newcg.setColor( QColorGroup::Text, c );
}
*/

void KCHMIndTocItem::setExpanded( bool open )
{
	if ( m_image_number != LCHMBookIcons::IMAGE_INDEX || open )
		QTreeWidgetItem::setExpanded( open );
}

void kchmFillListViewWithParsedData( QTreeWidget * list, const QVector< LCHMParsedEntry >& data, QMap<QString, KCHMIndTocItem*> * map )
{
	QVector< KCHMIndTocItem *> lastchild;
	QVector< KCHMIndTocItem *> rootentry;

	if ( map )
		map->clear();
	
	list->clear();	
	
	for ( int i = 0; i < data.size(); i++ )
	{
		int indent = data[i].indent;

		// Do we need to add another indent?
		if ( indent >= lastchild.size() )
		{
			lastchild.resize( indent + 1 );
			lastchild[indent] = 0;
		
			rootentry.resize( indent + 1 );
			rootentry[indent] = 0;
		}
	
		// Create the node
		KCHMIndTocItem * item;
		QString url = data[i].urls.join ("|");
		
		if ( indent == 0 )
			item = new KCHMIndTocItem( list, lastchild[indent], data[i].name, url, data[i].imageid );
		else
		{
			// New non-root entry. It is possible (for some buggy CHMs) that there is no previous entry: previoous entry had indent 1,
			// and next entry has indent 3. Backtracking it up, creating missing entries.
			if ( rootentry[indent-1] == 0 )
				qFatal("Child entry indented as %d with no root entry!", indent);

			item = new KCHMIndTocItem( rootentry[indent-1], lastchild[indent], data[i].name, url, data[i].imageid );
		}

		// Hack: if map is 0, we have index, so make it open
		if ( map )
		{
			for ( int li = 0; li < data[i].urls.size(); li++ )
				map->insert( data[i].urls[li], item );
		}
		else
			item->setExpanded( true );

		lastchild[indent] = item;
		rootentry[indent] = item;
	}		

	list->update();
}

KCMSearchTreeViewItem::KCMSearchTreeViewItem( const QString& name, const QString& loc, const QString& url )
	: QTableWidgetItem()
{
	m_name = name;
	m_loc = loc;
	m_url = url;
}

QString KCMSearchTreeViewItem::getUrl() const
{
	return m_url;
}

int KCHMIndTocItem::columnCount() const
{
	return 1;
}

QVariant KCHMIndTocItem::data(int column, int role) const
{
	int imagenum;

	if ( column != 0 )
		return QVariant();
	
	switch( role )
	{
		case Qt::DisplayRole:
			return m_name;
			
		case Qt::DecorationRole:
			if ( m_image_number != LCHMBookIcons::IMAGE_NONE 
			     && m_image_number != LCHMBookIcons::IMAGE_INDEX )
			{
				// If the item has children, we change the book image to "open book", or next image automatically
				if ( childCount() )
				{
					if ( isExpanded() )
						imagenum = (m_image_number == LCHMBookIcons::IMAGE_AUTO) ? 1 : m_image_number;
					else
						imagenum = (m_image_number == LCHMBookIcons::IMAGE_AUTO) ? 0 : m_image_number + 1;
				}
				else
					imagenum = (m_image_number == LCHMBookIcons::IMAGE_AUTO) ? 10 : m_image_number;
		
				const QPixmap *pix = ::mainWindow->chmFile()->getBookIconPixmap( imagenum );
				
				if ( !pix || pix->isNull() )
					abort();
				
				return *pix;
			}
			break;
	}
	
	return QVariant();
}
