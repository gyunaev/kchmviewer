/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
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
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.         *
 ***************************************************************************/

#include <qstringlist.h>
#include <qstyle.h>
#include <QPixmap>

#include "kchmtreeviewitem.h"
#include "kchmmainwindow.h"
#include "kchmdialogchooseurlfromlist.h"


KCHMIndTocItem::KCHMIndTocItem( QTreeWidgetItem * parent, QTreeWidgetItem * after, const QString& name, const QString& aurl, int image) 
	: QTreeWidgetItem( parent, after ), m_name(name), m_url(aurl), m_image_number(image)
{
}

KCHMIndTocItem::KCHMIndTocItem( QTreeWidget * parent, QTreeWidgetItem * after, const QString& name, const QString& aurl, int image) 
	: QTreeWidgetItem( parent, after ), m_name(name), m_url(aurl), m_image_number(image)
{
}


QString KCHMIndTocItem::getUrl( ) const
{
	if ( m_url.indexOf ('|') == -1 )
		return m_url;

	// Create a dialog with URLs, and show it, so user can select an URL he/she wants.
	QStringList urls = m_url.split( '|' );
	QStringList titles;
	LCHMFile * xchm = ::mainWindow->chmFile();

	for ( int i = 0; i < urls.size(); i++ )
	{
		QString title = xchm->getTopicByUrl (urls[i]);
		
		if ( title.isEmpty() )
		{
			qWarning( "Could not get item name for url '%s'", qPrintable( urls[i] ) );
			titles.push_back(QString::null);
		}
		else
			titles.push_back(title);
	}

	KCHMDialogChooseUrlFromList dlg( ::mainWindow );
	return dlg.getSelectedItemUrl( urls, titles );
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
		// Item name
		case Qt::DisplayRole:
			return m_name;
		
		// Item image
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
		
		// Item foreground color
		case Qt::ForegroundRole:
			// For Index URL it means that there is URL list in m_url
			if ( m_url.indexOf( '|' ) != -1 )
				return QBrush( QColor( Qt::red ) );
			// For Index URLs it means that this is "see also" URL
			else if ( !m_url.isEmpty() && m_url[0] == ':' )
				return QBrush( QColor( Qt::lightGray ) );
			break;
		
		case Qt::ToolTipRole:
		case Qt::WhatsThisRole:
			return m_name;
	}
	
	return QVariant();
}


void kchmFillListViewWithParsedData( QTreeWidget * list, const QVector< LCHMParsedEntry >& data, QMap<QString, KCHMIndTocItem*> * map )
{
	QVector< KCHMIndTocItem *> lastchild;
	QVector< KCHMIndTocItem *> rootentry;
	bool warning_shown = false;
	
	if ( map )
		map->clear();
	
	list->clear();	
	
	for ( int i = 0; i < data.size(); i++ )
	{
		int indent = data[i].indent;

		// Do we need to add another indent?
		if ( indent >= rootentry.size() )
		{
			int maxindent = rootentry.size() - 1;
			
			// Resize the arrays
			lastchild.resize( indent + 1 );
			rootentry.resize( indent + 1 );
			
			if ( indent > 0 && maxindent < 0 )
				qFatal("Invalid fisrt TOC indent (first entry has no root entry), aborting.");
			
			// And init the rest if needed
			if ( (indent - maxindent) > 1 )
			{
				if ( !warning_shown )
				{
					qWarning("Invalid TOC step, applying workaround. Results may vary.");
					warning_shown = true;
				}
				
				for ( int j = maxindent; j < indent; j++ )
				{
					lastchild[j+1] = lastchild[j];
					rootentry[j+1] = rootentry[j];
				}
			}
			
			lastchild[indent] = 0;
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
