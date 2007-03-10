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

#include "kchmtreeviewitem.h"
#include "kchmmainwindow.h"
#include "kchmdialogchooseurlfromlist.h"
#include "iconstorage.h"


KCHMIndTocItem::KCHMIndTocItem( QListViewItem * parent, QListViewItem * after, QString name, QString aurl, int image) : QListViewItem(parent, after, name), url(aurl), image_number(image)
{
}

KCHMIndTocItem::KCHMIndTocItem( QListView * parent, QListViewItem * after, QString name, QString aurl, int image) : QListViewItem(parent, after, name), url(aurl), image_number(image)
{
}


const QPixmap * KCHMIndTocItem::pixmap( int i ) const
{
	int imagenum;

	if ( i || image_number == LCHMBookIcons::IMAGE_NONE || image_number == LCHMBookIcons::IMAGE_INDEX )
        return 0;

	if ( firstChild () )
	{
		if ( isOpen() )
			imagenum = (image_number == LCHMBookIcons::IMAGE_AUTO) ? 1 : image_number;
		else
			imagenum = (image_number == LCHMBookIcons::IMAGE_AUTO) ? 0 : image_number + 1;
	}
	else
		imagenum = (image_number == LCHMBookIcons::IMAGE_AUTO) ? 10 : image_number;

	return ::mainWindow->chmFile()->getBookIconPixmap( imagenum );
}


QString KCHMIndTocItem::getUrl( ) const
{
	if ( url.find ('|') == -1 )
		return url;

	// Create a dialog with URLs, and show it, so user can select an URL he/she wants.
	QStringList urls = QStringList::split ('|', url);
	QStringList titles;
	LCHMFile * xchm = ::mainWindow->chmFile();

	for ( unsigned int i = 0; i < urls.size(); i++ )
	{
		QString title = xchm->getTopicByUrl (urls[i]);
		
		if ( !title )
		{
			qWarning ("Could not get item name for url '%s'", urls[i].ascii());
			titles.push_back(QString::null);
		}
		else
			titles.push_back(title);
	}

	KCHMDialogChooseUrlFromList dlg (urls, titles, ::mainWindow);

	if ( dlg.exec() == QDialog::Accepted )
		return dlg.getSelectedItemUrl();

	return QString::null;
}


void KCHMIndTocItem::paintBranches( QPainter * p, const QColorGroup & cg, int w, int y, int h )
{
	if ( image_number != LCHMBookIcons::IMAGE_INDEX )
		QListViewItem::paintBranches(p, cg, w, y, h);
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
		QListViewItem::paintCell( p, cg, column, width, align );
		return;
	}

    QListViewItem::paintCell( p, newcg, column, width, align );
	newcg.setColor( QColorGroup::Text, c );
}


void KCHMIndTocItem::setOpen( bool open )
{
	if ( image_number != LCHMBookIcons::IMAGE_INDEX || open )
		QListViewItem::setOpen (open);
}

void kchmFillListViewWithParsedData( QListView * list, const QValueVector< LCHMParsedEntry >& data, QMap<QString, KCHMIndTocItem*> * map )
{
	QValueVector< KCHMIndTocItem *> lastchild;
	QValueVector< KCHMIndTocItem *> rootentry;	

	if ( map )
		map->clear();
	
	list->clear();	
	
	for ( unsigned int i = 0; i < data.size(); i++ )
	{
		unsigned int indent = data[i].indent;

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
			for ( unsigned int li = 0; li < data[i].urls.size(); li++ )
				map->insert( data[i].urls[li], item );
		}
		else
			item->setOpen( true );

		lastchild[indent] = item;
		rootentry[indent] = item;
	}		

	list->triggerUpdate();
/*	
	KCHMMainTreeViewItem * item;

				if ( !root_indent_offset_set )
				{
					root_indent_offset_set = true;
					root_indent_offset = indent;
					
					if ( root_indent_offset > 1 )
						qWarning("CHM has improper index; root indent offset is %d", root_indent_offset);
				}

				int real_indent = indent - root_indent_offset;
				QString url = urls.join ("|");

				if ( real_indent == 0 )
				{
					// New root entry
					item = new KCHMMainTreeViewItem (tree, lastchild[real_indent], name, url, imagenum);
					DEBUGPARSER(("<root object>: '%s', new rootentry %08X\n", name.ascii(), item));
				}
				else
				{
					// New non-root entry
					if ( !rootentry[real_indent-1] )
						qFatal("CHMFile::ParseAndFillTopicsTree: child entry \"%s\" indented as %d with no root entry!", name.ascii(), real_indent);

					item = new KCHMMainTreeViewItem (rootentry[real_indent-1], lastchild[real_indent], name, url,  imagenum);
					DEBUGPARSER(("<object>: '%s', indent %d, rootentry %08X, item %08X\n", name.ascii(), real_indent, rootentry[real_indent-1], item));
				}

				lastchild[real_indent] = item;
				rootentry[real_indent] = item;

				if ( asIndex  )
					rootentry[real_indent]->setOpen(true);

				// There are no 'titles' in index file
				if ( add2treemap  )
				{
					for ( unsigned int li = 0; li < urls.size(); li++ )
						m_treeUrlMap[urls[li]] = item;
				}
			}
			else
			{
				if ( !urls.isEmpty() )
					qDebug ("CHMFile::ParseAndFillTopicsTree: <object> tag with url \"%s\" is parsed, but name is empty.", urls[0].ascii());
				else
					qDebug ("CHMFile::ParseAndFillTopicsTree: <object> tag is parsed, but both name and url are empty.");	
			}

			name = QString::null;
			urls.clear();
			in_object = false;
			imagenum = defaultimagenum;
		}
		}
		else if ( tagword == "ul" ) // increase indent level
		{
			// Fix for buggy help files		
			if ( ++indent >= MAX_NEST_DEPTH )
				qFatal("CHMFile::ParseAndFillTopicsTree: max nest depth (%d) is reached, error in help file", MAX_NEST_DEPTH);

			lastchild[indent] = 0;
			rootentry[indent] = 0;
			
			// This intended to fix <ul><ul>, which was seen in some buggy chm files,
			// and brokes rootentry[indent-1] check
			int real_indent = indent - root_indent_offset;
			if ( real_indent > 1
						  && rootentry[real_indent - 1] == 0
						  && rootentry[real_indent - 2] != 0 )
			{
				rootentry[real_indent - 1] = rootentry[real_indent - 2];
				qWarning("Broken CHM index/content: tree autocorrection enabled.");
			}
						  
			DEBUGPARSER(("<ul>: new indent is %d, last rootentry was %08X\n", indent - root_indent_offset, rootentry[indent-1]));
		}
		else if ( tagword == "/ul" ) // decrease indent level
		{
			if ( --indent < root_indent_offset )
				indent = root_indent_offset;

			rootentry[indent] = 0;
			DEBUGPARSER(("</ul>: new intent is %d\n", indent - root_indent_offset));
		}

		pos = i;	
	}
	
	return true;
*/
}
