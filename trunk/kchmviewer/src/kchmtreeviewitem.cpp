/***************************************************************************
 *   Copyright (C) 2004-2005 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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

	return ::mainWindow->getChmFile()->getBookIconPixmap( imagenum );
}


QString KCHMIndTocItem::getUrl( ) const
{
	if ( url.find ('|') == -1 )
		return url;

	// Create a dialog with URLs, and show it, so user can select an URL he/she wants.
	QStringList urls = QStringList::split ('|', url);
	QStringList titles;
	LCHMFile * xchm = ::mainWindow->getChmFile();

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
