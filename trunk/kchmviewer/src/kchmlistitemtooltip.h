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

#ifndef INCLUDE_KCHMLISTITEMTOOLTIP_H
#define INCLUDE_KCHMLISTITEMTOOLTIP_H

#include "kde-qt.h"
#include "forwarddeclarations.h"


/**
@author tim
*/
//FIXME! porting
/*
class KCHMListItemTooltip : public QToolTip
{
	public:
    	KCHMListItemTooltip( KQListView *parent )
			: QToolTip( parent->viewport() ) { m_pParent = parent; }
		
		virtual ~KCHMListItemTooltip()	{};

		void maybeTip ( const QPoint & pos )
		{
			Q3ListViewItem *it = m_pParent->itemAt( pos );

			if ( !it )
				return;
			
      		// Get the section the mouse is in
			int section = m_pParent->header()->sectionAt (pos.x ());
			
			// Get the rect of the whole item (the row for the tip)
			QRect itemRect = m_pParent->itemRect( it );

			// Get the rect of the whole section (the column for the tip)
			QRect headerRect = m_pParent->header ()->sectionRect (section);
				
      		// "Intersect" row and column to get exact rect for the tip
			QRect destRect( headerRect.left (), itemRect.top(), headerRect.width(), itemRect.height() );

			int item_width = it->width( m_pParent->fontMetrics(), m_pParent, 0 )
					+ it->depth() * m_pParent->treeStepSize();
			
			if ( m_pParent->rootIsDecorated() )
				item_width += m_pParent->treeStepSize();
			
			if ( item_width > m_pParent->viewport()->width() )
				tip( destRect, it->text(0) );
		}
	
	private:
		KQListView *	m_pParent;
};
*/
#endif /* INCLUDE_KCHMLISTITEMTOOLTIP_H */
