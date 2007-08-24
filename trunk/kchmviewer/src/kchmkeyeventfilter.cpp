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

#include "kchmkeyeventfilter.h"
//Added by qt3to4:
#include <QKeyEvent>
#include <QEvent>

KCHMKeyEventFilter	gKeyEventFilter;

KCHMKeyEventFilter::KCHMKeyEventFilter()
 : QObject()
{
	m_shiftPressed = false;
	m_ctrlPressed = false;
}

bool KCHMKeyEventFilter::eventFilter( QObject *, QEvent *e )
{
	// Handle KeyPress and KeyRelease events
	if ( e->type() == QEvent::KeyPress || e->type() == QEvent::KeyRelease )
	{
		bool * ptr = 0;
		QKeyEvent *k = (QKeyEvent *) e;
		
		// We're interested only in Shift and Control
		if ( k->key() == Qt::Key_Shift )
			ptr = &m_shiftPressed;
		else if ( k->key() == Qt::Key_Control )
			ptr = &m_ctrlPressed;
		
		// Set it
		if ( ptr )
			*ptr = e->type() == QEvent::KeyPress ? true : false;
	}

	return FALSE;	// Standard event processing
}
