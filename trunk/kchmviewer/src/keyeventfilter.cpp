/**************************************************************************
 *  Kchmviewer - a portable CHM file viewer with the best support for     *
 *  the international languages                                           *
 *                                                                        *
 *  Copyright (C) 2004-2012 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  Please read http://www.kchmviewer.net/reportbugs.html if you want     *
 *  to report a bug. It lists things I need to fix it!                    *
 *                                                                        *
 *  This program is free software: you can redistribute it and/or modify  *
 *  it under the terms of the GNU General Public License as published by  *
 *  the Free Software Foundation, either version 3 of the License, or     *
 *  (at your option) any later version.                                   *
 *																	      *
 *  This program is distributed in the hope that it will be useful,       *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *  GNU General Public License for more details.                          *
 *                                                                        *
 *  You should have received a copy of the GNU General Public License     *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 **************************************************************************/

#include <QKeyEvent>
#include <QEvent>

#include "keyeventfilter.h"

KeyEventFilter	gKeyEventFilter;

KeyEventFilter::KeyEventFilter()
	: QObject()
{
	m_shiftPressed = false;
	m_ctrlPressed = false;
}

bool KeyEventFilter::eventFilter( QObject *, QEvent *e )
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
