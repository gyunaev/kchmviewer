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

#include <QKeyEvent>
#include <QEvent>

#include "kchmkeyeventfilter.h"

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
