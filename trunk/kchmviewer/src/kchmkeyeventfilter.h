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

#ifndef INCLUDE_KCHMKEYEVENTFILTER_H
#define INCLUDE_KCHMKEYEVENTFILTER_H

#include <QObject>
#include <QEvent>


/*!*
 * This class must be installed as a global event handler. Its responsibility
 * is to intercept keyboard events, and store the Shift and Ctrl keys state information.
 * Unfortunately it seems to be the only way to do it in Qt.
 */
class KCHMKeyEventFilter : public QObject
{
	public:
    	KCHMKeyEventFilter();

		bool	isShiftPressed() const	{	return m_shiftPressed;	}
		bool	isCtrlPressed() const	{	return m_ctrlPressed;	}
		
	private:
		bool	eventFilter( QObject *, QEvent *e );
		
		bool	m_shiftPressed;
		bool	m_ctrlPressed;
};

extern KCHMKeyEventFilter	gKeyEventFilter;

#endif /* INCLUDE_KCHMKEYEVENTFILTER_H */
