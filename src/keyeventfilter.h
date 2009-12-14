/**************************************************************************
 *  Kchmviewer - a CHM file viewer with broad language support            *
 *  Copyright (C) 2004-2010 George Yunaev, kchmviewer@ulduzsoft.com       *
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

#ifndef KEYEVENTFILTER_H
#define KEYEVENTFILTER_H

#include <QObject>
#include <QEvent>


/*!*
 * This class must be installed as a global event handler. Its responsibility
 * is to intercept keyboard events, and store the Shift and Ctrl keys state information.
 * Unfortunately it seems to be the only way to do it in Qt.
 */
class KeyEventFilter : public QObject
{
	public:
		KeyEventFilter();

		bool	isShiftPressed() const	{	return m_shiftPressed;	}
		bool	isCtrlPressed() const	{	return m_ctrlPressed;	}
		
	private:
		bool	eventFilter( QObject *, QEvent *e );
		
		bool	m_shiftPressed;
		bool	m_ctrlPressed;
};

extern KeyEventFilter	gKeyEventFilter;

#endif /* INCLUDE_KCHMKEYEVENTFILTER_H */
