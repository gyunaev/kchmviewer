/****************************************************************************
** KCHMSearchWindow meta object code from reading C++ file 'kchmsearchwindow.h'
**
** Created: Sat Apr 9 01:57:31 2005
**      by: The Qt MOC ($Id$)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#undef QT_NO_COMPAT
#include "kchmsearchwindow.h"
#include <qmetaobject.h>
#include <qapplication.h>

#include <private/qucomextra_p.h>
#if !defined(Q_MOC_OUTPUT_REVISION) || (Q_MOC_OUTPUT_REVISION != 26)
#error "This file was generated using the moc from 3.3.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

const char *KCHMSearchWindow::className() const
{
    return "KCHMSearchWindow";
}

QMetaObject *KCHMSearchWindow::metaObj = 0;
static QMetaObjectCleanUp cleanUp_KCHMSearchWindow( "KCHMSearchWindow", &KCHMSearchWindow::staticMetaObject );

#ifndef QT_NO_TRANSLATION
QString KCHMSearchWindow::tr( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMSearchWindow", s, c, QApplication::DefaultCodec );
    else
	return QString::fromLatin1( s );
}
#ifndef QT_NO_TRANSLATION_UTF8
QString KCHMSearchWindow::trUtf8( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMSearchWindow", s, c, QApplication::UnicodeUTF8 );
    else
	return QString::fromUtf8( s );
}
#endif // QT_NO_TRANSLATION_UTF8

#endif // QT_NO_TRANSLATION

QMetaObject* KCHMSearchWindow::staticMetaObject()
{
    if ( metaObj )
	return metaObj;
    QMetaObject* parentObject = QWidget::staticMetaObject();
    static const QUMethod slot_0 = {"onReturnPressed", 0, 0 };
    static const QUParameter param_slot_1[] = {
	{ 0, &static_QUType_ptr, "QListViewItem", QUParameter::In },
	{ 0, &static_QUType_varptr, "\x0e", QUParameter::In },
	{ 0, &static_QUType_int, 0, QUParameter::In }
    };
    static const QUMethod slot_1 = {"onDoubleClicked", 3, param_slot_1 };
    static const QMetaData slot_tbl[] = {
	{ "onReturnPressed()", &slot_0, QMetaData::Private },
	{ "onDoubleClicked(QListViewItem*,const QPoint&,int)", &slot_1, QMetaData::Private }
    };
    metaObj = QMetaObject::new_metaobject(
	"KCHMSearchWindow", parentObject,
	slot_tbl, 2,
	0, 0,
#ifndef QT_NO_PROPERTIES
	0, 0,
	0, 0,
#endif // QT_NO_PROPERTIES
	0, 0 );
    cleanUp_KCHMSearchWindow.setMetaObject( metaObj );
    return metaObj;
}

void* KCHMSearchWindow::qt_cast( const char* clname )
{
    if ( !qstrcmp( clname, "KCHMSearchWindow" ) )
	return this;
    return QWidget::qt_cast( clname );
}

bool KCHMSearchWindow::qt_invoke( int _id, QUObject* _o )
{
    switch ( _id - staticMetaObject()->slotOffset() ) {
    case 0: onReturnPressed(); break;
    case 1: onDoubleClicked((QListViewItem*)static_QUType_ptr.get(_o+1),(const QPoint&)*((const QPoint*)static_QUType_ptr.get(_o+2)),(int)static_QUType_int.get(_o+3)); break;
    default:
	return QWidget::qt_invoke( _id, _o );
    }
    return TRUE;
}

bool KCHMSearchWindow::qt_emit( int _id, QUObject* _o )
{
    return QWidget::qt_emit(_id,_o);
}
#ifndef QT_NO_PROPERTIES

bool KCHMSearchWindow::qt_property( int id, int f, QVariant* v)
{
    return QWidget::qt_property( id, f, v);
}

bool KCHMSearchWindow::qt_static_property( QObject* , int , int , QVariant* ){ return FALSE; }
#endif // QT_NO_PROPERTIES
