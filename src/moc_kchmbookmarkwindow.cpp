/****************************************************************************
** KCHMBookmarkWindow meta object code from reading C++ file 'kchmbookmarkwindow.h'
**
** Created: Fri Apr 8 02:05:55 2005
**      by: The Qt MOC ($Id$)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#undef QT_NO_COMPAT
#include "kchmbookmarkwindow.h"
#include <qmetaobject.h>
#include <qapplication.h>

#include <private/qucomextra_p.h>
#if !defined(Q_MOC_OUTPUT_REVISION) || (Q_MOC_OUTPUT_REVISION != 26)
#error "This file was generated using the moc from 3.3.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

const char *KCHMBookmarkWindow::className() const
{
    return "KCHMBookmarkWindow";
}

QMetaObject *KCHMBookmarkWindow::metaObj = 0;
static QMetaObjectCleanUp cleanUp_KCHMBookmarkWindow( "KCHMBookmarkWindow", &KCHMBookmarkWindow::staticMetaObject );

#ifndef QT_NO_TRANSLATION
QString KCHMBookmarkWindow::tr( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMBookmarkWindow", s, c, QApplication::DefaultCodec );
    else
	return QString::fromLatin1( s );
}
#ifndef QT_NO_TRANSLATION_UTF8
QString KCHMBookmarkWindow::trUtf8( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMBookmarkWindow", s, c, QApplication::UnicodeUTF8 );
    else
	return QString::fromUtf8( s );
}
#endif // QT_NO_TRANSLATION_UTF8

#endif // QT_NO_TRANSLATION

QMetaObject* KCHMBookmarkWindow::staticMetaObject()
{
    if ( metaObj )
	return metaObj;
    QMetaObject* parentObject = QWidget::staticMetaObject();
    static const QUMethod slot_0 = {"onAddBookmarkPressed", 0, 0 };
    static const QUMethod slot_1 = {"onDelBookmarkPressed", 0, 0 };
    static const QUMethod slot_2 = {"onEditBookmarkPressed", 0, 0 };
    static const QUParameter param_slot_3[] = {
	{ 0, &static_QUType_ptr, "QListViewItem", QUParameter::In },
	{ 0, &static_QUType_varptr, "\x0e", QUParameter::In },
	{ 0, &static_QUType_int, 0, QUParameter::In }
    };
    static const QUMethod slot_3 = {"onDoubleClicked", 3, param_slot_3 };
    static const QMetaData slot_tbl[] = {
	{ "onAddBookmarkPressed()", &slot_0, QMetaData::Public },
	{ "onDelBookmarkPressed()", &slot_1, QMetaData::Private },
	{ "onEditBookmarkPressed()", &slot_2, QMetaData::Private },
	{ "onDoubleClicked(QListViewItem*,const QPoint&,int)", &slot_3, QMetaData::Private }
    };
    metaObj = QMetaObject::new_metaobject(
	"KCHMBookmarkWindow", parentObject,
	slot_tbl, 4,
	0, 0,
#ifndef QT_NO_PROPERTIES
	0, 0,
	0, 0,
#endif // QT_NO_PROPERTIES
	0, 0 );
    cleanUp_KCHMBookmarkWindow.setMetaObject( metaObj );
    return metaObj;
}

void* KCHMBookmarkWindow::qt_cast( const char* clname )
{
    if ( !qstrcmp( clname, "KCHMBookmarkWindow" ) )
	return this;
    return QWidget::qt_cast( clname );
}

bool KCHMBookmarkWindow::qt_invoke( int _id, QUObject* _o )
{
    switch ( _id - staticMetaObject()->slotOffset() ) {
    case 0: onAddBookmarkPressed(); break;
    case 1: onDelBookmarkPressed(); break;
    case 2: onEditBookmarkPressed(); break;
    case 3: onDoubleClicked((QListViewItem*)static_QUType_ptr.get(_o+1),(const QPoint&)*((const QPoint*)static_QUType_ptr.get(_o+2)),(int)static_QUType_int.get(_o+3)); break;
    default:
	return QWidget::qt_invoke( _id, _o );
    }
    return TRUE;
}

bool KCHMBookmarkWindow::qt_emit( int _id, QUObject* _o )
{
    return QWidget::qt_emit(_id,_o);
}
#ifndef QT_NO_PROPERTIES

bool KCHMBookmarkWindow::qt_property( int id, int f, QVariant* v)
{
    return QWidget::qt_property( id, f, v);
}

bool KCHMBookmarkWindow::qt_static_property( QObject* , int , int , QVariant* ){ return FALSE; }
#endif // QT_NO_PROPERTIES
