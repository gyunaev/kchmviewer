/****************************************************************************
** KCHMIndexWindow meta object code from reading C++ file 'kchmindexwindow.h'
**
** Created: Sat Apr 9 01:19:36 2005
**      by: The Qt MOC ($Id$)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#undef QT_NO_COMPAT
#include "kchmindexwindow.h"
#include <qmetaobject.h>
#include <qapplication.h>

#include <private/qucomextra_p.h>
#if !defined(Q_MOC_OUTPUT_REVISION) || (Q_MOC_OUTPUT_REVISION != 26)
#error "This file was generated using the moc from 3.3.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

const char *KCHMIndexWindow::className() const
{
    return "KCHMIndexWindow";
}

QMetaObject *KCHMIndexWindow::metaObj = 0;
static QMetaObjectCleanUp cleanUp_KCHMIndexWindow( "KCHMIndexWindow", &KCHMIndexWindow::staticMetaObject );

#ifndef QT_NO_TRANSLATION
QString KCHMIndexWindow::tr( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMIndexWindow", s, c, QApplication::DefaultCodec );
    else
	return QString::fromLatin1( s );
}
#ifndef QT_NO_TRANSLATION_UTF8
QString KCHMIndexWindow::trUtf8( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMIndexWindow", s, c, QApplication::UnicodeUTF8 );
    else
	return QString::fromUtf8( s );
}
#endif // QT_NO_TRANSLATION_UTF8

#endif // QT_NO_TRANSLATION

QMetaObject* KCHMIndexWindow::staticMetaObject()
{
    if ( metaObj )
	return metaObj;
    QMetaObject* parentObject = QWidget::staticMetaObject();
    static const QUParameter param_slot_0[] = {
	{ "newvalue", &static_QUType_QString, 0, QUParameter::In }
    };
    static const QUMethod slot_0 = {"onTextChanged", 1, param_slot_0 };
    static const QUMethod slot_1 = {"onReturnPressed", 0, 0 };
    static const QUParameter param_slot_2[] = {
	{ 0, &static_QUType_ptr, "QListViewItem", QUParameter::In },
	{ 0, &static_QUType_varptr, "\x0e", QUParameter::In },
	{ 0, &static_QUType_int, 0, QUParameter::In }
    };
    static const QUMethod slot_2 = {"onDoubleClicked", 3, param_slot_2 };
    static const QMetaData slot_tbl[] = {
	{ "onTextChanged(const QString&)", &slot_0, QMetaData::Private },
	{ "onReturnPressed()", &slot_1, QMetaData::Private },
	{ "onDoubleClicked(QListViewItem*,const QPoint&,int)", &slot_2, QMetaData::Private }
    };
    metaObj = QMetaObject::new_metaobject(
	"KCHMIndexWindow", parentObject,
	slot_tbl, 3,
	0, 0,
#ifndef QT_NO_PROPERTIES
	0, 0,
	0, 0,
#endif // QT_NO_PROPERTIES
	0, 0 );
    cleanUp_KCHMIndexWindow.setMetaObject( metaObj );
    return metaObj;
}

void* KCHMIndexWindow::qt_cast( const char* clname )
{
    if ( !qstrcmp( clname, "KCHMIndexWindow" ) )
	return this;
    return QWidget::qt_cast( clname );
}

bool KCHMIndexWindow::qt_invoke( int _id, QUObject* _o )
{
    switch ( _id - staticMetaObject()->slotOffset() ) {
    case 0: onTextChanged((const QString&)static_QUType_QString.get(_o+1)); break;
    case 1: onReturnPressed(); break;
    case 2: onDoubleClicked((QListViewItem*)static_QUType_ptr.get(_o+1),(const QPoint&)*((const QPoint*)static_QUType_ptr.get(_o+2)),(int)static_QUType_int.get(_o+3)); break;
    default:
	return QWidget::qt_invoke( _id, _o );
    }
    return TRUE;
}

bool KCHMIndexWindow::qt_emit( int _id, QUObject* _o )
{
    return QWidget::qt_emit(_id,_o);
}
#ifndef QT_NO_PROPERTIES

bool KCHMIndexWindow::qt_property( int id, int f, QVariant* v)
{
    return QWidget::qt_property( id, f, v);
}

bool KCHMIndexWindow::qt_static_property( QObject* , int , int , QVariant* ){ return FALSE; }
#endif // QT_NO_PROPERTIES
