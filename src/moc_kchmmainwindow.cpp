/****************************************************************************
** KCHMMainWindow meta object code from reading C++ file 'kchmmainwindow.h'
**
** Created: Sat Apr 9 01:19:33 2005
**      by: The Qt MOC ($Id$)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#undef QT_NO_COMPAT
#include "kchmmainwindow.h"
#include <qmetaobject.h>
#include <qapplication.h>

#include <private/qucomextra_p.h>
#if !defined(Q_MOC_OUTPUT_REVISION) || (Q_MOC_OUTPUT_REVISION != 26)
#error "This file was generated using the moc from 3.3.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

const char *KCHMMainWindow::className() const
{
    return "KCHMMainWindow";
}

QMetaObject *KCHMMainWindow::metaObj = 0;
static QMetaObjectCleanUp cleanUp_KCHMMainWindow( "KCHMMainWindow", &KCHMMainWindow::staticMetaObject );

#ifndef QT_NO_TRANSLATION
QString KCHMMainWindow::tr( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMMainWindow", s, c, QApplication::DefaultCodec );
    else
	return QString::fromLatin1( s );
}
#ifndef QT_NO_TRANSLATION_UTF8
QString KCHMMainWindow::trUtf8( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMMainWindow", s, c, QApplication::UnicodeUTF8 );
    else
	return QString::fromUtf8( s );
}
#endif // QT_NO_TRANSLATION_UTF8

#endif // QT_NO_TRANSLATION

QMetaObject* KCHMMainWindow::staticMetaObject()
{
    if ( metaObj )
	return metaObj;
    QMetaObject* parentObject = KCHM_MAINWINDOW_CLASS::staticMetaObject();
    static const QUParameter param_slot_0[] = {
	{ "item", &static_QUType_ptr, "QListViewItem", QUParameter::In }
    };
    static const QUMethod slot_0 = {"onTreeClicked", 1, param_slot_0 };
    static const QUMethod slot_1 = {"addBookmark", 0, 0 };
    static const QUParameter param_slot_2[] = {
	{ "link", &static_QUType_QString, 0, QUParameter::In }
    };
    static const QUMethod slot_2 = {"onLinkClicked", 1, param_slot_2 };
    static const QUParameter param_slot_3[] = {
	{ "enabled", &static_QUType_bool, 0, QUParameter::In }
    };
    static const QUMethod slot_3 = {"onBackwardAvailable", 1, param_slot_3 };
    static const QUParameter param_slot_4[] = {
	{ "enabled", &static_QUType_bool, 0, QUParameter::In }
    };
    static const QUMethod slot_4 = {"onForwardAvailable", 1, param_slot_4 };
    static const QUMethod slot_5 = {"choose", 0, 0 };
    static const QUMethod slot_6 = {"print", 0, 0 };
    static const QUMethod slot_7 = {"backward", 0, 0 };
    static const QUMethod slot_8 = {"forward", 0, 0 };
    static const QUMethod slot_9 = {"gohome", 0, 0 };
    static const QUMethod slot_10 = {"about", 0, 0 };
    static const QUMethod slot_11 = {"aboutQt", 0, 0 };
    static const QUMethod slot_12 = {"runAutoTest", 0, 0 };
    static const QMetaData slot_tbl[] = {
	{ "onTreeClicked(QListViewItem*)", &slot_0, QMetaData::Public },
	{ "addBookmark()", &slot_1, QMetaData::Public },
	{ "onLinkClicked(const QString&)", &slot_2, QMetaData::Private },
	{ "onBackwardAvailable(bool)", &slot_3, QMetaData::Private },
	{ "onForwardAvailable(bool)", &slot_4, QMetaData::Private },
	{ "choose()", &slot_5, QMetaData::Private },
	{ "print()", &slot_6, QMetaData::Private },
	{ "backward()", &slot_7, QMetaData::Private },
	{ "forward()", &slot_8, QMetaData::Private },
	{ "gohome()", &slot_9, QMetaData::Private },
	{ "about()", &slot_10, QMetaData::Private },
	{ "aboutQt()", &slot_11, QMetaData::Private },
	{ "runAutoTest()", &slot_12, QMetaData::Private }
    };
    metaObj = QMetaObject::new_metaobject(
	"KCHMMainWindow", parentObject,
	slot_tbl, 13,
	0, 0,
#ifndef QT_NO_PROPERTIES
	0, 0,
	0, 0,
#endif // QT_NO_PROPERTIES
	0, 0 );
    cleanUp_KCHMMainWindow.setMetaObject( metaObj );
    return metaObj;
}

void* KCHMMainWindow::qt_cast( const char* clname )
{
    if ( !qstrcmp( clname, "KCHMMainWindow" ) )
	return this;
    return KCHM_MAINWINDOW_CLASS::qt_cast( clname );
}

bool KCHMMainWindow::qt_invoke( int _id, QUObject* _o )
{
    switch ( _id - staticMetaObject()->slotOffset() ) {
    case 0: onTreeClicked((QListViewItem*)static_QUType_ptr.get(_o+1)); break;
    case 1: addBookmark(); break;
    case 2: onLinkClicked((const QString&)static_QUType_QString.get(_o+1)); break;
    case 3: onBackwardAvailable((bool)static_QUType_bool.get(_o+1)); break;
    case 4: onForwardAvailable((bool)static_QUType_bool.get(_o+1)); break;
    case 5: choose(); break;
    case 6: print(); break;
    case 7: backward(); break;
    case 8: forward(); break;
    case 9: gohome(); break;
    case 10: about(); break;
    case 11: aboutQt(); break;
    case 12: runAutoTest(); break;
    default:
	return KCHM_MAINWINDOW_CLASS::qt_invoke( _id, _o );
    }
    return TRUE;
}

bool KCHMMainWindow::qt_emit( int _id, QUObject* _o )
{
    return KCHM_MAINWINDOW_CLASS::qt_emit(_id,_o);
}
#ifndef QT_NO_PROPERTIES

bool KCHMMainWindow::qt_property( int id, int f, QVariant* v)
{
    return KCHM_MAINWINDOW_CLASS::qt_property( id, f, v);
}

bool KCHMMainWindow::qt_static_property( QObject* , int , int , QVariant* ){ return FALSE; }
#endif // QT_NO_PROPERTIES
