/****************************************************************************
** KCHMSearchAndViewToolbar meta object code from reading C++ file 'kchmsearchtoolbar.h'
**
** Created: Sat Apr 9 01:19:44 2005
**      by: The Qt MOC ($Id$)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#undef QT_NO_COMPAT
#include "kchmsearchtoolbar.h"
#include <qmetaobject.h>
#include <qapplication.h>

#include <private/qucomextra_p.h>
#if !defined(Q_MOC_OUTPUT_REVISION) || (Q_MOC_OUTPUT_REVISION != 26)
#error "This file was generated using the moc from 3.3.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

const char *KCHMSearchAndViewToolbar::className() const
{
    return "KCHMSearchAndViewToolbar";
}

QMetaObject *KCHMSearchAndViewToolbar::metaObj = 0;
static QMetaObjectCleanUp cleanUp_KCHMSearchAndViewToolbar( "KCHMSearchAndViewToolbar", &KCHMSearchAndViewToolbar::staticMetaObject );

#ifndef QT_NO_TRANSLATION
QString KCHMSearchAndViewToolbar::tr( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMSearchAndViewToolbar", s, c, QApplication::DefaultCodec );
    else
	return QString::fromLatin1( s );
}
#ifndef QT_NO_TRANSLATION_UTF8
QString KCHMSearchAndViewToolbar::trUtf8( const char *s, const char *c )
{
    if ( qApp )
	return qApp->translate( "KCHMSearchAndViewToolbar", s, c, QApplication::UnicodeUTF8 );
    else
	return QString::fromUtf8( s );
}
#endif // QT_NO_TRANSLATION_UTF8

#endif // QT_NO_TRANSLATION

QMetaObject* KCHMSearchAndViewToolbar::staticMetaObject()
{
    if ( metaObj )
	return metaObj;
    QMetaObject* parentObject = QToolBar::staticMetaObject();
    static const QUMethod slot_0 = {"onReturnPressed", 0, 0 };
    static const QUParameter param_slot_1[] = {
	{ 0, &static_QUType_QString, 0, QUParameter::In }
    };
    static const QUMethod slot_1 = {"onTextChanged", 1, param_slot_1 };
    static const QUMethod slot_2 = {"onBtnPrev", 0, 0 };
    static const QUMethod slot_3 = {"onBtnNext", 0, 0 };
    static const QUMethod slot_4 = {"onBtnFontInc", 0, 0 };
    static const QUMethod slot_5 = {"onBtnFontDec", 0, 0 };
    static const QUMethod slot_6 = {"onBtnViewSource", 0, 0 };
    static const QUMethod slot_7 = {"onBtnAddBookmark", 0, 0 };
    static const QUParameter param_slot_8[] = {
	{ "id", &static_QUType_int, 0, QUParameter::In }
    };
    static const QUMethod slot_8 = {"onMenuActivated", 1, param_slot_8 };
    static const QMetaData slot_tbl[] = {
	{ "onReturnPressed()", &slot_0, QMetaData::Private },
	{ "onTextChanged(const QString&)", &slot_1, QMetaData::Private },
	{ "onBtnPrev()", &slot_2, QMetaData::Private },
	{ "onBtnNext()", &slot_3, QMetaData::Private },
	{ "onBtnFontInc()", &slot_4, QMetaData::Private },
	{ "onBtnFontDec()", &slot_5, QMetaData::Private },
	{ "onBtnViewSource()", &slot_6, QMetaData::Private },
	{ "onBtnAddBookmark()", &slot_7, QMetaData::Private },
	{ "onMenuActivated(int)", &slot_8, QMetaData::Private }
    };
    metaObj = QMetaObject::new_metaobject(
	"KCHMSearchAndViewToolbar", parentObject,
	slot_tbl, 9,
	0, 0,
#ifndef QT_NO_PROPERTIES
	0, 0,
	0, 0,
#endif // QT_NO_PROPERTIES
	0, 0 );
    cleanUp_KCHMSearchAndViewToolbar.setMetaObject( metaObj );
    return metaObj;
}

void* KCHMSearchAndViewToolbar::qt_cast( const char* clname )
{
    if ( !qstrcmp( clname, "KCHMSearchAndViewToolbar" ) )
	return this;
    return QToolBar::qt_cast( clname );
}

bool KCHMSearchAndViewToolbar::qt_invoke( int _id, QUObject* _o )
{
    switch ( _id - staticMetaObject()->slotOffset() ) {
    case 0: onReturnPressed(); break;
    case 1: onTextChanged((const QString&)static_QUType_QString.get(_o+1)); break;
    case 2: onBtnPrev(); break;
    case 3: onBtnNext(); break;
    case 4: onBtnFontInc(); break;
    case 5: onBtnFontDec(); break;
    case 6: onBtnViewSource(); break;
    case 7: onBtnAddBookmark(); break;
    case 8: onMenuActivated((int)static_QUType_int.get(_o+1)); break;
    default:
	return QToolBar::qt_invoke( _id, _o );
    }
    return TRUE;
}

bool KCHMSearchAndViewToolbar::qt_emit( int _id, QUObject* _o )
{
    return QToolBar::qt_emit(_id,_o);
}
#ifndef QT_NO_PROPERTIES

bool KCHMSearchAndViewToolbar::qt_property( int id, int f, QVariant* v)
{
    return QToolBar::qt_property( id, f, v);
}

bool KCHMSearchAndViewToolbar::qt_static_property( QObject* , int , int , QVariant* ){ return FALSE; }
#endif // QT_NO_PROPERTIES
