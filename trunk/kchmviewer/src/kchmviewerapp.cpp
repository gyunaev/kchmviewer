#include "kchmviewerapp.h"
#include "mainwindow.h"

KchmviewerApp::KchmviewerApp(int &argc, char **argv, int version)
    : QApplication(argc, argv, version)
{
}

KchmviewerApp::~KchmviewerApp()
{
}

bool KchmviewerApp::event(QEvent* ev)
{
    if (ev->type() == QEvent::FileOpen)
      {
        m_nResend = 0;
        m_filePath = static_cast<QFileOpenEvent*>(ev)->file();
        onTimer();
        return true;
    }
    return QApplication::event(ev);
}

void KchmviewerApp::onTimer()
{
    MainWindow *main;
    foreach (QWidget *widget, QApplication::topLevelWidgets())
    {
        main = dynamic_cast<MainWindow *>(widget);
        if (main != 0)
        {
            break;
        }
    }
    if (main == 0)
    {
        qWarning("resending %s", m_filePath.toStdString().c_str());
        if (m_nResend >= 30)
        {
            qWarning("aborting loading of %s", m_filePath.toStdString().c_str());
            return;
        }
        QTimer::singleShot(250, this, SLOT(onTimer()));
        ++m_nResend;
        return;
    }
    main->loadFile(m_filePath);
}
