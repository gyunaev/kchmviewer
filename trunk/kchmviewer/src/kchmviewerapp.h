#ifndef KCHMVIEWERAPP_H
#define KCHMVIEWERAPP_H

#include <QApplication>
#include <QFileOpenEvent>

class KchmviewerApp : public QApplication
{
    Q_OBJECT
public:
    KchmviewerApp(int &argc, char **argv, int version= QT_VERSION);
    virtual ~KchmviewerApp();
    bool event(QEvent*);

private slots:
    void onTimer();

private:
    QString m_filePath;
    int m_nResend;
};

#endif // KCHMVIEWERAPP_H
