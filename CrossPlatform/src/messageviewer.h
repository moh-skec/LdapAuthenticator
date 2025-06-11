#ifndef MESSAGEVIEWER_H
#define MESSAGEVIEWER_H

#include <QMessageBox>

class MessageViewer : public QMessageBox
{
public:
    MessageViewer();
    
    void showError(const QString &title, const QString &message);
    void showInfo(const QString &title, const QString &message);
    bool showQuestion(const QString &title, const QString &message);
};

#endif // MESSAGEVIEWER_H
