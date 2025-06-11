#include "messageviewer.h"

MessageViewer::MessageViewer() = default;

void MessageViewer::showError(const QString &title, const QString &text)
{
    critical(this, title, text);
}

void MessageViewer::showInfo(const QString &title, const QString &text)
{
    information(this, title, text);
}

bool MessageViewer::showQuestion(const QString &title, const QString &message)
{
    return question(this, title, message, QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes;
}
