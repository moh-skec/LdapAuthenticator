#include "ldapauthenticator.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    LdapAuthenticator w;
    w.show();
    return a.exec();
}
