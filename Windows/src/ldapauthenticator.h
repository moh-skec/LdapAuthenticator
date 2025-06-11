// LdapAuthenticator.h
#ifndef LDAPAUTHENTICATOR_H
#define LDAPAUTHENTICATOR_H

#include <QMainWindow>
#include <QSettings>
#include <QScopedPointer>                // for QScopedPointer<Ui::LdapAuthenticator>
#include <windows.h>
#include <winldap.h>
#include <Winber.h>

namespace Ui {
class LdapAuthenticator;
}

class LdapAuthenticator : public QMainWindow
{
    Q_OBJECT

public:
    explicit LdapAuthenticator(QWidget *parent = nullptr);
    ~LdapAuthenticator() override;

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onConnectClicked();              // renamed for clarity
    void onLoginClicked();                // handle login pressed
    void togglePasswordVisibility();      // show/hide password

private:
    static constexpr auto KEY_HOST   = "host";
    static constexpr auto KEY_USERDN = "userDN";

    QScopedPointer<Ui::LdapAuthenticator> ui;  // RAII for UI :contentReference[oaicite:5]{index=5}
    QString m_host;
    int     m_port {389};
    QSettings m_settings;                       // application settings :contentReference[oaicite:6]{index=6}
    bool    m_connected {false};
    bool    m_passwordVisible {false};

    bool authenticate(const QString &userDN, const QString &password);
    bool searchAndDisplay(LDAP *ld, const QString &userDN);
    void showError(const QString &title, const QString &message);
    void displayLdapAttributes(LDAP *ld, LDAPMessage *msg);

    void initializeUi();

    void loadSettings();
    void saveSettings();
};

#endif // LDAPAUTHENTICATOR_H
