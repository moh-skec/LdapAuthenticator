#include "LdapAuthenticator.h"
#include "ui_ldapauthenticator.h"

#include <QMessageBox>
#include <QSettings>
#include <QScopedPointer>
#include <QCloseEvent>

// RAII wrapper for LDAP*
struct LdapHandle {
    LDAP* ld;
    LdapHandle(LDAP* handle) : ld(handle) {}
    ~LdapHandle() { if (ld) ldap_unbind(ld); }
    LdapHandle(const LdapHandle&) = delete;
    LdapHandle(LdapHandle&& o) noexcept : ld(o.ld) { o.ld = nullptr; }
    LdapHandle& operator=(LdapHandle&& o) noexcept {
        if (this != &o) {
            if (ld) ldap_unbind(ld);
            ld = o.ld;
            o.ld = nullptr;
        }
        return *this;
    }
};

LdapAuthenticator::LdapAuthenticator(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::LdapAuthenticator)
    , m_port(389)
    , m_settings("YourOrg", "LdapAuthApp")
    , m_connected(false)
    , m_passwordVisible(false)
{
    ui->setupUi(this);
    initializeUi();
    loadSettings();
}

LdapAuthenticator::~LdapAuthenticator() = default;

void LdapAuthenticator::initializeUi()
{
    ui->lineEditPassword->setEchoMode(QLineEdit::Password);
    ui->pushButtonEye->setCheckable(true);
    ui->pushButtonEye->setCursor(Qt::ArrowCursor);
    ui->pushButtonEye->setIcon(QIcon(":icons/eye_closed.png"));

    connect(ui->pushButtonEye, &QPushButton::clicked,
            this, &LdapAuthenticator::togglePasswordVisibility);
    connect(ui->pushButtonConnect, &QPushButton::clicked,
            this, &LdapAuthenticator::onConnectClicked);
    connect(ui->pushButtonLogin, &QPushButton::clicked,
            this, &LdapAuthenticator::onLoginClicked);
    connect(ui->lineEditDN, &QLineEdit::returnPressed,
            ui->pushButtonLogin, &QPushButton::click);
    connect(ui->lineEditPassword, &QLineEdit::returnPressed,
            ui->pushButtonLogin, &QPushButton::click);
}

void LdapAuthenticator::closeEvent(QCloseEvent *event)
{
    saveSettings();
    QMainWindow::closeEvent(event);
}

void LdapAuthenticator::loadSettings()
{
    ui->lineEditHost->setText(
        m_settings.value(KEY_HOST, QString()).toString());
    ui->lineEditDN->setText(
        m_settings.value(KEY_USERDN, QString()).toString());
}

void LdapAuthenticator::saveSettings()
{
    m_settings.setValue(KEY_HOST, ui->lineEditHost->text());
    m_settings.setValue(KEY_USERDN, ui->lineEditDN->text());
}

void LdapAuthenticator::togglePasswordVisibility()
{
    m_passwordVisible = !m_passwordVisible;
    ui->lineEditPassword->setEchoMode(
        m_passwordVisible ? QLineEdit::Normal : QLineEdit::Password);
    ui->pushButtonEye->setIcon(QIcon(
        m_passwordVisible ? ":/icons/eye_opened.png" : ":/icons/eye_closed.png"));
}

void LdapAuthenticator::onConnectClicked()
{
    const QString host = ui->lineEditHost->text();
    if (m_connected && host == m_host) {
        QMessageBox::information(this, tr("Already connected"),
                                 tr("Already connected to %1!").arg(host));
        ui->labelStatus->setText(tr("ℹ️ Already connected"));
        return;
    }

    m_host = host;
    saveSettings();

    LdapHandle handle{ ldap_initW(
        reinterpret_cast<PWCHAR>(m_host.toStdWString().data()), m_port) };
    if (!handle.ld) {
        showError("Connection Error",
                  tr("Could not initialize LDAP connection to %1:%2").arg(m_host).arg(m_port));
        ui->labelStatus->setText(tr("❌ Connect failed"));
        return;
    }

    ULONG version = LDAP_VERSION3;
    ldap_set_optionW(handle.ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    LDAP_TIMEVAL timeout{5,0};
    if (ldap_connect(handle.ld, &timeout) != LDAP_SUCCESS) {
        showError("Connect Failed",
                  tr("ldap_connect failed to %1").arg(m_host));
        ui->labelStatus->setText(tr("❌ Connect failed"));
        return;
    }

    ui->labelStatus->setText(tr("✅ Connected to %1").arg(m_host));
    m_connected = true;
}

void LdapAuthenticator::onLoginClicked()
{
    ui->treeWidgetAttributes->clear();
    if (!m_connected) {
        onConnectClicked();
        if (!m_connected) return;
    }

    const QString userDN   = ui->lineEditDN->text();
    const QString password = ui->lineEditPassword->text();

    if (authenticate(userDN, password)) {
        ui->labelStatus->setText(tr("✅ Login successful"));
    } else {
        ui->labelStatus->setText(tr("❌ Login failed"));
    }
}

bool LdapAuthenticator::authenticate(const QString &userDN, const QString &password)
{
    LdapHandle handle{ ldap_initW(
        reinterpret_cast<PWCHAR>(m_host.toStdWString().data()), m_port) };
    if (!handle.ld) {
        showError("Connection Error",
                  tr("Could not reinitialize LDAP connection to %1:%2")
                      .arg(m_host).arg(m_port));
        return false;
    }

    ULONG version = LDAP_VERSION3;
    ldap_set_optionW(handle.ld, LDAP_OPT_PROTOCOL_VERSION, &version);


    std::wstring wuserDN = userDN.toStdWString();
    std::wstring wPassword = password.toStdWString();
    ULONG res = ldap_bind_sW(handle.ld,
                       &wuserDN[0],
                       &wPassword[0],
                       LDAP_AUTH_SIMPLE);
    if (res != LDAP_SUCCESS) {
        showError("Authentication Failed",
                  tr("Bind failed with code %1").arg(res));
        return false;
    }

    if (!searchAndDisplay(handle.ld, userDN)) {
        return false;
    }
    return true;
}

bool LdapAuthenticator::searchAndDisplay(LDAP *ld, const QString &userDN)
{
    static wchar_t attrDefault[] = L"defaultNamingContext";
    static wchar_t attrMulti[]   = L"namingContexts";
    static const PCWSTR rootAttrs[]    = { attrDefault, attrMulti, nullptr };

    LDAPMessage *rootMsg = nullptr;
    LDAP_TIMEVAL tv{5,0};

    ULONG rc = ldap_search_ext_sW(
        ld, nullptr, LDAP_SCOPE_BASE,
        const_cast<PWSTR>(L"(objectClass=*)"),
        const_cast<PWSTR*>(rootAttrs),
        0, nullptr, nullptr, &tv, 0, &rootMsg);
    if (rc != LDAP_SUCCESS || !rootMsg) {
        ldap_msgfree(rootMsg);
        return false;
    }

    // Extract whichever namingContext we got
    LDAPMessage *entry = ldap_first_entry(ld, rootMsg);
    PWCHAR *defVals   = ldap_get_valuesW(ld, entry, attrDefault);
    PWCHAR *multiVals = ldap_get_valuesW(ld, entry, attrMulti);

    std::wstring baseDN;
    if (defVals && defVals[0]) {
        baseDN = defVals[0];
    }
    else if (multiVals && multiVals[0]) {
        baseDN = multiVals[0];
    }
    else {
        ldap_value_freeW(defVals);
        ldap_value_freeW(multiVals);
        ldap_msgfree(rootMsg);
        showError(tr("LDAP Error"), tr("No namingContext found in RootDSE"));
        return false;
    }

    ldap_value_freeW(defVals);
    ldap_value_freeW(multiVals);
    ldap_msgfree(rootMsg);

    // 3) Build filter: group objects where member/userDN matches
    std::wstring wUser = userDN.toStdWString();
    std::wstring filter =
        L"(&"
        L"(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup)(objectClass=group))"
        L"(|(member=" + wUser + L")(uniqueMember=" + wUser + L"))"
                                               L")";

    // Attributes to retrieve: dn and ou (or any you like)
    static constexpr PCWSTR grpAttrs[] = { L"dn", L"ou", nullptr };

    LDAP_TIMEVAL timeout{5,0};

    LDAPMessage *grpMsg = nullptr;
    rc = ldap_search_ext_sW(
        ld,
        const_cast<PWSTR>(baseDN.data()),
        LDAP_SCOPE_SUBTREE,
        const_cast<PWSTR>(filter.c_str()),
        const_cast<PWSTR*>(grpAttrs),
        0, nullptr, nullptr,
        &timeout,
        0,
        &grpMsg);
    if (rc != LDAP_SUCCESS) {
        ldap_msgfree(grpMsg);
        return false;
    }

    displayLdapAttributes(ld, grpMsg);
    ldap_msgfree(grpMsg);

    LDAPMessage *pSearchResult = nullptr;
    PZPWSTR attrs = nullptr;

    ULONG res = ldap_search_ext_sW(
        ld,
        const_cast<PWCHAR>(wUser.c_str()),
        LDAP_SCOPE_SUBTREE,
        nullptr,
        attrs,
        0,
        nullptr, nullptr,
        &tv,
        0,
        &pSearchResult
        );

    if (res != LDAP_SUCCESS) {
        // convert code to human-readable and bail out
        std::wstring err = L"ldap_search_ext_sW failed, code=" + std::to_wstring(res);
        showError(tr("Search Error"), QString::fromStdWString(err));
        return false;
    }

    displayLdapAttributes(ld, pSearchResult);
    ldap_msgfree(pSearchResult);

    return true;
}


void LdapAuthenticator::showError(const QString &title, const QString &text)
{
    QMessageBox::critical(this, title, text);
}

void LdapAuthenticator::displayLdapAttributes(LDAP *ld, LDAPMessage *msg)
{
    if (!msg)
        return;

    for (LDAPMessage *e = ldap_first_entry(ld, msg);
         e;
         e = ldap_next_entry(ld, e))
    {
        wchar_t *dn = ldap_get_dnW(ld, e); // :contentReference[oaicite:4]{index=4}
        if (dn)
        {
            QString qdn = QString::fromWCharArray(dn);

            new QTreeWidgetItem(ui->treeWidgetAttributes, {"memberOf", qdn});
            ldap_memfreeW(dn);
        }

        // ---- Iterate attributes for this entry ----
        BerElement *ber = nullptr;
        for (PWCHAR a = ldap_first_attribute(ld, e, &ber);
             a;
             a = ldap_next_attribute(ld, e, ber))
        {
            QString name = QString::fromWCharArray(a);

            PWCHAR *vals = ldap_get_valuesW(ld, e, a); // :contentReference[oaicite:7]{index=7}
            if (vals)
            {
                for (int i = 0; vals[i]; ++i)
                {
                    QString val = QString::fromWCharArray(vals[i]);
                    new QTreeWidgetItem(ui->treeWidgetAttributes, {name, val});
                }
                ldap_value_freeW(vals);
            }
            ldap_memfreeW(a);
        }
        if (ber)
            ber_free(ber, 0);
    }
}
