#include "ldapauthenticator.h"
#include "ui_ldapauthenticator.h"

#include "attributedetailsdialog.h"

#include <QScreen>
#include <QTimeZone>
#include <QFileDialog>

LdapAuthenticator::LdapAuthenticator(QWidget *parent)
    : QMainWindow(parent), LdapHandler(),
      ui(new Ui::LdapAuthenticator()), // NOSONAR
      m_port(636),
      m_settings("YourOrg", "LdapAuthApp"), m_passwordVisible(false)
{
    ui->setupUi(this);
    initializeUi();
    loadSettings();
}

LdapAuthenticator::~LdapAuthenticator()
{
    delete ui; // NOSONAR
    ldapUnbind();
    saveSettings();
}

void LdapAuthenticator::initializeUi()
{
    ui->lineEditPassword->setEchoMode(QLineEdit::Password);
    ui->pushButtonEye->setCheckable(true);
    ui->pushButtonEye->setCursor(Qt::ArrowCursor);
    ui->pushButtonEye->setIcon(QIcon(":/icons/eye_closed.png"));
    ui->widgetHome->hide();

    connect(ui->pushButtonCA, &QPushButton::clicked,
            this, &LdapAuthenticator::onCAClicked);
    connect(ui->pushButtonEye, &QPushButton::clicked,
            this, &LdapAuthenticator::togglePasswordVisibility);
    connect(ui->pushButtonLogin, &QPushButton::clicked,
            this, &LdapAuthenticator::onLoginClicked);
    connect(ui->pushButtonLogout, &QPushButton::clicked,
            this, &LdapAuthenticator::onLogoutClicked);
    connect(ui->pushButtonChangePassword, &QPushButton::clicked,
            this, &LdapAuthenticator::onChangePasswordClicked);
    connect(ui->lineEditUPN, &QLineEdit::returnPressed,
            ui->pushButtonLogin, &QPushButton::click);
    connect(ui->lineEditPassword, &QLineEdit::returnPressed,
            ui->pushButtonLogin, &QPushButton::click);
    connect(ui->treeWidgetAttributes, &QTreeWidget::itemDoubleClicked,
            this, &LdapAuthenticator::onTreeWidgetAttributesItemDoubleClicked);
}

void LdapAuthenticator::onCAClicked()
{
    QDir prevDir = QString::fromUtf8(KEY_CA_FILE_PATH);
    if (!prevDir.cdUp() || !prevDir.exists()) {
        prevDir = QDir::home();
    }

    QString filePath = QFileDialog::getOpenFileName(
        this,
        "Select CA Certificate",
        prevDir.absolutePath(),
        "Certificate Files (*.pem *.cer *.crt);;All Files (*)"
    );

    if (!filePath.isEmpty()) {
        ui->lineEditCA->setText(filePath);
    }
}

void LdapAuthenticator::togglePasswordVisibility()
{
    m_passwordVisible = !m_passwordVisible;
    ui->lineEditPassword->setEchoMode(
        m_passwordVisible ? QLineEdit::Normal : QLineEdit::Password);
    ui->pushButtonEye->setIcon(QIcon(
        m_passwordVisible ? ":/icons/eye_opened.png" : ":/icons/eye_closed.png"));
}

void LdapAuthenticator::onLoginClicked()
{
    ui->treeWidgetAttributes->clear();

    // Get host from UI and update member
    QString host = ui->lineEditHost->text();
    QString hostUtf8 = host.toUtf8().constData();
    setUri(QString("ldaps://%1:%2").arg(hostUtf8, QString::number(m_port)));

    QString caFilePath = ui->lineEditCA->text();
    setCaFilePath(caFilePath);

    saveSettings();

    if (ldapInit() != LDAP_SUCCESS || ldapConnect() != LDAP_SUCCESS)
        return;

    setUpn(ui->lineEditUPN->text());
    const QString password = ui->lineEditPassword->text();

    if (authenticate(getUpn(), password))
        showHomeAndGrow();
}

void LdapAuthenticator::onLogoutClicked()
{
    if (getMessageViewer().showQuestion("Confirm Logout",
                                        QString("Are you sure you want to log out as %1?").arg(getUpn())))
        restoreOriginalSize();
}

void LdapAuthenticator::onTreeWidgetAttributesItemDoubleClicked(const QTreeWidgetItem *item, int column)
{
    Q_UNUSED(column)
    QString attr = item->text(0);
    QString value = item->text(1);
    QString desc = item->data(0, DescriptionRole).toString();

    AttributeDetailsDialog dialog(attr, value, desc, this);
    dialog.exec();
}

void LdapAuthenticator::onChangePasswordClicked()
{
    ldapPasswd(this);
}

void LdapAuthenticator::loadSettings()
{
    ui->lineEditHost->setText(
        m_settings.value(KEY_HOST, QString()).toString());
    ui->lineEditCA->setText(
        m_settings.value(KEY_CA_FILE_PATH, QString()).toString());
    ui->lineEditUPN->setText(
        m_settings.value(KEY_USERPN, QString()).toString());
}

void LdapAuthenticator::saveSettings()
{
    m_settings.setValue(KEY_HOST, ui->lineEditHost->text());
    m_settings.setValue(KEY_CA_FILE_PATH, ui->lineEditCA->text());
    m_settings.setValue(KEY_USERPN, ui->lineEditUPN->text());
}

void LdapAuthenticator::showHomeAndGrow()
{
    ui->widgetLogin->hide();
    ui->widgetHome->show();

    m_originalGeometry = geometry();

    // Desired new size
    const QSize newSize(560, 346);

    // Center window on primary screen
    if (auto screen = QGuiApplication::primaryScreen())
    {
        QRect screenGeo = screen->availableGeometry();
        QPoint newTopLeft(
            screenGeo.center().x() - newSize.width() / 2,
            screenGeo.center().y() - newSize.height() / 2);
        setGeometry(QRect(newTopLeft, newSize));
    }
    else
    {
        resize(newSize);
    }
}

void LdapAuthenticator::restoreOriginalSize()
{
    ui->widgetHome->hide();
    ui->widgetLogin->show();

    if (m_originalGeometry.isValid())
    {
        setGeometry(m_originalGeometry);
    }
}

bool LdapAuthenticator::authenticate(const QString &userPN, const QString &password)
{
    if (ldapBind(password) != LDAP_SUCCESS)
        return false;
    return searchAndDisplay(userPN);
}

bool LdapAuthenticator::searchAndDisplay(const QString &userPN)
{
    // Convert UPN to BaseDN and prepare filter
    QByteArray baseDn = upnToBaseDN(userPN).toUtf8();
    QByteArray filter = QString("(userPrincipalName=%1)").arg(userPN).toUtf8();

    setUserDn(baseDn);

    // Search for the user entry
    LDAPMessage *msg = nullptr;
    if (int rc = ldapSearch(baseDn, LDAP_SCOPE_SUBTREE, filter, {"*"}, &msg);
        rc != LDAP_SUCCESS)
    {
        if (msg)
            ldap_msgfree(msg);

        return false;
    }

    LDAPMessage *entry = ldap_first_entry(getLdapHandle(), msg);
    if (!entry)
    {
        getMessageViewer().showError("No Entries",
                                     QString("No LDAP entries found for %1").arg(userPN));
        ldap_msgfree(msg);
        return false;
    }

    bool ok = displayLdapProperties(entry);
    ldap_msgfree(msg);
    return ok;
}

QString LdapAuthenticator::upnToBaseDN(const QString &upn)
{
    qsizetype atPos = upn.indexOf('@');
    if (atPos < 0)
        return {};

    const QString domain = upn.mid(atPos + 1);
    const QStringList parts = domain.split('.', Qt::SkipEmptyParts);

    QStringList dcChunks;
    for (const QString &part : parts)
        dcChunks << "DC=" + part;

    return dcChunks.join(',');
}

// Main display function: shows LDAP properties in a tree widget
bool LdapAuthenticator::displayLdapProperties(LDAPMessage *msg)
{
    // Prepare the attribute tree with 2 columns
    ui->treeWidgetAttributes->clear();
    ui->treeWidgetAttributes->setColumnCount(2);
    ui->treeWidgetAttributes->setHeaderLabels({QString("Attribute"), QString("Value")});
    QHeaderView *header = ui->treeWidgetAttributes->header();
    header->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(1, QHeaderView::Stretch);

    // Obtain subschema DN from settings or fetch & save if missing
    QString subschemaDN = m_settings.value(KEY_SUBSCHEMA_DN).toString();
    if (subschemaDN.isEmpty())
    {
        subschemaDN = fetchSchemaNamingContext();
        if (subschemaDN.isEmpty())
        {
            qWarning() << "Failed to fetch schema naming context";
            return false;
        }
        m_settings.setValue(KEY_SUBSCHEMA_DN, subschemaDN);
    }

    // Collect attributes and password info
    QSet<QString> attrNames;
    bool mustPwdChange = false;
    QString newExpireStr;
    collectAttributesAndCheckPassword(msg, attrNames, mustPwdChange, newExpireStr);
    if (attrNames.isEmpty())
    {
        getMessageViewer().showError("No Attributes Found", "No attributes found for the user.");
        return false;
    }

    

    if (mustPwdChange && !handlePasswordChange(newExpireStr))
    {
        ui->treeWidgetAttributes->clear();
        return false;
    }


    // Manage attribute descriptions (descMap)
    QVariant v = m_settings.value(KEY_DESC_MAP);
    QVariantMap descMap = v.isValid()
                              ? v.value<QVariantMap>()
                              : QVariantMap();

    // Determine missing attributes needing descriptions
    QSet<QString> missing = attrNames;
    for (auto it = descMap.constBegin(); it != descMap.constEnd(); ++it)
        missing.remove(it.key());

    if (!missing.isEmpty())
    {
        QVariantMap fetched;
        if (!subschemaDN.isEmpty() && fetchAttributeDescriptions(subschemaDN, missing, fetched))
        {
            for (auto it = fetched.constBegin(); it != fetched.constEnd(); ++it)
                descMap.insert(it.key(), it.value());
            m_settings.setValue(KEY_DESC_MAP, QVariant::fromValue(descMap));
        }
    }

    populateAttributeTree(msg, descMap, newExpireStr);
    ui->treeWidgetAttributes->expandAll();
    return true;
}

void LdapAuthenticator::collectAttributesAndCheckPassword(LDAPMessage *msg, QSet<QString> &attrNames, bool &mustPwdChange, QString &newExpireStr)
{
    BerElement *ber = nullptr;
    auto processAttribute = [&](const QString &attribute, berval **vals)
    {
        attrNames.insert(attribute.toLower());
        if (!vals)
            return;
        for (int i = 0; vals[i] != nullptr; ++i)
        {
            QString value = QString::fromUtf8(vals[i]->bv_val, vals[i]->bv_len);
            handleAttributeValue(attribute, value, mustPwdChange);
        }
        ldap_value_free_len(vals);
    };

    for (char *attr = ldap_first_attribute(getLdapHandle(), msg, &ber);
         attr != nullptr;
         attr = ldap_next_attribute(getLdapHandle(), msg, ber))
    {
        QString attribute = QString::fromUtf8(attr);
        berval **vals = ldap_get_values_len(getLdapHandle(), msg, attr);
        processAttribute(attribute, vals);
        ldap_memfree(attr);
    }
    if (ber)
        ber_free(ber, 0);

    // Set new password expiry date to 90 days from now in UTC
    newExpireStr = QDateTime::currentDateTimeUtc().addDays(90).toString("yyyyMMddhhmmss'.0Z'");
}

// Helper: Collect attribute names and check password conditions
void LdapAuthenticator::handleAttributeValue(const QString &attribute, const QString &value, bool &mustPwdChange)
{
    if (attribute == "distinguishedName")
    {
        setUserDn(value);
        return;
    }
    if (attribute == "pwdExpireDate")
    {
        QString expireStr = value;
        if (qsizetype dotPos = expireStr.indexOf('.'); dotPos != -1)
            expireStr = expireStr.left(dotPos) + "Z";
        QDateTime expireDate = QDateTime::fromString(expireStr, "yyyyMMddhhmmss'Z'");
        expireDate.setTimeZone(QTimeZone::utc());
        if (QDateTime now = QDateTime::currentDateTimeUtc(); expireDate.addDays(-5) <= now)
        {
            mustPwdChange = true;
            getMessageViewer().showInfo("Expired Password",
                                        QString("Your password has expired. You must change it now."));
        }
        return;
    }

    if (attribute == "isFirstLogon" && value == "TRUE")
    {
        mustPwdChange = true;
        getMessageViewer().showInfo("First Logon",
                                    QString("You have to change your password at first logon"));
    }
}

bool LdapAuthenticator::handlePasswordChange(const QString &newExpireStr)
{
    if (ldapPasswd(this) != LDAP_SUCCESS)
        return false;

    if (ldapModify({{LDAP_MOD_REPLACE, "isFirstLogon", "FALSE"},
                   {LDAP_MOD_REPLACE, "pwdExpireDate", newExpireStr}}) != LDAP_SUCCESS)
        return false;

    return true;
}

// Helper: Populate the attribute tree widget
void LdapAuthenticator::populateAttributeTree(LDAPMessage *msg, const QVariantMap &descMap, const QString &newExpireStr)
{
    BerElement *ber = nullptr;
    for (char *attr = ldap_first_attribute(getLdapHandle(), msg, &ber);
         attr != nullptr;
         attr = ldap_next_attribute(getLdapHandle(), msg, ber))
    {
        berval **vals = ldap_get_values_len(getLdapHandle(), msg, attr);
        if (!vals)
        {
            ldap_memfree(attr);
            continue;
        }

        QString attribute = QString::fromUtf8(attr);
        QString key = attribute.toLower();
        QString description = descMap.value(key, QString("<no description>")).toString();
        for (int i = 0; vals[i] != nullptr; ++i)
        {
            QString value = QString::fromUtf8(vals[i]->bv_val, vals[i]->bv_len);
            if (attribute == "isFirstLogon")
                value = "FALSE";
            else if (attribute == "pwdExpireDate")
                value = newExpireStr;
            auto item = new QTreeWidgetItem(ui->treeWidgetAttributes); // NOSONAR
            item->setText(0, attribute);
            item->setText(1, value);
            item->setData(0, DescriptionRole, description);
        }

        ldap_value_free_len(vals);
        ldap_memfree(attr);
    }
    if (ber)
        ber_free(ber, 0);
}


