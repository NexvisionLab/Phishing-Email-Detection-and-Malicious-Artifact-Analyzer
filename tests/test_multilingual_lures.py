"""Bank-style phishing in Malay, Indonesian, Arabic and Russian, a wallet recovery-phrase request and a QR-code lure, plus the genuine
emails that share words with them. Each scam email scored Low before these rules: the credential rules looked for the word "account"
next to "verify", but real messages say "verify your identity", "rekening", "تجميد حسابك" or "карта заблокирована"."""
from email.message import EmailMessage

import pytest

from phishing_analyzer.analyzer import analyze_email
from phishing_analyzer.locale_rules import SUPPORTED_LANGUAGES, detect_languages


def build(sender, subject, body):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "sarah.tan@example-corp.com"
    m["Subject"] = subject
    m["Date"] = "Sat, 26 Sep 2026 08:15:00 +0800"
    domain = sender.split("@")[-1].strip(">")
    m["Message-ID"] = f"<1234@{domain}>"
    m.set_content(body)
    return m.as_string()


SCAMS = {
    "malay": ("Maybank2u <alert@maybank2u-selamat.top>", "Akaun anda telah digantung",
              "Pelanggan yang dihormati, akaun anda telah digantung kerana aktiviti mencurigakan. Sila sahkan identiti anda dalam masa 24 jam di http://maybank2u-selamat.top/log-masuk untuk mengelakkan penutupan kekal."),
    "indonesian": ("BCA <info@bca-klikbca-aman.top>", "Rekening Anda diblokir sementara",
                   "Nasabah yang terhormat, rekening Anda diblokir karena aktivitas mencurigakan. Segera verifikasi identitas Anda di http://bca-klikbca-aman.top/login dalam 24 jam untuk menghindari penutupan permanen."),
    "russian": ("Сбербанк <security@sberbank-proverka.top>", "Ваша карта заблокирована",
                "Уважаемый клиент, ваша карта временно заблокирована из-за подозрительной активности. Подтвердите личность в течение 24 часов по ссылке http://sberbank-proverka.top/vhod, иначе карта будет заблокирована навсегда."),
    "arabic": ("البنك الأهلي <service@ahli-verify.top>", "تم تجميد حسابك",
               "عزيزي العميل، تم تجميد حسابك بسبب نشاط مشبوه. يرجى التحقق من هويتك خلال 24 ساعة عبر الرابط http://ahli-verify.top/login لتجنب الإغلاق النهائي."),
    "wallet-phrase": ("Ledger Support <support@ledger-verify.top>", "Security alert: verify your Ledger wallet",
                      "We detected suspicious activity on your wallet. To keep your funds safe, validate your wallet within 12 hours by entering your 24-word recovery phrase at https://ledger-verify.top/restore. Accounts not verified will be locked."),
    "qr-lure": ("IT Helpdesk <helpdesk@it-support-portal.top>", "MFA re-enrollment required",
                "Your multi-factor authentication expires today. Scan the QR code below with your phone to re-enroll. Failure to re-enroll will lock your account."),
}

GENUINE = {
    "bank-alert": ("DBS Bank <alerts@dbs.com>", "New sign-in to your account",
                   "Hi Sarah, we noticed a new sign-in to your DBS account from a new device. If this was you, no action is needed. If it was not you, call the number on the back of your card. We will never ask for your password or OTP by email."),
    "seed-advice": ("Ledger <security@ledger.com>", "Security reminder",
                    "Ledger will never ask for your 24-word recovery phrase. Never share your recovery phrase or private key with anyone, including support. If someone asks you to enter it on a website, it is a scam."),
    "billing-notice": ("Netflix <info@mailer.netflix.com>", "Your membership",
                       "Your payment method was declined. Update your payment details in your account settings to keep watching. If you do not update it, your membership will be cancelled at the end of the billing period."),
    "qr-checkin": ("Events <events@example-corp.com>", "Town hall check-in",
                   "For the town hall on Thursday, please scan the QR code at the entrance to check in. Doors open at 9am."),
    "id-bank-info": ("Bank Mandiri <info@bankmandiri.co.id>", "Informasi produk baru",
                     "Nasabah yang terhormat, kami menghadirkan produk tabungan baru dengan bunga menarik. Kunjungi cabang terdekat atau situs resmi kami. Kami tidak pernah meminta PIN atau OTP Anda melalui email."),
    "ru-newsletter": ("РБК <news@rbc.ru>", "Главные новости недели",
                      "Здравствуйте! Главные новости недели: экономика, технологии и образование. Читайте на нашем сайте https://www.rbc.ru. Чтобы отписаться, нажмите на ссылку в нижней части письма."),
    "mfa-notice": ("IT Helpdesk <helpdesk@example-corp.com>", "Scheduled MFA enrolment",
                   "As announced in the all-hands, MFA enrolment is due by Friday. Open the Authenticator app on your phone and follow the instructions on the intranet page."),
}


@pytest.mark.parametrize("name", SCAMS)
def test_each_scam_is_flagged(name):
    result = analyze_email(build(*SCAMS[name]))
    assert result.risk in {"suspicious", "likely_phishing", "high"}, (name, result.score)
    assert result.score >= 30


@pytest.mark.parametrize("name", GENUINE)
def test_genuine_emails_that_share_the_words_stay_low(name):
    result = analyze_email(build(*GENUINE[name]))
    assert result.risk == "low", (name, result.score, [f.title for f in result.findings])


def test_russian_is_a_supported_language_and_is_detected():
    assert SUPPORTED_LANGUAGES["ru"] == "Russian"
    assert detect_languages("Подтвердите личность, ваш аккаунт заблокирован")[0] == "ru"


def test_a_pointer_to_the_accounts_own_settings_is_not_a_credential_lure_but_a_link_is_still_flagged():
    settings = analyze_email(build("Netflix <info@mailer.netflix.com>", "Billing", "Please update your payment details in your account settings."))
    link = analyze_email(build("Netflix <info@netfIix-billing.top>", "Billing", "Your payment failed. Update your payment details here: http://netflix-billing.top/update to avoid suspension of your account."))
    assert settings.risk == "low"
    assert link.risk in {"suspicious", "likely_phishing", "high"}


def test_advice_not_to_share_a_recovery_phrase_is_not_a_request_for_it():
    advice = analyze_email(build(*GENUINE["seed-advice"]))
    request = analyze_email(build(*SCAMS["wallet-phrase"]))
    assert not any(f.code == "CONTENT_PATTERN" and "recovery phrase" in f.title.lower() for f in advice.findings)
    assert any("recovery phrase" in f.title.lower() for f in request.findings)
