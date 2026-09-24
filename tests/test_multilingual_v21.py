import pytest

from phishing_analyzer.analyzer import analyze_email
from phishing_analyzer.locale_rules import RULE_PACK_VERSION, SCAM_RULES, SUPPORTED_LANGUAGES, validate_rule_pack


@pytest.mark.parametrize(
    ("language", "message"),
    [
        ("en", "Please verify your account and password now."),
        ("zh-Hans", "请立即验证账户密码。"),
        ("zh-Hant", "請立即驗證帳戶密碼。"),
        ("ms", "Sila sahkan akaun dan kata laluan anda."),
        ("id", "Silakan verifikasi akun dan kata sandi Anda."),
        ("ta", "உங்கள் கணக்கு கடவுச்சொல் சரிபார்க்க வேண்டும்."),
        ("es", "Verifique su cuenta y contraseña ahora."),
        ("fr", "Vérifiez votre compte et mot de passe maintenant."),
        ("de", "Bitte bestätigen Sie Konto und Passwort."),
        ("pt", "Verifique sua conta e senha agora."),
        ("ar", "تحقق من حسابك وكلمة المرور الآن."),
        ("hi", "अपना खाता और पासवर्ड सत्यापित करें।"),
        ("bn", "আপনার অ্যাকাউন্ট পাসওয়ার্ড যাচাই করুন।"),
        ("ur", "اپنا اکاؤنٹ اور پاس ورڈ تصدیق کریں۔"),
        ("th", "ยืนยันบัญชีและรหัสผ่านของคุณ"),
        ("vi", "Xác minh tài khoản và mật khẩu của bạn."),
        ("ja", "アカウントとパスワードを確認してください。"),
        ("ko", "계정과 비밀번호를 확인하세요."),
        ("tl", "Beripikahin ang iyong account at password."),
    ],
)
def test_supported_language_credential_samples(language, message):
    result = analyze_email(message)
    assert result.classification == "Credential phishing"
    assert language in result.metadata["languages"]
    assert result.evidence_status["language_support"] == "evaluated"


@pytest.mark.parametrize(
    ("category", "message"),
    [
        ("Business email compromise", "Urgent confidential wire transfer: use our new banking account details."),
        ("Delivery or invoice lure", "Your parcel delivery failed. Pay a small fee to reschedule."),
        ("Job or task scam", "Remote job: complete simple tasks on Telegram and earn commission."),
        ("Prize or advance-fee scam", "You are the lottery winner. Pay the release fee to claim your prize."),
        ("Extortion or threat", "I recorded your webcam. Pay bitcoin or I will expose the video."),
        ("Investment or crypto scam", "Guaranteed risk-free crypto investment profit. Double your bitcoin."),
        ("Romance scam", "You are my soulmate and I love you. Hospital emergency: please send money."),
        ("Recovery scam", "We recover stolen crypto funds for an upfront fee payment."),
        ("Government or law-enforcement impersonation", "CBI officer: you are under digital arrest over a narcotics parcel."),
        ("Bank or payment-service impersonation", "Your bank card is blocked for unauthorized activity. Click to verify."),
        ("Tech-support or malware scam", "Security alert: your computer is infected. Call support for AnyDesk remote access."),
        ("Money-mule recruitment", "Receive and forward payments through your account and keep 10% commission."),
        ("Friend or family impersonation", "Mum, this is my new phone number. Urgent bill—transfer money on WhatsApp."),
        ("Toll or traffic-payment scam", "Unpaid toll notice: pay now to avoid a penalty."),
        ("Tax or refund scam", "IRS tax refund pending. Click to claim and enter bank details."),
        ("Utility or telecom scam", "Your electricity service will disconnect unless immediate payment is made."),
        ("Subscription or renewal scam", "Your antivirus subscription renewed and was charged. Call to cancel."),
        ("Charity or disaster scam", "Donate to the disaster relief fund using crypto to help victims."),
        ("Loan or debt scam", "Guaranteed loan approved after an upfront processing fee."),
        ("Immigration or visa scam", "Your work visa is guaranteed approved after a processing fee."),
    ],
)
def test_expanded_scam_families(category, message):
    assert analyze_email(message).classification == category


@pytest.mark.parametrize(
    ("region", "message"),
    [
        ("SG", "Singpass urgent: verify your account now."),
        ("MY", "LHDN urgent: verify your account now."),
        ("ID", "OJK: verifikasi akun Anda segera."),
        ("HK", "香港警務處：立即驗證帳戶。"),
        ("AU", "myGov tax refund pending. Click to claim."),
        ("US", "IRS tax refund pending. Click to claim."),
        ("CA", "CRA tax refund pending. Click to claim."),
        ("UK", "HMRC tax refund pending. Click to claim."),
        ("IN", "UPI account notice: verify your password."),
        ("JP", "日本郵便：アカウントを確認してください。"),
        ("KR", "국세청: 계정과 비밀번호를 확인하세요."),
        ("BR", "Receita Federal: verifique sua conta e senha."),
        ("PH", "GCash: beripikahin ang account at password."),
        ("MENA", "وزارة الداخلية: تحقق من حسابك وكلمة المرور."),
        ("AFRICA", "M-Pesa account: verify your password."),
    ],
)
def test_regional_patterns_are_non_attributive_hints(region, message):
    result = analyze_email(message)
    codes = {item["code"] for item in result.metadata["regional_pattern_matches"]}
    assert region in codes
    assert result.metadata["governance"]["regional_match_is_origin_attribution"] is False


@pytest.mark.parametrize(
    "message",
    [
        "You do not need to verify your account or click any link.",
        "No debe verificar su cuenta ni hacer clic en ningún enlace.",
        "Vous ne devez pas vérifier votre compte via un lien.",
        "Sie müssen Ihr Konto nicht bestätigen.",
        "Não precisa verificar sua conta por link.",
        "不要点击链接验证账户。",
        "Jangan sahkan akaun melalui pautan.",
        "अपने खाते को सत्यापित नहीं करें।",
        "อย่ายืนยันบัญชีผ่านลิงก์นี้",
        "Huwag beripikahin ang account sa link.",
    ],
)
def test_multilingual_benign_warnings_are_suppressed(message):
    assert analyze_email(message).classification == "Pattern undetermined"


def test_rule_pack_schema_and_governance_metadata():
    assert validate_rule_pack() == []
    assert len(SUPPORTED_LANGUAGES) == 19
    assert len({rule.category for rule in SCAM_RULES}) >= 19
    result = analyze_email("hello")
    assert result.metadata["rule_pack_version"] == RULE_PACK_VERSION
    assert result.evidence_status["language_support"] == "limited"
