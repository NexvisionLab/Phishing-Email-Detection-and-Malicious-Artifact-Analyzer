from __future__ import annotations

import re
from dataclasses import dataclass

RULE_PACK_VERSION = "2026.09.1"


@dataclass(frozen=True, slots=True)
class ScamRule:
    rule_id: str
    category: str
    language: str
    pattern: str
    title: str
    points: int
    regions: tuple[str, ...] = ()


SUPPORTED_LANGUAGES = {
    "en": "English",
    "zh-Hans": "Simplified Chinese",
    "zh-Hant": "Traditional Chinese",
    "ms": "Malay",
    "id": "Indonesian",
    "ta": "Tamil",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
    "pt": "Portuguese",
    "ar": "Arabic",
    "hi": "Hindi",
    "bn": "Bengali",
    "ur": "Urdu",
    "th": "Thai",
    "vi": "Vietnamese",
    "ja": "Japanese",
    "ko": "Korean",
    "tl": "Filipino/Tagalog",
}


# Markers are intentionally conservative. Script alone can establish that the
# analyzer supports the writing system, but closely related languages require
# lexical evidence. Results are screening hints, never nationality inference.
LANGUAGE_MARKERS: dict[str, tuple[str, ...]] = {
    "en": (" your ", " account", "please ", "payment", "click "),
    "zh-Hans": ("账户", "验证", "点击", "付款", "紧急", "包裹"),
    "zh-Hant": ("帳戶", "驗證", "點擊", "付款", "緊急", "包裹"),
    "ms": ("akaun", "sila", "pautan", "bayaran", "segera", "bungkusan"),
    "id": ("akun", "silakan", "tautan", "pembayaran", "segera", "paket"),
    "ta": ("கணக்கு", "வங்கி", "சரிபார்க்க", "பணம்", "அவசரம்"),
    "es": ("cuenta", "verifique", "contraseña", "pago", "urgente", "paquete"),
    "fr": ("compte", "vérifiez", "mot de passe", "paiement", "immédiatement", "colis"),
    "de": ("konto", "bestätigen", "passwort", "zahlung", "dringend", "paket"),
    "pt": ("conta", "verifique", "senha", "pagamento", "urgente", "encomenda"),
    "ar": ("حساب", "تحقق", "كلمة المرور", "دفع", "عاجل", "طرد"),
    "hi": ("खाता", "सत्यापित", "पासवर्ड", "भुगतान", "तुरंत", "पार्सल"),
    "bn": ("অ্যাকাউন্ট", "যাচাই", "পাসওয়ার্ড", "পেমেন্ট", "জরুরি", "পার্সেল"),
    "ur": ("اکاؤنٹ", "تصدیق", "پاس ورڈ", "ادائیگی", "فوری", "پارسل"),
    "th": ("บัญชี", "ยืนยัน", "รหัสผ่าน", "ชำระ", "ด่วน", "พัสดุ"),
    "vi": ("tài khoản", "xác minh", "mật khẩu", "thanh toán", "khẩn cấp", "bưu kiện"),
    "ja": ("アカウント", "確認", "パスワード", "支払い", "緊急", "荷物"),
    "ko": ("계정", "확인", "비밀번호", "결제", "긴급", "택배"),
    "tl": ("beripikahin", "iyong account", "bayad", "kagyat", "padala", "gcash"),
}

SCRIPT_HINTS = {
    "ta": re.compile(r"[\u0b80-\u0bff]"),
    "hi": re.compile(r"[\u0900-\u097f]"),
    "bn": re.compile(r"[\u0980-\u09ff]"),
    "th": re.compile(r"[\u0e00-\u0e7f]"),
    "ja": re.compile(r"[\u3040-\u30ff]"),
    "ko": re.compile(r"[\uac00-\ud7af]"),
}


SCAM_RULES: tuple[ScamRule, ...] = (
    # Credential and account takeover lures.
    ScamRule(
        "cred.en.verify",
        "Credential phishing",
        "en",
        r"\b(verify|validate|confirm|update|unlock)\b.{0,40}\b(account|identity|password|login|mailbox)\b",
        "Requests account verification",
        18,
    ),
    ScamRule(
        "cred.en.signin",
        "Credential phishing",
        "en",
        r"\b(sign[ -]?in|log[ -]?in)\b.{0,45}\b(link|below|now|here)\b",
        "Directs recipient to sign in",
        15,
    ),
    ScamRule(
        "cred.zh-hans",
        "Credential phishing",
        "zh-Hans",
        r"(验证|确认|更新|解锁).{0,12}(账户|密码|身份)|点击.{0,8}(登录|链接)",
        "Requests credential action",
        18,
        ("CN", "SG"),
    ),
    ScamRule(
        "cred.zh-hant",
        "Credential phishing",
        "zh-Hant",
        r"(驗證|確認|更新|解鎖).{0,12}(帳戶|密碼|身分)|點擊.{0,8}(登入|連結)",
        "Requests credential action",
        18,
        ("HK", "TW"),
    ),
    ScamRule(
        "cred.ms",
        "Credential phishing",
        "ms",
        r"(sahkan|kemas kini|aktifkan semula).{0,28}(akaun|kata laluan)|klik.{0,18}(log masuk|pautan)",
        "Requests credential action",
        18,
        ("MY", "SG"),
    ),
    ScamRule(
        "cred.id",
        "Credential phishing",
        "id",
        r"(verifikasi|perbarui|aktifkan kembali).{0,28}(akun|kata sandi)|klik.{0,18}(masuk|tautan)",
        "Requests credential action",
        18,
        ("ID",),
    ),
    ScamRule(
        "cred.ta",
        "Credential phishing",
        "ta",
        r"(சரிபார்க்க|புதுப்பிக்க|உறுதிப்படுத்த).{0,22}(கணக்கு|கடவுச்சொல்)",
        "Requests credential action",
        18,
        ("IN", "SG", "LK"),
    ),
    ScamRule(
        "cred.es",
        "Credential phishing",
        "es",
        r"(verifi(?:que|car)|actuali(?:ce|zar)|confirme).{0,35}(cuenta|contraseña|identidad|inicio de sesión)",
        "Requests credential action",
        18,
        ("ES", "LATAM"),
    ),
    ScamRule(
        "cred.fr",
        "Credential phishing",
        "fr",
        r"(vérifi(?:ez|er)|mettre à jour|confirmez).{0,35}(compte|mot de passe|identité|connexion)",
        "Requests credential action",
        18,
        ("FR", "CA"),
    ),
    ScamRule(
        "cred.de",
        "Credential phishing",
        "de",
        r"(bestätigen|aktualisieren|überprüfen).{0,35}(konto|passwort|identität|anmeldung)",
        "Requests credential action",
        18,
        ("DE", "AT", "CH"),
    ),
    ScamRule(
        "cred.pt",
        "Credential phishing",
        "pt",
        r"(verifi(?:que|car)|atuali(?:ze|zar)|confirme).{0,35}(conta|senha|identidade|login)",
        "Requests credential action",
        18,
        ("BR", "PT"),
    ),
    ScamRule(
        "cred.ar",
        "Credential phishing",
        "ar",
        r"(تحقق|تحديث|تأكيد).{0,22}(الحساب|حسابك|كلمة المرور|الهوية)",
        "Requests credential action",
        18,
        ("MENA",),
    ),
    ScamRule(
        "cred.hi",
        "Credential phishing",
        "hi",
        r"(सत्यापित|अपडेट|पुष्टि).{0,28}(खाता|पासवर्ड|पहचान)|(खाता|पासवर्ड|पहचान).{0,28}(सत्यापित|अपडेट|पुष्टि)",
        "Requests credential action",
        18,
        ("IN",),
    ),
    ScamRule(
        "cred.bn",
        "Credential phishing",
        "bn",
        r"(যাচাই|আপডেট|নিশ্চিত).{0,28}(অ্যাকাউন্ট|পাসওয়ার্ড|পরিচয়)|(অ্যাকাউন্ট|পাসওয়ার্ড|পরিচয়).{0,28}(যাচাই|আপডেট|নিশ্চিত)",
        "Requests credential action",
        18,
        ("BD", "IN"),
    ),
    ScamRule(
        "cred.ur",
        "Credential phishing",
        "ur",
        r"(تصدیق|اپ ڈیٹ).{0,28}(اکاؤنٹ|پاس ورڈ|شناخت)|(اکاؤنٹ|پاس ورڈ|شناخت).{0,28}(تصدیق|اپ ڈیٹ)",
        "Requests credential action",
        18,
        ("PK",),
    ),
    ScamRule(
        "cred.th", "Credential phishing", "th", r"(ยืนยัน|อัปเดต|ตรวจสอบ).{0,22}(บัญชี|รหัสผ่าน|ตัวตน)", "Requests credential action", 18, ("TH",)
    ),
    ScamRule(
        "cred.vi",
        "Credential phishing",
        "vi",
        r"(xác minh|cập nhật|xác nhận).{0,28}(tài khoản|mật khẩu|danh tính)",
        "Requests credential action",
        18,
        ("VN",),
    ),
    ScamRule(
        "cred.ja",
        "Credential phishing",
        "ja",
        r"(確認|更新|認証).{0,20}(アカウント|パスワード|本人)|(アカウント|パスワード|本人).{0,20}(確認|更新|認証)|リンク.{0,10}(ログイン|サインイン)",
        "Requests credential action",
        18,
        ("JP",),
    ),
    ScamRule(
        "cred.ko",
        "Credential phishing",
        "ko",
        r"(확인|업데이트|인증).{0,20}(계정|비밀번호|본인)|(계정|비밀번호|본인).{0,20}(확인|업데이트|인증)|링크.{0,10}(로그인|접속)",
        "Requests credential action",
        18,
        ("KR",),
    ),
    ScamRule(
        "cred.tl",
        "Credential phishing",
        "tl",
        r"(beripikahin|i-update|kumpirmahin).{0,30}(account|password|pagkakakilanlan)",
        "Requests credential action",
        18,
        ("PH",),
    ),
    # Payment diversion / business email compromise.
    ScamRule(
        "bec.en.urgent",
        "Business email compromise",
        "en",
        r"\b(urgent|confidential)\b.{0,45}\b(payment|transfer|invoice|wire)\b",
        "Urgent payment language",
        20,
    ),
    ScamRule(
        "bec.en.bankchange",
        "Business email compromise",
        "en",
        r"\b(change|updated?|new)\b.{0,32}\b(bank|banking|payment)\b.{0,24}\b(detail|account)",
        "Requests changed banking details",
        28,
    ),
    ScamRule(
        "bec.giftcards",
        "Business email compromise",
        "en",
        r"\b(gift cards?|itunes|steam cards?|google play cards?)\b",
        "Requests gift cards",
        25,
    ),
    ScamRule(
        "bec.es",
        "Business email compromise",
        "es",
        r"(urgente|confidencial).{0,35}(pago|transferencia|factura)|cambi(?:e|o).{0,25}(datos bancarios|cuenta bancaria)",
        "Urgent or changed payment request",
        24,
        ("ES", "LATAM"),
    ),
    ScamRule(
        "bec.fr",
        "Business email compromise",
        "fr",
        r"(urgent|confidentiel).{0,35}(paiement|virement|facture)|chang(?:ez|ement).{0,25}(coordonnées bancaires|compte bancaire)",
        "Urgent or changed payment request",
        24,
        ("FR", "CA"),
    ),
    ScamRule(
        "bec.de",
        "Business email compromise",
        "de",
        r"(dringend|vertraulich).{0,35}(zahlung|überweisung|rechnung)|geändert.{0,25}(bankdaten|bankkonto)",
        "Urgent or changed payment request",
        24,
        ("DE", "AT", "CH"),
    ),
    ScamRule(
        "bec.pt",
        "Business email compromise",
        "pt",
        r"(urgente|confidencial).{0,35}(pagamento|transferência|fatura)|alter(?:e|ação).{0,25}(dados bancários|conta bancária)",
        "Urgent or changed payment request",
        24,
        ("BR", "PT"),
    ),
    ScamRule(
        "bec.asia",
        "Business email compromise",
        "zh-Hans",
        r"(紧急|保密).{0,18}(付款|转账|发票)|更改.{0,12}银行.{0,12}(资料|账户)",
        "Urgent or changed payment request",
        24,
        ("CN", "SG"),
    ),
    ScamRule(
        "bec.ms",
        "Business email compromise",
        "ms",
        r"(segera|sulit).{0,30}(bayaran|pindahan|invois)|ubah.{0,20}(akaun bank|butiran bank)",
        "Urgent or changed payment request",
        24,
        ("MY", "SG"),
    ),
    # Delivery, toll, tax, utility and subscription lures.
    ScamRule(
        "delivery.en",
        "Delivery or invoice lure",
        "en",
        r"\b(parcel|package|shipment|delivery)\b.{0,38}\b(fee|failed|pending|reschedul|address)\b",
        "Delivery problem or fee lure",
        16,
    ),
    ScamRule(
        "delivery.multi.zh",
        "Delivery or invoice lure",
        "zh-Hans",
        r"(包裹|快递|配送).{0,18}(费用|失败|待处理|重新安排|地址)",
        "Delivery problem or fee lure",
        16,
        ("CN", "SG"),
    ),
    ScamRule(
        "delivery.multi.latam",
        "Delivery or invoice lure",
        "es",
        r"(paquete|envío|entrega).{0,32}(tarifa|fallid|pendiente|reprogram|dirección)",
        "Delivery problem or fee lure",
        16,
        ("ES", "LATAM"),
    ),
    ScamRule(
        "delivery.multi.eu",
        "Delivery or invoice lure",
        "fr",
        r"(colis|livraison).{0,30}(frais|échou|suspend|reprogramm|adresse)",
        "Delivery problem or fee lure",
        16,
        ("FR", "CA"),
    ),
    ScamRule(
        "delivery.multi.de",
        "Delivery or invoice lure",
        "de",
        r"(paket|lieferung).{0,30}(gebühr|fehlgeschlagen|ausstehend|adresse)",
        "Delivery problem or fee lure",
        16,
        ("DE", "AT", "CH"),
    ),
    ScamRule(
        "delivery.multi.br",
        "Delivery or invoice lure",
        "pt",
        r"(encomenda|pacote|entrega).{0,30}(taxa|falhou|pendente|endereço)",
        "Delivery problem or fee lure",
        16,
        ("BR", "PT"),
    ),
    ScamRule(
        "delivery.multi.asia",
        "Delivery or invoice lure",
        "ja",
        r"(荷物|配達).{0,18}(料金|失敗|保留|再配達|住所)",
        "Delivery problem or fee lure",
        16,
        ("JP",),
    ),
    ScamRule(
        "toll.en",
        "Toll or traffic-payment scam",
        "en",
        r"\b(unpaid|overdue)\b.{0,30}\b(toll|parking|traffic (?:ticket|fine))\b|\b(toll|parking fine)\b.{0,30}\b(pay now|penalty)",
        "Claims an unpaid road or parking charge",
        20,
        ("US", "CA", "UK", "AU", "SG"),
    ),
    ScamRule(
        "toll.es",
        "Toll or traffic-payment scam",
        "es",
        r"(peaje|multa de tráfico|estacionamiento).{0,30}(impag|pagar|recargo)",
        "Claims an unpaid road or parking charge",
        20,
        ("ES", "LATAM"),
    ),
    ScamRule(
        "tax.multi",
        "Tax or refund scam",
        "en",
        r"\b(tax refund|rebate|irs refund|hmrc refund|ato refund|cra refund)\b.{0,45}\b(claim|pending|click|bank details|fee)",
        "Unexpected tax refund or rebate",
        20,
        ("US", "UK", "AU", "CA"),
    ),
    ScamRule(
        "tax.es",
        "Tax or refund scam",
        "es",
        r"(reembolso|devolución).{0,24}(impuesto|hacienda).{0,35}(reclamar|datos bancarios|tasa)",
        "Unexpected tax refund or rebate",
        20,
        ("ES", "LATAM"),
    ),
    ScamRule(
        "utility.en",
        "Utility or telecom scam",
        "en",
        r"\b(electricity|power|gas|internet|mobile service)\b.{0,40}\b(disconnect|suspend|overdue|immediate payment)",
        "Threatens utility or telecom disconnection",
        20,
    ),
    ScamRule(
        "subscription.en",
        "Subscription or renewal scam",
        "en",
        r"\b(subscription|antivirus|membership)\b.{0,35}\b(renewed|renewal|charged|refund)\b.{0,50}\b(call|contact|cancel)",
        "Unexpected subscription renewal or refund",
        18,
    ),
    # Job, task, investment, romance and recovery fraud.
    ScamRule(
        "job.en",
        "Job or task scam",
        "en",
        r"\b(part[ -]?time|remote job|simple tasks?|product review)\b.{0,60}\b(commission|earn|salary|whatsapp|telegram)\b",
        "High-reward job or task offer",
        18,
    ),
    ScamRule(
        "job.deposit",
        "Job or task scam",
        "en",
        r"\b(top[ -]?up|recharge|deposit)\b.{0,45}\b(task|commission|withdraw)",
        "Task scam deposit cycle",
        26,
    ),
    ScamRule(
        "job.asia",
        "Job or task scam",
        "zh-Hans",
        r"(兼职|刷单|任务).{0,20}(佣金|赚钱|充值|提现)",
        "Job or task scam language",
        24,
        ("CN", "SG"),
    ),
    ScamRule(
        "job.ms",
        "Job or task scam",
        "ms",
        r"(kerja sambilan|tugasan).{0,32}(komisen|pendapatan|deposit|tambah nilai)",
        "Job or task scam language",
        24,
        ("MY", "SG"),
    ),
    ScamRule(
        "job.id",
        "Job or task scam",
        "id",
        r"(kerja paruh waktu|tugas|ulas produk).{0,32}(komisi|penghasilan|deposit|isi saldo)",
        "Job or task scam language",
        24,
        ("ID",),
    ),
    ScamRule(
        "job.hi",
        "Job or task scam",
        "hi",
        r"(पार्ट.?टाइम|घर से काम|टास्क).{0,28}(कमीशन|कमाई|जमा|रिचार्ज)",
        "Job or task scam language",
        24,
        ("IN",),
    ),
    ScamRule(
        "investment.en",
        "Investment or crypto scam",
        "en",
        r"\b(guaranteed|risk[ -]?free)\b.{0,35}\b(return|profit|investment|crypto)|\bdouble your (?:money|bitcoin)\b",
        "Promises guaranteed investment returns",
        25,
    ),
    ScamRule(
        "investment.es",
        "Investment or crypto scam",
        "es",
        r"(rentabilidad|ganancia).{0,25}(garantizada|sin riesgo)|duplica.{0,16}(dinero|bitcoin)",
        "Promises guaranteed investment returns",
        25,
        ("ES", "LATAM"),
    ),
    ScamRule(
        "investment.zh",
        "Investment or crypto scam",
        "zh-Hans",
        r"(保证|稳赚|零风险).{0,18}(收益|回报|投资|加密货币)|杀猪盘",
        "Promises guaranteed investment returns",
        25,
        ("CN", "SG"),
    ),
    ScamRule(
        "investment.pt",
        "Investment or crypto scam",
        "pt",
        r"(retorno|lucro).{0,24}(garantido|sem risco)|duplique.{0,16}(dinheiro|bitcoin)",
        "Promises guaranteed investment returns",
        25,
        ("BR", "PT"),
    ),
    ScamRule(
        "romance.en",
        "Romance scam",
        "en",
        r"\b(love you|soulmate|future together)\b.{0,120}\b(emergency|hospital|customs|ticket|send money|gift card)",
        "Romantic trust paired with a money emergency",
        24,
    ),
    ScamRule(
        "romance.es",
        "Romance scam",
        "es",
        r"(te amo|alma gemela|futuro juntos).{0,120}(emergencia|hospital|aduana|billete|envía dinero)",
        "Romantic trust paired with a money emergency",
        24,
        ("ES", "LATAM"),
    ),
    ScamRule(
        "recovery.en",
        "Recovery scam",
        "en",
        r"\b(recover|retrieve|get back)\b.{0,35}\b(lost|stolen|scammed)\b.{0,45}\b(funds|money|crypto)\b.{0,45}\b(upfront|fee|payment)",
        "Offers recovery of lost funds for an upfront fee",
        28,
    ),
    ScamRule(
        "recovery.es",
        "Recovery scam",
        "es",
        r"(recuperar).{0,35}(fondos|dinero|cripto).{0,45}(tasa|pago por adelantado|anticipo)",
        "Offers recovery of lost funds for an upfront fee",
        28,
        ("ES", "LATAM"),
    ),
    # Impersonation, coercion, money mule and advance-fee fraud.
    ScamRule(
        "gov.en",
        "Government or law-enforcement impersonation",
        "en",
        r"\b(irs|hmrc|police|federal agent|social security|immigration|court)\b.{0,70}\b(arrest|warrant|deport|fine|gift card|crypto|transfer)",
        "Government or police threat paired with payment",
        28,
    ),
    ScamRule(
        "gov.india",
        "Government or law-enforcement impersonation",
        "en",
        r"\b(digital arrest|cbi officer|customs officer|narcotics parcel)\b",
        "Digital-arrest or authority impersonation language",
        30,
        ("IN",),
    ),
    ScamRule(
        "gov.zh-hant",
        "Government or law-enforcement impersonation",
        "zh-Hant",
        r"(警察|入境處|稅務局|法院).{0,35}(拘捕|通緝|罰款|轉帳)",
        "Government or police threat paired with payment",
        28,
        ("HK", "TW"),
    ),
    ScamRule(
        "bank.en",
        "Bank or payment-service impersonation",
        "en",
        r"\b(bank|paypal|wallet|card)\b.{0,38}\b(blocked|suspended|unauthori[sz]ed|fraud)\b.{0,45}\b(click|verify|reverse|secure)",
        "Bank alert directs recipient to take action",
        22,
    ),
    ScamRule(
        "tech.en",
        "Tech-support or malware scam",
        "en",
        r"\b(virus|infected|security alert|hacker)\b.{0,45}\b(call|remote access|anydesk|teamviewer|support)",
        "False security alert requests support access",
        25,
    ),
    ScamRule(
        "mule.en",
        "Money-mule recruitment",
        "en",
        r"\b(receive|process|forward)\b.{0,30}\b(payments?|funds?|transfers?)\b.{0,40}\b(commission|keep \d+%|your account)",
        "Recruits recipient to move money",
        28,
    ),
    ScamRule(
        "friend.en",
        "Friend or family impersonation",
        "en",
        r"\b(new (?:phone|number)|lost my phone|mum|mom|dad|daughter|son)\b.{0,70}\b(urgent|bill|money|transfer|whatsapp)",
        "Friend or family emergency payment request",
        24,
    ),
    ScamRule(
        "friend.pt",
        "Friend or family impersonation",
        "pt",
        r"(número novo|celular novo|mãe|pai|filho|filha).{0,70}(urgente|boleto|pix|transferência)",
        "Friend or family emergency payment request",
        24,
        ("BR",),
    ),
    ScamRule(
        "prize.en",
        "Prize or advance-fee scam",
        "en",
        r"\b(winner|won|lottery|prize|inheritance)\b.{0,70}\b(fee|claim|release|processing|tax)",
        "Unexpected prize or funds requires payment",
        24,
    ),
    ScamRule(
        "prize.multi",
        "Prize or advance-fee scam",
        "es",
        r"(ganador|lotería|premio|herencia).{0,55}(tasa|reclamar|liberar|impuesto)",
        "Unexpected prize or funds requires payment",
        24,
        ("ES", "LATAM"),
    ),
    ScamRule(
        "charity.en",
        "Charity or disaster scam",
        "en",
        r"\b(donate|donation|relief fund|victims?)\b.{0,50}\b(crypto|gift card|wire|personal account)",
        "Donation request uses hard-to-reverse payment",
        20,
    ),
    ScamRule(
        "loan.en",
        "Loan or debt scam",
        "en",
        r"\b(guaranteed loan|debt relief|loan approved)\b.{0,45}\b(upfront fee|processing fee|gift card|crypto)",
        "Loan or debt offer requires an upfront fee",
        24,
    ),
    ScamRule(
        "immigration.en",
        "Immigration or visa scam",
        "en",
        r"\b(visa|immigration|residency|work permit)\b.{0,45}\b(guaranteed|approved|avoid deportation|processing fee)",
        "Visa or immigration promise/threat requires payment",
        24,
    ),
    ScamRule(
        "extortion.en",
        "Extortion or threat",
        "en",
        r"\b(compromising|webcam|recorded you|expose|leak)\b.{0,80}\b(bitcoin|crypto|pay|wallet)",
        "Coercive demand for payment",
        28,
    ),
)


GENERIC_RULES: tuple[tuple[str, str, int], ...] = (
    (
        r"\b(urgent|immediately|within 24 hours|act now|final warning)\b|紧急|立即|緊急|segera|அவசரம்|urgente|immédiatement|dringend|عاجل|तुरंत|জরুরি|فوری|ด่วน|khẩn cấp|至急|긴급|kagyat",
        "Uses urgency or time pressure",
        8,
    ),
    (
        r"\b(dear customer|dear user|valued customer)\b|尊敬的客户|尊敬的客戶|pelanggan yang dihargai|estimado cliente|cher client|sehr geehrter kunde|prezado cliente|عزيزي العميل|प्रिय ग्राहक|প্রিয় গ্রাহক|محترم صارف|เรียนลูกค้า|kính gửi quý khách|お客様|고객님|mahal na customer",
        "Uses a generic greeting",
        5,
    ),
    (
        r"\bdo not (call|contact|tell|discuss)\b|不要(联系|告诉)|不要(聯絡|告訴)|jangan (hubungi|beritahu)|no (llame|contacte|cuente)|ne (contactez|dites)|nicht (anrufen|kontaktieren)|لا (تتصل|تخبر)",
        "Discourages independent verification",
        15,
    ),
    (
        r"\b(click|open|follow)\b.{0,25}\b(link|button|attachment)\b|点击.{0,10}(链接|按钮)|點擊.{0,10}(連結|按鈕)|klik.{0,15}(pautan|tautan|butang)|haga clic.{0,15}(enlace|botón)|cliquez.{0,15}(lien|bouton)|klicken.{0,15}(link|schaltfläche)",
        "Prompts the recipient to open content",
        7,
    ),
)


NEGATION_PATTERNS: tuple[str, ...] = (
    r"\b(do not|don't|never|no need to|will not)\b",
    r"不要|无需|無需|jangan|tidak perlu",
    r"\b(no (?:debe|necesita)|nunca|ne (?:devez|faut) pas|niemals|nicht erforderlich)\b",
    r"\b(não (?:precisa|clique)|nunca)\b|لا (?:تضغط|حاجة)|ضرورت نہیں",
    r"வேண்டாம்|नहीं|করবেন না|อย่า|không (?:cần|nhấp)|しないで|하지 마|huwag",
)


REGION_MARKERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "SG": ("Singapore", ("singpass", "cpf", "iras", "paynow", "scamshield", "lta", "ica singapore")),
    "MY": ("Malaysia", ("lhdn", "jpj", "pdrm", "touch 'n go", "tng ewallet", "maybank")),
    "ID": ("Indonesia", ("ojk", "kominfo", "bca", "bri", "dana", "gopay", "pinjol")),
    "HK": ("Hong Kong", ("入境處", "香港警務處", "強積金", "mpf", "轉數快", "fps")),
    "AU": ("Australia", ("mygov", "ato", "medicare", "centrelink", "linkt")),
    "NZ": ("New Zealand", ("ird", "nzta", "wakat kotahi", "realme")),
    "US": ("United States", ("irs", "social security", "usps", "ez-pass", "medicare")),
    "CA": ("Canada", ("cra", "service canada", "canada post", "interac")),
    "UK": ("United Kingdom", ("hmrc", "dvla", "nhs", "royal mail", "tv licence")),
    "IN": ("India", ("upi", "aadhaar", "pan card", "income tax department", "digital arrest", "cbi officer")),
    "JP": ("Japan", ("マイナンバー", "国税庁", "日本郵便", "再配達")),
    "KR": ("South Korea", ("국세청", "경찰청", "택배", "과태료")),
    "BR": ("Brazil", ("pix", "receita federal", "boleto", "correios", "gov.br")),
    "LATAM": ("Latin America", ("hacienda", "aduana", "mercado pago", "whatsapp", "transferencia bancaria")),
    "MENA": ("Middle East / North Africa", ("إقامة", "الهوية الوطنية", "وزارة الداخلية", "مخالفة مرورية", "زكاة")),
    "AFRICA": ("Sub-Saharan Africa", ("mobile money", "m-pesa", "business grant", "airtime", "mo momo")),
    "PH": ("Philippines", ("gcash", "maya wallet", "sss", "bir", "philpost")),
}


def language_scores(text: str) -> dict[str, int]:
    padded = f" {text.casefold()} "

    def contains(marker: str) -> bool:
        marker = marker.casefold().strip()
        if re.fullmatch(r"[a-zà-öø-ÿ' -]+", marker):
            return re.search(rf"(?<!\w){re.escape(marker)}(?!\w)", padded, re.IGNORECASE) is not None
        return marker in padded

    scores = {code: sum(1 for marker in markers if contains(marker)) for code, markers in LANGUAGE_MARKERS.items()}
    for code, pattern in SCRIPT_HINTS.items():
        if pattern.search(text):
            scores[code] += 2
    # Han text without kana is separated using simplified/traditional markers.
    if re.search(r"[\u3400-\u9fff]", text) and scores["zh-Hans"] == scores["zh-Hant"] == 0:
        scores["zh-Hans"] = 1
    # Arabic script needs lexical markers to distinguish Arabic and Urdu.
    if re.search(r"[\u0600-\u06ff]", text) and not (scores["ar"] or scores["ur"]):
        scores["ar"] = 1
    return {code: score for code, score in scores.items() if score > 0}


def detect_languages(text: str) -> list[str]:
    scores = language_scores(text)
    if not scores:
        return ["undetermined"]
    return [code for code, _score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))]


def region_signals(text: str, matched_rules: tuple[ScamRule, ...] = ()) -> list[dict[str, object]]:
    lowered = text.casefold()
    hits: dict[str, set[str]] = {}
    for code, (label, markers) in REGION_MARKERS.items():
        matched = {marker for marker in markers if marker.casefold() in lowered}
        if matched:
            hits.setdefault(code, set()).update(matched)
    for rule in matched_rules:
        for code in rule.regions:
            hits.setdefault(code, set()).add(f"rule:{rule.rule_id}")
    results: list[dict[str, object]] = []
    for code, evidence in sorted(hits.items(), key=lambda item: (-len(item[1]), item[0])):
        label = REGION_MARKERS.get(code, (code, ()))[0]
        results.append(
            {"code": code, "label": label, "strength": "strong" if len(evidence) >= 2 else "possible", "evidence": sorted(evidence)[:8]}
        )
    return results


def validate_rule_pack() -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    categories: dict[str, int] = {}
    for rule in SCAM_RULES:
        if rule.rule_id in seen:
            errors.append(f"duplicate rule id: {rule.rule_id}")
        seen.add(rule.rule_id)
        if rule.language not in SUPPORTED_LANGUAGES:
            errors.append(f"unsupported language for {rule.rule_id}: {rule.language}")
        if not 1 <= rule.points <= 40:
            errors.append(f"invalid points for {rule.rule_id}: {rule.points}")
        try:
            re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            errors.append(f"invalid regex for {rule.rule_id}: {exc}")
        categories[rule.category] = categories.get(rule.category, 0) + 1
    if len(categories) < 12:
        errors.append("rule pack must cover at least 12 scam categories")
    return errors
