from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter

PROTOTYPES = {
    "Credential phishing": [
        "verify account password login immediately",
        "mailbox suspended sign in to restore access",
        "验证账户密码点击登录",
        "sahkan akaun kata laluan klik log masuk",
        "கணக்கு கடவுச்சொல் சரிபார்க்க",
    ],
    "Business email compromise": [
        "urgent confidential wire transfer invoice change bank details",
        "buy gift cards and send the codes",
        "紧急转账更改银行资料",
        "segera pindahan ubah butiran bank",
    ],
    "Delivery or invoice lure": [
        "package delivery failed pay small fee reschedule",
        "invoice remittance purchase order attached",
        "包裹配送失败支付费用",
        "penghantaran gagal bayar yuran",
    ],
    "Job or task scam": [
        "remote part time job simple task commission deposit withdraw",
        "product review task top up to unlock earnings",
        "兼职刷单任务佣金充值提现",
        "kerja sambilan tugasan komisen deposit",
    ],
    "Prize or advance-fee scam": [
        "lottery winner prize inheritance processing release fee",
        "中奖奖品领取手续费",
    ],
    "Extortion or threat": [
        "recorded webcam compromising video pay bitcoin wallet or expose",
        "blackmail cryptocurrency demand",
    ],
    "Investment or crypto scam": [
        "guaranteed risk free investment return double your money crypto profit",
        "ganancia garantizada inversión sin riesgo",
        "lucro garantido investimento bitcoin",
        "保证稳赚零风险投资收益",
    ],
    "Government or law-enforcement impersonation": [
        "police federal agent arrest warrant transfer money",
        "digital arrest customs officer narcotics parcel",
        "警察拘捕通缉罚款转账",
    ],
    "Bank or payment-service impersonation": [
        "bank card blocked unauthorized payment click verify account",
        "wallet suspended secure your account",
    ],
    "Tech-support or malware scam": [
        "computer infected virus call support remote access anydesk teamviewer",
    ],
    "Romance scam": [
        "love soulmate future together emergency hospital send money gift card",
        "te amo alma gemela emergencia envía dinero",
    ],
    "Recovery scam": [
        "recover stolen crypto lost funds upfront fee",
        "recuperar fondos tasa pago por adelantado",
    ],
    "Friend or family impersonation": [
        "new phone number mum dad urgent bill transfer money",
        "número novo pix urgente mãe pai",
    ],
    "Toll or traffic-payment scam": [
        "unpaid toll parking traffic fine pay now penalty",
    ],
    "Tax or refund scam": [
        "tax refund rebate pending claim bank details fee",
    ],
}


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text.casefold())
    # Collapse deliberate single-character spacing such as "v e r i f y".
    text = re.sub(r"(?:(?<=\b\w)\s+(?=\w\b)){2,}", "", text)
    return re.sub(r"[^\w\u3400-\u9fff\u0b80-\u0bff]+", " ", text)


def _features(text: str) -> Counter[str]:
    compact = _normalize(text).replace(" ", "_")[:20_000]
    features: Counter[str] = Counter()
    for n in (3, 4):
        features.update(compact[i : i + n] for i in range(max(0, len(compact) - n + 1)))
    return features


def _cosine(left: Counter[str], right: Counter[str]) -> float:
    shared = set(left).intersection(right)
    numerator = sum(left[key] * right[key] for key in shared)
    denominator = math.sqrt(sum(v * v for v in left.values()) * sum(v * v for v in right.values()))
    return numerator / denominator if denominator else 0.0


_VECTORS = {category: [_features(sample) for sample in samples] for category, samples in PROTOTYPES.items()}


def classify_local(text: str) -> tuple[str, float]:
    vector = _features(text)
    scores = {
        category: max((_cosine(vector, prototype) for prototype in prototypes), default=0.0) for category, prototypes in _VECTORS.items()
    }
    category = max(scores, key=lambda name: scores[name])
    return category, scores[category]
