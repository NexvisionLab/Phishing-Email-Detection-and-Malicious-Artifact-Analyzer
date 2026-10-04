"""Builds 20 test emails (15 attacks, 5 tricky legitimate messages) as .eml files under tests/cases/, plus a manifest.
The attachments are harmless stand-ins (a few bytes with the shape or name of the real thing); no domain here is a real
brand's, and the analyzer never opens a link. Run:  python tests/make_cases.py"""
import io
import json
import os
import zipfile
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import format_datetime

OUT = os.path.join(os.path.dirname(__file__), "cases")
os.makedirs(OUT, exist_ok=True)
NOW = datetime(2026, 9, 24, 9, 30, tzinfo=UTC)
CASES = []


def add(cid, title, expected, min_risk, msg, note=""):
    path = os.path.join(OUT, f"{cid}.eml")
    with open(path, "wb") as f:
        f.write(msg.as_bytes())
    CASES.append({"id": cid, "title": title, "expected": expected, "min_risk": min_risk, "file": f"{cid}.eml", "note": note})


def base(frm, to, subject, auth=None, reply_to=None, extra=None):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = format_datetime(NOW)
    m["Message-ID"] = f"<{abs(hash((frm, subject))) % 10**10}@mail.example.net>"
    if reply_to:
        m["Reply-To"] = reply_to
    if auth:
        m["Authentication-Results"] = auth
    for k, v in (extra or {}).items():
        m[k] = v
    return m


def zip_bytes(files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return b.getvalue()


BAD_AUTH = "mx.corp.example.org; spf=fail smtp.mailfrom=micr0soft-online.com; dkim=none; dmarc=fail header.from=micr0soft-online.com"
GOOD_AUTH = "mx.corp.example.org; spf=pass smtp.mailfrom=mail.example-bank.com; dkim=pass header.d=example-bank.com; dmarc=pass header.from=example-bank.com"

# ---------------------------------------------------------------- attacks
m = base('"Microsoft 365 Security" <security-noreply@micr0soft-online.com>', "j.tan@acme-corp.com",
         "Action required: your mailbox will be deactivated in 24 hours", auth=BAD_AUTH)
m.set_content("Your Microsoft 365 password expires today. Verify your account now to keep access to email and Teams.\n\n"
              "Sign in: https://login.microsoftonline.com.secure-verify-account.com/common/oauth2/authorize?client_id=8842\n\nMicrosoft Account Team")
add("P01", "Microsoft 365 credential phish, digit-swap sender, brand used as a subdomain, failed SPF/DKIM/DMARC", "phish", "likely_phishing", m)

m = base('"David Lim (CEO)" <david.lim.ceo@gmail.com>', "priya.nair@acme-corp.com", "Quick favour - are you at your desk?",
         auth="mx.corp.example.org; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass", reply_to="david.lim.private@proton.me")
m.set_content("Priya,\n\nI'm in a board meeting and can't take calls. I need you to purchase 5 x $200 Apple gift cards for a client "
              "urgently. Scratch off the codes and email me the photos. Keep this confidential, I'll reimburse you today.\n\nDavid\nSent from my iPhone")
add("P02", "BEC: executive display-name spoof from a free mailbox, gift cards, reply-to switch, no links", "phish", "suspicious", m)

m = base('"Accounts - Northwind Supplies" <accounts@northwind-supplies.co>', "ap@acme-corp.com", "Re: Invoice 4471 - updated remittance details",
         auth="mx.corp.example.org; spf=pass smtp.mailfrom=northwind-supplies.co; dkim=pass header.d=northwind-supplies.co",
         reply_to="accounts@northwlnd-supplies.co", extra={"In-Reply-To": "<a1b2c3@mail.acme-corp.com>", "References": "<a1b2c3@mail.acme-corp.com>"})
m.set_content("Hi,\n\nPlease note our bank has changed. Kindly send the outstanding payment of USD 48,250.00 for invoice 4471 to the new account below "
              "and confirm by return.\n\nBank: Global Trust Bank\nAccount name: Northwind Supplies Ltd\nIBAN: DE44 5001 0517 5407 3249 31\nSWIFT: GTBKDEFF\n\n"
              "Please ignore the previous details. Do not call the old number, our lines are being migrated.\n\nRegards,\nAccounts Team")
add("P03", "Vendor bank-detail change in a hijacked thread, reply-to one letter off (rn -> l), pressure not to call", "phish", "suspicious", m)

m = base('"Sarah Wong" <sarah.wong.hr1984@outlook.com>', "payroll@acme-corp.com", "Direct deposit update",
         auth="mx.corp.example.org; spf=pass smtp.mailfrom=outlook.com; dkim=pass header.d=outlook.com")
m.set_content("Hello Payroll,\n\nI have changed banks. Please update my direct deposit before Friday's run. New routing and account number: "
              "021000021 / 4409 8821 3307. I can't access the HR portal from here. Thanks!\n\nSarah Wong, Finance")
add("P04", "Payroll diversion: staff display name on a free mailbox, bank details, avoids the portal", "phish", "suspicious", m)

html_smuggle = ("<html><body><script>var d='JVBERi0xLjQKJcfsj6IK';function go(){var b=new Blob([atob(d)],{type:'application/octet-stream'});"
                "var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='Statement.exe';a.click();}window.onload=go;</script>"
                "<p>Loading secure document...</p></body></html>")
m = base('"Accounts Receivable" <ar@bright-logistics-inc.com>', "finance@acme-corp.com", "Payment advice PA-88213 attached")
m.set_content("Dear finance team,\n\nOur payment advice is attached. Please open the attachment in your browser to view remittance details.\n\nRegards")
m.add_attachment(html_smuggle.encode(), maintype="text", subtype="html", filename="Payment_Advice_PA-88213.html")
add("P05", "HTML smuggling: attached .html builds a Blob from base64 and auto-downloads an .exe", "phish", "likely_phishing", m)

m = base('"Fatima Noor" <fatima.noor@trade-partners-hk.com>', "ops@acme-corp.com", "Shipping documents - BL and Invoice")
m.set_content("Hello,\n\nPlease find the shipping documents attached (password: 2026). The container leaves Friday; we need confirmation today.\n\nBest regards")
m.add_attachment(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00 stand-in", maintype="application", subtype="octet-stream", filename="BL-Invoice-99123.pdf.exe")
add("P06", "Double-extension executable (pdf.exe) with a password hint in the body", "phish", "likely_phishing", m)

docm = zip_bytes({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>", "word/vbaProject.bin": b"\xd0\xcf\x11\xe0 macro stand-in AutoOpen Shell"})
m = base('"Procurement" <po@meridian-industrial.net>', "purchasing@acme-corp.com", "Purchase Order PO-55102 - please review and sign")
m.set_content("Hello,\n\nAttached is PO-55102 for your approval. If the document opens in Protected View, click Enable Editing and Enable Content "
              "to see the amounts.\n\nThank you")
m.add_attachment(docm, maintype="application", subtype="vnd.ms-word.document.macroEnabled.12", filename="PO-55102.docm")
add("P07", "Macro-enabled Word document with an 'Enable Content' instruction", "phish", "likely_phishing", m)

m = base('"Legal Department" <legal@harborview-partners.org>', "cfo@acme-corp.com", "Subpoena documents - confidential")
m.set_content("Please review the attached documents regarding case 24-CV-1187. The archive is password protected: 7741\n\nThis message is privileged and confidential.")
m.add_attachment(zip_bytes({"Subpoena_24-CV-1187.iso": b"CD001 stand-in iso image", "readme.txt": "open the image"}), maintype="application", subtype="zip", filename="Documents.zip")
add("P08", "Password-protected zip carrying an ISO disk image, legal-threat lure", "phish", "likely_phishing", m)

m = base('"PayPal Billing" <service@paypal-billing-help.net>', "j.tan@acme-corp.com", "Invoice INV-7788341: $499.99 charged to your account",
         auth="mx.corp.example.org; spf=softfail smtp.mailfrom=paypal-billing-help.net; dkim=none; dmarc=fail")
m.set_content("Hello,\n\nA payment of $499.99 to GeekSquad Protection Services was processed on 24 Sep.\n\nIf you did not authorize this charge, call our "
              "dispute line immediately at +1 (888) 555-0142 (toll free). Our agents are available 24/7 to cancel the order and refund you.\n\nInvoice: INV-7788341\nPayPal Billing")
add("P09", "Callback phishing: fake invoice, phone number to dispute, no link at all", "phish", "suspicious", m)

m = base('"DocuSign via Secure Mail" <dse@secure-docsign-mail.com>', "j.tan@acme-corp.com", "Completed: Please review and sign 'Q3 Agreement.pdf'")
m.set_content("Your document is ready. Review: https://bit.ly/3xQ9kLm")
m.add_alternative("""<html><body><p>Your document is ready.</p>
<p><a href="https://www.google.com/url?q=https%3A%2F%2Fdocs-review-portal.xyz%2Fsign%3Fid%3D7781&sa=D">REVIEW DOCUMENT</a></p>
<p>Or open: <a href="https://bit.ly/3xQ9kLm">https://app.docusign.com/documents/details</a></p>
<p>Powered by Docusign</p></body></html>""", subtype="html")
add("P10", "DocuSign lure through a Google open redirect and a bit.ly link whose visible text names docusign.com", "phish", "suspicious", m)

m = base('"PayPal" <service@paypal.com>', "j.tan@acme-corp.com", "Your account has been limited",
         auth="mx.corp.example.org; spf=fail smtp.mailfrom=xn--pypal-4ve.com; dkim=fail; dmarc=fail")
m.set_content("We noticed unusual activity. Sign in: https://xn--pypal-4ve.com/signin/verify")
m.add_alternative("""<html><body><p>We noticed unusual activity.</p>
<p><a href="https://xn--pypal-4ve.com/signin/verify">https://www.paypal.com/signin</a></p>
<p>File: <a href="https://cdn-files.xyz/download/\u202egpj.exe">Statement</a></p></body></html>""", subtype="html")
add("P11", "IDN homoglyph (xn--pypal) behind a paypal.com anchor text, right-to-left override in a link, failed authentication", "phish", "likely_phishing", m)

m = base('"Ahmad Rahman" <ahmad.rahman@gmail.com>', "j.tan@acme-corp.com", "Ahmad shared 'Salary Review 2026' with you")
m.set_content("Ahmad shared a document. https://drive.google.com/file/d/1AbCdEf/view")
m.add_alternative("""<html><body><p>Ahmad Rahman shared a document with you.</p>
<a href="https://sites.google.com/view/salary-review-2026-portal/login">https://drive.google.com/file/d/1AbCdEf/view</a>
<p>Google Drive: Share and store files online.</p></body></html>""", subtype="html")
add("P12", "Shared-document lure: visible link says drive.google.com, real target is a Google Sites page", "phish", "suspicious", m)

m = base('"MetaMask Support" <support@metamask-wallet-verify.com>', "j.tan@acme-corp.com", "Wallet suspended - verify your recovery phrase")
m.set_content("Your MetaMask wallet has been temporarily suspended after a security review. To restore access within 12 hours, verify your 12-word secret "
              "recovery phrase at https://metamask-wallet-verify.com/restore. Failure to do so will result in permanent loss of your funds.\n\nMetaMask Support Team")
add("P13", "Crypto wallet phish asking for the recovery phrase", "phish", "likely_phishing", m)

m = base('"Direction Generale des Finances" <remboursement@impots-gouv-fr-services.com>', "marie.dupont@acme-corp.fr",
         "Vous avez droit a un remboursement d'impots de 487,20 EUR")
m.set_content("Cher contribuable,\n\nApres le dernier calcul de votre declaration, vous avez droit a un remboursement de 487,20 EUR. Pour le recevoir, "
              "veuillez confirmer vos coordonnees bancaires avant 48 heures : https://impots-gouv-fr-services.com/remboursement\n\nLe non-respect de ce delai entrainera l'annulation.")
add("P14", "French tax-refund phish with a lookalike domain and a 48-hour deadline", "phish", "suspicious", m)

m = base('"Parcel Service" <no-reply@postal-redelivery-sg.com>', "j.tan@acme-corp.com", "Your parcel could not be delivered - fee 1.99 SGD")
m.set_content("Your parcel is held at our depot. Pay the redelivery fee at https://postal-redelivery-sg.com/pay/8841 within 24 hours.")
m.set_content("Priya Nair sent you a document to review and sign. https://na3.docusign.net/Signing/EmailStart.aspx?a=1f2e3d4c")
m.add_alternative("""<html><body>
<div style="color:#ffffff;font-size:1px;line-height:1px">invoice statement meeting agenda schedule newsletter report minutes quarterly review team update thank you regards</div>
<p>Your parcel <b>SG88213</b> could not be delivered. A redelivery fee of <b>SGD 1.99</b> is required.</p>
<a href="https://postal-redelivery-sg.com/pay/8841" style="background:#e60000;color:#fff;padding:10px">Pay now</a>
<img src="https://track.postal-redelivery-sg.com/px.gif?e=j.tan" width="1" height="1"></body></html>""", subtype="html")
add("P15", "Delivery-fee scam: hidden white-on-white filler text, tracking pixel, HTML says 1.99 while plain text differs in framing", "phish", "suspicious", m)

# ---------------------------------------------------------------- legitimate but tricky
m = base('"Loop Coffee Roasters" <hello@news.loopcoffee.com>', "j.tan@acme-corp.com", "Last chance: 48-hour flash sale - free shipping ends tonight!",
         auth="mx.corp.example.org; spf=pass smtp.mailfrom=bounce.news.loopcoffee.com; dkim=pass header.d=news.loopcoffee.com; dmarc=pass",
         extra={"List-Unsubscribe": "<https://news.loopcoffee.com/unsub?u=8842>", "List-Id": "<weekly.news.loopcoffee.com>"})
m.set_content("Flash sale ends tonight! Free shipping on orders over $40. Shop now: https://news.loopcoffee.com/sale?utm_source=email&utm_campaign=flash\n\nUnsubscribe: https://news.loopcoffee.com/unsub?u=8842")
add("B01", "Legitimate marketing newsletter with urgency wording, tracking parameters and list headers", "benign", "low", m)

m = base('"Example Bank Alerts" <alerts@mail.example-bank.com>', "j.tan@acme-corp.com", "New sign-in to your account", auth=GOOD_AUTH)
m.set_content("Hello J. Tan,\n\nWe noticed a new sign-in to Example Bank Online from a Windows device in Singapore on 24 Sep 2026, 09:12.\n\n"
              "If this was you, no action is needed. If you don't recognise it, call the number on the back of your card or visit a branch. "
              "We will never ask for your password, PIN or one-time code by email, SMS or phone.\n\nExample Bank Security")
add("B02", "Legitimate bank security notice: passes SPF/DKIM/DMARC, tells you never to share codes", "benign", "low", m)

m = base('"IT Service Desk" <itservicedesk@acme-corp.com>', "j.tan@acme-corp.com", "Your password expires in 3 days",
         auth="mx.acme-corp.com; spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.d=acme-corp.com; dmarc=pass")
m.set_content("Hi J. Tan,\n\nYour network password expires on 27 Sep. Please change it before then using the self-service portal: https://sso.acme-corp.com/password/change\n\n"
              "If you need help, raise a ticket at https://helpdesk.acme-corp.com or call ext. 4400.\n\nIT Service Desk")
add("B03", "Legitimate internal password-expiry notice from the company's own domain with a link to its own SSO", "benign", "low", m,
    note="Reads like a credential lure but is authenticated and on-domain.")

m = base('"DocuSign System" <dse_na3@docusign.net>', "j.tan@acme-corp.com", "Please DocuSign: Vendor Agreement.pdf",
         auth="mx.corp.example.org; spf=pass smtp.mailfrom=docusign.net; dkim=pass header.d=docusign.net; dmarc=pass header.from=docusign.net")
m.add_alternative("""<html><body><p>Priya Nair sent you a document to review and sign.</p>
<p><a href="https://na3.docusign.net/Signing/EmailStart.aspx?a=1f2e3d4c&etti=24&acct=9912&er=e5b1">REVIEW DOCUMENT</a></p>
<p>Do not share this email. If you did not expect it, contact the sender directly.</p></body></html>""", subtype="html")
add("B04", "Genuine DocuSign request: authenticated docusign.net sender and matching links", "benign", "low", m)

ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Google Inc//Google Calendar 70.9054//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\n"
       "DTSTART:20260928T020000Z\r\nDTEND:20260928T030000Z\r\nSUMMARY:Q4 planning sync\r\nORGANIZER;CN=Priya Nair:mailto:priya.nair@acme-corp.com\r\n"
       "LOCATION:https://meet.google.com/abc-defg-hij\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
m = base('"Priya Nair" <calendar-notification@google.com>', "j.tan@acme-corp.com", "Invitation: Q4 planning sync @ Mon 28 Sep",
         auth="mx.corp.example.org; spf=pass smtp.mailfrom=google.com; dkim=pass header.d=google.com; dmarc=pass")
m.set_content("Priya Nair has invited you to Q4 planning sync.\nJoin with Google Meet: https://meet.google.com/abc-defg-hij\n")
m.add_attachment(ics.encode(), maintype="text", subtype="calendar", filename="invite.ics")
add("B05", "Genuine Google Calendar invitation with an .ics attachment", "benign", "low", m)

with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(CASES, f, indent=1)
print(len(CASES), "cases written to", OUT)
