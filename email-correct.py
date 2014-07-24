#!/usr/bin/python
# file: gyogyito2.py
# -*- coding: utf-8 -*-

import os
import sys
import email
import email.charset
import email.encoders
from email.header import Header
from email.utils import getaddresses
from email.utils import formataddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import courier.control
from courier.xfilter import XFilter
from courier.xfilter import XFilterError
from lxml import etree
#import html5lib
#from html5lib import treebuilders, treewalkers, serializer

import html2text

__VERSION__ = "1.09"

DEFAULT_CHARSET = "ISO-8859-2"

debug = False

# Courier 0.60.0 /etc/courier/bofh: "opt BOFHBADMIME=accept"
# check: etree.__version__ >= 3


def is_nonascii(string):
    return isinstance(string, basestring) and any(ord(c) & 0x80 for c in string)

def check_preamble(msg, healed):
    if msg.preamble is not None and is_nonascii(msg.preamble):
        healed += ["PREAMBLE"]
        u_preamble = unicode(msg.preamble, DEFAULT_CHARSET)
        msg.preamble = u_preamble.encode('ascii', 'replace')

def check_mimeversion(msg, healed):
    # rfc2045
    if msg.get("mime-version") is None and (msg.is_multipart() or msg.get("content-transfer-encoding") is not None):
        healed += ['MIME-Version']
        msg['MIME-Version'] = '1.0'

def check_encoding(part, healed):
    # ez duplikalhatja vagy szuksegtelenul beallithatja a cte header-oket
    #if not part.is_multipart():
    #    old_cte = part['content-transfer-encoding']
    #    email.encoders.encode_7or8bit(part)
    #    if old_cte != part['content-transfer-encoding']:
    #        healed += ["7BIT_TO_8BIT"]
    if (part['content-transfer-encoding'] is None or part['content-transfer-encoding'] != '8bit') and is_nonascii(part.get_payload()):
        healed += ["7BIT_TO_8BIT"]
        del part['content-transfer-encoding']
        part['Content-Transfer-Encoding'] = "8bit"

def check_addresses(part, healed, charset):
    for header in ("To", "From", "Cc", "Bcc", "Reply-To"):
        addresses = part.get_all(header)
        if addresses is None:
            continue
        del part[header]

        if len(addresses) > 1:
            healed += ["MULTI_" + header.upper()]
        for addressline in addresses:
            addrlist = getaddresses([addressline])
            new_addrlist = []
            for (name, addr) in addrlist:
                if is_nonascii(name):
                    healed += [header.upper()]
                    new_name = Header(name, charset, errors='replace').encode().encode('ascii', 'replace')
                    new_addrlist += [(new_name, addr)]
                else:
                    new_addrlist += [(name, addr)]
            part[header] = ', '.join(map(formataddr, new_addrlist))

def is_invalid_header(value):
    if value and not isinstance(value, tuple) and is_nonascii(value):
        return True

    return False

def check_headers(part, healed, charset):
    subject = part['Subject']
    if is_invalid_header(subject):
        healed += ["SUBJECT"]
        part.replace_header("subject", Header(subject, charset).encode().encode('ascii', 'replace'))

    maildate = part['Date']
    if is_invalid_header(maildate):
        healed += ["DATE"]
        part.replace_header("date", Header(maildate, charset).encode().encode('ascii', 'replace'))

    # remelhetoleg rovidesen javitjak az indasok:
    mailgeoip = part['X-GeoIP']
    if is_invalid_header(mailgeoip):
        healed += ["GEOIP"]
        part.replace_header("x-geoip", Header(mailgeoip, charset).encode().encode('ascii', 'replace'))

    charset = part.get_content_charset() or charset

    value = part.get_param("name")
    if is_invalid_header(value):
        healed += ["NAME"]
        value = Header(value, charset).encode().encode('ascii', 'replace')
        part.set_param("name", value)

    value = part.get_param('filename', header='content-disposition')
    if is_invalid_header(value):
        healed += ["FILENAME"]
        value = Header(value, charset).encode().encode('ascii', 'replace')
        part.set_param("filename", value, "Content-Disposition")

def check_htmlonly(msg, healed):
    # Ha multipartos, vagy ha nem text/html a contenttype, nem csinalunk semmit
    if msg.is_multipart() or msg.get('content-type') is None or msg.get('content-type').split(';')[0].strip().lower() != 'text/html':
        return msg
    # FIXME  Hogyan vegyuk eszre, ha egy multipartos uzenetben NINCS text/plain resz?

    email.charset.add_charset('utf-8', email.charset.QP, email.charset.QP, 'utf-8')

    # ha nincs head: Legyen, head-be <base href="http://@UTANI_RESZ/"> (a relativ linkekhez)

    charset = msg.get_content_charset() or DEFAULT_CHARSET

    # uj alternative multipartos mime-level
    new_msg = MIMEMultipart('alternative')
    # "it is not necessary" - http://bugs.python.org/issue21567
    #new_msg.set_charset(charset)

    # vegigmegyunk az eredeti level headerjein, es ket kivetellel mindet atirjuk az uj levelbe is
    for (key, value) in msg.items():
        if key.lower() not in ['content-type', 'content-disposition']:
            new_msg[key] = value

    payload = msg.get_payload(decode=True)

    #FIXME  encode (QP) every header line of all parts
    #       not decodable (by Content-Type: charset) character in body (raw8bit, BASE64 or QP)
    #       https://docs.python.org/2/library/email.message.html#email.message.Message.defects

    parser = etree.HTMLParser(encoding=str(charset), recover=True)
    dom_tree = etree.fromstring(payload, parser)
    #etree.dump(dom_tree, pretty_print=True)
    output = etree.tostring(dom_tree, pretty_print=True, method='html')
    # trying ...
    #output = etree.tounicode(dom_tree, pretty_print=True, method='html')
    #output = etree.tostring(dom_tree, encoding=str(charset), pretty_print=True, method='html')


#    # beszappanozzuk
#    parser = html5lib.HTMLParser(tree=treebuilders.getTreeBuilder("dom"))
#    # javitott HIBA 1.04-ben: a helyes utf8-as HTMLonly leveleket ketszer kodolta utf8-ba, az oka:
#    # dom_tree = parser.parse(payload)
#    dom_tree = parser.parse(payload, encoding=str(charset))
#    walker = treewalkers.getTreeWalker("dom")
#    stream = walker(dom_tree)
#    serializr = serializer.htmlserializer.HTMLSerializer(omit_optional_tags=False)
#    output_generator = serializr.serialize(stream, encoding="utf-8")
#
#    output = ""
#    for item in output_generator:
#        output = output + str(item)

    # visszacsinaljuk unicode-da
    html_payload = output.decode('utf-8')
    try:
        text_payload = html2text.html2text(html_payload)
    except Exception, error:
        text_payload = "No text part Nincs szoveges resz"
        pid = str(os.getpid())
        sys.stderr.write("gyogyito2.py[" + pid + "] Exception in html2text: %s; %s; charset=%s\n" % (str(type(error)), str(error), str(charset)))
        bf = open("/tmp/bodyFile." + pid, "w")
        # ne az egeszet, csak a bajos HTML-t
        #bf.write(msg.as_string())
        bf.write(output)
        bf.close()

    # eredeti charsetet megtartva letrehozzuk a ket mimepartot
    part1 = MIMEText(text_payload.encode(str(charset), "replace"), "plain", charset)
    part2 = MIMEText(html_payload.encode(str(charset), "replace"), "html", charset)
    part1['Content-Disposition'] = "inline"
    part2['Content-Disposition'] = "inline"
    part1['Content-Description'] = "Plaintext Version of Message"
    part2['Content-Description'] = "HTML Version of Message"

    # csatoljuk a levelhez a partokat
    new_msg.preamble = 'This is a MIME-formatted message.  If you see this text it means that your\nE-mail software does not support MIME-formatted messages.\n'
    new_msg.attach(part1)
    new_msg.attach(part2)

    # jeloljuk, hogy tevekenykedtunk
    healed += ['HTMLONLY']

    # visszaadjuk az uj levelet
    return new_msg

def initFilter():
    #courier.config.applyModuleConfig('gyogyito2.py', globals())
    sys.stderr.write('Initialized the "gyogyito2" ' + __VERSION__ + ' python filter\n')

def doFilter(bodyFile, controlFileList):
    healed = []
    try:
        xf = XFilter("gyogyito2", bodyFile, controlFileList)
    except XFilterError:
        sys.stderr.write("gyogyito2: Loop + exit\n")
        return ''
    pid = str(os.getpid())
    # https://docs.python.org/2/library/email.message.html
    msg = xf.getMessage()

    if debug:
        to = msg['to']
    else:
        tolist = courier.control.getRecipientsData(controlFileList)
        if tolist is not None:
            to = tolist[0][0]

    check_preamble(msg, healed)
    check_mimeversion(msg, healed)

    for part in msg.walk():
        charset = part.get_charset() or part.get_param("charset") or DEFAULT_CHARSET
        check_encoding(part, healed)
        check_addresses(part, healed, charset)
        check_headers(part, healed, charset)

    msg = check_htmlonly(msg, healed)

    if healed:
        msg.set_param("healed", ",".join(healed), "X-MAIL-HEALER")
        msg.set_param("version", __VERSION__, "X-MAIL-HEALER")
        xf.setMessage(msg)
        try:
            xf.submit()
        except Exception, error:
            sys.stderr.write("gyogyito2.py[" + pid + "] Exception in submit: %s; %s\n" % (str(type(error)), str(error)))
            bf = open("/tmp/bodyFile2." + pid, "w")
            bf.write(msg.as_string())
            bf.close()
        sys.stderr.write("gyogyito2.py[" + pid + "] To: " + to + " healed=" + ",".join(healed) + "\n")
    elif debug:
        sys.stderr.write("gyogyito2.py[" + pid + "] To: " + to + " healthy\n")

    return ''

if __name__ == "__main__":
    debug = True
    initFilter()
    doFilter(sys.argv[1], sys.argv[2:])
