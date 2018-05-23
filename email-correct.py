#!/usr/bin/python
# file: email-correct.py
# -*- coding: utf-8 -*-

import os
import sys
import email
import email.charset
import email.encoders
from email.header import Header
from email.utils import getaddresses
from email.utils import formataddr
from email.utils import parseaddr
from email.utils import make_msgid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import courier.control
from courier.xfilter import XFilter
from courier.xfilter import XFilterError
from lxml import etree
import html2text

__VERSION__ = '1.10'
SELF = 'email-correct'

DEFAULT_CHARSET = 'ISO-8859-2'

debug = False

#TODO
# unknown encoding: scz-1171-1 - check all .encode() and .decode()

# Courier 0.60.0 /etc/courier/bofh
#opt MIME=none
#opt BOFHBADMIME=accept
# check etree version >= 3
#from lxml import etree; etree.__version__

def is_nonascii(string):
    return isinstance(string, basestring) and any(ord(c) & 0x80 for c in string)

def check_preamble(msg, corrected):
    if msg.preamble is not None and is_nonascii(msg.preamble):
        corrected += ['PREAMBLE']
        u_preamble = unicode(msg.preamble, DEFAULT_CHARSET)
        msg.preamble = u_preamble.encode('ascii', 'replace')

def check_msgid(msg, corrected):
    # rfc2822
    if msg.get('message-id') is None:
        if msg.get('from') is None:
            domain = 'msgid.missing'
        else:
            name, email = parseaddr(msg.get('from'))
            domain = email.split('@')[1]
        corrected += ['MESSAGE_ID']
        msg['Message-ID'] = make_msgid(domain)

def check_mimeversion(msg, corrected):
    # rfc2045
    if msg.get('mime-version') is None and (msg.is_multipart() or msg.get('content-transfer-encoding') is not None):
        corrected += ['MIME_VERSION']
        msg['MIME-Version'] = '1.0'

def check_encoding(part, corrected):
    if (part['content-transfer-encoding'] is None or part['content-transfer-encoding'] != '8bit') and is_nonascii(part.get_payload()):
        corrected += ['7BIT_TO_8BIT']
        del part['content-transfer-encoding']
        part['Content-Transfer-Encoding'] = '8bit'

def check_addresses(part, corrected, charset):
    # https://tools.ietf.org/html/rfc5504#section-3.2
    for header in ('From', 'Sender', 'To', 'Cc', 'Bcc', 'Reply-To', 'Resent-From', 'Resent-Sender', 'Resent-To', 'Resent-Cc', 'Resent-Bcc', 'Resent-Reply-To', 'Return-Path', 'Disposition-Notification-To'):
        addresses = part.get_all(header)
        if addresses is None:
            continue
        del part[header]

        if len(addresses) > 1:
            corrected += ['MULTI_' + header.upper()]
        for addressline in addresses:
            addrlist = getaddresses([addressline])
            new_addrlist = []
            for (name, addr) in addrlist:
                if is_nonascii(name):
                    corrected += [header.upper()]
                    new_name = Header(name, charset, errors='replace').encode().encode('ascii', 'replace')
                    new_addrlist += [(new_name, addr)]
                else:
                    new_addrlist += [(name, addr)]
            part[header] = ', '.join(map(formataddr, new_addrlist))

def is_invalid_header(value):
    if value and not isinstance(value, tuple) and is_nonascii(value):
        return True

    return False

def check_headers(part, corrected, charset):
    subject = part['Subject']
    if is_invalid_header(subject):
        corrected += ['SUBJECT']
        part.replace_header('subject', Header(subject, charset).encode().encode('ascii', 'replace'))

    maildate = part['Date']
    if is_invalid_header(maildate):
        corrected += ['DATE']
        part.replace_header('date', Header(maildate, charset).encode().encode('ascii', 'replace'))

    # indamail.hu problem
    mailgeoip = part['X-GeoIP']
    if is_invalid_header(mailgeoip):
        corrected += ['GEOIP']
        part.replace_header('x-geoip', Header(mailgeoip, charset).encode().encode('ascii', 'replace'))

    charset = part.get_content_charset() or charset

    # attachments
    value = part.get_param('name')
    if is_invalid_header(value):
        corrected += ['NAME']
        value = Header(value, charset).encode().encode('ascii', 'replace')
        part.set_param('name', value)

    value = part.get_param('filename', header='content-disposition')
    if is_invalid_header(value):
        corrected += ['FILENAME']
        value = Header(value, charset).encode().encode('ascii', 'replace')
        part.set_param('filename', value, 'Content-Disposition')

def check_htmlonly(msg, corrected):
    # Skip if multipart or Content-Type is not HTML
    if msg.is_multipart() or msg.get('content-type') is None or msg.get('content-type').split(';')[0].strip().lower() != 'text/html':
        return msg

    ###FIXME How to detect multipart messages without plain text part?

    email.charset.add_charset('utf-8', email.charset.QP, email.charset.QP, 'utf-8')

    ###TODO Messages without <head> should get <base href="http://<FROM_DOMAIN>/"> for relative links.

    charset = msg.get_content_charset() or DEFAULT_CHARSET

    # New message with alternative multipart MIME-level
    new_msg = MIMEMultipart('alternative')

    # Loop through the original message's headers and copy those to the new one (except two headers)
    for (key, value) in msg.items():
        if key.lower() not in ['content-type', 'content-disposition']:
            new_msg[key] = value

    payload = msg.get_payload(decode=True)

    ###FIXME Encode (QP) every header line of all parts
    ###      with non-decodable (by Content-Type: <CHARSET>) character
    # https://docs.python.org/2/library/email.message.html#email.message.Message.defects

    parser = etree.HTMLParser(encoding=str(charset), recover=True)
    dom_tree = etree.fromstring(payload, parser)
    if debug:
        etree.dump(dom_tree, pretty_print=True)
    output = etree.tostring(dom_tree, pretty_print=True, method='html')

    # Revert to UNICODE
    html_payload = output.decode('utf-8')
    try:
        text_payload = html2text.html2text(html_payload)
    except Exception as error:
        # English - Hungarian
        text_payload = 'No text part - Nincs szoveges resz'
        pid = str(os.getpid())
        sys.stderr.write(SELF + '.py[' + pid + '] Exception in html2text: %s; %s; charset=%s\n' % (str(type(error)), str(error), str(charset)))
        bf = open('/tmp/' + SELF + '_bodyFile.' + pid, 'w')
        # Only the non-convertable (broken) HTML
        #bf.write(msg.as_string())
        # The whole original message
        bf.write(output)
        bf.close()

    # Creating two MIME parts keeping the character set
    part1 = MIMEText(text_payload.encode(str(charset), 'replace'), 'plain', charset)
    part2 = MIMEText(html_payload.encode(str(charset), 'replace'), 'html', charset)
    part1['Content-Disposition'] = 'inline'
    part2['Content-Disposition'] = 'inline'
    part1['Content-Description'] = 'Plaintext Version of Message'
    part2['Content-Description'] = 'HTML Version of Message'

    # Attaching the parts to the new message
    new_msg.preamble = 'This is a MIME-formatted message.  If you see this text it means that your\nE-mail software does not support MIME-formatted messages.\n'
    new_msg.attach(part1)
    new_msg.attach(part2)

    corrected += ['HTMLONLY']
    return new_msg

def initFilter():
    # No variables for this module yes
    ###TODO e.g. DEFAULT_CHARSET, path for exception body files
    #courier.config.applyModuleConfig(SELF + '.py', globals())
    sys.stderr.write('Initialized the "' + SELF + '.py" ' + __VERSION__ + ' python filter\n')

def doFilter(bodyFile, controlFileList):
    corrected = []
    try:
        xf = XFilter(SELF, bodyFile, controlFileList)
    except XFilterError:
        sys.stderr.write(SELF + ': Loop + exit\n')
        return ''
    pid = str(os.getpid())
    # Representing an email message:
    # https://docs.python.org/2/library/email.message.html
    msg = xf.getMessage()

    if debug:
        to = msg['to']
    else:
        tolist = courier.control.getRecipientsData(controlFileList)
        if tolist is not None:
            to = tolist[0][0]

    check_preamble(msg, corrected)
    check_msgid(msg, corrected)
    check_mimeversion(msg, corrected)

    for part in msg.walk():
        charset = part.get_charset() or part.get_param('charset') or DEFAULT_CHARSET
        check_encoding(part, corrected)
        check_addresses(part, corrected, charset)
        check_headers(part, corrected, charset)

    msg = check_htmlonly(msg, corrected)

    if corrected:
        msg.set_param('corrected', ','.join(corrected), 'X-Email-Correct')
        msg.set_param('version', __VERSION__, 'X-Email-Correct')
        xf.setMessage(msg)
        try:
            xf.submit()
        except Exception as error:
            sys.stderr.write(SELF + '.py[' + pid + '] Exception in XFilter.submit: %s; %s\n' % (str(type(error).__name__), str(error)))
            bf = open('/tmp/' + SELF + '_bodyFile2.' + pid, 'w')
            bf.write(msg.as_string())
            bf.close()
        sys.stderr.write(SELF + '.py[' + pid + '] To: ' + to + ' corrected=' + ','.join(corrected) + '\n')
    elif debug:
        sys.stderr.write(SELF + '.py[' + pid + '] To: ' + to + ' correct\n')

    return ''

if __name__ == '__main__':
    debug = True
    initFilter()
    doFilter(sys.argv[1], sys.argv[2:])
