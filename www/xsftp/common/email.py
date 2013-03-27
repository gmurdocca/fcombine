#!/usr/bin/python
############################################################################
#
# Fcombine - An enterprise grade automounter and file server
# Copyright (C) 2013 George Murdocca
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#############################################################################

def send_email(subject, body, to, bcc=None, attachments=None, headers=None, smtp_port=25):
    ''' subject:     string
        body:        string
        to:  list of strings
        bcc: list of strings
        attachments: list of three-tuples as (string, string, string), which correspond to (filename, content, mimtype)
        headers:     a dictionary of header:value pairs (string:string)

        Raises:      Email_Error
    '''
    import xsftp.webui.models
    # get the port number
    smtp_port = xsftp.webui.models.Configuration.objects.all()[0].smtp_port
    # set the fqdn inside django.core.mail
    django.core.mail.DNS_NAME._fqdn = xsftp.webui.models.Configuration.objects.all()[0].device_name
    smtp_server = xsftp.webui.models.Configuration.objects.all()[0].smtp_server
    from_address = xsftp.webui.models.Configuration.objects.all()[0].smtp_from_address or "admin@%s" % (xsftp.webui.models.Configuration.objects.all()[0].device_name or xsftp.webui.models.Configuration.objects.all()[0].ip_address)
    if not smtp_server:
        raise Email_Error("SMTP server not defined")
    try:
        smtpcon = django.core.mail.SMTPConnection(host=smtp_server, port=smtp_port)
        email = django.core.mail.EmailMessage(subject=subject, body=body, from_email=from_address, to=to, connection=smtpcon)
        if bcc:
            email.bcc = bcc
        if attachments:
            email.attachments = attachments
        if headers:
            email.headers = headers
        email.send()
    #except (socket.error, socket.gaierror, smtplib.SMTPException), e: #XXX shouldn't this be used instead of the below line?
    except Exception, e:
        raise Email_Error(str(e))
    try:
        smtpcon.close()
    except:
        pass # fail silently on close()



