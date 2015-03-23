#!/usr/bin/python
# courier.xfilter -- python module for modifying messages in the queue
# Copyright (C) 2006  Gordon Messmer <gordon@dragonsdawn.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import os
import sys
import thread
import email
# Compatibility with email version 3:
# http://docs.python.org/lib/email-pkg-history.html
try:
    import email.Generator
    email.generator = email.Generator
except ImportError:
    import email.generator
import courier.control
import courier.config


_envLock = thread.allocate_lock()


class XFilterError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class InitError(XFilterError):
    pass


class LoopError(XFilterError):
    pass


class SubmitError(XFilterError):
    pass


class XFilter:
    """Modify messages in the Courier spool.

    This class will load a specified message from Courier's spool and
    allow you to modify it.  This is implemented by loading the
    message as an email.Message object which will be resubmitted to
    the spool.  If the new message is submitted, the original message
    will be marked completed.  If the new message is not submitted,
    no changes will be made to the original message.

    Arguments:
    filterName -- a name identifying the filter calling this class
    bodyFile -- the same argument given to the doFilter function
    controlFileList -- the same argument given to the doFilter function

    The class will raise xfilter.InitError when instantiated if it
    cannot open the bodyFile or any of the control files.  It will
    raise xfilter.LoopError if the message headers indicate that the
    message has already been filtered under the same filterName.  When
    creating an XFilter object, you should catch xfilter.LoopError and
    return without attempting to modify the message further.

    After creating an instance of this class, use the getMessage
    method to get the email.Message object created from the bodyFile.
    Make any modifications required using the normal python functions
    usable with that object.

    When modifications are complete, call the XFilter object's submit
    method to insert the new message into the spool.  If there is an
    error submitting the modified message, xfilter.SubmitError will
    be raised.  Otherwise, the modified message has been submitted,
    and the recipients of the original message will be marked
    complete.  If no exception is raised, return '050 Ok' to stop all
    further filtering of the message by all courierfilters.  Because
    modifying the message creates a new message in Courier's queue,
    you must not reject a message that has been modified; it is no
    longer possible to notify the sender that the message was
    rejected.  Filters that modify messages should be run last.

    """
    def __init__(self, filterName, bodyFile, controlFileList):
        try:
            bfStream = open(bodyFile)
        except:
            raise InitError('Internal failure opening message data file')
        try:
            self.message = email.message_from_file(bfStream)
        except Exception, e:
            raise InitError('Internal failure parsing message data file: %s' % str(e))
        # Check that message hasn't been filtered previously, to prevent loops
        if 'X-Filtered-By' in self.message:
            filters = self.message.get_all('X-Filtered-By')
            if filterName in filters:
                raise LoopError('Message has already been filtered by %s' % filterName)
        # Add a marker to this message so that it's not filtered again.
        self.message.add_header('X-Filtered-By', filterName)
        # Save the arguments
        self.filterName = filterName
        self.bodyFile = bodyFile
        self.controlFileList = controlFileList
        # Parse the control files and save their data
        self.controlData = courier.control.getControlData(controlFileList)


    def getMessage(self):
        return self.message


    def getControlData(self):
        return self.controlData


    def submitInject(self, source, recipients):
        def _submit_read_response(sOutput):
            # Read an SMTP style response from the submit program, and
            # return the assembled response.
            response = ''
            sbuf = sOutput.readline()
            while sbuf and len(sbuf) > 4:
                response += sbuf
                if sbuf[3] == ' ':
                    return response
                sbuf = sOutput.readline()
            # We will have returned unless an empty or malformed response
            # was read, in which case we need to raise an exception.
            raise SubmitError('Error reading response, got "%s"' % response)

        def _submit_send(sendData, sInput, sOutput):
            # Write "sendData" to submit's stdin
            try:
                sInput.write(sendData)
            except IOError:
                sInput.close()
                sOutput.close()
                os.wait()
                raise SubmitError('IOError writing: "%s"' % sendData)

        def _submit_send_message(sendData, sInput, sOutput):
            # Write email.message object "sendData" to submit's stdin
            try:
                g = email.generator.Generator(sInput, mangle_from_=False)
                g.flatten(sendData)
            except IOError:
                sInput.close()
                sOutput.close()
                os.wait()
                raise SubmitError('IOError writing: "%s"' % sendData)

        def _submit_recv(sInput, sOutput):
            # Read the response.  If it's not a 2XX code, raise an exception
            # and allow submit to exit.
            recvData = _submit_read_response(sOutput)
            if recvData[0] in '45':
                if not sInput.closed:
                    sInput.close()
                if not sOutput.closed:
                    sOutput.close()
                os.wait()
                raise SubmitError(recvData)

        def _submit_toXtext(text):
            def _xtchar(char):
                ochar = ord(char)
                if( ochar < 33 or ochar > 126
                    or char in '+\\(' ):
                    return '+%X' % ochar
                else:
                    return char
            xtext = ''.join(map(_xtchar, text))
            return xtext

        # Prepare the submit command and args
        submitPath = courier.config.libexecdir + '/courier/submit'
        submitArgs = [submitPath]
        if self.controlData['u']:
            submitArgs.append('-src=%s' % self.controlData['u'])
        submitArgs.append(source)
        submitArgs.append(self.controlData['f'])
        _envLock.acquire()
        os.environ['RELAYCLIENT'] = ''
        _envLock.release()
        (sInput, sOutput) = os.popen2(submitArgs, 't', 0)

        # Feed in the message sender
        sbuf = self.controlData['s'] + '\t'
        if self.controlData['t']:
            sbuf += self.controlData['t']
        if self.controlData['V']:
            sbuf += 'V'
        if self.controlData['U']:
            sbuf += self.controlData['U']
        if self.controlData['e']:
            sbuf += '\t' + _submit_toXtext(self.controlData['e'])
        sbuf += '\n'
        _submit_send(sbuf, sInput, sOutput)
        _submit_recv(sInput, sOutput)

        # Feed in each of the recipients
        for x in recipients:
            # If the canonical address starts with '".xalias/', it's an alias
            # in aliasdir that must be submited via its original address.
            if x[0].startswith('".xalias/'):
                if x[1].startswith('rfc822;'):
                    xaliasaddr = x[1][7:]
                else:
                    xaliasaddr = x[1]
                sbuf = '%s\t%s\t%s\n' % (xaliasaddr, _submit_toXtext(x[2]), x[1])
            else:
                sbuf = '%s\t%s\t%s\n' % (x[0], _submit_toXtext(x[2]), x[1])
            _submit_send(sbuf, sInput, sOutput)
            _submit_recv(sInput, sOutput)

        # Terminate the recipient list by sending a blank line
        _submit_send('\n', sInput, sOutput)

        # Send the message
        _submit_send_message(self.message, sInput, sOutput)
        # Close submit's input stream, marking the end of the messsage.
        sInput.close()
        # Check submit's final response.
        _submit_recv(sInput, sOutput)
        # Close the remaining stream and wait() for submit's exit.
        sOutput.close()
        os.wait()


    def oldSubmit(self):
        self.submitInject('esmtp', self.controlData['r'])
        # Finally, if the message was accepted by submit, mark all of
        # the recipients still in the list as complete in the original
        # message.
        for x in self.controlData['r']:
            courier.control.delRecipientData(self.controlFileList, x)


    def newSubmit(self):
        bfo = open(self.bodyFile, 'w')
        g = email.generator.Generator(bfo, mangle_from_=False)
        g.flatten(self.message)
        bfo.close()


    def submit(self):
        if courier.config.isMinVersion('0.57.1'):
            self.newSubmit()
        else:
            self.oldSubmit()