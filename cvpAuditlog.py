#!/usr/bin/env python
#

import argparse
from getpass import getpass
import sys
import json
import requests
from requests import packages
import time

import smtplib
import os.path as op
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from email import encoders

# CVP manipulation class

# Set up classes to interact with CVP API
# serverCVP exception class

class serverCvpError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

# Create a session to the CVP server

class serverCvp(object):

    def __init__ (self,HOST,USER,PASS):
        self.url = "https://%s"%HOST
        self.authenticateData = {'userId' : USER, 'password' : PASS}
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS'
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except packages.urllib3.exceptions.ProtocolError as e:
            if str(e) == "('Connection aborted.', gaierror(8, 'nodename nor servname provided, or not known'))":
                raise serverCvpError("DNS Error: The CVP Server %s can not be found" % CVPSERVER)
            elif str(e) == "('Connection aborted.', error(54, 'Connection reset by peer'))":
                raise serverCvpError( "Error, connection aborted")
            else:
                raise serverCvpError("Could not connect to Server")

    def logOn(self):
        try:
            headers = { 'Content-Type': 'application/json' }
            loginURL = "/web/login/authenticate.do"
            response = requests.post(self.url+loginURL,json=self.authenticateData,headers=headers,verify=False)
            if "errorMessage" in str(response.json()):
                text = "Error log on failed: %s" % response.json()['errorMessage']
                raise serverCvpError(text)
        except requests.HTTPError as e:
            raise serverCvpError("Error HTTP session to CVP Server: %s" % str(e))
        except requests.exceptions.ConnectionError as e:
            raise serverCvpError("Error connecting to CVP Server: %s" % str(e))
        except:
            raise serverCvpError("Error in session to CVP Server")
        self.cookies = response.cookies
        return response.json()

    def logOut(self):
        headers = { 'Content-Type':'application/json' }
        logoutURL = "/cvpservice/login/logout.do"
        response = requests.post(self.url+logoutURL, cookies=self.cookies, json=self.authenticateData,headers=headers,verify=False)
        return response.json()
    
    def getAuditlogs(self, startTime, endTime, category, objectKey):
        getURL = "/cvpservice/audit/exportLogs.do?startTime="+startTime + "&endTime=" + endTime + "&category=" + category + "&objectKey=" + objectKey
        response = requests.get(self.url+getURL,cookies=self.cookies,verify=False)
        return response
  
    def getUsers(self):
        getURL = "/cvpservice/user/getUsers.do?"
        getParams = {"startIndex":0, "endIndex":0}
        response = requests.get(self.url+getURL,cookies=self.cookies,params=getParams,verify=False)
        if "errorMessage" in str(response.json()):
            text = "Error retrieving users failed: %s" % response.json()['errorMessage']
            raise serverCvpError(text)
        users = response.json()["users"]
        return users

def send_mail(send_from, send_to, subject, message, files,
              server, port, username, password,
              use_tls):

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(message))

    for path in files:
        part = MIMEBase('application', "octet-stream")
        with open(path, 'rb') as file:
            part.set_payload(file.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition',
                        'attachment; filename="{}"'.format(op.basename(path)))
        msg.attach(part)

    smtp = smtplib.SMTP(server, port)
    if use_tls:
        smtp.starttls()
    smtp.login(username, password)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.quit()

def main():
    
    d1 = time.strftime("%Y_%m_%d_%H_%M_%S", time.gmtime())
    currenttime=time.time()
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', required=True)
    parser.add_argument('--cvpServer', required=True)

    args = parser.parse_args()
    username = args.username
    password = getpass()
    cvpServer=args.cvpServer
    
    print ("Attaching to API on %s to get Data" %cvpServer)
    try:
        cvpSession = serverCvp(str(cvpServer),username,password)
        logOn = cvpSession.logOn()
    except serverCvpError as e:
        text = "serverCvp:(main1)-%s" % e.value
        print (text)
    print ("Login Complete")
    
    userlist = []
    files = []
    users = cvpSession.getUsers()
    
    endTime = str(int(currenttime)) + "000"
    startTime = str(int(currenttime)-86400) + "000"

    for user in users:
        objectKey= user["userId"]
        auditLogs = cvpSession.getAuditlogs(startTime, endTime,"User", objectKey)
        filename= "Audit_logs_user_" + objectKey + "_" + d1 + ".csv"
        with open(filename,'w') as f:
            f.write(auditLogs.text)
        files.append(filename)

    print ("Logout from CVP:%s"% cvpSession.logOut()['data'])
    send_from = "sender@domain.com"
    send_to = ["receiver@domain.com"]
    subject = "User Audit Logs "+d1
    message = ""
    server = "smtp.domain.com"
    username = "username"
    password = "password"
    port =587
    use_tls = True
    send_mail(send_from, send_to, subject, message, files, server, port, username, password, use_tls )

if __name__ == '__main__':
    main()

            
