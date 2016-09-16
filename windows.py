#!/usr/bin/python
import random
import socket
import time
import sys
import datetime
import json
from collections import OrderedDict

token='efb8bcc1-dddc-3056-9dce-09836f4e01e2'

def rando():
	hostnames = ['Server1', 'Server2', 'Server3', 'Server4', 'Server5']
	users = ['ADMINISTRATOR', 'ADMIN', 'USER', 'ADMINISTRADOR', 'TEST', 'ROOT', 'USER1', 'SUPPORT', 'MANAGER', 'GUEST', 'Administrator', 'SCANNER', 'SERVER', 'OFFICE', 'BACKUP', 'LOGIN', 'SYSTEM', 'SQL', 'SCAN', 'ADMINS', 'QWERTY', '123', 'USERNAME', 'TEST1', 'SYS', 'SERVERS', 'PASSWORD', 'NETWORK', 'ADMINISTRATORS', 'ZCTZ', 'XEROX', 'SKLAD', 'NEADMIN', 'MYSQL', 'LOCAL', 'BOSSAADMIN', 'ADMINUSER', 'ADMINISTRATEUR', 'ADMIN123', 'ZSUPPORT']
	OUs = ['Finance', 'Developers', 'Support T1', 'Sales', 'IT_HelpDesk', 'IT_Admin', 'HR']
	r_host = random.choice(hostnames)
	r_user = random.choice(users)
	r_OU = random.choice(OUs)
	#failed_login: %s1 = timestamp, $s2 = hostname, $s4 = msg_user, %s5 = target_user, %s6 = timestamp
	Failed_Login = '{"EventTime":"%s","Hostname":"%s","Keywords":"-9218868437227405312","EventType":"AUDIT_FAILURE","SeverityValue":"4","Severity":"ERROR","EventID":"4625","SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Version":"0","Task":12544,"OpcodeValue":0,"RecordNumber":87418,"ProcessID":660,"ThreadID":3128,"Channel":"Security","Message":"An account failed to log on.  Subject:  Security ID:  S-1-0-0  Account Name:  -  Account Domain:  -  Logon ID:  0x0  Logon Type:   3  Account For Which Logon Failed:  Security ID:  S-1-0-0  Account Name:  %s  Account Domain:    Failure Information:  Failure Reason:  Unknown user name or bad password.  Status:   0xC000006D  Sub Status:  0xC0000064  Process Information:  Caller Process ID: 0x0  Caller Process Name: -  Network Information:  Workstation Name:   Source Network Address: -  Source Port:  -  Detailed Authentication Information:  Logon Process:  NtLmSsp   Authentication Package: NTLM  Transited Services: -  Package Name (NTLM only): -  Key Length:  0  This event is generated when a logon request fails. It is generated on the computer where access was attempted.  The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.  The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).  The Process Information fields indicate which account and process on the system requested the logon.  The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.  The authentication information fields provide detailed information about this specific logon request.  - Transited services indicate which intermediate services have participated in this logon request.  - Package name indicates which sub-protocol was used among the NTLM protocols.  - Key length indicates the length of the generated session key. This will be 0 if no session key was requested.","Category":"Logon","Opcode":"Info","SubjectUserSid":"S-1-0-0","SubjectUserName":"-","SubjectDomainName":"-","SubjectLogonId":"0x0","TargetUserSid":"S-1-0-0","TargetUserName":"%s","Status":"0xc000006d","FailureReason":"%%2313","SubStatus":"0xc0000064","LogonType":"3","LogonProcessName":"NtLmSsp ","AuthenticationPackageName":"NTLM","TransmittedServices":"-","LmPackageName":"-","KeyLength":"0","ProcessName":"-","IpAddress":"-","IpPort":"-","EventReceivedTime":"%s","SourceModuleName":"eventlog","SourceModuleType":"im_msvistalog"}'
	#admin_created: %s1 = timestamp, %s2 = hostname, %s4 = msg_hostname, %s5 = sub_username, %s6 = hostname, %s7 = timestamp2
	Admin_Created = '{"EventTime": "%s", "Hostname": "%s", "Keywords": -9214364837600035000, "EventType": "AUDIT_SUCCESS", "SeverityValue": 2, "Severity": "INFO", "EventID": "4732", "SourceName": "Microsoft-Windows-Security-Auditing", "ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}", "Version": 0, "Task": 13826, "OpcodeValue": 0, "RecordNumber": 91958, "ProcessID": 660, "ThreadID": 3300, "Channel": "Security", "Message": "A member was added to a security-enabled local group. Subject: Security ID: S-1-5-21-1084394783-3819715951-2594813741-500 Account Name: Administrator Account Domain: %s Logon ID: 0x337D1 Member: Security ID: S-1-5-21-1084394783-3819715951-2594813741-1002 Account Name: - Group: Security ID: S-1-5-32-545 Group Name: Users Group Domain: Builtin Additional Information: Privileges: -", "Category": "Security Group Management", "Opcode": "Info", "MemberName": "-", "MemberSid": "S-1-5-21-1084394783-3819715951-2594813741-1002", "TargetUserName": "Users", "TargetDomainName": "Builtin", "TargetSid": "S-1-5-32-545", "SubjectUserSid": "S-1-5-21-1084394783-3819715951-2594813741-500", "SubjectUserName": "%s", "SubjectDomainName": "%s", "SubjectLogonId": "0x337d1", "PrivilegeList": "-", "EventReceivedTime": "%s", "SourceModuleName": "eventlog", "SourceModuleType": "im_msvistalog"}'
	#audit_policy_c: %s1 = timestamp, %s2 = hostname, %s3 = eventid, %s4 = msg_username, %s5 = msg_hostname, %s6 = sub_username, %s7 = sub_hostname, %s8 = timestamp2
	Audit_Policy_C = '{"EventTime": "%s", "Hostname": "%s", "Keywords": -9214364837600035000, "EventType": "AUDIT_SUCCESS", "SeverityValue": 2, "Severity": "INFO", "EventID": "4719", "SourceName": "Microsoft-Windows-Security-Auditing", "ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}", "Version": 0, "Task": 13568, "OpcodeValue": 0, "RecordNumber": 92006, "ProcessID": 660, "ThreadID": 1476, "Channel": "Security", "Message": "System audit policy was changed. Subject: Security ID: S-1-5-21-1084394783-3819715951-2594813741-500 Account Name: %s Account Domain: %s Logon ID: 0x337D1 Audit Policy Change: Category: Account Logon Subcategory: Kerberos Authentication Service Subcategory GUID: {0CCE9242-69AE-11D9-BED3-505054503030} Changes: Success removed, Failure added", "Category": "Audit Policy Change", "Opcode": "Info", "SubjectUserSid": "S-1-5-21-1084394783-3819715951-2594813741-500", "SubjectUserName": "%s", "SubjectDomainName": "%s", "SubjectLogonId": "0x337d1", "CategoryId": "%%8280", "SubcategoryId": "%%14339", "SubcategoryGuid": "{0CCE9242-69AE-11D9-BED3-505054503030}", "AuditPolicyChanges": "%%8448, %%8451", "EventReceivedTime": "%s", "SourceModuleName": "eventlog", "SourceModuleType": "im_msvistalog"}'
	#audit_policy_d: %s1 = timestamp, %s2 = hostname, %s3 = eventid, %s4 = msg_user, %s5 = msg_hostname, %s6 = timestamp
	Audit_Policy_D = '{"EventTime": "%s", "Hostname": "%s", "Keywords": 4620693217682129000, "EventType": "INFO", "SeverityValue": 2, "Severity": "INFO", "EventID": "1102", "SourceName": "Microsoft-Windows-Eventlog", "ProviderGuid": "{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}", "Version": 0, "Task": 104, "OpcodeValue": 0, "RecordNumber": 92023, "ProcessID": 876, "ThreadID": 1448, "Channel": "Security", "Message": "The audit log was cleared. Subject: Security ID: S-1-5-21-1084394783-3819715951-2594813741-500 Account Name: %s Domain Name: %s Logon ID: 0x337D1", "Category": "Log clear", "Opcode": "Info", "EventReceivedTime": "%s", "SourceModuleName": "eventlog", "SourceModuleType": "im_msvistalog"}'
	#acct_locked_out: %s1 = timestamp, %s2 = hostname, %s3 = eventid, %s4 = msg_user, %s5 = msg_OU, %s6 = msg_user2, %s7 = msg_hostname, %s8 = target_host, %s9 = target_OU, %s10 = timestamp
	Account_Locked_Out = '{"EventTime": "%s", "Hostname": "%s", "Keywords": "-9214364837600035000", "EventType": "AUDIT_SUCCESS", "SeverityValue": "2", "Severity": "INFO", "EventID": "4740", "SourceName": "Microsoft-Windows-Security-Auditing", "ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}", "Version": "0", "Task": "13824", "OpcodeValue": "0", "RecordNumber": "92043", "ProcessID": "660", "ThreadID": "3156", "Channel": "Security", "Message": "A user account was locked out. Subject: Security ID: S-1-5-18 Account Name: %s Account Domain: WORKGROUP Logon ID: 0x3E7 Account That Was Locked Out: Security ID: S-1-5-21-1084394783-3819715951-2594813741-1005 Account Name: %s Additional Information: Caller Computer Name: %s", "Category": "User Account Management", "Opcode": "Info", "TargetUserName": "%s", "TargetDomainName": "%s", "TargetSid": "S-1-5-21-1084394783-3819715951-2594813741-1005", "SubjectUserSid": "S-1-5-18", "SubjectUserName": "%s", "SubjectDomainName": "%s", "SubjectLogonId": "0x3e7", "EventReceivedTime": "%s", "SourceModuleName": "eventlog", "SourceModuleType": "im_msvistalog"}'
	Events = [Failed_Login, Admin_Created, Audit_Policy_C, Audit_Policy_D, Account_Locked_Out]
	Rando_Event = random.choice(Events)

	now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	if Rando_Event == Failed_Login:
		the_event = Rando_Event % (now, r_host, r_user, r_user, now)
	if Rando_Event == Admin_Created:
		the_event = Rando_Event % (now, r_host, r_host, r_user, r_host, now)
	if Rando_Event == Audit_Policy_C:
		the_event = Rando_Event % (now, r_host, r_user, r_host, r_user, r_host, now)
	if Rando_Event == Audit_Policy_D:
		the_event = Rando_Event % (now, r_host, r_user, r_host, now)
	if Rando_Event == Account_Locked_Out:
		the_event = Rando_Event % (now, r_host, r_user, r_user, r_host, r_user, r_host, r_user, r_OU, now)
	return the_event

def sender(the_event):
	HOST='data.logentries.com'
	PORT=80
	a = "%s %s\n" % (token, the_event)
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOST, PORT))
	s.sendall(a)
   	s.close()
   	print a

def main():
	while True:
		event = rando()
		sender(event)

if __name__ == "__main__":
    main()
