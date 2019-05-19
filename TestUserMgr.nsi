# Test installer for UserMng plugin
#
# To test Unicode version use "makensis /DUNICODE"

!ifdef UNICODE
    Unicode true
    !addplugindir "Release Unicode"
    OutFile "usermgr-unicode-sample.exe"
!else
    Unicode false
    !addplugindir "Release"
    OutFile "usermgr-sample.exe"
!endif

# Installer setup
Name "UserMgr.dll Sample Installation Script"
RequestExecutionLevel admin
ShowInstDetails show
Page instfiles 

#
# Be careful when using these functions, especially the "Remove" and "Delete"
# commands!!!
#

Section -
	UserMgr::CreateAccount "myuser" "mypassword" "A test user created by the UserMgr plugin"
	Pop $0
    DetailPrint "CreateAccount Result : $0"

	UserMgr::AddToGroup  "myuser" "Administrators"
	Pop $0
    DetailPrint "AddToGroup Result : $0"

	UserMgr::SetRegKeyAccess "myuser" "HKLM" "SYSTEM\CurrentControlSet\Services\EventLog\Application\NTP" "=a"
	Pop $0
    DetailPrint "SetRegKeyAccess GrantAccess Result : $0"

	UserMgr::SetRegKeyAccess "myuser" "HKLM" "SYSTEM\CurrentControlSet\Services\EventLog\Application\NTP" "=r"
	Pop $0
    DetailPrint "SetRegKeyAccess RevokeWriteAccess Result : $0"

	UserMgr::SetRegKeyAccess "myuser" "HKLM" "SYSTEM\CurrentControlSet\Services\EventLog\Application\NTP" ""
	Pop $0
    DetailPrint "SetRegKeyAccess RevokeAccess Result : $0"

	UserMgr::DeleteAccount "myuser"
	Pop $0
    DetailPrint "DeleteAccount Result: $0"

	DetailPrint "################################"
    #######################################################################

	UserMgr::CreateAccountEx "myuserA" "mypassword" "A test user created by the UserMgr plugin" "My User A" "A test user created by the UserMgr plugin" "UF_PASSWD_NOTREQD|UF_DONT_EXPIRE_PASSWD"
	Pop $0
    DetailPrint "CreateAccountEx Result : $0"

	UserMgr::BuiltAccountEnv "myuserA" "mypassword"
	Pop $0
    DetailPrint "BuiltAccountEnv Result : $0"

	UserMgr::RegLoadUserHive "myuserA"
	Pop $0
    DetailPrint "RegLoadUserHive Result : $0"

    WriteRegStr HKEY_USERS "myuserA\Software\My Company\My Software" "String Value" "dead beef"

	UserMgr::RegUnLoadUserHive "myuserA"
	Pop $0
    DetailPrint "RegUnLoadUserHive Result : $0"

	UserMgr::ChangeUserPassword "myuserA" "mypassword" "mypasswordb"
	Pop $0
    DetailPrint "ChangeUserPassword Result : $0"

	UserMgr::SetUserInfo "myuserA" "PASSWORD" "mypasswordc"
	Pop $0
    DetailPrint "SetUserInfo PASSWORD Result : $0"

	UserMgr::DeleteAccount "myuserA"
	Pop $0
    DetailPrint "DeleteAccount Result: $0"

	DetailPrint "################################"
    #######################################################################

	UserMgr::GetCurrentUserName
	Pop $0
    DetailPrint "GetCurrentUserName Result: $0"

	UserMgr::GetSIDFromUserName "" "$0"
	Pop $0
    DetailPrint "GetSIDFromUserName Result: $0"

	UserMgr::GetUserNameFromSID "$0"
	Pop $0
    DetailPrint "GetUserNameFromSID Result: $0"
SectionEnd