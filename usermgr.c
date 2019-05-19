#include <windows.h>
#include "pluginapi.h"
#include "UserMgr.h"
// JPR 123007: Added Userenv.h for the new BuiltAccountEnv function (Also Added Userenv.lib in the Link->Object/Library modules in the project settings)
// NOTE Platform SDK is needed for this header (The February 2003 build is the latest version which work with VC6)
#include <Userenv.h>
#include <winnls.h>
#include <AccCtrl.h>
#include <AclApi.h>
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0501
#endif
#include <WinNT.h>
#include <Sddl.h>

HINSTANCE g_hInstance;

HWND g_hwndParent;

// Unicode port by Jason Ross, aka JasonFriday13.

#define NSISFunction(funcname) void __declspec(dllexport) funcname(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra)

void ShowError (TCHAR *Errormessage);

BOOL WINAPI DllMain(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
	g_hInstance = hInst;
	return TRUE;
}

static UINT_PTR PluginCallback(enum NSPIM msg)
{
  return 0;
}

void pusherror1(TCHAR *out, DWORD code1)
{
	_stprintf(out, _T("ERROR %d"), code1);
	pushstring(out);
}

void pusherror2(TCHAR *out, DWORD code1, DWORD code2)
{
	_stprintf(out, _T("ERROR %d %d"), code1, code2);
	pushstring(out);
}

// my_swprintf(), turns a TCHAR into a WCHAR.
int my_swprintf(WCHAR *out, TCHAR *in)
{
#ifdef UNICODE
	wcscpy(out, in);
	return 0;
#else
	if (_swprintf(out, L"%S", in) == -1)
		return 1;
	else
		return 0;
#endif
}

// my_sprintf(), turns a WCHAR into a TCHAR.
int my_sprintf(TCHAR *out, WCHAR *in)
{
#ifdef UNICODE
	wcscpy(out, in);
	return 0;
#else
	if (sprintf(out, "%S", in) == -1)
		return 1;
	else
		return 0;
#endif
}

NTSTATUS AddPrivileges(PSID AccountSID, LSA_HANDLE PolicyHandle, LSA_UNICODE_STRING lucPrivilege)
{
	NTSTATUS ntsResult;

	// Create an LSA_UNICODE_STRING for the privilege name(s).

	ntsResult = LsaAddAccountRights(PolicyHandle,  // An open policy handle.
									AccountSID,    // The target SID.
									&lucPrivilege, // The privilege(s).
									1);            // Number of privileges.
									                
	return ntsResult;

} 

NTSTATUS RemovePrivileges(PSID AccountSID, LSA_HANDLE PolicyHandle, LSA_UNICODE_STRING lucPrivilege)
{
	NTSTATUS ntsResult;

	// Create an LSA_UNICODE_STRING for the privilege name(s).

	ntsResult = LsaRemoveAccountRights( PolicyHandle,  // An open policy handle.
										AccountSID,    // The target SID.
										FALSE,         // Delete all rights? We should not even think about that...
										&lucPrivilege, // The privilege(s).
										1);            // Number of privileges.

	return ntsResult;

} 

NET_API_STATUS EnablePrivilege(LPCTSTR dwPrivilege)
{
   HANDLE hProcessToken = NULL;

   TOKEN_PRIVILEGES tkp; 
   
   NET_API_STATUS nStatus;

   if (!OpenProcessToken(GetCurrentProcess(), 
                         TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, 
                         &hProcessToken)) 
   {
	   nStatus=GetLastError();
	   return nStatus;
   }

   tkp.PrivilegeCount = 1; 
   tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 

   if (!LookupPrivilegeValue(NULL, 
	                         dwPrivilege, 
		                     &tkp.Privileges[0].Luid))
   {
	   nStatus=GetLastError();
       CloseHandle(hProcessToken);
	   return nStatus;
   }
   if (!AdjustTokenPrivileges(hProcessToken, 
	                          FALSE, 
		                      &tkp, 
		                      0, 
		                      NULL, 
		                      0)) 
   {
	   nStatus=GetLastError();
       CloseHandle(hProcessToken);
	   return nStatus;
   }

   CloseHandle(hProcessToken);
   return 0;
}

LSA_HANDLE GetPolicyHandle()
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS ntsResult;
	LSA_HANDLE lsahPolicyHandle;

	// Object attributes are reserved, so initialize to zeroes.
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	// Get a handle to the Policy object.
	ntsResult = LsaOpenPolicy(NULL,			   //only localhost
							&ObjectAttributes, //Object attributes.
							POLICY_ALL_ACCESS, //Desired access permissions.
							&lsahPolicyHandle);//Receives the policy handle.
							

	if (ntsResult != STATUS_SUCCESS)
	{
		// An error occurred. Display it as a win32 error code.
		return NULL;
	} 
	return lsahPolicyHandle;
}

BOOL InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
	return FALSE;

	if (NULL != pwszString) 
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
		return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length =  (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength= (USHORT)(dwLen+1) * sizeof(WCHAR);

	return TRUE;
}

BOOL GetAccountSid(LPTSTR SystemName, LPTSTR AccountName, PSID *Sid) 
{
	LPTSTR ReferencedDomain = NULL;
	DWORD cbSid = 128;    /* initial allocation attempt */
	DWORD cbReferencedDomain = 16; /* initial allocation size */
	SID_NAME_USE peUse;
	BOOL bSuccess = FALSE; /* assume this function will fail */

	__try {
		/*
		 * initial memory allocations
		 */
		if ((*Sid = HeapAlloc(GetProcessHeap(), 0, cbSid)) == NULL)
			__leave;

		if ((ReferencedDomain = (LPTSTR) HeapAlloc(GetProcessHeap(), 0,
				       cbReferencedDomain)) == NULL) __leave;

		/*
		 * Obtain the SID of the specified account on the specified system.
		 */
		while (!LookupAccountName(SystemName, AccountName, *Sid, &cbSid,
					  ReferencedDomain, &cbReferencedDomain,
					  &peUse))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				/* reallocate memory */
				if ((*Sid = HeapReAlloc(GetProcessHeap(), 0,
					*Sid, cbSid)) == NULL) __leave;

				if ((ReferencedDomain= (LPTSTR) HeapReAlloc(
					GetProcessHeap(), 0, ReferencedDomain,
					cbReferencedDomain)) == NULL)
				__leave;
			}
			else 
				__leave;
		}
		bSuccess = TRUE;
	} /* finally */
	__finally {

		/* Cleanup and indicate failure, if appropriate. */

		HeapFree(GetProcessHeap(), 0, ReferencedDomain);

		if (!bSuccess) {
			if (*Sid != NULL) {
				HeapFree(GetProcessHeap(), 0, *Sid);
				*Sid = NULL;
			}
		}

	}

	return (bSuccess);
}

NSISFunction(CreateAccount)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		USER_INFO_1 ui;	
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		NET_API_STATUS nStatus;

		static TCHAR userid[256];
		static TCHAR passwd[256];
		static TCHAR comment[1024];

		static WCHAR u_userid[256];
		static WCHAR u_passwd[256];
		static WCHAR u_comment[1024];

		memset( u_userid, 0, sizeof( u_userid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
    my_swprintf(u_userid, userid);

		popstring(passwd);
		my_swprintf(u_passwd, passwd);

		popstring(comment);
		my_swprintf(u_comment, comment);

		ui.usri1_name = u_userid;
		ui.usri1_password = u_passwd;
		ui.usri1_password_age = 0;
		ui.usri1_priv = USER_PRIV_USER;
		ui.usri1_home_dir = NULL;
		ui.usri1_comment = u_comment;
		ui.usri1_flags = UF_DONT_EXPIRE_PASSWD | UF_SCRIPT;
		ui.usri1_script_path = NULL;


		//
		// Call the NetUserAdd function, specifying level 1.
		//
		nStatus = NetUserAdd(NULL,
							dwLevel,
							(LPBYTE)&ui,
							&dwError);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring(_T("OK"));
			return;
		}
		else
		{
			pusherror1(userid, nStatus);
			return;
		}
	}
}


// JPR 123007: Added CreateAccountEx function
NSISFunction(CreateAccountEx)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		USER_INFO_2 ui;	
		DWORD dwLevel = 2;
		DWORD dwError = 0;
		NET_API_STATUS nStatus;

		static TCHAR userid[256];
		static TCHAR passwd[256];
		static TCHAR comment[1024];
		static TCHAR fullname[256];
		static TCHAR usr_comment[1024];
		static TCHAR flags[1024];

		static WCHAR u_userid[256];
		static WCHAR u_passwd[256];
		static WCHAR u_comment[1024];
		static WCHAR u_fullname[256];
		static WCHAR u_usr_comment[1024];

		memset( u_userid, 0, sizeof( u_userid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		my_swprintf(u_userid, userid);

		popstring(passwd);
		my_swprintf(u_passwd, passwd);

		popstring(comment);
		my_swprintf(u_comment, comment);

		popstring(fullname);
		my_swprintf(u_fullname, fullname);

		popstring(usr_comment);
		my_swprintf(u_usr_comment, usr_comment);

		popstring(flags);

		ui.usri2_name=u_userid;  
		ui.usri2_password=u_passwd;  
		ui.usri2_priv=USER_PRIV_USER;
		ui.usri2_home_dir=NULL;  
		ui.usri2_comment=u_comment;  
		ui.usri2_flags=UF_SCRIPT | UF_NORMAL_ACCOUNT;  
		if(_tcsstr(flags,_T("UF_ACCOUNTDISABLE")))
		{
			ui.usri2_flags|=UF_ACCOUNTDISABLE;
		}
		if(_tcsstr(flags,_T("UF_PASSWD_NOTREQD")))
		{
			ui.usri2_flags|=UF_PASSWD_NOTREQD;
		}
		if(_tcsstr(flags,_T("UF_PASSWD_CANT_CHANGE")))
		{
			ui.usri2_flags|=UF_PASSWD_CANT_CHANGE;
		}
		if(_tcsstr(flags,_T("UF_DONT_EXPIRE_PASSWD")))
		{
			ui.usri2_flags|=UF_DONT_EXPIRE_PASSWD;
		}
		ui.usri2_script_path=NULL;  
		ui.usri2_auth_flags=0;  
		ui.usri2_full_name=u_fullname;  
		ui.usri2_usr_comment=u_usr_comment;  
		ui.usri2_parms=NULL;
		ui.usri2_workstations=NULL;  
		ui.usri2_acct_expires=TIMEQ_FOREVER;
		ui.usri2_max_storage=USER_MAXSTORAGE_UNLIMITED;  
		ui.usri2_logon_hours=NULL;  
		ui.usri2_country_code=0;  
		ui.usri2_code_page=0;

		//
		// Call the NetUserAdd function, specifying level 2.
		//
		nStatus = NetUserAdd(NULL,
							dwLevel,
							(LPBYTE)&ui,
							&dwError);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring(_T("OK"));
			return;
		}
		else
		{
			pusherror1(userid, nStatus);
			return;
		}
	}
}


// JPR 123007: Added BuiltAccountEnv function
NSISFunction(BuiltAccountEnv)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		HANDLE hLogonToken = NULL;

		PROFILEINFO PI;

		static TCHAR userid[256];
		static TCHAR passwd[256];

		g_hwndParent=hwndParent;

		popstring(userid);

		popstring(passwd);

		nStatus=EnablePrivilege(SE_RESTORE_NAME);
		if (nStatus) 
		{
			pusherror1(userid, nStatus);
			return;
		}

		if(!LogonUser(userid,
					_T("."),
					passwd,
					LOGON32_LOGON_INTERACTIVE,
					LOGON32_PROVIDER_DEFAULT,
					&hLogonToken))
		{
			TCHAR tmp[256];
			pusherror1(tmp, GetLastError());
			return;
		}

		PI.dwSize=sizeof(PROFILEINFO);
		PI.dwFlags=0;
		PI.lpUserName=userid;
		PI.lpProfilePath=NULL;
		PI.lpDefaultPath=NULL;
		PI.lpServerName=NULL;
		PI.lpPolicyPath=NULL;
		PI.hProfile=HKEY_CURRENT_USER;

		if(!LoadUserProfile(hLogonToken,&PI))
		{
			TCHAR tmp[256];
			CloseHandle(hLogonToken);
			pusherror1(tmp, GetLastError());
			return;
		}

		if(!UnloadUserProfile(hLogonToken,PI.hProfile))
		{
			TCHAR tmp[256];
			CloseHandle(hLogonToken);
			pusherror1(tmp, GetLastError());
			return;
		}

		CloseHandle(hLogonToken);

		pushstring(_T("OK"));
		return;
	}
}


// JPR 123007: Added RegLoadUserHive function
NSISFunction(RegLoadUserHive)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static TCHAR userid[256];

		HKEY hKey;
		DWORD valueSize;

		static TCHAR NTUser_dat[256];
		static TCHAR DocumentsAndSettings[256];
		static TCHAR DocumentsAndSettingsT[256];
		static TCHAR SYSTEMDRIVE[256];

		PSID user_sid;

		LPTSTR strSid;

		g_hwndParent=hwndParent;

		popstring(userid);

		nStatus=EnablePrivilege(SE_RESTORE_NAME);
		if (nStatus) 
		{
			pusherror1(userid, nStatus);
			return;
		}

		GetEnvironmentVariable(_T("SYSTEMDRIVE"),SYSTEMDRIVE,512);
		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			pusherror1(userid, GetLastError());
			return;
		}

		if (!ConvertSidToStringSid(user_sid,&strSid))
		{
			pusherror1(userid, GetLastError());
			return;
		}
		else
		{
			_stprintf(DocumentsAndSettings,_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s"),strSid);
		}
		RegOpenKeyEx(HKEY_LOCAL_MACHINE,DocumentsAndSettings,0,KEY_READ,&hKey);
// JPR 011508 Get localized "Documents and Settings" string
		RegQueryValueEx(hKey,_T("ProfileImagePath"),NULL,NULL,(LPVOID)DocumentsAndSettingsT,&valueSize);
// JPR 011508 Remove "%SystemDrive%\"
		_stprintf(DocumentsAndSettings, _T("%s"), &DocumentsAndSettingsT[14]);
		_stprintf(NTUser_dat, _T("%s\\%s\\NTUSER.DAT"), SYSTEMDRIVE,DocumentsAndSettings);
		RegCloseKey(hKey);
		nStatus = RegLoadKey(HKEY_USERS, userid, NTUser_dat);

		if (nStatus == NERR_Success)
		{
			pushstring(_T("OK"));
			return;
		}
		else
		{
			pusherror1(userid, nStatus);
			return;
		}
	}
}


// JPR 123007: Added RegUnLoadUserHive function
NSISFunction(RegUnLoadUserHive)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static TCHAR userid[256];

		static char NTUSER_DAT[256];
		static char SYSTEMDRIVE[256];

		g_hwndParent=hwndParent;

		popstring(userid);

		nStatus = RegUnLoadKey(HKEY_USERS, userid);

		if (nStatus == NERR_Success)
		{
			pushstring(_T("OK"));
			return;
		}
		else
		{
			pusherror1(userid, nStatus);
			return;
		}
	}
}

NSISFunction(DeleteAccount)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static TCHAR userid[256];
		static WCHAR u_userid[256];

		memset( u_userid, 0, sizeof( u_userid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		my_swprintf(u_userid, userid);

		nStatus = NetUserDel(NULL, u_userid);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring(_T("OK"));
			return;
		}
		else
		{
			pusherror1(userid, nStatus);
			return;
		}
	}
}


// JPR 011208: Added GetCurrentUserName function
NSISFunction(GetCurrentUserName)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static TCHAR userid[256];
		DWORD Size=256;

		g_hwndParent=hwndParent;

		nStatus = GetUserName(userid, &Size);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus)
		{
			pushstring(userid);
			return;
		}
		else
		{
			pusherror1(userid, GetLastError());
			return;
		}
	}
}


// JPR 012109: Added GetCurrentDomain function
NSISFunction(GetCurrentDomain)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;
		LPWKSTA_USER_INFO_1 wksta_info;

		static TCHAR userdomain[256];

		g_hwndParent=hwndParent;

		nStatus = NetWkstaUserGetInfo(NULL, 1, (LPBYTE *)&wksta_info);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			my_sprintf(userdomain, wksta_info->wkui1_logon_domain);
			pushstring(userdomain);

			if (wksta_info != NULL)NetApiBufferFree(wksta_info);
			return;
		}
		else
		{
			pusherror1(userdomain, GetLastError());
			return;
		}
	}
}

// JPR 011208: Added GetLocalizedStdAccountName function
NSISFunction(GetLocalizedStdAccountName)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		static TCHAR pid[256];

		PSID pSid = NULL;

		TCHAR username[256];
		TCHAR domain[256];

		DWORD usize=256;
		DWORD dsize=256;

		DWORD SidSize = SECURITY_MAX_SID_SIZE;

		SID_NAME_USE snu;

		g_hwndParent=hwndParent;

		popstring(pid);

		pSid=LocalAlloc(LMEM_FIXED, SidSize);
		if(!ConvertStringSidToSid(pid,&pSid))
		{
			if (pSid != NULL)LocalFree(pSid);
			pushstring(_T("ERROR"));
			return;
		}
		if(!LookupAccountSid(NULL,pSid,username, &usize, domain, &dsize, &snu))
		{
			if (pSid != NULL)LocalFree(pSid);
			pushstring(_T("ERROR"));
			return;
		}
		if (pSid != NULL)LocalFree(pSid);
		_stprintf(pid,_T("%s\\%s"),domain,username);
		pushstring(pid);
		return;
	}
}

// JPR 020909: Added GetUserNameFromSID function
NSISFunction(GetUserNameFromSID)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		static TCHAR pid[256];

		PSID pSid = NULL;

		TCHAR username[256];
		TCHAR domain[256];

		DWORD usize=256;
		DWORD dsize=256;

		DWORD SidSize = SECURITY_MAX_SID_SIZE;

		SID_NAME_USE snu;

		g_hwndParent=hwndParent;

		popstring(pid);

		pSid=LocalAlloc(LMEM_FIXED, SidSize);
		if(!ConvertStringSidToSid(pid,&pSid))
		{
			if (pSid != NULL)LocalFree(pSid);
			pushstring(_T("ERROR"));
			return;
		}
		if(!LookupAccountSid(NULL,pSid,username, &usize, domain, &dsize, &snu))
		{
			if (pSid != NULL)LocalFree(pSid);
			pushstring(_T("ERROR"));
			return;
		}
		if (pSid != NULL)LocalFree(pSid);
		_tcscpy(pid,domain);

		if ( _tcscmp(domain,_T("")) != 0 )
			_stprintf(pid,_T("%s\\%s"),domain,username);
		else _tcscpy(pid,username);

		pushstring(pid);
		return;
	}
}

// JPR 020909: Added GetSIDFromUserName function
NSISFunction(GetSIDFromUserName)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		PSID user_sid;

		static TCHAR userid[256];
		static TCHAR domain[256];
		LPTSTR strSid;

		g_hwndParent=hwndParent;

		popstring(domain);

		popstring(userid);

		if (!GetAccountSid(domain,userid,&user_sid))
		{
			pushstring(_T("ERROR GetAccountSid"));
			return;
		}

		if (!ConvertSidToStringSid(user_sid,&strSid))
		{
			pushstring(_T("ERROR ConvertSidToStringSid"));
			return;
		}
		else
		{
			_tcscpy(userid,strSid);
			pushstring(userid);
			return;
		}
	}
}

NSISFunction(GetUserInfo)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		LPUSER_INFO_2 ui;
		DWORD dwLevel = 2;
		DWORD dwError = 0;
		NET_API_STATUS nStatus;

		static TCHAR userid[256];
		static TCHAR field[256];
		static TCHAR response[1024];

		static WCHAR u_userid[256];
		static WCHAR u_field[256];

		memset( u_userid, 0, sizeof( u_userid ) );
		memset( u_field, 0, sizeof( u_field ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		my_swprintf(u_userid, userid);

		popstring(field);
		_tcsupr(field);

		my_swprintf(u_field, field);

		//
		//  Set up the USER_INFO_1 structure.
		//  USER_PRIV_USER: name identifies a user, 
		//  rather than an administrator or a guest.
		//  UF_SCRIPT: required for LAN Manager 2.0 and
		//  Windows NT and later.
		//

		nStatus = NetUserGetInfo(NULL, 
								u_userid, 
								dwLevel, 
								(LPBYTE *)&ui );

		if (nStatus != NERR_Success)
		{
			pusherror1(userid, nStatus);
// JPR 011208: Freeing ui buffer properly
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( _tcscmp(field,_T("EXISTS")) == 0 ) 
		{
			pushstring(_T("OK"));
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( _tcscmp(field,_T("FULLNAME")) == 0 ) 
		{
			my_sprintf(response, ui->usri2_full_name);	   
			pushstring(response);

			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}


		if ( _tcscmp(field,_T("COMMENT")) == 0 ) 
		{
			my_sprintf(response, ui->usri2_comment);
			pushstring(response);

			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( _tcscmp(field,_T("NAME")) == 0 ) 
		{
			my_sprintf(response, ui->usri2_name);	   
			pushstring(response);

			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( _tcscmp(field,_T("HOMEDIR")) == 0 ) 
		{
			my_sprintf(response, ui->usri2_home_dir);	   
			pushstring(response);

			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( _tcscmp(field,_T("PASSWD_STATUS")) == 0 ) 
		{
			if ( ui->usri2_flags & UF_DONT_EXPIRE_PASSWD ) pushstring(_T("NEVEREXPIRES"));
			else
			{
				if ( ui->usri2_flags & UF_PASSWD_CANT_CHANGE )
				pushstring (_T("CANTCHANGE"));
			}
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}
		if (ui != NULL)NetApiBufferFree(ui);
		pushstring(_T("ERROR"));
		return;
	}
}

NSISFunction(SetUserInfo)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		LPUSER_INFO_2 ui;
		LPUSER_INFO_2 uiTemp;
// JPR 123007: Needed to change a user password
		USER_INFO_1003 ui1003;
// JPR 020108: Use USER_INFO_1011 to change the users fullname instead of USER_INFO_1
		USER_INFO_1011 ui1011;
		DWORD dwLevel = 2;
		DWORD dwError = 0;
		NET_API_STATUS nStatus;

		static TCHAR userid[256];
		static TCHAR field[256];
		static TCHAR newvalue[256];
		static TCHAR response[1024];

		static WCHAR u_userid[256];
		static WCHAR u_field[256];
		static WCHAR u_pwd[256];
		static WCHAR u_fullname[256];

		memset( u_userid, 0, sizeof( u_userid ) );
		memset( u_field, 0, sizeof( u_field ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		my_swprintf(u_userid, userid);

		popstring(field);
		_tcsupr(field);

		popstring(newvalue);

		my_swprintf(u_field, field);


		nStatus = NetUserGetInfo(NULL, 
								u_userid, 
								dwLevel, 
								(LPBYTE *)&ui );

		if (nStatus != NERR_Success)
		{
			pusherror1(userid, nStatus);
// JPR 011208: Freeing ui buffer properly
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

// JPR 011208: Copy ui buffer to a temp buffer so original buffer will not be invalidated
		if ((uiTemp = ui) == NULL)
		{
			_tcscpy(userid, _T("ERROR INVALID USERINFO"));
			pushstring(userid);
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( _tcscmp(field,_T("FULLNAME")) == 0 ) 
		{
			my_swprintf(u_fullname, newvalue);
			ui1011.usri1011_full_name=u_fullname;
			dwLevel=1011;
		}

// JPR 123007: Added PASSWORD field
		if ( _tcscmp(field,_T("PASSWORD")) == 0 ) 
		{
			my_swprintf(u_pwd, newvalue);
			ui1003.usri1003_password=u_pwd;
			dwLevel=1003;
		}

		if ( _tcscmp(field,_T("COMMENT")) == 0 ) 
		{
			my_swprintf(uiTemp->usri2_comment, newvalue);	   
		}

		if ( _tcscmp(field,_T("NAME")) == 0 ) 
		{
			my_swprintf(uiTemp->usri2_name, newvalue);	   
		}

		if ( _tcscmp(field,_T("HOMEDIR")) == 0 ) 
		{
			my_swprintf(uiTemp->usri2_home_dir, newvalue);	   
		}

		if ( _tcscmp(field,_T("PASSWD_NEVER_EXPIRES")) == 0 ) 
		{
			if (_tcscmp(newvalue, _T("YES")) == 0)
				uiTemp->usri2_flags |= UF_DONT_EXPIRE_PASSWD;
			else
				uiTemp->usri2_flags |=~ UF_DONT_EXPIRE_PASSWD;
		}

// JPR 123007: Different for changing a user password
		if(dwLevel==1003)
		{
			nStatus = NetUserSetInfo(NULL, 
									u_userid, 
									dwLevel, 
									(LPBYTE) &ui1003,
									NULL );
		}
// JPR 020108: Different for changing a user fullname
		else if(dwLevel==1011)
		{
			nStatus = NetUserSetInfo(NULL, 
									u_userid, 
									dwLevel, 
									(LPBYTE) &ui1011,
									NULL );
		}
		else
		{
			nStatus = NetUserSetInfo(NULL, 
									u_userid, 
									dwLevel, 
									(LPBYTE) uiTemp,
									NULL );
		}

		if (nStatus != NERR_Success)
		{
			pusherror1(userid, nStatus);
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		pushstring(_T("OK"));
		if (ui != NULL)NetApiBufferFree(ui);
		return;
	}
}


// JPR 123007: Added ChangeUserPassword function
NSISFunction(ChangeUserPassword)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static TCHAR userid[256];
		static TCHAR oldpwd[256];
		static TCHAR newpwd[256];

		static WCHAR u_userid[256];
		static WCHAR u_oldpwd[256];
		static WCHAR u_newpwd[256];

		memset( userid, 0, sizeof( userid ) );

		g_hwndParent=hwndParent;

		popstring(userid);  
		my_swprintf(u_userid, userid);

		popstring(oldpwd);  
		my_swprintf(u_oldpwd, oldpwd);

		popstring(newpwd);  
		my_swprintf(u_newpwd, newpwd);

		nStatus = NetUserChangePassword (NULL, u_userid, u_oldpwd, u_newpwd );

		//
		// If the call succeeds, inform the user.
		//

		if (nStatus != NERR_Success)
		{
			pusherror1(userid, nStatus);
			return;
		}

		pushstring(_T("OK"));
		return;
	}
}

NSISFunction(DeleteGroup)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static TCHAR groupid[256];
		static WCHAR u_groupid[256];
		DWORD dwError = 0;

		memset( u_groupid, 0, sizeof( u_groupid ) );

		g_hwndParent=hwndParent;

		popstring(groupid);  
		my_swprintf(u_groupid, groupid);

		nStatus = NetLocalGroupDel(NULL, u_groupid );

		//
		// If the call succeeds, inform the user.
		//

		if (nStatus == NERR_Success)
		{
			#ifdef _USRDLL
				pushstring(_T("OK"));
			#endif
			return;
		}
		else
		{
			#ifdef _USRDLL
				pusherror2(groupid, nStatus, dwError);
			#endif
			return;
		}
	}
}

NSISFunction(CreateGroup)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static TCHAR groupid[256];
		static TCHAR comment[1024];

		static WCHAR u_groupid[256];
		static WCHAR u_comment[1024];
		DWORD dwError = 0;
		LOCALGROUP_INFO_1 ginfo;

		memset( u_groupid, 0, sizeof( u_groupid ) );
		memset( u_comment, 0, sizeof( u_comment) );

		g_hwndParent=hwndParent;

		popstring(groupid);  
		popstring(comment);

		memset (&ginfo,0,sizeof(ginfo));

		my_swprintf(u_groupid, groupid);
		my_swprintf(u_comment, comment);

		ginfo.lgrpi1_name = u_groupid;
		ginfo.lgrpi1_comment= u_comment;

		nStatus = NetLocalGroupAdd(NULL, 1, (LPBYTE)&ginfo, &dwError);

		//
		// If the call succeeds, inform the user.
		//

		if (nStatus == NERR_Success)
		{
			pushstring(_T("OK"));
			return;
		}
		else
		{
			pusherror2(groupid, nStatus, dwError);
			return;
		}
	}
}

NSISFunction(AddToGroup)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		LOCALGROUP_MEMBERS_INFO_3 LMI;

		static TCHAR userid[256];
		static TCHAR groupid[256];

		static WCHAR u_userid[256];
		static WCHAR u_groupid[256];

		memset( u_userid, 0, sizeof( u_userid ) );
		memset( u_groupid, 0, sizeof( u_groupid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		my_swprintf(u_userid, userid);

		popstring(groupid);
		my_swprintf(u_groupid, groupid);

// JPR 123007: Changed to NetLocalGroupAddMembers to make this function work
		LMI.lgrmi3_domainandname = u_userid;
		nStatus = NetLocalGroupAddMembers(NULL, u_groupid,3,(LPBYTE)&LMI,1);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring(_T("OK"));
			return;
		}
		else
		{
			pusherror1(userid, nStatus);
			return;
		}
	}
}


// JPR 011208: Added function IsMemberOfGroup
NSISFunction(IsMemberOfGroup)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
	   NET_API_STATUS nStatus;

	   LPLOCALGROUP_MEMBERS_INFO_1 pBuf = NULL;

	   DWORD dwLevel = 1;
	   DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	   DWORD dwEntriesRead = 0;
	   DWORD dwTotalEntries = 0;
	   DWORD dwResumeHandle = 0;

	   static TCHAR userid[256];
	   static TCHAR userid2[256];
	   static TCHAR groupid[256];
	   static WCHAR u_groupid[256];
	   static TCHAR groupid2[256];

	   memset( u_groupid, 0, sizeof( u_groupid ) );

	   g_hwndParent=hwndParent;

	   popstring(userid);

	   popstring(groupid);

	   //
	   // Call the NetLocalGroupGetMembers function 
	   //  specifying information level 1.
	   //
	   my_swprintf(u_groupid, groupid);
	   nStatus = NetLocalGroupGetMembers(NULL,
										 u_groupid,
										 dwLevel,
										 (LPBYTE *) &pBuf,
										 dwPrefMaxLen,
										 &dwEntriesRead,
										 &dwTotalEntries,&dwResumeHandle);
		//
		// If the call succeeds,
		//
		if (nStatus == NERR_Success)
		{
			LPLOCALGROUP_MEMBERS_INFO_1 pTmpBuf;
			DWORD i;
			DWORD dwTotalCount = 0;

			if ((pTmpBuf = pBuf) != NULL)
			{
				//
				// Loop through the entries and 
				//  print the names of the local groups 
				//  to which the user belongs. 
				//
				for (i = 0; i < dwEntriesRead; i++)
				{

					if (pTmpBuf == NULL)
					{
						if (pBuf != NULL)NetApiBufferFree(pBuf);
						_tcscpy(userid, _T("ERROR: An access violation has occurred"));
						pushstring(userid);
						return;
					}

					my_sprintf(userid2, pTmpBuf->lgrmi1_name);
					if(_tcscmp(userid2,userid) == 0)
					{
						if (pBuf != NULL)NetApiBufferFree(pBuf);
						pushstring(_T("TRUE"));
						return;
					}
					pTmpBuf++;
					dwTotalCount++;
				}
			}
			if (pBuf != NULL)NetApiBufferFree(pBuf);
			pushstring(_T("FALSE"));
			return;
		}
		else
		{
			if (pBuf != NULL)NetApiBufferFree(pBuf);
			pusherror1(userid, nStatus);
			return;
		}
	}
}


NSISFunction(RemoveFromGroup)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static TCHAR userid[256];
		static TCHAR groupid[256];

		static WCHAR u_userid[256];
		static WCHAR u_groupid[256];

		memset( u_userid, 0, sizeof( u_userid ) );
		memset( u_groupid, 0, sizeof( u_groupid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		my_swprintf(u_userid, userid);

		popstring(groupid);
		my_swprintf(u_groupid, groupid);

		nStatus = NetGroupDelUser(NULL, u_groupid, u_userid);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring(_T("OK"));
			return;
		}
		else
		{
			pusherror1(userid, nStatus);
			return;
		}
	}
}

NSISFunction(AddPrivilege)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		PSID user_sid;
		LSA_HANDLE my_policy_handle;
		LSA_UNICODE_STRING lucPrivilege;   

		static TCHAR tempbuf[1024];
		static TCHAR userid[256];
		static TCHAR privilege[256];

		static WCHAR u_userid[256];
		static WCHAR u_privilege[256];

		g_hwndParent=hwndParent;

		memset (u_userid,0, sizeof(u_userid));
		memset (u_privilege,0, sizeof(u_privilege));

		popstring(userid);
		my_swprintf(u_userid, userid);

		popstring(privilege);
		my_swprintf(u_privilege, privilege);

		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			pushstring(_T("ERROR GetAccountSid"));
			return;
		}

		my_policy_handle = GetPolicyHandle();

		if (my_policy_handle == NULL)
		{
			pushstring(_T("ERROR GetPolicyHandle"));
			return;
		}

		if (!InitLsaString(&lucPrivilege, u_privilege))
		{
			LsaClose(my_policy_handle);
			pushstring(_T("ERROR InitLsaString"));
			return;
		}

		if (AddPrivileges(user_sid, my_policy_handle, lucPrivilege) != STATUS_SUCCESS)
		{
			LsaClose(my_policy_handle);
			pushstring(_T("ERROR AddPrivileges"));
			return;
		}

		LsaClose(my_policy_handle);
		pushstring(_T("OK"));
		return;
	}
}

NSISFunction(SetRegKeyAccess)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		unsigned int i = 0;

		INT grant_or_revoke = GRANT_ACCESS;
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		DWORD dwRes;	  
		PSID user_sid;
		PACL pDacl=NULL;
		PACL pNewDacl=NULL;
		EXPLICIT_ACCESS ea;   
		PSECURITY_DESCRIPTOR pSD=NULL;

		static TCHAR tempbuf[1024];
		static TCHAR userid[256];
		static TCHAR hive[128];
		static TCHAR regkey[512];
		static TCHAR rights[8];
		TCHAR myhive[32];
		TCHAR myregkey[512];

		static WCHAR u_userid[256];
		unsigned long accessrights = 0;
		unsigned long aclentries = 64;

		g_hwndParent=hwndParent;

		memset (u_userid,0, sizeof(u_userid));

		popstring(userid);
		my_swprintf(u_userid, userid);

		popstring(hive);
		popstring(regkey);
		popstring(rights);

		_tcscpy (myhive,_T(""));

		if ( _tcscmp(hive,_T("HKLM")) == 0 )
			_tcscpy(myhive,_T("MACHINE"));

		if ( _tcscmp(hive,_T("HKCU")) == 0 )
			_tcscpy(myhive,_T("CURRENT_USER"));

		if ( _tcscmp(hive,_T("HKU")) == 0 )
			_tcscpy(myhive,_T("USERS"));

		if ( _tcscmp(hive,_T("HKCR")) == 0 )
			_tcscpy(myhive,_T("CLASSES_ROOT"));

		if ( _tcscmp (myhive,_T("")) == 0 )
		{
			pushstring(_T("ERROR Illegal Root Key (use HKLM|HKCU|HKU|HKCR)"));
			return;
		}

		_sntprintf(myregkey,sizeof(myregkey)-1,_T("%s\\%s"),myhive,regkey);
		if ( lstrlen(rights) <= 0 ) 
		{
			grant_or_revoke = REVOKE_ACCESS;
		}

		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			pushstring(_T("ERROR GetAccountSid"));
			return;
		}

		if(dwRes=GetNamedSecurityInfo(myregkey,SE_REGISTRY_KEY,DACL_SECURITY_INFORMATION,
									NULL,NULL,&pDacl,NULL,&pSD)!=ERROR_SUCCESS)
		{
			_stprintf(tempbuf,_T("ERROR GetSecurityInfo %d"), dwRes);
			pushstring(tempbuf);
			return;
		}

		ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

		for (i=0;i<=(unsigned)lstrlen(rights);i++) 
		{
			switch(rights[i])
			{
				case '+':
					grant_or_revoke = GRANT_ACCESS;
					break;
				case '-':
					grant_or_revoke = DENY_ACCESS;
					break;
				case '=':
					grant_or_revoke = SET_ACCESS;
					break;
				case 'r':
					accessrights |= KEY_READ;
					break;
				case 'w':
					accessrights |= KEY_WRITE;
					break;
				case 'a':
					accessrights |= KEY_ALL_ACCESS;
					break;
				case 'x':
					accessrights |= KEY_EXECUTE;
					break;
				default:
				break;
			}
		}

		ea.grfAccessPermissions = accessrights;
		ea.grfAccessMode = grant_or_revoke;
		ea.grfInheritance= SUB_CONTAINERS_ONLY_INHERIT;
		ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
		ea.Trustee.ptstrName = user_sid;

		if(dwRes=SetEntriesInAcl(1,&ea,pDacl,&pNewDacl)!=ERROR_SUCCESS)
		{
			_stprintf(tempbuf,_T("ERROR SetEntriesInAcl Error %d"), dwRes);
			pushstring( tempbuf);
			return;
		}

		if (dwRes = SetNamedSecurityInfo(myregkey, SE_REGISTRY_KEY,DACL_SECURITY_INFORMATION,NULL,NULL,pNewDacl,NULL) != ERROR_SUCCESS)
		{
			_stprintf(tempbuf,_T("ERROR SetNamedSecurityInfo %d"), dwRes);
			pushstring( tempbuf);
			return;
		}

		_tcscpy(tempbuf,_T("OK"));
		pushstring(tempbuf);
		return;
	}
}

NSISFunction(RemovePrivilege)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		PSID user_sid;
		LSA_HANDLE my_policy_handle;
		LSA_UNICODE_STRING lucPrivilege;   

		static TCHAR tempbuf[1024];
		static TCHAR userid[256];
		static TCHAR privilege[256];

		static WCHAR u_userid[256];
		static WCHAR u_privilege[256];

		g_hwndParent=hwndParent;

		memset (u_userid,0, sizeof(u_userid));
		memset (u_privilege,0, sizeof(u_privilege));

		popstring(userid);
		my_swprintf(u_userid,userid);

		popstring(privilege);
		my_swprintf(u_privilege, privilege);

		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			pushstring(_T("ERROR GetAccountSid"));
			return;
		}

		my_policy_handle = GetPolicyHandle();

		if (my_policy_handle == NULL)
		{
			pushstring(_T("ERROR GetPolicyHandle"));
			return;
		}

		if (!InitLsaString(&lucPrivilege, u_privilege))
		{
			LsaClose(my_policy_handle);
			pushstring(_T("ERROR InitLsaString"));
			return;
		}


		if (RemovePrivileges(user_sid, my_policy_handle, lucPrivilege) != STATUS_SUCCESS)
		{
			LsaClose(my_policy_handle);
			pushstring(_T("ERROR RemovePrivileges"));
			return;
		}

		LsaClose(my_policy_handle);
		pushstring(_T("OK"));
		return;
	}
}


// JPR 020108: Added function HasPrivilege
NSISFunction(HasPrivilege)
{
	EXDLL_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		PSID user_sid;
		LSA_HANDLE my_policy_handle;
		LSA_UNICODE_STRING *lucPrivilege;   
		LSA_UNICODE_STRING *pTmpBuf;
		ULONG count;
		DWORD i;
		NTSTATUS ntStatus;	  

		static TCHAR tempbuf[1024];
		static TCHAR userid[256];
		static TCHAR privilege[256];
		static TCHAR privilege2[256];

		static WCHAR u_userid[256];
		static WCHAR u_privilege[256];

		g_hwndParent=hwndParent;

		memset (u_userid,0, sizeof(u_userid));
		memset (u_privilege,0, sizeof(u_privilege));

		popstring(userid);
		my_swprintf(u_userid, userid);

		popstring(privilege);
		my_swprintf(u_privilege, privilege);

		if (EnablePrivilege(SE_RESTORE_NAME)) 
		{
			pushstring(_T("ERROR EnablePrivilege"));
			return;
		}

		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			pushstring(_T("ERROR GetAccountSid"));
			return;
		}

		my_policy_handle = GetPolicyHandle();

		if (my_policy_handle == NULL)
		{
			pushstring(_T("ERROR GetPolicyHandle"));
			return;
		}

		if (ntStatus = LsaEnumerateAccountRights(my_policy_handle, user_sid, (LSA_UNICODE_STRING **) &lucPrivilege, &count) != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(ntStatus);
			if(dwError == ERROR_FILE_NOT_FOUND) _tcscpy(tempbuf,_T("FALSE"));
			else if(dwError == ERROR_MR_MID_NOT_FOUND) _stprintf(tempbuf,_T("ERROR LsaEnumerateAccountRights n%ld"), ntStatus);
			else _stprintf(tempbuf,_T("ERROR LsaEnumerateAccountRights w%lu"), dwError);
			if (lucPrivilege != NULL)LsaFreeMemory(&lucPrivilege);
			LsaClose(my_policy_handle);
			pushstring(tempbuf);
			return;
		}

		if ((pTmpBuf = lucPrivilege) != NULL)
		{
			for (i = 0; i < count; i++)
			{
				if (pTmpBuf == NULL)
				{
					if (lucPrivilege != NULL)LsaFreeMemory(&lucPrivilege);
					LsaClose(my_policy_handle);
					_tcscpy(userid, _T("ERROR: An access violation has occurred"));
					pushstring(userid);
					return;
				}

				my_sprintf(privilege2, pTmpBuf->Buffer);
				if(_tcscmp(privilege2,privilege) == 0)
				{
					if (lucPrivilege != NULL)LsaFreeMemory(&lucPrivilege);
					LsaClose(my_policy_handle);
					pushstring(_T("TRUE"));
					return;
				}
				pTmpBuf++;
			}
		}
		if (lucPrivilege != NULL)LsaFreeMemory(&lucPrivilege);
		LsaClose(my_policy_handle);
		pushstring(_T("FALSE"));
		return;
	}
}

void ShowError (TCHAR *Errormessage)
{
#ifdef _USRDLL
    MessageBox(g_hwndParent,Errormessage,0,MB_OK);
#else
	_tprintf(Errormessage);
#endif
}

#ifdef _USRDLL

#endif