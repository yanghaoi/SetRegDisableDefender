// StopDF.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
// 需要先安装一款其他安全软件后才能进行喔~， 不是 Defense Evasion 技术。

#pragma warning(disable : 4996)
#include <iostream>
#include <windows.h>
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 4096


//封装字符型（REG_SZ）注册表查询
CHAR* getValueInReg(HKEY hRoot, const char* szSubKey, const char* szValueName)
{
	// https://docs.microsoft.com/en-us/windows/win32/sysinfo/enumerating-registry-subkeys
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 
	DWORD i, retCode;
	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// 初始化
	DWORD dataSize = 0; // 数据的缓冲区
	HKEY hKey = NULL;   // 注册表句柄
	DWORD lResult = 0;  // 状态值
	char* rData = NULL; // 函数返回的数据

	// 设置 KEY_WOW64_64KEY，指定在64位注册表下工作
	lResult = RegOpenKeyExA(hRoot, szSubKey, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey);
	if (ERROR_SUCCESS != lResult) {
		if (lResult == ERROR_FILE_NOT_FOUND) {
			printf("[-] Key %s not found.\n", szSubKey);
		}
		else {
			printf("[-] RegOpenKeyExA failed (%d)\n", lResult);
		}
		return 0;
	}

	// 枚举注册表中的 键 和 值
	// Get the class name and the value count. 
	printf("----------------------------------------");
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	// Enumerate the subkeys, until RegEnumKeyEx fails.
	// Enumerate the subkeys, until RegEnumKeyEx fails.

	if (cSubKeys)
	{
		printf("\n[*] Number of subkeys: %d\n", cSubKeys);

		for (i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				printf(TEXT("[+] (%d) %s\n"), i + 1, achKey);
			}
		}
	}

	// Enumerate the key values. 
	if (cValues)
	{
		printf("\n[*] Number of values: %d\n", cValues);

		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
		{
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			retCode = RegEnumValue(hKey, i,
				achValue,
				&cchValue,
				NULL,
				NULL,
				NULL,
				NULL);

			if (retCode == ERROR_SUCCESS)
			{
				printf(TEXT("[+] (%d) %s\n"), i + 1, achValue);
			}
		}
	}
	printf("----------------------------------------");
	printf("\n[*] Read data for %s in %s : \n", szValueName,( hRoot == HKEY_LOCAL_MACHINE)?"HKLM":"HKCU" );
	// 获取需要的键值的数据
	// Debug ERROR_MORE_DATA, https://docs.microsoft.com/zh-cn/windows/win32/api/winreg/nf-winreg-reggetvaluea ,先获取缓冲区大小 dataSize
	// RRF_NOEXPAND: 如果值为 REG_EXPAND_SZ 类型，则不要自动扩展环境字符串。
	lResult = RegGetValueA(hKey, NULL, szValueName, RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, NULL, NULL, &dataSize);
	if (ERROR_SUCCESS == lResult) {
		printf("[*] Value %s's Data need buffer = %d \n", szValueName,dataSize);
	}
	else {
		printf("[-] RegGetValueA failed (%d)\n", lResult);
		return 0;
	}

	// 动态分配内存，赋值给 char* 指针
	char* GetValue = (char*)calloc(dataSize + 1 ,sizeof(char));
	if (GetValue == NULL) { printf("calloc error \n"); return 0; }
	// 打印地址
	// printf("P GetValue: %p \n", GetValue);
	// 将读取到的值写入地址 GetValue
	lResult = RegGetValueA(hKey, NULL, szValueName, RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, NULL, GetValue, &dataSize);
	switch (lResult) {
	case ERROR_SUCCESS: {
		printf("[*] Value %s's Data: %s\n", szValueName,GetValue);
		break;
	}
	case ERROR_MORE_DATA: {
		//先将 RegGetValueA 第六个参数为NULL，获取到缓冲区大小，通过动态内存分配，再次进行查询。
		printf("[-] %s 缓冲区太小\n", szValueName);
		break;
	}
	case ERROR_FILE_NOT_FOUND: {
		//检查下是否是32位和64位的区别
		printf("[-] %s 注册表值不存在\n", szValueName);
		break;
	}
	default:
	{
		printf("[-] RegGetValueA failed (%d)\n", lResult);
		break;
	}
	}
	//Clean
	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	return GetValue;
}


//封装数值型（DWORD）注册表操作
BOOL setDWORDValueToReg(HKEY hRoot, const char* szSubKey, const char* szValueName, DWORD szValue)
{
	HKEY hKey;
	DWORD lResult = 0, lpdwDisposition = 0;
	BOOL RtStatus = TRUE;
	lResult = RegCreateKeyExA(hRoot, szSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &lpdwDisposition);
	if (lResult == ERROR_SUCCESS) {
		if (REG_CREATED_NEW_KEY == lpdwDisposition) {
			// printf("[*] RegCreateKey\n");
		}
		else if (REG_OPENED_EXISTING_KEY == lpdwDisposition) {
			// printf("[*] OpenKey\n");
		}

		// 内存复制
		/* szValue = 7777;
		BYTE* S = (BYTE*)calloc(2, sizeof(DWORD));
		if (S == NULL) return FALSE;
		memcpy(S, &szValue, sizeof szValue);
		printf("S Data = %ld \n", *S);
		lResult = RegSetValueExA(hKey, szValueName, 0, REG_DWORD, S, sizeof(DWORD));
		free(S); */

		lResult = RegSetValueExA(hKey, szValueName, 0, REG_DWORD, (BYTE*)&szValue, sizeof(DWORD));
		if (lResult == ERROR_SUCCESS) {
			printf("[+] RegSetValueEx Successfully.\n");
		}
		else {
			printf("[-] RegSetValueExA Error Code: %d \n", lResult);
			return !RtStatus;
		}
	}
	else {
		printf("[-] RegCreateKeyExA Error Code: %d \n", lResult);
		return !RtStatus;
	}
	if (hKey != NULL) {
		RegCloseKey(hKey);
	}
	return RtStatus;
}

//封装数值型（DWORD）注册表查询
DWORD getDWORDValueToReg(HKEY hRoot, const char* szSubKey, const char* szValueName)
{
	DWORD GetValue = 0;
	DWORD dataSize = sizeof(GetValue);
	HKEY hKey = NULL;
	DWORD lResult = 0;
	lResult = RegOpenKeyExA(hRoot, szSubKey, 0, KEY_ALL_ACCESS, &hKey);

	if (ERROR_SUCCESS != lResult) {
		if (lResult == ERROR_FILE_NOT_FOUND) {
			printf("[-] Key %s not found.\n", szSubKey);
		}
		else {
			printf("[-] RegOpenKeyExA failed (%d)\n", lResult);
		}
		return FALSE;
	}

	lResult = RegGetValueA(hKey, NULL, szValueName, RRF_RT_REG_DWORD, NULL, &GetValue, &dataSize);
	switch (lResult) {
	case ERROR_SUCCESS: {
		printf("[*] RegGet %s %s is %d\n", szSubKey, szValueName, GetValue);
		break;
	}
	case ERROR_MORE_DATA: {
		printf("[-] %s 缓冲区太小\n", szValueName);
		break;
	}
	case ERROR_FILE_NOT_FOUND: {
		printf("[-] %s 注册表值不存在\n", szValueName);
		break;
	}
	default:
	{
		printf("[-] RegQueryValueEx failed (%d)\n", lResult);
		break;
	}
	}
	RegCloseKey(hKey);
	return GetValue;
}

BOOL DisableTray() {
	BOOL RtStatus = TRUE;
	HKEY hKey;
	DWORD lResult = 0;
	lResult = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &hKey, NULL);

	if (lResult != ERROR_SUCCESS) {
		printf("ErrorCode:%d\n", lResult);
		return false;
	}
	
	// https://stackoverflow.com/questions/66903672/how-to-enable-disable-windows-startup-items-programmatically
	// dwData 是一个有三个元素的数组，每个元素是8位的16进制(写入时取8位，不足8位的前面补0)，奇数表示禁用，偶数表示其他；其他位表示时间
	// DWORD dwData[] = { 0x00000003,0x00000000,0x00000000 };
	// DWORD dwData[] = { 0x00000003,0xF83489A0,0x01D82FE0 }; 
	// DWORD dwData[] = { 0x00000003,0xF83489A0,0x01D82FE0 }; 

	// 这里面是用的UTC时间。 禁用标识位，dwLowDateTime,dwHighDateTime(10进制转Hex 1d82fed)
	// dwLowDateTime: 2103655744
	// dwHighDateTime: 30945261
	// File Time: 132908886064840000
    // FileTimeToSystemTime: 2022 - 3 - 4 17 : 30 : 6
	// => 2022-3-5 1:30
	// Windows会自动转换到LocalTime, 
	// DWORD dwData[] = { 0x00000003,0x7d633d40,0x1d82fed };
	
	//	GetSystemTime Time : 2022 - 3 - 4 18 : 27 : 45
	//	dwLowDateTime : -1964959920
	//	dwHighDateTime : 30945269
	//	File Time : 132908920650930000
	//	FileTimeToSystemTime : 2022 - 3 - 4 18 : 27 : 45


	DWORD dwData[3] = { 0x00000003,0x751ee8b0,0x1d82ff5 };

	// 源码示例: https://docs.microsoft.com/en-us/windows/win32/sysinfo/changing-a-file-time-to-the-current-time
	FILETIME ft,ft1;
	SYSTEMTIME st,f2l,st1,f2l1;
	// 时区
	TIME_ZONE_INFORMATION tzi;
	// 64位的无符号整型值 ,利用 ULONGLONG QuadPart; 算术运算得到 FileTime
	ULARGE_INTEGER uli;

	//1.  GetLocalTime <=> LocalFileTime 本地时间转为本地文件时间
	GetLocalTime(&st);              // Gets the current Local system time
	printf("[*] Local system time:%d-%d-%d %d:%d:%d\n", st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
	// 获取时区
	GetTimeZoneInformation(&tzi);
	// 本地时间转本地文件时间
	LocalSystemTimeToLocalFileTime(&tzi,&st, &ft);

    // FileTime 分为两段存储，以前的方法不能表示64位，所以有两段。
	printf("[*] dwLowDateTime: %d\n", ft.dwLowDateTime);
	printf("[*] dwHighDateTime: %d\n", ft.dwHighDateTime);

	// 利用 ULARGE_INTEGER 来运算高低位
	// https://wenku.baidu.com/view/2acab930376baf1ffc4fad0a.html
	// http://t.zoukankan.com/findumars-p-5401616.html 分别拷贝到 ULARGE_INTEGER
	uli.LowPart = ft.dwLowDateTime;
	uli.HighPart = ft.dwHighDateTime;

	// 用 ULARGE_INTEGER 的 QuadPart 成员进行算术运算，得到了LocalFileTime
	printf("[*] LocalFileTime: %llu \n", uli.QuadPart);

	// 再将LocalFileTime转回LocalSystemTime
	LocalFileTimeToLocalSystemTime(&tzi, &ft, &f2l);
	printf("[*] LocalFileTimeToLocalSystemTime: %d-%d-%d %d:%d:%d\n", f2l.wYear, f2l.wMonth, f2l.wDay, f2l.wHour, f2l.wMinute, f2l.wSecond);


	printf("\n");

	//2. UTC 时间转文件时间 GetSystemTime <=> FileTime
	GetSystemTime(&st1);  // Gets the current system time
	printf("[*] GetSystemTime Time:%d-%d-%d %d:%d:%d\n", st1.wYear, st1.wMonth, st1.wDay, st1.wHour, st1.wMinute, st1.wSecond);
	// 系统时间转换到文件时间
	SystemTimeToFileTime(&st1, &ft1); // Converts the current system time to file time format
	// 结构体运算 . 运算符
	printf("[*] dwLowDateTime: %d\n", ft1.dwLowDateTime);
	printf("[*] dwHighDateTime: %d\n", ft1.dwHighDateTime);
	// ULARGE_INTEGER
	uli.LowPart = ft1.dwLowDateTime;
	uli.HighPart = ft1.dwHighDateTime;
	printf("[*] FileTime: %llu \n", uli.QuadPart);
	// 再将得到的FileTime转回SystemTime 进行验证
	FileTimeToSystemTime(&ft1,&f2l1);
	printf("[*] FileTimeToSystemTime: %d-%d-%d %d:%d:%d\n", f2l1.wYear, f2l1.wMonth, f2l1.wDay, f2l1.wHour, f2l1.wMinute, f2l1.wSecond);

	// 将当前的时间写入到注册表。
	dwData[1] = uli.LowPart ;
	dwData[2] = uli.HighPart ;

	lResult = RegSetValueExA(hKey, "SecurityHealth", 0, REG_BINARY, (LPBYTE)&dwData, sizeof(dwData));

	if (lResult != ERROR_SUCCESS) {
		printf("[-] RegSetValueExA Error Code:%d\n", lResult);
		RtStatus = FALSE;
	}

	lResult = RegCloseKey(hKey);
	if (lResult != ERROR_SUCCESS) {
		printf("[-] RegCloseKey Error code:%d\n", lResult);
		RtStatus = FALSE;
	}
	return RtStatus;
}

int main()
{
	double run_time;
	_LARGE_INTEGER time_start;	//开始时间
	_LARGE_INTEGER time_over;	//结束时间
	double dqFreq;		//计时器频率
	LARGE_INTEGER f;	//计时器频率
	QueryPerformanceFrequency(&f);
	dqFreq = (double)f.QuadPart;
	QueryPerformanceCounter(&time_start);	//计时开始

	BOOL RtStatus = TRUE;

	// WinDefend HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend Start
	DWORD WinDefend = 0;
	WinDefend = getDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WinDefend", "Start");

	// SecurityHealthService HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService
	DWORD SecurityHealthService = 0;
	SecurityHealthService = getDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService", "Start");

	// Sense HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense
	DWORD Sense = 0;
	Sense = getDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Sense", "Start");

	// WdNisSvc HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc
	DWORD WdNisSvc = 0;
	WdNisSvc = getDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WdNisSvc", "Start");

	if (WinDefend == 4) {
		printf("[!] Service WinDefend is Disabled.\n");
	}
	else {
		if (setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WinDefend", "Start", 4)) {
			printf("[+] Set WinDefend Disable Successfully \n");
		}
		else {
			printf("[-] Set WinDefend Disable failed\n");
		}
	}

	if (SecurityHealthService == 4) {
		printf("[!] Service SecurityHealthService is Disabled.\n");
	}
	else {
		if (setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService", "Start", 4)) {
			printf("[+] Set SecurityHealthService Disable Successfully \n");
		}
		else {
			printf("[-] Set SecurityHealthService Disable failed\n");
		}
	}

	if (Sense == 4) {
		printf("[!] Service Sense is Disabled.\n");
	}
	else {
		if (setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Sense", "Start", 4)) {
			printf("[+] Set Sense Disable Successfully \n");
		}
		else {
			printf("[-] Set Sense Disable failed\n");
		}
	}
	
	if (WdNisSvc == 4) {
		printf("[!] Service WdNisSvc is Disabled.\n");
	}
	else {
		if (setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WdNisSvc", "Start", 4)) {
			printf("[+] Set WdNisSvc Disable Successfully \n");
		}
		else {
			printf("[-] Set WdNisSvc Disable failed\n");
		}
	}

	// Run Tray
	char* AutoRunTray = NULL;
	AutoRunTray = getValueInReg(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SecurityHealth");

	// printf("P AutoRunTray: %p \n", AutoRunTray);
	// 获取地址指向的值，如果没有该注册表键值，则获取到的数据为空。
	if ( AutoRunTray != NULL ) {
		printf("[+] rtData: %s \n", AutoRunTray);
		if (DisableTray()) {
			printf("[+] DisableTray Successfully \n");
		};

		// where use , where free.
		free(AutoRunTray); AutoRunTray = NULL;
	}

	QueryPerformanceCounter(&time_over);	//计时结束
	run_time = 1000000 * (time_over.QuadPart - time_start.QuadPart) / dqFreq;
	printf("\n[*] Done. Time used: %f μs (%5.3lf seconds).\n", run_time, run_time / 1000000);

	return RtStatus;
}







