#include <windows.h>
#include <stdio.h>

#define DEVICE_NAME \
	L"NetworkTrafficAnalyzer"

#define DEVICE_PATH \
	L"\\\\.\\" DEVICE_NAME

INT wmain()
{
	HANDLE hDevice = CreateFile(
		DEVICE_PATH,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("error CreateFile %i", GetLastError());
		system("pause");
		return -1;
	}

	UINT ipAddresses[128] = { 0 };
	DWORD r;
	BOOL status = ReadFile(hDevice, ipAddresses, sizeof(ipAddresses), &r, NULL);
	if (!status)
	{
		printf("error ReadFile %i", GetLastError());
		system("pause");
		return -1;
	}

	PUINT8 ip;

	printf("IP\n----------------------\n");
	for (INT i = 0; i < r / sizeof(UINT); ++i)
	{
		ip = (PUINT8)&ipAddresses[i];

		printf("%i.%i.%i.%i\n",
			ip[0], ip[1], ip[2], ip[3]);
	}

	CloseHandle(hDevice);

	system("pause");
	return 0;
}