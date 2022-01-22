#include <windows.h>
#include <stdio.h>

#define DEVICE_NAME \
	L"NetworkTrafficAnalyzer"

#define DEVICE_PATH \
	L"\\\\.\\" DEVICE_NAME

#define BUFF_SIZE 256

INT main(VOID)
{
	do 
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
			puts("Function 'CreateFile' failed");
			break;
		}

		UINT ipAddresses[BUFF_SIZE] = { 0 };
		DWORD r;
		BOOL status;

		status = ReadFile(
			hDevice,
			ipAddresses,
			sizeof(ipAddresses),
			&r,
			NULL);

		if (!status)
		{
			puts("Function 'ReadFile' failed");
			break;
		}

		puts("IP\n----------------------");

		for (INT i = 0; i < r / sizeof(UINT); ++i)
		{
			PUINT8 ip = (PUINT8)&ipAddresses[i];

			printf("%hhu.%hhu.%hhu.%hhu\n",
				ip[0], ip[1], ip[2], ip[3]);
		}

		puts("----------------------");

		status = CloseHandle(hDevice);
		if (!status)
		{
			puts("Function 'CloseHandle' failed");
			break;
		}

	} while (FALSE);

	DWORD status = GetLastError();
	printf("the program completed with status %lu\n", status);
	system("pause");
	return status;
}