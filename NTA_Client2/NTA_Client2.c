﻿#include <windows.h>
#include <stdio.h>

#define HEADER									\
	"+------------------------------------------+\n"	\
	"|         Network Traffic Analyzer         |\n"	\
	"+----+-----------------+-------------------+\n"	\
	"| #  |       IP        |        MAC        |\n"	\
	"+----+-----------------+-------------------+\n"

#define FOOTER									\
	"+----+-----------------+-------------------+\n"

#define DEVICE_NAME \
	L"NetworkTrafficAnalyzer"

#define DEVICE_PATH \
	L"\\\\.\\" DEVICE_NAME

#define BUFF_SIZE 64

#define NORMALIZATION_OF_ADDRESS(addr) \
	(PUINT8)&(addr)

typedef struct _OUTPUT_DATA_EXTENSION
{
	UINT64 mac;
	UINT ip;

} OUTPUT_DATA_EXTENSION, *POUTPUT_DATA_EXTENSION;

BOOL
SetPos(
	INT x,
	INT y)
{
	return SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), (COORD){ x, y });
}

INT main(VOID)
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
		printf("Function 'CreateFile' failed - status: %d", GetLastError());
		getchar();
		return -1;
	}

	OUTPUT_DATA_EXTENSION ipAddresses[BUFF_SIZE] = { 0 };

	DWORD r;
	BOOL status = ReadFile(
		hDevice,
		ipAddresses,
		sizeof(ipAddresses),
		&r,
		NULL);

	if (!status)
	{
		CloseHandle(hDevice);
		printf("Function 'ReadFile' failed - status: %d", GetLastError());
		getchar();
		return -1;
	}

	printf(HEADER);

	PUINT8 ip;
	PUINT8 mac;
	INT count = r / sizeof(OUTPUT_DATA_EXTENSION);

	for (INT i = 0; i < count; ++i)
	{
		ip = NORMALIZATION_OF_ADDRESS(ipAddresses[i].ip);
		mac = NORMALIZATION_OF_ADDRESS(ipAddresses[i].mac);

		printf("|");
		SetPos(2, i + 5);
		printf("%u", i + 1);
		SetPos(5, i + 5);
		printf("| %hhu.%hhu.%hhu.%hhu ", ip[0], ip[1], ip[2], ip[3]);
		SetPos(23, i + 5);
		printf("| %02x:%02x:%02x:%02x:%02x:%02x ", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		SetPos(43, i + 5);
		printf("|\n");
	}

	printf(FOOTER);
	CloseHandle(hDevice);
	getchar();
	return 0;
}