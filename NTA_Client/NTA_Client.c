#include <windows.h>
#include <ntddndis.h>
#include <stdio.h>

#define DEVICE_NAME \
	L"NetworkTrafficAnalyzer"

#define DEVICE_PATH \
	L"\\\\.\\" DEVICE_NAME

INT main()
{
	system("pause");
	return EXIT_SUCCESS;
}