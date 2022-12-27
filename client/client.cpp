#include <iostream>

#include <Windows.h>

#define IO_READ_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_READ_REQUEST {
	ULONG process_id;
	ULONG address;
	PVOID buffer_address;
	ULONG size;
	SIZE_T return_size;
} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
	ULONG process_id;
	ULONG address;
	PVOID buffer_address;
	ULONG size;
	SIZE_T return_size;
} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

class Driver {
public: 
    HANDLE driver;

    Driver(LPCSTR registry_path) {
        driver = CreateFileA(registry_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    }

	template<typename T>
	T read_process_memory(ULONG process_id, ULONG read_address, SIZE_T size) {
		T buffer;

		KERNEL_READ_REQUEST request;
		request.process_id = process_id;
		request.address = read_address;
		request.buffer_address = &buffer;
		request.size = size;

		if (!DeviceIoControl(driver, IO_READ_PROCESS_MEMORY, &request, sizeof(request), &request, sizeof(request), 0, 0)) {
			// TODO: error handling
		}

		return buffer;
	}

	template<typename T>
	void write_process_memory(ULONG process_id, ULONG write_address, T value, SIZE_T size) {
		KERNEL_WRITE_REQUEST request;
		request.process_id = process_id;
		request.address = write_address;
		request.buffer_address = &value;
		request.size = size;

		if (!DeviceIoControl(driver, IO_WRITE_PROCESS_MEMORY, &request, sizeof(request), &request, sizeof(request), 0, 0)) {
			// TODO: error handling
		}
	}
};

int main()
{
    auto driver = Driver("\\\\.\\mydriver");
    std::cout << "Hello World!\n";

    system("pause");
}

