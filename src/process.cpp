#include <iostream>
#include <fstream>
#include <filesystem>
#include <Windows.h>

#include "process.h"
#include "pe_header.h"

#define ADDR "0x%08X"

struct import_data_t
{
	std::string descriptor;
	uint32_t imports;
};

std::vector<import_data_t> import_data;

void process_imports(uint8_t* buf, PIMAGE_NT_HEADERS nt, PIMAGE_DATA_DIRECTORY idd)
{
	printf("\nProcessing imports:\n");

	if (!idd->Size)
	{
		printf("  No imports\n");
		return;
	}

	auto iat = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(buf + rva_to_u32_offset(nt, idd->VirtualAddress));

	printf("  IAT entry point: " ADDR "\n", iat);

	auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(buf + rva_to_u32_offset(nt, iat->OriginalFirstThunk));

	printf("  First thunk:     " ADDR "\n", first_thunk);

	printf("\nProcessing import descriptors:");

	printf("size: %d\n", sizeof(size_t));

	uint32_t n_descriptors = 0, n_imports = 0;
	while (iat->OriginalFirstThunk)
	{
		auto original_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(buf + rva_to_u32_offset(nt, iat->OriginalFirstThunk));
		auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(buf + rva_to_u32_offset(nt, iat->FirstThunk));
		auto name = reinterpret_cast<DWORD>(buf + rva_to_u32_offset(nt, iat->Name));

		uint32_t n = 0;
		printf("\n  %s:\n", reinterpret_cast<const char*>(name));
		while (original_first_thunk->u1.AddressOfData)
		{
			auto name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(buf + rva_to_u32_offset(nt, original_first_thunk->u1.AddressOfData));
			auto ordinal = original_first_thunk->u1.Ordinal;

			printf("  ");
			printf("%-3d ", ++n);
			printf(" ");

			//	Function exported by ordinal
			if (IMAGE_SNAP_BY_ORDINAL32(ordinal))
			{
				printf("[ %-3d ] ", IMAGE_ORDINAL32(ordinal));
				printf("----------");
				printf(" ");
				printf("----------");
			}
			//	Function exported by name
			else
			{
				printf("[ n/a ] ");
				printf(ADDR, original_first_thunk->u1.Function);
				printf(" ");
				printf("%s", reinterpret_cast<const char*>(name->Name));
			}

			printf("\n");

			original_first_thunk++;
			first_thunk++;

			n_imports++;
		}

		import_data_t d =
		{
			reinterpret_cast<const char*>(name), 
			n
		};

		import_data.emplace_back(d);

		iat++;

		n_descriptors++;
	}

	printf("\n  --- %d descriptors (%d imports) ---\n", n_descriptors, n_imports);

	std::sort(import_data.begin(), import_data.end(), [](const import_data_t& d, const import_data_t& d1) { return d.imports > d1.imports; });

	printf("\n");
	for (const auto& idata : import_data)
	{
		float per = ((float)idata.imports / n_imports) * 100.f;
		printf("  [%3d] %4.1f%% -> %s\n", idata.imports, per, idata.descriptor.c_str());
	}

	printf("\n");
}

void process_sections(PIMAGE_NT_HEADERS nt, uint32_t count)
{
	printf("\nProcessing sections:\n");

	if (!count)
	{
		printf("Error: No sections\n");
		return;
	}

	printf("%d sections\n", count);

	const auto sections_header = IMAGE_FIRST_SECTION(nt);

	printf("     name     physical   virtual        size\n");
	for (uint32_t i = 0; i < count; i++)
	{
		const auto section = &sections_header[i];

		printf("  %2d %c", i, section->Name[0]);
		for (uint32_t k = 1; k < IMAGE_SIZEOF_SHORT_NAME; k++)
		{
			const char c = section->Name[k];
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'A') || (c >= '0' && c <= '9'))
				printf("%c", c);
			else
				printf(" ");
		}

		printf(" ");
		printf(ADDR, section->Misc.PhysicalAddress);
		printf(" ");
		printf(ADDR, section->VirtualAddress);
		printf(" ");
		printf("%8d", section->SizeOfRawData);

		printf("\n");
	}
}

void process_data_entries(uint8_t* buf, PIMAGE_NT_HEADERS nt)
{
	auto print_data_section = [&](const char* name, PIMAGE_DATA_DIRECTORY idd)
	{
		printf("  ");
		printf("%-10s", name);
		printf(" ");
		printf(ADDR, idd->VirtualAddress);
		printf(" ");
		printf("%6d", idd->Size);
		printf("\n");
	};

	const auto optional_header = &nt->OptionalHeader;

	printf("\nProcessing data entries:\n");
	printf("  name       virtual      size\n");
	print_data_section("exports", &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	print_data_section("imports", &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	print_data_section("resources", &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]);

	process_imports(buf, nt, &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
}

bool process_pe_header(uint8_t* buf)
{
	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buf);

	uint16_t wDOSMagic = dos_header->e_magic;
	if (!check_dos_header_magic(wDOSMagic))
	{
		printf("Error: Invalid DOS magic %hu\n", wDOSMagic);
		return false;
	}

	const auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(buf + dos_header->e_lfanew);
	printf("NT header at " ADDR ".\n", nt_header);

	uint16_t wNTMagic = nt_header->Signature;
	if (!check_nt_header_magic(wNTMagic))
	{
		printf("Error: Invalid NT magic %hu\n", wNTMagic);
		return false;
	}

	const auto file_header = &nt_header->FileHeader;
	process_sections(nt_header, file_header->NumberOfSections);

	process_data_entries(buf, nt_header);

	return true;
}

uint8_t* allocate_file_buffer(const std::filesystem::path& p, uint32_t file_size)
{
	printf("Allocated %d bytes.\n", file_size);

	return new uint8_t[file_size];
}

void deallocate_file_buffer(uint8_t* buf)
{
	delete[] buf;
	buf = nullptr;
}

bool process_file(const std::filesystem::path& p)
{
	uint8_t* buf = nullptr;

	const uint32_t file_size = std::filesystem::file_size(p);

	if (!(buf = allocate_file_buffer(p, file_size)))
	{
		printf("Error: Allocation fail.\n");
		return false;
	}

	std::ifstream ifs(p, std::ios_base::in | std::ios_base::binary);

	if (!ifs.good())
	{
		printf("Error: File open fail.\n");
		return false;
	}

	printf("Opened file.\n");

	ifs.read((char*)buf, file_size);

	printf("Copied buffer.\n");

	ifs.close();

	if (!process_pe_header(buf))
	{
		printf("Error: PE header process fail.\n");
		return false;
	}

	deallocate_file_buffer(buf);

	return true;
}
