#include <iostream>
#include <Windows.h>

#include "pe_header.h"

bool check_dos_header_magic(uint16_t magic)
{
	if (magic != IMAGE_DOS_SIGNATURE || !magic)
		return false;

	return true;
}

bool check_nt_header_magic(uint16_t magic)
{
	if (magic != IMAGE_NT_SIGNATURE || !magic)
		return false;

	return true;
}

uint32_t rva_to_u32_offset(PIMAGE_NT_HEADERS nt, uint32_t rva)
{
	auto section_header = IMAGE_FIRST_SECTION(nt);

	for (uint32_t i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		if (section_header->VirtualAddress <= rva)
		{
			if ((section_header->VirtualAddress + section_header->Misc.VirtualSize) > rva)
			{
				rva -= section_header->VirtualAddress;
				rva += section_header->PointerToRawData;

				return rva;
			}
		}

		section_header++;
	}

	return NULL;
}

void print_dword_string(DWORD *str)
{
	while (true)
	{
		const char c = *str++;
		if (c == EOF || c == NULL)
			break;

		printf("%c", c);
	}
}
