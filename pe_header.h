#pragma once

extern bool check_dos_header_magic( uint16_t magic );
extern bool check_nt_header_magic( uint16_t magic );
extern uint32_t rva_to_u32_offset( PIMAGE_NT_HEADERS nt, uint32_t rva );
extern void print_dword_string( DWORD* str );
