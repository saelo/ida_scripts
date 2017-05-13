# -*- coding: utf-8 -*-
#
# Resolve syscall table entries in the Windows kernel.
# Tested on ntoskrnl.exe and win32k.sys
# Apply .pdb information first!
# 64-bit images only.
#
# Copyright (c) 2017 Samuel Groß
#

from idaapi import *

tables = [
        ("KiServiceTable", "KiServiceLimit"),
        ("W32pServiceTable", "W32pServiceLimit"),
        ("W32pServiceTableFilter", "W32pServiceLimitFilter"),
]

def resolve_table_entries(table, limit, imagebase):
    for i in range(limit):
        entry_ea = table + i*4
        # This is what KeCompactServiceTable does during kernel initialization
        entry = 16 * (imagebase - table + Dword(entry_ea))
        # This is what KiSystemCall64 does during each syscall
        handler_ea = (table + (entry >> 4))

        MakeDword(entry_ea)
        name = GetFunctionName(handler_ea)
        MakeComm(entry_ea, name)


for table_name, table_size_name in tables:
    table_ea = LocByName(table_name)
    if table_ea == 0xffffffffffffffff:              # TODO check for accessibility instead
        continue
    table_size = Dword(LocByName(table_size_name))
    resolve_table_entries(table_ea, table_size, get_imagebase())
