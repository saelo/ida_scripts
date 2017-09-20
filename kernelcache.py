# -*- coding: utf-8 -*-
#
# Identify and rename function stubs (plt entries) in an iOS kernelcache. ARM64 only.
#
# Before:
# FFFFFFF00630F528 sub_fffffff00630f528                    ; CODE XREF: sub_FFFFFFF006308C34+104↑p
# FFFFFFF00630F528                 ADRP            X16, #qword_FFFFFFF006E40668@PAGE
# FFFFFFF00630F52C                 LDR             X16, [X16,#qword_FFFFFFF006E40668@PAGEOFF]
# FFFFFFF00630F530                 BR              X16
#
# After:
# FFFFFFF00630F528 ; void *__cdecl memmove_1(void *, const void *, size_t)
# FFFFFFF00630F528 _memmove_1                              ; CODE XREF: sub_FFFFFFF006308C34+104↑p
# FFFFFFF00630F528                 ADRP            X16, #qword_FFFFFFF006E40668@PAGE
# FFFFFFF00630F52C                 LDR             X16, [X16,#qword_FFFFFFF006E40668@PAGEOFF]
# FFFFFFF00630F530                 BR              X16     ; _memmove
#
# Copyright (c) 2017 Samuel Groß
#

from idaapi import *

funcname_counts = {}
def rename_stub(ea):
    if not (ua_mnem(ea) == 'ADRP' and ua_mnem(ea + 4) == 'LDR' and ua_mnem(ea + 8) == 'BR'):
        print("Not a stub function @ 0x{:x}??".format(ea))
        return

    changed_name = False
    changed_type = False

    page = get_immvals(ea, 1)[0]
    offset = get_immvals(ea + 4, 1)[0]
    target_func = get_qword(page + offset)

    name = get_name(target_func)
    if name and not name.startswith('sub_') and not name.startswith('loc_'):
        if not name in funcname_counts:
            funcname_counts[name] = 0

        # Some functions already have a numerical suffix. In that case increment the suffix and try again
        success = False
        while not success:
            funcname_counts[name] += 1
            success = set_name(ea, name + '_' + str(funcname_counts[name]), SN_NOWARN)

        # Add a comment to easily navigate to the called function from the stub
        set_cmt(ea + 8, name, 0)

        changed_name = True

    func_type = print_type(target_func, 0)
    if func_type:
        changed_type = apply_cdecl(None, ea, func_type + ';')

    print("{:x}: {} {}".format(ea, "y" if changed_name else "n", "y" if changed_type else "n"))

for n in xrange(get_segm_qty()):
    seg = getnseg(n)

    segname = get_segm_name(seg)
    # The __stubs segments contain the jump tables
    if not segname.endswith('__stubs'):
        continue

    func = get_func(seg.start_ea)
    if func is None:
        func = get_next_func(seg.start_ea)

    while func and func.start_ea < seg.end_ea:
        rename_stub(func.start_ea)
        func = get_next_func(func.start_ea)
