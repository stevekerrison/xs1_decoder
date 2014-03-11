XS1 Decoder - An instruction decoder for the XMOS XS1(b) ISA

Takes either xobjdump format or just the hex of the instructions in the same
format as objdump.

Copyright (c) 2014, Steve Kerrison, All rights reserved
This software is freely distributable under a derivative of the
University of Illinois/NCSA Open Source License posted in
LICENSE.txt and at <http://github.xcore.com/>

Decode method from <https://github.com/rlsosborne/tool_axe/>
Copyright (c) 2011-2012, Richard Osborne, All rights reserved

Usage:
    xs1_decoder.py [options]

Options:
    --xobjdump-sub              Substitute non-architectural instructions in
                                xobjdump output for architectural ones, e.g.
                                ldw (lru6) becomes LDWSP_lru6 or LDWDP_lru6
    --xobjdump-merge <prefix>   Append architectural command to the end of
                                valid lines with <prefix>
    --default                   Just output any instructions we find
                                (default)

Examples:
    xobjdump -d program.xe | xs1_decoder.py --xobjdump-sub
    echo "dd a6" | ./xs1_decoder.py
