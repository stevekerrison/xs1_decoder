#!/usr/bin/python

"""
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

"""

from docopt import docopt
import sys
import re
import struct

class XS1Decoder(object):
    """
        Decode xobjdump output or one instruction per line space separated hex
        into XMOS XS1b architecture mnemonics
    """
    # Pattern to match instructions (required)
    instrpattern = r'(([0-9a-f]{2}\s*){2,4})'
    # Xobjdump pattern prefix (optional)
    xobjpattern = r'^(\.\w*)?\s*(0x[0-9a-f]+):\s*'
    # Non-architectural instruction format from xobjdump e.g. "add (2rus)"
    xobjinstr = r':\s*(\w+\s*\(\w+\)\s*)'
    # Pre compiled whitespace remover
    whitematcher = re.compile(r'\s+', re.I)
    # Regex
    imatcher = re.compile('({})?{}'.format(xobjpattern, instrpattern), re.I)
    # Replacer
    nonarchmatcher = re.compile(
            '{}{}{}'.format(xobjpattern, instrpattern, xobjinstr), re.I)
    # Address matcher
    addrmatcher = re.compile(xobjpattern, re.I)
    # Decoder dictionary - recursive lambdas until we get an instruction string
    decode_opc = {
        0x00: lambda(x): {
            3:  lambda(x): 'STW_2rus',
            2:  lambda(x): {
                    0: 'TINITPC_2r',
                    1: 'GETST_2r',
                }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'EDU_1r',
                    1: 'EEU_1r',
                }[ x['self'].bit(x['low'], 4) ],
            0:  lambda(x): {
                    0x07ec: 'WAITEU_0r',
                    0x07ed: 'CLRE_0r',
                    0x07ee: 'SSYNC_0r',
                    0x07ef: 'FREET_0r',
                    0x07fc: 'DCALL_0r',
                    0x07fd: 'KRET_0r',
                    0x07fe: 'DRET_0r',
                    0x07ff: 'SETKEP_0r',
                    }[x['low']],
            }[x['self'].num_operands(x['low'])](x),
        0x01: lambda(x): {
            3:  lambda(x): 'LTW_2rus',
            2:  lambda(x): {
                    0: 'TINITDP_2r',
                    1: 'OUTT_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'WAITET_1r',
                    1: 'WAITEF_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            0:  lambda(x): {
                    0x0fec: lambda(x): 'LDSPC_0r',
                    0x0fed: lambda(x): 'STPSC_0r',
                    0x0fee: lambda(x): 'LDSSR_0r',
                    0x0fef: lambda(x): 'STSSR_0r',
                    0x0ffc: lambda(x): 'STSED_0r',
                    0x0ffd: lambda(x): 'STET_0r',
                    0x0ffe: lambda(x): 'GETED_0r',
                    0x0fff: lambda(x): 'GETET_0r'
                    }[x['low']](x),
            }[x['self'].num_operands(x['low'])](x),
        0x02: lambda(x): {
            3:  lambda(x): 'ADD_3r',
            2:  lambda(x): {
                    0: 'TINITSP_2r',
                    1: 'SETD_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'FREER_1r',
                    1: 'MJOIN_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            0:  lambda(x): {
                    0x17ec: lambda(x): 'DENTSP_0r',
                    0x17ed: lambda(x): 'DRESTSP_0r',
                    0x17ee: lambda(x): 'GETID_0r',
                    0x17ef: lambda(x): 'GETKEP_0r',
                    0x17fc: lambda(x): 'GETKSP_0r',
                    0x17fd: lambda(x): 'LDSED_0r',
                    0x17fe: lambda(x): 'LDET_0r',
                    }[x['low']](x),
            }[x['self'].num_operands(x['low'])](x),
        0x03: lambda(x): {
            3:  lambda(x): 'SUB_3r',
            2:  lambda(x): {
                    0: 'TINITCP_2r',
                    1: 'TSETMR_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'TSTART_1r',
                    1: 'MSYNC_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x04: lambda(x): {
            3:  lambda(x): 'SHL_3r',
            2:  lambda(x): {
                    1: 'EET_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'BLA_1r',
                    1: 'BAU_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x05: lambda(x): {
            3:  lambda(x): 'SHR_3r',
            2:  lambda(x): {
                    0: 'ANDNOT_2r',
                    1: 'EEF_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'BRU_1r',
                    1: 'SETSP_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x06: lambda(x): {
            3:  lambda(x): 'EQ_3r',
            2:  lambda(x): {
                    0: 'SEXT_2r',
                    1: 'SEXT_rus',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'SETDP_1r',
                    1: 'SETCP_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x07: lambda(x): {
            3:  lambda(x): 'AND_3r',
            2:  lambda(x): {
                    0: 'GETTS_2r',
                    1: 'SETPT_rus',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'DGETREG_1r',
                    1: 'SETEV_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x08: lambda(x): {
            3:  lambda(x): 'OR_3r',
            2:  lambda(x): {
                    0: 'ZEXT_2r',
                    1: 'ZEXT_rus',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'KCALL_1r',
                    1: 'SETV_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x09: lambda(x): {
            3:  lambda(x): 'LDW_3r',
            2:  lambda(x): {
                    0: 'OUTCT_2r',
                    1: 'OUTCT_rus',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'ECALLF_1r',
                    1: 'ECALLT_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x0a: lambda(x): {
            0:  lambda(x): 'STWDP_ru6',
            1:  lambda(x): 'STWSP_ru6',
            }[x['self'].bit(x['low'], 10)](x),
        0x0b: lambda(x): {
            0:  lambda(x): 'LDWDP_ru6',
            1:  lambda(x): 'LDWSP_ru6',
            }[x['self'].bit(x['low'], 10)](x),
        0x0c: lambda(x): {
            0:  lambda(x): 'LDAWDP_ru6',
            1:  lambda(x): 'LDAWSP_ru6',
            }[x['self'].bit(x['low'], 10)](x),
        0x0d: lambda(x): {
            0:  lambda(x): 'LDC_ru6',
            1:  lambda(x): 'LDWCP_ru6',
            }[x['self'].bit(x['low'], 10)](x),
        0x0e: lambda(x): {
            True: lambda(x): {
                0: lambda(x): 'BRFT_ru6',
                1: lambda(x): 'BRBT_ru6',
                }[x['self'].bit(x['low'], 10)](x),
            False: lambda(x): {
                0x0c: lambda(x): 'BRFU_u6',
                0x0d: lambda(x): 'BLAT_u6',
                0x0e: lambda(x): 'EXTDP_u6',
                0x0f: lambda(x): 'KCALL_u6',
                0x1c: lambda(x): 'BRBU_u6',
                0x1d: lambda(x): 'ENTSP_u6',
                0x1e: lambda(x): 'EXTSP_u6',
                0x1f: lambda(x): 'RETSP_u6',
                }[x['self'].bit_range(x['low'], 10, 6)](x),
            }[x['self'].test_ru6(x['low'])](x),
        0x0f: lambda(x): {
            True: lambda(x): {
                0: lambda(x): 'BRFF_ru6',
                1: lambda(x): 'BRBF_ru6',
                }[x['self'].bit(x['low'], 10)](x),
            False: lambda(x): {
                0x0c: lambda(x): 'CLRSR_u6',
                0x0d: lambda(x): 'SETSR_u6',
                0x0e: lambda(x): 'KENTSP_u6',
                0x0f: lambda(x): 'KRESTSP_u6',
                0x1c: lambda(x): 'GETSR_u6',
                0x1d: lambda(x): 'LDAWCP_u6',
                }[x['self'].bit_range(x['low'], 10, 6)](x),
            }[x['self'].test_ru6(x['low'])](x),
        0x10: lambda(x): {
            3:  lambda(x): 'LD16S_3r',
            2:  lambda(x): {
                    0: 'NOT_2r',
                    1: 'INCT_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            1:  lambda(x): {
                    0: 'CLRPT_1r',
                    1: 'SYNCR_1r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x11: lambda(x): {
            3:  lambda(x): 'LD8U_3r',
            2:  lambda(x): {
                    0: 'NOT_2r',
                    1: 'INT_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x12: lambda(x): {
            3:  lambda(x): 'ADD_2rus',
            2:  lambda(x): {
                    0: 'NEG_2r',
                    1: 'ENDIN_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x13: lambda(x): {
            3:  lambda(x): 'SUB_2rus',
            }[x['self'].num_operands(x['low'])](x),
        0x14: lambda(x): {
            3:  lambda(x): 'SHL_2rus',
            2:  lambda(x): {
                    0: 'MKMSK_2r',
                    1: 'MKMSK_rus',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x15: lambda(x): {
            3:  lambda(x): 'SHR_2rus',
            2:  lambda(x): {
                    0: 'OUT_2r',
                    1: 'OUTSHR_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x16: lambda(x): {
            3:  lambda(x): 'EQ_2rus',
            2:  lambda(x): {
                    0: 'IN_2r',
                    1: 'INSHR_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x17: lambda(x): {
            3:  lambda(x): 'TSETR_3r',
            2:  lambda(x): {
                    0: 'PEEK_2r',
                    1: 'TESTCT_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x18: lambda(x): {
            3:  lambda(x): 'LSS_3r',
            2:  lambda(x): {
                    0: 'SETPSC_2r',
                    1: 'TESTWCT_2r',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x19: lambda(x): {
            3:  lambda(x): 'LSU_r3',
            2:  lambda(x): {
                    0: 'CHKCT_2r',
                    1: 'CHKCT_rus',
                    }[ x['self'].bit(x['low'], 4) ],
            }[x['self'].num_operands(x['low'])](x),
        0x1a: lambda(x): {
            1:  lambda(x): 'BLRB_u10',
            0:  lambda(x): 'BLRF_u10',
            }[x['self'].bit(x['low'], 10)](x),
        0x1b: lambda(x): {
            1:  lambda(x): 'LDAPB_u10',
            0:  lambda(x): 'LDAPF_u10',
            }[x['self'].bit(x['low'], 10)](x),
        0x1c: lambda(x): {
            1:  lambda(x): 'LDWCPL_u10',
            0:  lambda(x): 'BLACP_u10',
            }[x['self'].bit(x['low'], 10)](x),
        0x1d: lambda(x): {
            True: lambda(x): {
                0: lambda(x): 'SETC_ru6',
                }[x['self'].bit(x['low'], 10)](x),
            }[x['self'].test_ru6(x['low'])](x),
        #Prefixed
        0x1e: lambda(x): {
            True:  lambda(x): {
                0x0a: lambda(x): {
                    0: lambda(x): 'STWDP_lru6',
                    1: lambda(x): 'STWSP_lru6',
                    }[x['self'].bit(x['high'], 10)](x),
                0x0b: lambda(x): {
                    0: lambda(x): 'LDWDP_lru6',
                    1: lambda(x): 'LDWSP_lru6',
                    }[x['self'].bit(x['high'], 10)](x),
                0x0c: lambda(x): {
                    0: lambda(x): 'LDAWDP_lru6',
                    1: lambda(x): 'LDAWSP_lru6',
                    }[x['self'].bit(x['high'], 10)](x),
                0x0d: lambda(x): {
                    0: lambda(x): 'LDC_lru6',
                    1: lambda(x): 'LDWCP_lru6',
                    }[x['self'].bit(x['high'], 10)](x),
                0x0e: lambda(x): {
                    True: lambda(x): {
                        0: lambda(x): 'BRFT_lru6',
                        1: lambda(x): 'BRBT_lru6',
                        }[x['self'].bit(x['high'], 10)](x),
                    False: lambda(x): {
                        0x0c: lambda(x): 'BRFU_lu6',
                        0x0d: lambda(x): 'BLAT_lu6',
                        0x0e: lambda(x): 'EXTDP_lu6',
                        0x0f: lambda(x): 'KCALL_lu6',
                        0x1c: lambda(x): 'BRBU_lu6',
                        0x1d: lambda(x): 'ENTSP_lu6',
                        0x1e: lambda(x): 'EXTSP_lu6',
                        0x1f: lambda(x): 'RETSP_lu6',
                        }[x['self'].bit_range(x['high'], 10, 6)](x),
                    }[x['self'].test_ru6(x['high'])](x),
                0x0f: lambda(x): {
                    True: lambda(x): {
                        0: lambda(x): 'BRFF_lru6',
                        1: lambda(x): 'BRBF_lru6',
                        }[x['self'].bit(x['high'], 10)](x),
                    False: lambda(x): {
                        0x0c: lambda(x): 'CLRSR_lu6',
                        0x0d: lambda(x): 'SETSR_lu6',
                        0x0e: lambda(x): 'KENTSP_lu6',
                        0x0f: lambda(x): 'KRESTSP_lu6',
                        0x1c: lambda(x): 'GETSR_lu6',
                        0x1d: lambda(x): 'LDAWCP_lu6',
                        }[x['self'].bit_range(x['high'], 10, 6)](x),
                    }[x['self'].test_ru6(x['high'])](x),
                0x1a: lambda(x): {
                    1: lambda(x): 'BLRB_lu10',
                    0: lambda(x): 'BLRF_lu10',
                    }[x['self'].bit(x['high'], 10)](x),
                0x1b: lambda(x): {
                    1: lambda(x): 'LDAPB_lu10',
                    0: lambda(x): 'LDAPF_lu10',
                    }[x['self'].bit(x['high'], 10)](x),
                0x1c: lambda(x): {
                    1: lambda(x): 'LDWCPL_lu10',
                    0: lambda(x): 'BLACP_lu10',
                    }[x['self'].bit(x['high'], 10)](x),
                0x1d: lambda(x): {
                    True: lambda(x): {
                        0: lambda(x): 'SETC_lru6',
                        }[x['self'].bit(x['high'], 10)](x),
                    }[x['self'].test_ru6(x['high'])](x),
                }[x['self'].bit_range(x['high'], 15, 11)](x),
            }[x['self'].bit(x['low'], 10) == 0 and x['highvalid']](x),
        #Extra operands
        0x1f: lambda(x): {
            True:  lambda(x): {
                0x00: lambda(x): {
                    6:  lambda(x): 'LMUL_l6r',
                    5:  lambda(x): {
                        1:  lambda(x): 'LADD_l5r',
                        0:  lambda(x): 'LDIVU_l5r',
                        }[x['self'].bit(x['high'], 4)](x),
                    4:  lambda(x): {
                        0x7e:   lambda(x): 'CRC8_l4r',
                        0x7f:   lambda(x): 'MACCU_l4r',
                        }[x['self'].bit_range(x['high'], 10, 4)](x),
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'STW_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    2:  lambda(x): {
                        0x0c:  lambda(x): 'BITREV_l2r',
                        0x1c:  lambda(x): 'BYTEREV_l2r',
                        }[ int(x['self'].bit(x['low'], 4) << 4)
                            | x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x01: lambda(x): {
                    5:  lambda(x): {
                        True:  lambda(x): 'LSUB_l5r',
                        }[x['self'].bit(x['high'], 4) != 0](x),
                    4:  lambda(x): {
                        0x7e:   lambda(x): 'MACCS_l4r',
                        }[x['self'].bit_range(x['high'], 10, 4)](x),
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'XOR_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    2:  lambda(x): {
                        0x0c:  lambda(x): 'CLZ_l2r',
                        0x1c:  lambda(x): 'SETCLK_l2r',
                        }[ int(x['self'].bit(x['low'], 4) << 4)
                            | x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x02: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'ASHR_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    2:  lambda(x): {
                        0x0c:  lambda(x): 'TINITLR_l2r',
                        0x1c:  lambda(x): 'GETPS_l2r',
                        }[ int(x['self'].bit(x['low'], 4) << 4)
                            | x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x03: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'LDAWF_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    2:  lambda(x): {
                        0x0c:  lambda(x): 'SETPS_l2r',
                        0x1c:  lambda(x): 'GETD_l2r',
                        }[ int(x['self'].bit(x['low'], 4) << 4)
                            | x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x04: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'LDAWB_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    2:  lambda(x): {
                        0x0c:  lambda(x): 'TESTLCL_l2r',
                        0x1c:  lambda(x): 'SETTW_l2r',
                        }[ int(x['self'].bit(x['low'], 4) << 4)
                            | x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x05: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'LDA16F_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    2:  lambda(x): {
                        0x0c:  lambda(x): 'SETRDY_l2r',
                        0x1c:  lambda(x): 'SETC_l2r',
                        }[ int(x['self'].bit(x['low'], 4) << 4)
                            | x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x06: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'LDA16B_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    2:  lambda(x): {
                        0x0c:  lambda(x): 'SETN_l2r',
                        0x1c:  lambda(x): 'GETN_l2r',
                        }[ int(x['self'].bit(x['low'], 4) << 4)
                            | x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x07: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'MUL_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x08: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'DIVS_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x09: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'DIVU_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x10: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'ST16_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x11: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'ST8_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x12: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'ASHR_l2rus',
                        0x0d:  lambda(x): 'OUTPW_l2rus',
                        0x0e:  lambda(x): 'INPW_l2rus',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x13: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'LDAWF_l2rus',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x14: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'LDAWB_l2rus',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x15: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'CRC_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x18: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'REMS_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                0x19: lambda(x): {
                    3:  lambda(x): {
                        0x0c:  lambda(x): 'REMU_l3r',
                        }[x['self'].bit_range(x['high'], 3, 0)](x),
                    }[x['self'].num_operands(x['low'], x['high'])](x),
                }[x['self'].bit_range(x['high'], 15, 11)](x),
            }[x['highvalid']](x),
    }

    def __init__(self, file_handle=None):
        self.file = file_handle

    def num_operands(self, low, high=None):
        """
            Calculate the number of operands for a long or short instruction.
            We do not care if the operands are immediate or register.
        """
        ret = 0
        # Long instruction decoding
        if high is not None:
            if (self.bit_range(low, 10, 6) < 27
                    and self.bit_range(high, 10, 6) < 27):
                ret = 6
            elif (self.bit_range(low, 10, 6) < 27
                    and (self.bit_range(high, 10, 6)
                    - 27 + self.bit(high, 5) * 5) < 9):
                ret = 5
            elif (self.bit_range(low, 10, 6) < 27
                    and self.bit_range(high, 3, 0) < 12 
                    and self.bit_range(high, 10, 5) == 0x3f):
                ret = 4
            elif (self.bit_range(low, 10, 6) < 27
                    and self.bit_range(high, 10, 4) == 0x7e):
                ret = 3
            elif (self.bit_range(low, 10, 6) - 27 + self.bit(low, 5) * 5 < 9
                    and self.bit_range(high, 10, 4) == 0x7e):
                ret = 2
        # Short instruction decoding
        elif self.bit_range(low, 10, 6) < 27:
            ret = 3
        elif self.bit_range(low, 10, 6) - 27 + self.bit(low, 5) * 5 < 9:
            ret = 2
        elif (self.bit_range(low, 10, 5) == 0x3f
                and self.bit_range(low, 3, 0) < 12):
            ret = 1
        return ret

    def test_ru6(self, value):
        """
            Test for unsigned immediate
        """
        return self.bit_range(value, 9, 6) < 12

    def bits(self, value, shift, size):
        """
            Get a bit-field from the supplied value
        """
        return (value >> shift) & ((1 << size) - 1)

    def bit_range(self, value, high, low):
        """
            Get from bit high to bit low
        """
        return self.bits(value, low, 1 + high - low)

    def bit(self, value, shift):
        """
            Get a single bit from a value
        """
        return self.bits(value, shift, 1)

    def decode_file(self, merge=None, file_handle=None, replace=False):
        """
            Decode a file of hex or objdump output. Return mnemonics, or...
            Merge will produce line + merge + mnemonic
            Replace will substitute old instruction "stw (l2rus)" with new
            "STWCP_l2rus" in each line
        """
        if not file_handle:
            file_handle = self.file
        assert file_handle
        ret = []
        for line in file_handle:
            decoded = self.decode_line(line, merge, replace)
            ret += [decoded]
        return ret

    def decode_word(self, low, high, highvalid=False):
        """
            Take a low (and possibly high) instruction word and return
            the mnemonic for it as INSTR_ENCODING, e.g. add_3r
        """
        opc = self.bit_range(low, 15, 11)
        params = {
                'self': self, 'low': low, 'high': high, 'highvalid': highvalid
        }
        try:
            decoded = self.decode_opc[opc](params)
            return decoded
        except:
            print "{:02x} {:02x} {:02x}".format(
                params['low'], params['high'], opc
            )
            raise

    def decode_bin(self, instr, iwords=1):
        """
            Decode an instruction of 1 or 2 instruction words
        """
        assert iwords in [1, 2]
        binstr = struct.pack('>I', instr)
        high = 0
        if iwords == 2:
            low, high = struct.unpack('<HH', binstr)
        else:
            unused, low = struct.unpack('<HH', binstr)
        return self.decode_word(low, high, iwords == 2)

    def decode_line(self, line, merge=None, replace=False, tup=False):
        """
            Decode a line of hex or objdump output. Return mnemonic, or...
            Merge will produce line + merge + mnemonic
            Replace will substitute old instruction "stw (l2rus)" with new
            "STWCP_l2rus" in the line
        """
        xmatch = self.imatcher.match(line)
        if xmatch:
            prefix = ''
            if merge is not None:
                prefix = line.rstrip() + merge
            string = self.whitematcher.sub('', xmatch.group(4))
            length = len(string)
            assert length in [4, 8]
            length /= 4
            instr = int(string, 16)
            try:
                decoded = self.decode_bin(instr, length)
                if tup:
                    return { int(self.addrmatcher.match(line).group(2)): decoded }
                elif merge is not None:
                    return line.rstrip() + merge + decoded
                elif replace:
                    match = self.nonarchmatcher.match(line)
                    length = len(match.group(5))
                    return line.replace(match.group(5),
                        decoded.ljust(length)).rstrip()
                else:
                    return decoded
            except:
                print prefix
                raise
        if merge is not None or replace:
            return line.rstrip()
        else:
            return None

if __name__ == "__main__":
    ARGS = docopt(__doc__)
    if ARGS['--xobjdump-sub']:
        DC = XS1Decoder()
        for l in sys.stdin:
            print DC.decode_line(l, replace=True)
    elif ARGS['--xobjdump-merge']:
        DC = XS1Decoder()
        for l in sys.stdin:
            print DC.decode_line(l, merge=ARGS['--xobjdump-merge'])
    elif ARGS['--default'] or True: #Yeah
        DC = XS1Decoder()
        for l in sys.stdin:
            nl = DC.decode_line(l)
            if nl:
                print nl

