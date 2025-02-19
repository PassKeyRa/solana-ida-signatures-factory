#!/usr/bin/env python3

# This is the Solana eBPF preprocessor for FLAIR tools that
# are used to generate FLIRT signatures. The result of 
# the tool is a .pat file for a corresponding library, 
# which can be passed to the sigmake tool to generate 
# the final .sig file

# TODO:
# - read files that contain .debug_* sections
# - detect internal functions length, in case they aren't presented as top-level relocations

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import argparse
import cxxfilt
import crcmod.predefined
import ctypes
import ar
import os

REL_PATCH_SIZE = {
    0: None,
    1: 32,
    2: 64,
    3: 32,
    4: 32,
    8: 32,
    10: 32
}

REL_TYPE = {
    0: 'R_BPF_NONE',
    1: 'R_BPF_64_64',
    2: 'R_BPF_64_ABS64',
    3: 'R_BPF_64_ABS32',
    4: 'R_BPF_64_NODYLD32',
    8: 'R_BPF_64_RELATIVE', # SOLANA SPEC (https://github.com/solana-labs/llvm-project/blob/038d472bcd0b82ff768b515cc77dfb1e3a396ca8/llvm/include/llvm/BinaryFormat/ELFRelocs/BPF.def#L11)
    10: 'R_BPF_64_32'
}

# Source modifiers:
## BPF source operand modifier: 32-bit immediate value.
BPF_K = 0x00
## BPF source operand modifier: `src` register.
BPF_X = 0x08

# Operation codes -- BPF_JMP class:
## BPF JMP operation code: jump.
BPF_JA = 0x00
## BPF JMP operation code: jump if equal.
BPF_JEQ = 0x10
## BPF JMP operation code: jump if greater than.
BPF_JGT = 0x20
## BPF JMP operation code: jump if greater or equal.
BPF_JGE = 0x30
## BPF JMP operation code: jump if `src` & `reg`.
BPF_JSET = 0x40
## BPF JMP operation code: jump if not equal.
BPF_JNE = 0x50
## BPF JMP operation code: jump if greater than (signed).
BPF_JSGT = 0x60
## BPF JMP operation code: jump if greater or equal (signed).
BPF_JSGE = 0x70
## BPF JMP operation code: syscall function call.
BPF_CALL = 0x80
## BPF JMP operation code: return from program.
BPF_EXIT = 0x90
## BPF JMP operation code: jump if lower than.
BPF_JLT = 0xa0
## BPF JMP operation code: jump if lower or equal.
BPF_JLE = 0xb0
## BPF JMP operation code: jump if lower than (signed).
BPF_JSLT = 0xc0
## BPF JMP operation code: jump if lower or equal (signed).
BPF_JSLE = 0xd0

BPF_JMP = 0x05

BRANCH_INSTRUCTIONS = [
    BPF_JMP | BPF_JA,
    BPF_JMP | BPF_K | BPF_JEQ,
    BPF_JMP | BPF_X | BPF_JEQ,
    BPF_JMP | BPF_K | BPF_JGT,
    BPF_JMP | BPF_X | BPF_JGT,
    BPF_JMP | BPF_K | BPF_JGE,
    BPF_JMP | BPF_X | BPF_JGE,
    BPF_JMP | BPF_K | BPF_JLT,
    BPF_JMP | BPF_X | BPF_JLT,
    BPF_JMP | BPF_K | BPF_JLE,
    BPF_JMP | BPF_X | BPF_JLE,
    BPF_JMP | BPF_K | BPF_JSET,
    BPF_JMP | BPF_X | BPF_JSET,
    BPF_JMP | BPF_K | BPF_JNE,
    BPF_JMP | BPF_X | BPF_JNE,
    BPF_JMP | BPF_K | BPF_JSGT,
    BPF_JMP | BPF_X | BPF_JSGT,
    BPF_JMP | BPF_K | BPF_JSGE,
    BPF_JMP | BPF_X | BPF_JSGE,
    BPF_JMP | BPF_K | BPF_JSLT,
    BPF_JMP | BPF_X | BPF_JSLT,
    BPF_JMP | BPF_K | BPF_JSLE,
    BPF_JMP | BPF_X | BPF_JSLE,
]

CALL_INSTRUCTION = BPF_JMP | BPF_CALL
CALLX_INSTRUCTION = BPF_JMP | BPF_X | BPF_CALL
EXIT_INSTRUCTION = BPF_JMP | BPF_EXIT

def resolve_jmp_addr(ea, ins_bytes):
    offset = int.from_bytes(ins_bytes[2:4], byteorder='little', signed=True)
    addr = 8 * offset + ea + 8
    return addr

def resolve_call_addr(ea, ins_bytes):
    registers = ins_bytes[1]
    src = (registers >> 4) & 15
    dst = registers & 15

    imm = int.from_bytes(ins_bytes[4:8], byteorder='little')

    if imm == 0xFFFFFFFF:
        return None
    
    if src == 0:
        return 8 * imm
    elif src == 1:
        return 8 * imm + ea + 8
    else:
        return None
    
def resolve_callx_addr(ea, ins_bytes):
    return None # address is in the register

def find_function_max_end(libdata, ea, checked_ea, max_end):
    while True:
        if ea in checked_ea:
            return max_end
        
        checked_ea.append(ea)

        if ea >= max_end:
            return checked_ea,max_end
        
        opcode = libdata[ea]
        if opcode in BRANCH_INSTRUCTIONS:
            jump_addr = resolve_jmp_addr(ea, libdata[ea:ea+8])
            if jump_addr:
                checked_ea, max_end = find_function_max_end(libdata, jump_addr, checked_ea, max_end)
        elif opcode == EXIT_INSTRUCTION:
            return checked_ea, max_end
        
        ea += 8
        

def find_function_len(elffile, libdata, ea):
    # First check if the address is in an executable section
    found = False
    for section in elffile.iter_sections():
        if section.header['sh_flags'] & 0x4:  # SHF_EXECINSTR flag
            section_start = section.header['sh_addr']
            section_end = section_start + section.header['sh_size']
            
            if section_start <= ea < section_end:
                found = True
                break
    
    if not found:
        return -1

    end = find_function_max_end(libdata, ea, [], -1)
    return end - ea



def parse_relocation(rel_type, loc, val):
    type_ = REL_TYPE[rel_type]
    changes = []
    if type_ == 'R_BPF_64_64':
        changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc + 4, 'val': val & 0xFFFFFFFF})
        changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc + 8 + 4, 'val': val >> 32})
    elif type_ == 'R_BPF_64_ABS64':
        changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc, 'val': val})
    elif type_ == 'R_BPF_64_ABS32':
        pass
    elif type_ == 'R_BPF_64_NODYLD32':
        changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc, 'val': val & 0xFFFFFFFF})
    elif type_ == 'R_BPF_64_32':
        changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc + 4, 'val': val & 0xFFFFFFFF})
    elif type_ == 'R_BPF_64_RELATIVE':
        changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc + 4, 'val': val & 0xFFFFFFFF})
    else:
        print(f'[WARN] unknown relocation type: {type_}')
    
    return changes

def decode_name(name):
    name = name.replace('.rel.text.','')
    name = name.replace('.rel.data.rel.ro.','')
    return name

def extract_relocations_and_functions(elffile):
    sections = []
    for section in elffile.iter_sections():
        sections.append(section)

    relocations = {}
    functions = {}

    symtab_s = elffile.get_section_by_name('.symtab')
    symtab = []

    if symtab_s:
        for sym in symtab_s.iter_symbols():
            symtab.append({'name': sym.name, 'val': sym.entry['st_value']})
    
    for s in sections:
        #print(s.name, s.header['sh_type'])
        if s.header['sh_type'] == 'SHT_PROGBITS' and s.name.startswith('.text.'):
            # parse .text.<name>
            name = s.name[5:]
            if name.startswith('.unlikely'):
                name = name[9:]
            if name.startswith('.'):
                name = name[1:]
            
            if name not in functions:
                functions[name] = {'offset': s.header['sh_offset'], 'func_size': s.header['sh_size'], 'internal': [], 'from_relocations': False}

        if s.header['sh_type'] == 'SHT_REL' and s.name == '.rel.dyn':
            # parse dynamic relocations
            dynsym = elffile.get_section_by_name(".dynsym")
            if not dynsym or not isinstance(dynsym, SymbolTableSection):
                #print("dynsym not found. what?")
                continue
        
            symbols = []
            for symbol in dynsym.iter_symbols():
                symbols.append({'name': symbol.name, 'val': symbol.entry['st_value']})

            for reloc in s.iter_relocations():
                relsym = symbols[reloc['r_info_sym']]

                name = decode_name(relsym['name'])

                reloc_parsed = parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                mods = []

                for r in reloc_parsed:
                    mods.append({'loc': r['loc'], 'val': r['val']})
                
                relocation = {
                    'type': reloc['r_info_type'],
                    'name': name,
                    'mods': mods
                }

                relocations[reloc['r_offset']] = relocation
                
                continue

        if s.header['sh_type'] == 'SHT_REL':
            if not symtab_s:
                print("symtab section not found")
                exit(0)

            code_s = sections[s.header['sh_info']]
            base_offset = code_s.header['sh_offset']

            section_name = decode_name(s.name)

            if s.name.startswith('.rel.text.'):
                # Parse a function
                func_name = section_name

                # try to demangle, but put the mangled name in the result
                try:
                    func_name_ = cxxfilt.demangle(func_name)
                except Exception as e:
                    func_name_ = None

                if func_name_:
                    if func_name in functions:
                        if functions[func_name]['from_relocations']:
                            continue
                        # if the function was from .text section, replace by relocations

                    functions[func_name] = {'offset': base_offset, 'func_size': code_s.header['sh_size'], 'internal': [], 'from_relocations': True}
            
            elif s.name.startswith('.rel.data.rel.ro.'):
                continue

            # Parse all relocations
            for reloc in s.iter_relocations():
                relsym = symtab[reloc['r_info_sym']]

                name = decode_name(relsym['name'])

                reloc_parsed = parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                mods = []

                for r in reloc_parsed:
                    mods.append({'loc': base_offset + r['loc'], 'val': r['val']}) # file offset
                
                relocation = {
                    'type': reloc['r_info_type'],
                    'name': name,
                    'mods': mods
                }

                relocations[base_offset + reloc['r_offset']] = relocation # file offset
    
                if section_name in functions:
                    internal_relocation = {
                        'type': reloc['r_info_type'],
                        'name': name,
                        'offset': reloc['r_offset'], # function offset
                        'value': relsym['val']
                    }

                    functions[section_name]['internal'].append(internal_relocation)

    return relocations, functions

def parse_function_internals(libdata, relocations, ea, name, size):
    current_ea = ea
    internal_relocations = []
    while current_ea < ea + size:
        if current_ea in relocations:
            reloc = {
                'type': relocations[current_ea]['type'],
                'name': relocations[current_ea]['name'],
                'offset': current_ea - ea,
                'value': 0xFFFFFFFF # doesn't matter
            }
            internal_relocations.append(reloc)
        current_ea += 1
    
    return internal_relocations

# CRC16 from https://github.com/mandiant/flare-ida/blob/master/python/flare/idb2pat.py

CRC16_TABLE = [
  0x0, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1,
  0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x108, 0x3393, 0x221a,
  0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64,
  0xf9ff, 0xe876, 0x2102, 0x308b, 0x210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a,
  0x1291, 0x318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50,
  0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x420, 0x15a9,
  0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x528, 0x37b3, 0x263a, 0xdecd, 0xcf44,
  0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014, 0x519d,
  0x2522, 0x34ab, 0x630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3,
  0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581,
  0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x840, 0x19c9, 0x2b52, 0x3adb,
  0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324,
  0xf1bf, 0xe036, 0x18c1, 0x948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb,
  0xa50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
  0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0xb58, 0x7fe7, 0x6e6e,
  0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0xc60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704,
  0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e,
  0x1ce1, 0xd68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3,
  0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0xe70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e,
  0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0xf78]


def crc16(data, crc):
    for byte in data:
        crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ byte) & 0xFF]
    crc = (~crc) & 0xFFFF
    crc = (crc << 8) | ((crc >> 8) & 0xFF)
    return crc & 0xffff

def process_function(libdata, relocations, fname, fdata):
    #print('[FUNCTION]', fname, 'size', fdata['func_size'])
    #print('[RELOCATIONS]', fdata['internal'])
    fbytes = libdata[fdata['offset'] : fdata['offset'] + fdata['func_size']]

    if len(fbytes) >= 0x8000:
        return None # too long function 
    
    if len(fbytes) < 35:
        return None # too short function
    
    if not fdata['from_relocations']:
        fdata['internal'] = parse_function_internals(libdata, relocations, fdata['offset'], fname, fdata['func_size'])

    fhex = fbytes.hex().upper()

    internal_names = {}

    # Drop all variable bytes based on relocations and generate
    # internal function names list
    for reloc in fdata['internal']:
        mods = parse_relocation(reloc['type'], reloc['offset'], reloc['value'])
        for mod in mods:
            size = int(mod['size'] / 8)
            fhex = fhex[:mod['loc']*2] + '..' * size + fhex[(mod['loc']+size)*2:]
        
        if REL_TYPE[reloc['type']] == 'R_BPF_64_32':
            internal_names[hex(mods[0]['loc'])[2:].upper().zfill(4)] = reloc['name']
        elif REL_TYPE[reloc['type']] == 'R_BPF_64_64':
            internal_names[hex(mods[0]['loc'])[2:].upper().zfill(4)] = reloc['name'] # only first mod
        elif REL_TYPE[reloc['type']] == 'R_BPF_64_RELATIVE':
            if reloc['name']:
                internal_names[hex(mods[0]['loc'])[2:].upper().zfill(4)] = reloc['name']

    # Replace remaining unrelocated calls if any (shouldn't be)
    fhex = fhex.replace('85100000FFFFFFFF', '85100000' + '..' * 4)
    
    pat_data = fhex[:64]

    alen = 255 if len(fhex) - 64 > 255 * 2 else (len(fhex) - 64 - 2) // 2
    if '..' in fhex[64:64+alen*2]:
        alen = (fhex.index('..', 64) - 64)//2
    
    if alen <= 2:
        # Too short function with many mutations
        return None
    
    crc = hex(crc16(int(fhex[64:64+alen*2], 16).to_bytes(alen), crc=0xFFFF))[2:].upper().zfill(4)

    func_len = hex(fdata['func_size'])[2:].upper().zfill(4)

    pat_data += f" {hex(alen)[2:].upper().zfill(2)} {crc} {func_len} :0000 {fname}"

    for ioff in internal_names:
        pat_data += f" ^{ioff} {internal_names[ioff]}"
    
    pat_data += f" {fhex[64+alen*2:]}"

    return pat_data

def process_library(libfile):
    libelf = ELFFile(libfile)

    # The first approach will be a function detection by the
    # section type and name. For each function we need its offset
    # and size. After that, it will be possible to process each 
    # function data
    relocations, functions = extract_relocations_and_functions(libelf)
    #import pprint; pprint.pprint(functions)

    pat_funcs = []
    libfile.seek(0)
    libdata = libfile.read()

    for f in functions:
        pat_data_ = process_function(libdata, relocations, f, functions[f])
        if pat_data_ != None:
            pat_funcs.append(pat_data_)
        #print()

    return '\n'.join(pat_funcs) + '\n---\n'

def process_file(file_path):
    if file_path.endswith('.rlib'): # needs to be unpacked
        with open(file_path, 'rb') as f:
            archive = ar.Archive(f)
            for entry in archive.entries:
                if entry.name.endswith('.o'):
                    with archive.open(entry, 'rb') as e:
                        return process_library(e)
    else:
        with open(file_path, 'rb') as f:
            return process_library(f)

def main():
    parser = argparse.ArgumentParser(description="Solana eBPF libraries PAT files generator")
    parser.add_argument('-if', '--input-folder', required=False, help='Folder with .rlib or .o libraries')
    parser.add_argument('-of', '--output-folder', required=False, help='Resulted PAT files folder (separate file for each library)')
    parser.add_argument('-i', '--input-file', required=False, help='Single library file')
    parser.add_argument('-o', '--output-file', required=False, help='Single resulted PAT file')
    args = parser.parse_args()

    if not args.input_file and not args.input_folder:
        parser.error('Either --input-file or --input-folder must be provided')
    
    if not args.output_file and not args.output_folder:
        parser.error('Either --output-file or --output-folder must be provided')
    
    if args.input_file and args.input_folder:
        parser.error('Cannot provide both --input-file and --input-folder')
    
    if args.output_file and args.output_folder:
        parser.error('Cannot provide both --output-file and --output-folder')
    

    input_files = []
    if args.input_folder:
        input_files = [os.path.join(args.input_folder, f) for f in os.listdir(args.input_folder) if f.endswith('.rlib') or f.endswith('.o')]
    else:
        input_files.append(args.input_file)

    patdatas = []
    for input_file in input_files:
        print(f'Processing {input_file}...')
        patdatas.append(process_file(input_file))
        functions_count = len(patdatas[-1].split('\n')) - 1
        print(f'{functions_count} functions extracted')
    
    if args.output_file:
        patdata = '\n'.join(patdatas)
        with open(os.path.basename(args.output_file) + '.pat', 'w') as f:
            f.write(patdata)
    else:
        assert len(patdatas) == len(input_files), "Number of PAT files differs from the number of input files!"

        for i in range(len(patdatas)):
            with open(args.output_folder + '/' + os.path.basename(input_files[i]) + '.pat', 'w') as f:
                f.write(patdatas[i])
    
    print('The PAT files generated successfully')

if  __name__ == '__main__':
    main()
