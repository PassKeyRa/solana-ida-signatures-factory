import argparse
import os
import re
import rust_demangler
import hashlib

from packaging.version import Version

def pattern_hash(pattern):
    p = pattern[4:-1]
    p_ = []
    for e in range(0, len(p), 2):
        p_.append(p[e])
        p_.append('<INTERNALREF>')
    joined =  pattern[:4] + p_ + [pattern[-1]]
    return hashlib.sha256(' '.join(joined).encode()).hexdigest()

def join_pat_files(input_folder, lib_name, output_file, drop_duplicates):
    pat_files = []
    for f in os.listdir(input_folder):
        m = re.match('^' + lib_name + '-(\d+\.\d+\.\d+)\.', f)
        if m:
            version = m.group(1)
            pat_files.append((version, f))
    
    pat_files.sort(key=lambda x: Version(x[0]))

    functions = []
    functions_idx = 0
    cache = {}
    for version, f in pat_files:
        with open(os.path.join(input_folder, f), 'r') as f:
            lines = f.readlines()
            for i in range(len(lines) - 1):
                func = lines[i].strip().split(' ')
                
                pat_hash = pattern_hash(func)
                if pat_hash not in cache:
                    cache[pat_hash] = []
                cache[pat_hash].append(functions_idx)

                func_name = func[5]
                if func_name.startswith('unlikely.'):
                    func_name = func_name[9:]
                try:
                    rust_demangler.demangle(func_name)
                    assert func_name[-1] == 'E'
                    appendix = '$SP$v' + version
                    func_name = func_name[:-1] + str(len(appendix)) + appendix + 'E'
                except Exception as e:
                    func_name = func_name + '@v' + version
                func[5] = func_name

                functions.append(func)
                functions_idx += 1

    out_funcs = []
    if drop_duplicates:
        for h in cache.keys():
            out_funcs.append(functions[cache[h][0]]) # only the first occurrence of the pattern is kept (lower version)
    else:
        out_funcs = functions
    
    with open(output_file, 'w') as f:
        for func in out_funcs:
            f.write(' '.join(func) + '\n')
        f.write('---\n')
    
    print(f'Joined {len(out_funcs)} functions from {len(functions)}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-if', '--input-folder', required=True, help='Input folder with PAT files (<lib_name>-<version>.pat)')
    parser.add_argument('-l', '--lib-name', required=True, help='Library name (joins all versions of *.pat for that library)')
    parser.add_argument('-o', '--output-file', required=True, help='Output file')
    parser.add_argument('-dd', '--drop-duplicates', action='store_true', help='Drop duplicates')
    args = parser.parse_args()

    join_pat_files(args.input_folder, args.lib_name, args.output_file, args.drop_duplicates)