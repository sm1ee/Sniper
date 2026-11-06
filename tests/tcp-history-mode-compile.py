#!/usr/bin/env python3
"""Compile the real open_at helper with narrow/wide Unix mode_t aliases.

Requires rustc and a Unix host. This is a host-side type regression, not a
macOS cross-build, link, or runtime check. The shim matches libc's variadic
openat declaration, with mode_t = u16 (Darwin) or u32 (Linux).
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    '--source', type=Path,
    default=Path(__file__).resolve().parents[1] / 'src/tcp_capture/history_io.rs',
)
parser.add_argument('--rustc', default=os.environ.get('RUSTC', 'rustc'))
args = parser.parse_args()
source = args.source.read_text()
# Use the production method, not a copied version of its variadic call. Fail
# clearly if a refactor changes this method boundary and needs a new harness.
matches = re.findall(r'^    fn open_at\(.*?^    }$', source, re.M | re.S)
assert len(matches) == 1, 'expected exactly one complete open_at method'
method = matches[0]
assert 'libc::openat(' in method, 'open_at no longer calls libc::openat'

SHIM = '''
#![allow(dead_code, non_camel_case_types, unused_imports)]
use std::{ffi::OsStr, fs::File, io};
mod libc {
    pub use std::os::raw::{c_char, c_int, c_uint};
    pub type mode_t = MODE_TYPE;
    // Values are irrelevant: the harness only emits compiler metadata.
    pub const O_NOFOLLOW: c_int = 0;
    pub const O_CLOEXEC: c_int = 0;
    extern "C" {
        pub fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    }
}
fn invalid() -> io::Error { io::Error::from(io::ErrorKind::InvalidData) }
struct HistoryDirectory { handle: File }
impl HistoryDirectory {
METHOD
}
'''


def compile_method(directory, name, mode_type, body):
    fixture = directory / f'{name}.rs'
    fixture.write_text(SHIM.replace('MODE_TYPE', mode_type).replace('METHOD', body))
    return subprocess.run(
        [args.rustc, '--edition=2021', '--crate-type=lib', '--emit=metadata',
         '-Dwarnings', str(fixture), '-o', str(directory / f'{name}.rmeta')],
        capture_output=True, text=True, check=False,
    )


with tempfile.TemporaryDirectory(prefix='sniper-tcp-mode-compile-') as temporary:
    directory = Path(temporary)
    for mode_type in ('u16', 'u32'):
        result = compile_method(directory, f'mode_{mode_type}', mode_type, method)
        assert result.returncode == 0, f'{mode_type} helper failed:\n{result.stderr}'
        print(f'PASS production open_at compiles with mode_t = {mode_type}')

    # Confirm this harness detects the original bug rather than merely checking
    # valid standalone Rust. The original unpromoted u16 call must be E0617.
    unpromoted, count = re.subn(r'mode as libc::c_uint\b', 'mode', method)
    assert count == 1, 'update the negative control if the promotion changes'
    result = compile_method(directory, 'unpromoted_u16', 'u16', unpromoted)
    assert result.returncode != 0 and 'E0617' in result.stderr, result.stderr
    print('PASS unpromoted u16 negative control fails with E0617')

print('Host-side type regression passed; no foreign build or runtime was performed.')
