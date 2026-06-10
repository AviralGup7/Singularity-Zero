# Third-Party Software Notices

This project uses third-party software packages. The following notices are provided
in accordance with the licenses of those packages.

## SciPy

This project optionally depends on SciPy (scipy). SciPy is licensed under the BSD
3-Clause License. However, SciPy binaries may include GCC runtime libraries
(libgfortran, libquadmath) that are licensed under the GNU General Public License
(GPL) version 3, with the GCC Runtime Library Exception (GCC-exception-3.1).

The GCC Runtime Library Exception permits dynamically linking against GPL-licensed
code without requiring the entire work to be GPL-licensed. However, if distributing
binary wheels that embed these runtimes, the GCC-exception-3.1 license text must be
included.

For more information, see:
- SciPy license: https://github.com/scipy/scipy/blob/main/LICENSE.txt
- GCC Runtime Library Exception: https://www.gnu.org/licenses/gcc-exception-3.1.html

## Other Dependencies

All other Python dependencies in this project are licensed under compatible open-source
licenses (MIT, BSD, Apache 2.0, or similar). Refer to individual package licenses for
details.
