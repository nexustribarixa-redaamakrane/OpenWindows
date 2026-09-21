# Third-Party Notices

OpenWindows uses sibling projects and generated inputs that remain subject to
their own licenses. The GPL-3.0-or-later license for OpenWindows-owned code
does not automatically relicense these components.

| Component | Location or role | License |
| --- | --- | --- |
| SuperUnicode / SUCS / SUTF | `../superunicode/` and imported `sutf` sources | MIT **or** Apache-2.0, at the recipient's option; see `../superunicode/LICENSE`, `LICENSE-MIT`, and `LICENSE-APACHE` |
| OpenWindows-Storage | `../OpenWindows-Storage/` and imported OWFS/USFS sources | MIT **or** Apache-2.0, at the recipient's option; see `../OpenWindows-Storage/LICENSE`, `LICENSE-MIT`, and `LICENSE-APACHE` |
| UniVIP / FVIP | `../vip/` and imported VIP sources | See the dependency's license and notices before redistribution |
| OpenWindows-Essentials `owinit` | `../OpenWindows-Essentials/` and the generated `boot/owinit_image.h` | See the Essentials project's license and notices |
| GCC, Python, CMake, QEMU, VirtualBox, NASM | Build and validation tools | Each tool retains its own license; these tools are not relicensed by OpenWindows |

When publishing source or binary releases, include the applicable third-party
license files and notices alongside the corresponding components.