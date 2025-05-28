# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules('gssapi.raw')

block_cipher = None

gui_a = Analysis(
    ['laps-gui-script.py'],
    pathex=['.'],
    binaries=[],
    datas=[ ('../assets/laps.png', '.') ],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
    optimize=0,
)
cli_a = Analysis(
    ['laps-cli-script.py'],
    pathex=['.'],
    binaries=[],
    datas=[ ('../assets/laps.png', '.') ],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
    optimize=0,
)
MERGE( (gui_a, 'laps-gui', 'laps-gui'), (cli_a, 'laps-cli', 'laps-cli') )

gui_pyz = PYZ(gui_a.pure, gui_a.zipped_data, cipher=block_cipher)
gui_exe = EXE(gui_pyz, gui_a.scripts, [],
    exclude_binaries=True,
    name='laps-gui',
    contents_directory='.',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

cli_pyz = PYZ(cli_a.pure, cli_a.zipped_data, cipher=block_cipher)
cli_exe = EXE(cli_pyz, cli_a.scripts, [],
    exclude_binaries=True,
    name='laps-cli',
    contents_directory='.',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    gui_exe, gui_a.binaries, gui_a.zipfiles, gui_a.datas,
    cli_exe, cli_a.binaries, cli_a.zipfiles, cli_a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='laps-client'
)
