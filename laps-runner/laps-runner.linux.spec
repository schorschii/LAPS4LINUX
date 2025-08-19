# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules('gssapi.raw')
hiddenimports += collect_submodules('passlib')
hiddenimports += collect_submodules('passlib.context')
hiddenimports += collect_submodules('passlib.handlers.sha2_crypt')

block_cipher = None

a = Analysis(
    ['laps-runner-script.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(pyz, a.scripts, [],
    exclude_binaries=True,
    name='laps-runner',
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
coll = COLLECT(exe, a.binaries, a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='laps-runner',
)
