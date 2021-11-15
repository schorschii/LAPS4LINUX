# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['laps-gui.py'],
             pathex=['C:\\Users\\vm2\\Desktop\\laps4linux'],
             binaries=[],
             datas=[ ('setup\\laps.png', '.') ],
             hiddenimports=['winkerberos', 'cryptography'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='laps-gui',
          icon='setup\\laps.ico',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=False )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='laps-gui')
