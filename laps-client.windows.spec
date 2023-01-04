# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


gui_a = Analysis(['laps-gui.py'],
             pathex=['.'],
             binaries=[],
             datas=[ ('assets\\laps.png', '.') ],
             hiddenimports=['winkerberos', 'cryptography'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
cli_a = Analysis(['laps-cli.py'],
             pathex=['.'],
             binaries=[],
             datas=[ ('assets\\laps.png', '.') ],
             hiddenimports=['winkerberos', 'cryptography'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
MERGE( (gui_a, 'laps-gui', 'laps-gui'), (cli_a, 'laps-cli', 'laps-cli') )

gui_pyz = PYZ(gui_a.pure, gui_a.zipped_data, cipher=block_cipher)
gui_exe = EXE(gui_pyz, gui_a.scripts, [],
          exclude_binaries=True,
          name='laps-gui',
          icon='assets\\laps.ico',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=False )

cli_pyz = PYZ(cli_a.pure, cli_a.zipped_data, cipher=block_cipher)
cli_exe = EXE(cli_pyz, cli_a.scripts, [],
          exclude_binaries=True,
          name='laps-cli',
          icon='assets\\laps.ico',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True )

coll = COLLECT(gui_exe, gui_a.binaries, gui_a.zipfiles, gui_a.datas,
               cli_exe, cli_a.binaries, cli_a.zipfiles, cli_a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='LAPS4WINDOWS')
