# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(['laps-gui.py'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
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
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=False,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas, 
               strip=False,
               upx=True,
               upx_exclude=[],
               name='laps-gui')
app = BUNDLE(coll,
             name='LAPS4MAC.app',
             icon='setup/laps.icns',
             bundle_identifier='systems.sieber.laps4mac',
             version='1.5.2',
             info_plist={
               'CFBundleURLTypes': [
                  {
                    'CFBundleURLName': 'Local Administrator Password Solution',
                    'CFBundleURLSchemes': ['laps']
                  }
                ]
              })
