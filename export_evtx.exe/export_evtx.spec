# -*- mode: python -*-

block_cipher = None


a = Analysis(['export_evtx.py'],
             pathex=,
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries + [('libevtx.dll','libevtx.dll', 'BINARY'), ('msvcr120.dll','c:\\windows\\system32\\msvcr120.dll','BINARY')],
          a.zipfiles,
          a.datas,
          name='export_evtx',
          debug=False,
          strip=False,
          upx=True,
          console=True )
