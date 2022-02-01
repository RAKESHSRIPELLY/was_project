# -*- mode: python -*-

block_cipher = None


a = Analysis(['execSuite.py'],
             pathex=['/home/virsec/was'],
             binaries=[],
             datas=[],
             hiddenimports=[],
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
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='run_cli',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )

import shutil
import os

dir_list = ['attack', 'crawl', 'service', 'webapp', 'config','artefacts', 'lib', 'ZAP']
file_list = ['']

for _dir in dir_list:
        dir_path = os.path.join(os.getcwd() + '/dist/' + _dir)
        if os.path.exists(dir_path) and os.path.isdir(dir_path):
                shutil.rmtree(dir_path)
        shutil.copytree(_dir, ('{0}/'+_dir).format(DISTPATH), ignore=shutil.ignore_patterns('*.py*', '_*', '*.log'))

for _file in file_list:
        shutil.copyfile(_file, ('{0}/'+_file).format(DISTPATH))
