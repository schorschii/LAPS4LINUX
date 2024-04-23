from distutils.command.clean import clean
from distutils import log
from setuptools import setup
import os

# Get the long description from the README file
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
      name='laps4linux_runner',
      version=__import__('laps_runner').__version__,
      description='Rotate and store local administrator (LAPS) passwords in your AD/LDAP directory',
      long_description=long_description,
      long_description_content_type='text/markdown',
      install_requires=[i.strip() for i in open('requirements.txt').readlines()],
      license=__import__('laps_runner').__license__,
      author='Georg Sieber',
      keywords='laps password administrator ad ldap',
      url=__import__('laps_runner').__website__,
      classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Intended Audience :: System Administrators',
            'Operating System :: POSIX :: Linux',
            'Operating System :: MacOS',
            'Operating System :: Microsoft :: Windows',
            'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3',
      ],
      packages=['laps_runner'],
      entry_points={
            'console_scripts': [
                  'laps-runner = laps_runner.laps_runner:main',
            ],
      },
      platforms=['all'],
      #install_requires=[],
      #test_suite='tests',
)
