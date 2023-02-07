#!/usr/bin/env python

from setuptools import setup, find_packages, Extension

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(name='kafl_fuzzer',
      version='0.6',
      description='kAFL/Nyx Kernel Fuzzer',
      maintainer='Steffen Schulz',
      maintainer_email='steffen.schulz@intel.com',
      url='https://github.com/IntelLabs/kAFL',
      install_requires=requirements,
      packages=find_packages(),
      package_data={'kafl_fuzzer': ['logging.yaml', 'common/config/default_settings.yaml']},
      include_package_data=True,
      ext_modules = [
          Extension('kafl_fuzzer.native.bitmap',
                    sources = ['kafl_fuzzer/native/bitmap.c'],
                    extra_compile_args=["-O3", "-fPIC", "-mtune=native"],
                    ),
          ],
      entry_points = {
        'console_scripts': ['kafl=kafl_fuzzer.__main__:main'],
      },
	  classifiers=[
		  'Development Status :: 4 - Beta',
		  'Environment :: Console',
		  'Intended Audience :: Developers',
		  'Intended Audience :: Science/Research',
		  'License :: OSI Approved :: GNU Affero General Public License v3',
		  'Operating System :: POSIX :: Linux',
		  'Programming Language :: Python',
		  'Topic :: Security',
		  ],
     )
