#!/usr/bin/env python

VERSION = '0.1'
DESCRIPTION = 'Python module to disassemble regex'


def main():
    try:
        from setuptools import setup
    except ImportError:
        from distutils.core import setup

    with open('README.rst', 'r') as f:
        readme = f.read()

    setup(
        name='regdis',
        version=VERSION,
        license='Apache 2.0 license',
        description=DESCRIPTION,
        long_description=readme,
        author='Jelle Zijlstra',
        author_email='jelle.zijlstra@gmail.com',
        packages=['regdis'],
        url='https://github.com/JelleZijlstra/regdis',
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'License :: OSI Approved :: Apache Software License',
            'Programming Language :: Python :: 2.7',
        ],
    )


if __name__ == '__main__':
    main()
