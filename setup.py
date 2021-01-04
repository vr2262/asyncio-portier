"""Setup for asncyio-portier."""
from codecs import open
from os import path

from setuptools import setup

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='asyncio-portier',
    version='0.2.0',
    description='Portier authentication asyncio-aware Python helpers.',
    long_description=long_description,
    url='https://github.com/vr2262/asyncio-portier',
    author='Viktor Roytman',
    author_email='viktor@viktorroytman.com',
    license='GPLv3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3.9',
    ],
    keywords='web services',
    packages=['asyncio_portier'],
    package_data={'asyncio_portier': ['py.typed']},
    zip_safe=False,
    install_requires=['cryptography', 'PyJWT'],
    extras_require={},
)
