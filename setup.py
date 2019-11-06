import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(

    name='py_hd_wallet',

    version='0.1',

    packages=['py_hd_wallet'],

    license='LICENSE.txt',

    author="Nguyen Tran Ho Thanh Son",

    author_email="nguyentranhothanhson@gmail.com",

    description="A multi-cryptocurrency HD wallet implemented by Python",

    long_description=long_description,
    long_description_content_type='text/x-rst',

    url="https://github.com/nthtson/py_hd_wallet",

    install_requires=[
        'pywallet==0.1.0',
        'pycoin==0.80',
        'mnemonic==0.18',
        'pysha3==1.0.2',
        'pycryptodome==3.8.2',
        'hashprint==1.0.1',
        'pysha3==1.0.2',
        'pycoin==0.80',
        'seed-phrases-for-stellar==0.2',
        'toml==0.10.0'
    ]

)
