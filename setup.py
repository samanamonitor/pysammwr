from setuptools import setup, find_packages

setup(
    name='pysammwr',
    version='0.0.1',
    packages=find_packages(include=['pysammwr', 'pysammwr.*']),
    install_requires=[
        'winrm',
        'xml',
        'xmltodict',
        'uuid'
    ]
)