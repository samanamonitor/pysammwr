from setuptools import setup, find_packages

setup(
    name='sammwr',
    version='0.0.1',
    packages=find_packages(include=['sammwr', 'sammwr.*']),
    install_requires=[
        'winrm',
        'xml',
        'xmltodict',
        'uuid'
    ]
)