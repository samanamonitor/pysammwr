from setuptools import setup, find_packages
from sammwr import __version__
import re

def set_control_version():
    with open("./debian/control.tmpl", "r") as src, open("./debian/control", "w") as dst:
        while True:
            datain = src.readline()
            if len(datain) == 0: break
            dataout = re.sub(r"%VERSION%", __version__, datain)
            dst.write(dataout)

if __name__ == "__main__":
    set_control_version()
    setup(
        name='sammwr',
        version=__version__,
        packages=find_packages(include=['sammwr', 'sammwr.*']),
        install_requires=[
            'pywinrm',
            'xmltodict',
            'uuid'
        ]
    )
