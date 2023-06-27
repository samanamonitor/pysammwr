# PYSAMMWR package
This package allows for WinRM querying and command execution

# To build deb package
`docker run -it --rm --mount type=bind,source=$(pwd),target=/usr/src/build -w /usr/src/build ubuntu:jammy support/build-deb.sh`

# To compile
`docker run -it --rm --mount type=bind,source=$(pwd),target=/usr/src/pysammwr -w /usr/src/pysammwr ubuntu:bionic /bin/bash`
