# PYSAMMWR package
This package allows for WinRM querying and command execution

# Build DEB package
`docker run -it --rm -v $(pwd):/usr/src sammrepo /usr/local/bin/build-deb.sh`

# Upload to repo
`package=<package deb file>
arch=<architecture name arm64 or amd64>
docker run --rm -it -v $(pwd):/usr/src -v $(pwd)/../gpg:/gpg -v ~/.aws:/root/.aws -w /usr/src sammrepo /usr/local/bin/add-file-repo.sh $package jammy $arch`

# To compile
`docker run -it --rm --mount type=bind,source=$(pwd),target=/usr/src/pysammwr -w /usr/src/pysammwr ubuntu:bionic /bin/bash`

# Docs
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/1bcf0ed8-3511-4ea9-9c55-bdfcf4e3f4bd


# Installed applications that wmi doesn't show
`Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
