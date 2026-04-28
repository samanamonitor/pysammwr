FROM python:3.12

RUN pip install pykerberos pywinrm; \
apt update && apt install -y krb5-user
WORKDIR /usr/src