FROM python:3.12.3
ADD . /OauthLab
WORKDIR /OauthLab
RUN pip install -r requirements.txt