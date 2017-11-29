FROM buildpack-deps:buster

LABEL maintainer="Mark Forrer <mark.forrer@lbl.gov>"

ENV LANG C.UTF-8

RUN apt-get clean && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
       build-essential \
       python3-all-dev \
       python3-pip\
       python3-setuptools \
       python3-wheel \
       git \
    && apt-get autoremove -y \
    && ln -s /usr/bin/python3 /usr/local/bin/python \
    && ln -s /usr/bin/pip3 /usr/local/bin/pip \
    && pip install --no-cache-dir virtualenv \
    && rm -rf /var/lib/apt/lists/*

# Do a sparse checkout of just the JBEI REST client code, leaving out EDD itself
ARG GIT_BRANCH=master
ARG GIT_URL=https://github.com/JBEI/edd.git
RUN mkdir /code/
WORKDIR /code/
RUN git init \
    && git remote add origin ${GIT_URL} \
    && git config core.sparsecheckout true \
    && echo jbei/* >> .git/info/sparse-checkout \
    && git pull origin ${GIT_BRANCH} \
    && ls

# Install required libraries (very few at this point, so should be fast)
RUN pip install -r jbei/requirements.txt
ENTRYPOINT ["/bin/bash"]