# The Queen's University of Belfast ECIT 2018
# This file is subject to the terms and conditions defined in
# file 'LICENSE.md', which is part of this source code package.
#
# User ID mapping reference from:
#   https://gist.github.com/renzok/29c9e5744f1dffa392cf

FROM ubuntu:16.04
LABEL maintainer="n.hanley@qub.ac.uk" vendor="CSIT, QUB"
ENV USER=developer USER_ID=1000 USER_GID=1000

# initial setup and package install
ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386 && \
  apt-get update && \
  apt-get install -y \
  autotools-dev \
  autoconf \
  autoconf-archive \
  automake \
  libtool \
  doxygen \
  texlive \
  pkg-config \
  subunit \
  gmpc \
  check \
  texlive-latex-extra \
  graphviz

# set up user to match uid/gid of host when container is run in order to allow
# modification of files in the shared folder
RUN groupadd \
      --gid "${USER_GID}" \
      "${USER}" \
    && useradd \
      --system \
      --uid ${USER_ID} \
      --gid ${USER_GID} \
      --shell /bin/bash \
      ${USER}

COPY usermap.sh /
RUN  chmod u+x usermap.sh

ENTRYPOINT ["/usermap.sh"]
