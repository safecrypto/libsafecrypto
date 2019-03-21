# The Queen's University of Belfast ECIT 2018
# This file is subject to the terms and conditions defined in
# file 'LICENSE.md', which is part of this source code package.

FROM ubuntu:16.04
LABEL maintainer="n.hanley@qub.ac.uk" vendor="CSIT, QUB"

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
