# syntax=docker/dockerfile:1.4
# this does not get you mod_auth_kerb just apache
# built by someone else.
# FROM httpd:2.4-alpine

FROM ubuntu:22.04

ARG JHBRANCH=master

ENV AuthName EXAMPLE.COM
ENV DefaultKrbRealm EXAMPLE.COM

CMD  [ "/usr/sbin/apache2", "-D", "FOREGROUND"]

RUN mkdir /etc/jazzhands
COPY minter_logging.cfg /etc/jazzhands/minter_logging.cfg

COPY <<EOF /etc/krb5.conf
[libdefaults]
default_realm = EXAMPLE.COM
dns_lookup_realm = true
dns_lookup_kdc = true
EOF

RUN apt-get update

#
# umm, yeah...  This is just to slow to git checkout for now.
# This is slow but necessary
#
RUN apt-get install -y git make
RUN git clone --depth 1 --no-tags --single-branch --branch ${JHBRANCH} https://github.com/JazzHandsCMDB/jazzhands.git origin

#
RUN cd origin/management/util/perl && perl Makefile.PL && make && make install
RUN cd origin/management/appauthal/perl/AppAuthAL && perl Makefile.PL && make && make install
RUN cd origin/management/util/perl-vault && perl Makefile.PL && make && make install
RUN cd origin/management/appauthal/perl/DBI && perl Makefile.PL && make && make install
RUN rm -rf origin
RUN apt-get purge -y git make

RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y libapache2-mod-auth-kerb mime-support
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y perl libcrypt-cbc-perl libcrypt-jwt-perl libcrypt-rijndael-perl \
	libcgi-pm-perl libjson-xs-perl libjson-perl \
	libuuid-perl libdbi-perl libdbd-pg-perl
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y liblwp-protocol-https-perl
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y libapache2-mod-perl2 libapache-dbi-perl

# for flexibility if it gets used
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y liblog-log4perl-perl

RUN apt-get autoremove -y

COPY httpd.conf /etc/apache2/apache2.conf
RUN mkdir -p /var/run/apache2
RUN chown www-data:www-data /var/run/apache2
RUN mkdir -p /var/www/docs/
RUN mkdir -p /var/www/token/
COPY minter.pl /var/www/token/minter.pl
