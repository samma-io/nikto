from ubuntu:latest


# Install nikto and the NATS client. nikto is a perl HTTP scanner and needs
# no privileges, so it runs as the unprivileged samma user below and the
# image has no sudo.
RUN apt-get update && apt-get install nikto python3-pip -y
RUN pip3 install nats-py --break-system-packages
RUN nikto -update





RUN mkdir /out
COPY  ./code /code

# samma is uid 1000, the uid the samma operator runs scanner pods as
# (runAsUser 1000). ubuntu:latest already ships an `ubuntu` user on that uid,
# so it is removed first; on a base without it the useradd runs alone.
RUN if id ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi \
 && useradd --uid 1000 --create-home --shell /bin/bash samma
# At run time nikto writes only its report (-output) under /out, which samma
# owns. Its config (/etc/nikto/config.txt), plugins and databases under
# /var/lib/nikto stay root-owned and are only read; `nikto -update` above ran
# as root at build time.
RUN chown samma:samma /out
RUN chown samma:samma /code/*.py
RUN chmod 664 /code/*.py
RUN chmod +x /code/scan.py

# Escape hatch for NIKTO_USE_SUDO=1 in scan.py: build with
# --build-arg INSTALL_SUDO=1 to get sudo and the old sudoers rule back. The
# published image is built without it, so nothing in it can escalate.
ARG INSTALL_SUDO=0
RUN if [ "$INSTALL_SUDO" = "1" ]; then \
      apt-get install -y sudo && echo "samma ALL=NOPASSWD: /usr/bin/nikto" >> /etc/sudoers; \
    fi

USER samma

CMD python3 /code/scan.py
