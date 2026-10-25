# Ubuntu 24.04 LTS, pinned by digest so a rebuild gets the same base.
# Bump the tag and digest together: docker buildx imagetools inspect ubuntu:24.04
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac


#Install nmap
RUN apt-get update && apt-get install sudo nikto python3-pip -y
RUN pip3 install nats-py --break-system-packages
RUN nikto -update





RUN mkdir /out
COPY  ./code /code

RUN useradd -ms /bin/bash samma
RUN chown samma:samma /out
RUN chown samma:samma /code/*.py
RUN chmod 664 /code/*.py

RUN echo "samma ALL=NOPASSWD: /bin/nikto" >> /etc/sudoers
USER samma


RUN chmod +x /code/scan.py

CMD python3 /code/scan.py
