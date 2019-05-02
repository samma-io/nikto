from ubuntu


#Install nmap
RUN apt-get update && apt-get install nikto python3-pip -y
RUN pip3 install --upgrade pip
RUN pip3 install xmltodict amqplib


COPY  ./code /code


CMD nikto
