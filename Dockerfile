from ubuntu


#Install nmap
RUN apt-get update && apt-get install nikto python3-pip -y
RUN pip3 install --upgrade pip
RUN pip3 install xmltodict amqplib
RUN nikto -update


COPY  ./code /code
RUN chmod +x /code/scan.py

CMD python3 /code/scan.py
