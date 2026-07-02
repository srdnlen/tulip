FROM python:3.10

WORKDIR /app

COPY flagids/ /app/

COPY flagids/requirements.txt /app/

RUN pip install -r ./requirements.txt

COPY flagids/flagids.py /app/
COPY api/configurations.py /app/

STOPSIGNAL SIGINT

CMD ["python3", "./flagids.py"]
