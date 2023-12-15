FROM python:3.10

COPY ./requirements.txt /app/requirements.txt
WORKDIR /app

RUN pip install -r requirements.txt

COPY ./ /app

RUN python -m grpc_tools.protoc -I=proto --python_out=. --pyi_out=. --grpc_python_out=. proto/alert.proto


RUN python3 init_db.py
EXPOSE 80

ENV GRPC_HOST="172.17.0.3:50051"

CMD [ "python3", "app.py"]
