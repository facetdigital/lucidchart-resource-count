FROM python:3.8.3
RUN pip3 install botocore==1.13.0
WORKDIR /aws
COPY aws_cli_script.py /aws/.
ENTRYPOINT ["python", "aws_cli_script.py"]
