FROM python:3.11-slim
RUN pip install --no-cache-dir dnslib
COPY dns_server.py /dns_server.py
CMD ["python","/dns_server.py"]
