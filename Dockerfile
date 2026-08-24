FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Debian slim 基础镜像支持直接拉取 cryptography 预编译 wheel 包
RUN pip install --no-cache-dir cryptography

COPY warp_ddns.py .

CMD ["python", "warp_ddns.py"]
