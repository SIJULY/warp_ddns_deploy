FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Debian slim 基础镜像支持直接拉取 cryptography 的预编译 wheel 包 (涵盖 amd64/arm64)
# 彻底免去软路由环境编译 rust 和 gcc 的痛苦
RUN pip install --no-cache-dir cryptography

COPY warp_ddns.py .

CMD ["python", "warp_ddns.py"]
