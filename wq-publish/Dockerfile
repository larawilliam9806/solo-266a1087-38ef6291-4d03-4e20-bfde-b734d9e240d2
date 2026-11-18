FROM python:3.11-slim

# 仅在构建期禁用 pip 版本检查，运行期不依赖网络
ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    WQ_DATA_DIR=/data \
    WQ_DOWNSTREAM_DIR=/downstream

WORKDIR /app

# 先装依赖，利用层缓存
COPY requirements.txt ./
RUN pip install -r requirements.txt

# 再拷应用代码
COPY wq_publish ./wq_publish
COPY wsgi.py docker_entry.py ./

# 数据/下游目录由 compose 挂载为卷；非 root 运行
RUN mkdir -p /data /downstream \
    && useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /data /downstream /app
USER appuser

VOLUME ["/data", "/downstream"]
EXPOSE 5000

# Storage() 在应用构造时执行启动一致性恢复（含盲化导出核对）
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/partners', timeout=4).status==200 else 1)"

CMD ["python", "-I", "docker_entry.py"]
