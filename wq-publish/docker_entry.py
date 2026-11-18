"""容器入口：用 waitress 启动 WSGI 应用（单进程多线程）。

并发正确性依赖 SQLite 的 BEGIN IMMEDIATE 文件锁与同目录 os.replace，
因此容器内只跑单进程；线程内的写串行由数据库写锁保证。
"""
import os
import sys

# python -I 不会把脚本目录/工作目录加入 sys.path，容器内显式加入应用目录
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from waitress import serve

from wsgi import create_app

app = create_app()

if __name__ == "__main__":
    serve(
        app,
        host=os.environ.get("WQ_HOST", "0.0.0.0"),
        port=int(os.environ.get("WQ_PORT", "5000")),
        threads=8,
    )
