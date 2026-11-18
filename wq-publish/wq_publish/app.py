"""Flask 路由：上传校验 → 预览增删改 → 确认整批替换。"""
from __future__ import annotations

import os
import secrets
import sqlite3

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    url_for,
)

from .storage import (
    LIVE_FILENAME,
    ExportError,
    PartnerError,
    PublishConflictError,
    Storage,
)
from .validation import format_concentration, validate_csv

MAX_UPLOAD_BYTES = 16 * 1024 * 1024


def create_app(data_dir: str | None = None, downstream_dir: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    base = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    data_dir = data_dir or os.environ.get("WQ_DATA_DIR") or os.path.join(base, "data")
    downstream_dir = (
        downstream_dir
        or os.environ.get("WQ_DOWNSTREAM_DIR")
        or os.path.join(base, "downstream")
    )

    secret_path = os.path.join(data_dir, "flask_secret")
    os.makedirs(data_dir, exist_ok=True)
    if os.path.exists(secret_path):
        with open(secret_path, "rb") as fh:
            app.secret_key = fh.read()
    else:
        key = secrets.token_bytes(32)
        with open(secret_path, "wb") as fh:
            fh.write(key)
        os.chmod(secret_path, 0o600)
        app.secret_key = key

    storage = Storage(data_dir, downstream_dir)
    app.storage = storage  # 供自测脚本直接访问

    @app.template_filter("conc")
    def _conc(value):
        return format_concentration(value)

    @app.get("/")
    def index():
        reg = storage.current_registry()
        rows = storage.current_rows()
        events = storage.recent_events()
        return render_template(
            "index.html", reg=reg, rows=rows, events=events,
            live_filename=LIVE_FILENAME,
        )

    @app.post("/preview")
    def preview():
        upload = request.files.get("csv_file")
        batch_no = request.form.get("batch_no", "")
        if upload is None or not upload.filename:
            flash("请选择仪器导出的 CSV 文件", "error")
            return redirect(url_for("index"))
        raw = upload.read()
        if len(raw) > MAX_UPLOAD_BYTES:
            flash("CSV 文件超过 16MB 上限", "error")
            return redirect(url_for("index"))

        rows, errors = validate_csv(raw, batch_no)
        if errors:
            for msg in errors:
                flash(msg, "error")
            return redirect(url_for("index"))

        reg = storage.current_registry()
        base_version = reg["current_version"] if reg else 0
        token = storage.create_session(batch_no.strip(), base_version, rows)
        diff = storage.preview_diff(rows)
        storage.log(
            "preview",
            f"会话 {token[:8]} 基于 v{base_version} 预览批次 {batch_no.strip()}："
            f"新增 {len(diff['inserts'])} / 修改 {len(diff['updates'])} / "
            f"撤回 {len(diff['deletes'])} / 不变 {len(diff['unchanged'])}",
        )
        return render_template(
            "preview.html",
            token=token,
            batch_no=batch_no.strip(),
            base_version=base_version,
            current_version=base_version,
            rows=rows,
            diff=diff,
            live_filename=LIVE_FILENAME,
        )

    @app.post("/publish/<token>")
    def publish(token):
        session = storage.get_session(token)
        if session is None:
            flash("修订会话不存在或已过期，请重新上传 CSV", "error")
            return redirect(url_for("index"))

        reg = storage.current_registry()
        current_version = reg["current_version"] if reg else 0
        if session["status"] != "pending" or session["base_version"] != current_version:
            # 会话在预览期间被别的发布超越：作废会话，展示基于旧版的差异，要求重新预览
            if session["status"] == "pending":
                storage.mark_obsolete(token, current_version)
                stale_reason = (
                    f"您基于 v{session['base_version']} 发起修订，"
                    f"但当前版本已变为 v{current_version}（另一页面已成功发布）"
                )
            else:
                reason_map = {
                    "published": "该修订已经发布，不能重复发布",
                    "obsolete": "该预览已被更新的发布超越而作废",
                    "cancelled": "该修订已被放弃（取消）",
                }
                stale_reason = reason_map.get(session["status"], "该修订会话已失效")
            diff = storage.preview_diff(session["rows"])
            storage.log(
                "conflict",
                f"会话 {token[:8]} 发布被拒（基线 v{session['base_version']}，"
                f"当前 v{current_version}，状态 {session['status']}）",
            )
            return render_template(
                "preview.html",
                token=token,
                batch_no=session["batch_no"],
                base_version=session["base_version"],
                current_version=current_version,
                rows=session["rows"],
                diff=diff,
                stale=True,
                stale_reason=stale_reason,
                live_filename=LIVE_FILENAME,
            ), 409

        try:
            new_version, row_count = storage.publish(token)
        except PublishConflictError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))
        except sqlite3.OperationalError as exc:  # 极端并发下写锁等待超时
            app.logger.warning("publish lock contention: %s", exc)
            flash("当前有其他发布正在写入，请稍后重新预览再发布", "error")
            return redirect(url_for("index"))
        flash(f"发布成功：v{new_version} 已生效，共 {row_count} 行", "success")
        return redirect(url_for("index"))

    @app.post("/cancel/<token>")
    def cancel(token):
        if storage.cancel_session(token):
            flash("已放弃本次修订，当前发布版本未受影响", "info")
        return redirect(url_for("index"))

    @app.get("/published.csv")
    def published_csv():
        if not os.path.exists(storage.live_path):
            abort(404, description="尚无已发布的 CSV")
        return send_file(
            storage.live_path, mimetype="text/csv",
            download_name=LIVE_FILENAME, as_attachment=False,
        )

    # ---------- 浏览器盲化供数 ----------
    @app.get("/partners")
    def partners_page():
        partners = storage.list_partners()
        return render_template("partners.html", partners=partners)

    @app.post("/partners")
    def partners_create():
        name = request.form.get("name", "")
        try:
            partner = storage.create_partner(name)
        except PartnerError as exc:
            flash(str(exc), "error")
            return redirect(url_for("partners_page"))
        flash(f"合作方“{partner['name']}”已建立，盲化域独立且主密钥已持久化", "success")
        return redirect(url_for("partner_detail", partner_id=partner["id"]))

    @app.post("/partners/<int:partner_id>/revoke")
    def partners_revoke(partner_id):
        try:
            changed = storage.revoke_partner(partner_id)
        except PartnerError as exc:
            flash(str(exc), "error")
            return redirect(url_for("partners_page"))
        if changed:
            flash("合作方已撤销：旧下载地址不再受理新请求，进行中的下载可正常结束", "info")
        else:
            flash("该合作方此前已撤销", "info")
        return redirect(url_for("partner_detail", partner_id=partner_id))

    @app.get("/partners/<int:partner_id>")
    def partner_detail(partner_id):
        partner = storage.get_partner(partner_id)
        if partner is None:
            abort(404, description="合作方不存在")
        exports = storage.list_exports(partner_id)
        versions = storage.published_versions()
        return render_template(
            "partner_detail.html",
            partner=partner, exports=exports, versions=versions,
        )

    @app.post("/partners/<int:partner_id>/exports")
    def exports_create(partner_id):
        partner = storage.get_partner(partner_id)
        if partner is None:
            abort(404, description="合作方不存在")
        try:
            version = int(request.form.get("version", ""))
        except (TypeError, ValueError):
            flash("请选择一个已发布版本", "error")
            return redirect(url_for("partner_detail", partner_id=partner_id))
        try:
            record = storage.create_blind_export(partner_id, version)
        except (PartnerError, ExportError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("partner_detail", partner_id=partner_id))
        flash(
            f"v{record['version']} 盲化导出已生成（仅含盲码、检测项目、浓度），"
            "可通过下方固定地址下载",
            "success",
        )
        return redirect(url_for("partner_detail", partner_id=partner_id))

    @app.get("/blind/<token>")
    def blind_download(token):
        record = storage.get_ready_export(token)
        if record is None:
            # 合作方撤销 / 导出不存在或未就绪：旧地址一律不再取数
            abort(410, description="该下载地址已失效或合作方已撤销")
        path = storage.export_path(record["file_name"])
        if not os.path.exists(path):
            # 文件被外部移走：交给启动恢复重建，此刻不提供半份数据
            abort(410, description="导出文件暂不可用，请联系管理员")
        download_name = (
            f"blind_partner{record['partner_id']}_v{record['version']}.csv"
        )
        # send_file 打开文件后即持有独立句柄；撤销合作方只改数据库状态，
        # 不会删除文件，因此已经开始（已受理）的下载可以完整结束
        return send_file(
            path, mimetype="text/csv",
            download_name=download_name, as_attachment=True,
        )

    @app.errorhandler(413)
    def too_large(_):
        flash("上传文件超过 16MB 上限", "error")
        return redirect(url_for("index"))

    @app.errorhandler(410)
    def gone(exc):
        return (
            render_template_string(
                "<!doctype html><html lang='zh-CN'><meta charset='utf-8'>"
                "<title>下载地址已失效</title>"
                "<body style='font-family:sans-serif;padding:40px;line-height:1.7'>"
                "<h2>410 · 下载地址已失效</h2>"
                "<p>{{ desc }}</p>"
                "<p>合作方撤销后旧地址立即停止受理；如仍需数据，请联系实验室重新建立合作。</p>"
                "<p><a href='/'>返回首页</a></p></body>",
                desc=getattr(exc, "description", "该资源已不可用"),
            ),
            410,
        )

    return app
