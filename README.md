# 🔒 安全用户管理系统 (Secure User Management System)

基于 Flask 的安全用户管理平台，修复了 15 项安全漏洞。

## 🚀 快速启动

```bash
pip install -r requirements.txt
python app.py
# 访问 http://192.168.13.128:5000
```

## 📁 项目结构

```
secured/
├── app.py                 # 安全版主程序
├── requirements.txt       # 依赖
├── VULNERABILITY_REPORT.md  # 漏洞分析报告
├── templates/             # 模板
└── static/css/            # 样式
```

## 🔒 防护的攻击

- 暴力破解 / 字典攻击
- CSRF 跨站请求伪造
- XSS 跨站脚本攻击
- Session 劫持 / 伪造
- 时序攻击
- 用户名枚举
- 信息泄露
- Session 固定攻击
