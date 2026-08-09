# ===== 阶段 1：构建 Vue 前端 =====
FROM node:20-slim AS frontend
WORKDIR /fe
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build
# 产物在 /fe/../web/dist → /web/dist

# ===== 阶段 2：Python 应用 + 全套安全工具（融合版增强） =====
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 系统工具 + 挖洞常用工具（原版）
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget git ca-certificates \
        nmap \
        python3-pip \
        jq dnsutils iputils-ping netcat-openbsd \
        whatweb \
    && rm -rf /var/lib/apt/lists/*

# === 融合版新增：MCP 扩展安全工具 ===
RUN apt-get update && apt-get install -y --no-install-recommends \
        nikto \
        gobuster \
        dirb \
        wordlists \
        hydra \
        john \
        masscan \
    && rm -rf /var/lib/apt/lists/*

# sqlmap（git 安装，复用官方）
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# ProjectDiscovery 工具：nuclei + httpx（从官方 release 拉二进制，避免装 Go）
# TARGETARCH 由 buildkit 自动注入(arm64/amd64)
ARG TARGETARCH
RUN set -eux; \
    NUCLEI_VER=3.3.7; HTTPX_VER=1.6.9; \
    cd /tmp; \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip" -O nuclei.zip; \
    wget -q "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip" -O httpx.zip; \
    apt-get update && apt-get install -y --no-install-recommends unzip; \
    unzip -o nuclei.zip nuclei -d /usr/local/bin/; \
    unzip -o httpx.zip httpx -d /usr/local/bin/; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx; \
    rm -f /tmp/*.zip; \
    apt-get purge -y unzip; rm -rf /var/lib/apt/lists/*

# === 融合版新增：Go 编写的安全工具（从 Release 拉预编译二进制，避免装 Go 编译器） ===
ARG TARGETARCH
RUN set -eux; \
    cd /tmp; \
    apt-get update && apt-get install -y --no-install-recommends unzip; \
    # subfinder
    SUBFINDER_VER=2.6.7; \
    wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VER}/subfinder_${SUBFINDER_VER}_linux_${TARGETARCH}.zip" -O subfinder.zip; \
    unzip -o subfinder.zip subfinder -d /usr/local/bin/; \
    # ffuf
    FFUF_VER=2.1.0; \
    wget -q "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_${TARGETARCH}.tar.gz" -O ffuf.tar.gz; \
    tar xzf ffuf.tar.gz ffuf -C /usr/local/bin/; \
    # wafw00f - Python 安装更轻量
    pip install --no-cache-dir wafw00f; \
    # dalfox
    DALFOX_VER=2.9.2; \
    wget -q "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VER}/dalfox_${DALFOX_VER}_linux_${TARGETARCH}.tar.gz" -O dalfox.tar.gz; \
    tar xzf dalfox.tar.gz dalfox -C /usr/local/bin/; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/ffuf /usr/local/bin/dalfox; \
    rm -f /tmp/*.zip /tmp/*.tar.gz; \
    apt-get purge -y unzip; rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 更新 nuclei 模板（失败不阻断构建）
RUN nuclei -update-templates -silent || true

COPY . .

# 拷入前端构建产物（覆盖空的 web/dist）
COPY --from=frontend /web/dist /app/web/dist

# 工作区 + 数据目录 + 知识库目录（数据目录建议挂卷持久化）
RUN mkdir -p /work /app/data /app/data/chroma
ENV WORKER_WORK_ROOT=/work \
    DB_PATH=/app/data/autohunter.db \
    KNOWLEDGE_DB_PATH=/app/data/chroma \
    MCP_TOOL_DIR=/app/tools/mcp

EXPOSE 18800

CMD ["sh", "/app/scripts/run-with-watchdog.sh"]
