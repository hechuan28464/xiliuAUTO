#!/bin/bash
# ============================================================================
#  xiliuAUTO 融合版一键部署脚本
#  AutoHunter × CyberStrikeAI 深度融合
#  适配 2C4G Linux 服务器
# ============================================================================
set -e

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          xiliuAUTO 融合版部署                            ║"
echo "║   AutoHunter × CyberStrikeAI Deep Fusion                 ║"
echo "║   MCP工具生态 + RAG知识库 + RBAC + HITL + 通知            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# 1. 检查 Docker
echo "[1/6] 检查 Docker 环境..."
if ! command -v docker &>/dev/null; then
    echo "  Docker 未安装，正在安装..."
    curl -fsSL https://get.docker.com | sh
    sudo systemctl enable --now docker
    sudo usermod -aG docker $USER && newgrp docker
fi
echo "  ✓ Docker 已就绪"

# 2. 检查 Docker Compose
echo "[2/6] 检查 Docker Compose..."
if docker compose version &>/dev/null; then
    echo "  ✓ Docker Compose v2 已就绪"
else
    echo "  ✗ Docker Compose v2 不可用，请先安装"
    exit 1
fi

# 3. 配置文件
echo "[3/6] 生成配置文件..."
if [ ! -f .env ]; then
    cp .env.example .env
fi

# 交互式引导
read -p "  请输入 LLM API Key (必填，DeepSeek/OpenAI/Claude 等): " LLM_KEY
if [ -n "$LLM_KEY" ]; then
    sed -i "s|LLM_API_KEY=.*|LLM_API_KEY=${LLM_KEY}|" .env
fi

read -p "  请输入 LLM Base URL (默认 DeepSeek，回车跳过): " LLM_URL
if [ -n "$LLM_URL" ]; then
    sed -i "s|LLM_BASE_URL=.*|LLM_BASE_URL=${LLM_URL}|" .env
fi

read -p "  请输入 LLM 模型名 (默认 deepseek-chat，回车跳过): " LLM_MODEL
if [ -n "$LLM_MODEL" ]; then
    sed -i "s|LLM_MODEL=.*|LLM_MODEL=${LLM_MODEL}|" .env
fi

read -p "  请输入 FOFA Key (可选，回车跳过): " FOFA_KEY
if [ -n "$FOFA_KEY" ]; then
    sed -i "s|FOFA_KEY=.*|FOFA_KEY=${FOFA_KEY}|" .env
fi

read -p "  请输入访问端口 (默认 18800): " PORT
PORT=${PORT:-18800}
sed -i "s|AUTOHUNTER_HOST_PORT=.*|AUTOHUNTER_HOST_PORT=${PORT}|" .env

# 生成管理员密码
ADMIN_PASS=$(openssl rand -base64 12 2>/dev/null || echo "admin$(date +%s)")
sed -i "s|XILIU_ADMIN_PASSWORD=.*|XILIU_ADMIN_PASSWORD=${ADMIN_PASS}|" .env

# 生成 API Token
TOKEN=$(openssl rand -hex 32 2>/dev/null || echo "token$(date +%s)")
sed -i "s|AUTOHUNTER_API_TOKEN=.*|AUTOHUNTER_API_TOKEN=${TOKEN}|" .env

echo "  ✓ 配置完成"

# 4. 开放防火墙
echo "[4/6] 检查防火墙..."
if command -v ufw &>/dev/null; then
    sudo ufw allow ${PORT}/tcp 2>/dev/null || true
    echo "  ✓ ufw 已放行 ${PORT}/tcp"
elif command -v firewall-cmd &>/dev/null; then
    sudo firewall-cmd --permanent --add-port=${PORT}/tcp 2>/dev/null || true
    sudo firewall-cmd --reload 2>/dev/null || true
    echo "  ✓ firewalld 已放行 ${PORT}/tcp"
else
    echo "  - 未检测到防火墙，请手动放行 ${PORT}/tcp"
fi

# 5. 构建并启动
echo "[5/6] 构建镜像并启动（首次约 5-15 分钟）..."
docker compose up -d --build
echo "  ✓ 构建完成"

# 6. 输出信息
echo "[6/6] 部署完成！"
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              部署信息                                    ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  访问地址: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):${PORT}/"
echo "║  管理员: admin"
echo "║  管理员密码: ${ADMIN_PASS}"
echo "║  API Token: ${TOKEN}"
echo "║                                                           ║"
echo "║  日志查看: docker compose logs -f                        ║"
echo "║  重启: docker compose restart                             ║"
echo "║  停止: docker compose down                                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "⚠  请妥善保存以上信息！首次登录后请立即修改管理员密码。"
echo ""
