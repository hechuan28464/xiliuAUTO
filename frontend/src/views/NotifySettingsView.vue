<script setup>
import { ref, onMounted } from "vue";

const loading = ref(true);
const saving = ref(false);
const testing = ref(false);

const config = ref({
  enabled: false,
  webhook_url: "",
  dingtalk_token: "",
  wecom_key: "",
  feishu_token: "",
  telegram_bot_token: "",
  telegram_chat_id: "",
});

const CHANNELS = [
  { key: "webhook_url", label: "Webhook URL", placeholder: "https://hooks.example.com/..." },
  { key: "dingtalk_token", label: "钉钉 Token", placeholder: "dingtalk access_token" },
  { key: "wecom_key", label: "企微 Key", placeholder: "wecom bot key" },
  { key: "feishu_token", label: "飞书 Token", placeholder: "feishu bot token" },
  { key: "telegram_bot_token", label: "Telegram Bot Token", placeholder: "123456:ABC-DEF..." },
  { key: "telegram_chat_id", label: "Telegram Chat ID", placeholder: "chat id" },
];

function authHeaders(extra = {}) {
  const token = localStorage.getItem("ah-api-token") || "";
  return { Authorization: `Bearer ${token}`, ...extra };
}

async function apiFetch(url, opts = {}) {
  const headers = authHeaders(opts.headers);
  const res = await fetch(url, { ...opts, headers });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${text}`);
  }
  if (res.status === 204) return null;
  const text = await res.text();
  if (!text) return null;
  try { return JSON.parse(text); }
  catch { return text; }
}

async function loadConfig() {
  loading.value = true;
  try {
    const res = await apiFetch("/api/notify/config");
    if (res) config.value = { ...config.value, ...res };
  } catch (e) {
    alert(`加载通知配置失败：${e?.message || e}`);
  } finally {
    loading.value = false;
  }
}

async function saveConfig() {
  saving.value = true;
  try {
    await apiFetch("/api/notify/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config.value),
    });
    alert("配置已保存");
  } catch (e) {
    alert(`保存配置失败：${e?.message || e}`);
  } finally {
    saving.value = false;
  }
}

async function testNotify() {
  testing.value = true;
  try {
    const res = await apiFetch("/api/notify/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    alert(res?.message || "测试消息已发送，请检查各渠道");
  } catch (e) {
    alert(`测试发送失败：${e?.message || e}`);
  } finally {
    testing.value = false;
  }
}

onMounted(loadConfig);
</script>

<template>
  <section class="view notify-settings-view">
    <header class="page-head split">
      <div>
        <h2>通知配置 <span class="intel-chip">NOTIFY</span></h2>
        <p class="page-sub">配置漏洞告警与任务事件的多渠道通知——Webhook、钉钉、企微、飞书、Telegram。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div v-if="loading" class="intel-grid">
      <div v-for="n in 4" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else class="notify-body">
      <div class="toggle-card">
        <label class="toggle-row">
          <span class="toggle-info">
            <b>通知总开关</b>
            <small>关闭后所有渠道都不会发送通知</small>
          </span>
          <label class="switch">
            <input type="checkbox" v-model="config.enabled" />
            <span class="slider"></span>
          </label>
        </label>
      </div>

      <div class="channels-card">
        <h3>渠道配置</h3>
        <div class="channel-grid">
          <div v-for="ch in CHANNELS" :key="ch.key" class="channel-field">
            <label>{{ ch.label }}</label>
            <input v-model="config[ch.key]" :placeholder="ch.placeholder" :type="ch.key.includes('token') || ch.key.includes('key') ? 'password' : 'text'" />
          </div>
        </div>
      </div>

      <div class="notify-actions">
        <button class="primary" @click="saveConfig" :disabled="saving">{{ saving ? "保存中…" : "保存配置" }}</button>
        <button class="btn-ghost" @click="testNotify" :disabled="testing">{{ testing ? "发送中…" : "测试发送" }}</button>
      </div>
    </div>
  </section>
</template>

<style scoped>
.notify-body {
  display: flex;
  flex-direction: column;
  gap: 20px;
}
.toggle-card,
.channels-card {
  border: 1px solid var(--border-soft);
  border-radius: 10px;
  background: var(--surface);
  padding: 18px;
}
.toggle-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.toggle-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.toggle-info b {
  font-size: 14px;
  font-weight: 600;
  color: var(--ink);
}
.toggle-info small {
  font-size: 12.5px;
  color: var(--muted);
}
.switch {
  position: relative;
  display: inline-block;
  width: 46px;
  height: 26px;
  flex-shrink: 0;
}
.switch input {
  opacity: 0;
  width: 0;
  height: 0;
}
.slider {
  position: absolute;
  cursor: pointer;
  inset: 0;
  background: var(--border);
  border-radius: 26px;
  transition: .25s;
}
.slider::before {
  content: "";
  position: absolute;
  height: 20px;
  width: 20px;
  left: 3px;
  bottom: 3px;
  background: var(--surface);
  border-radius: 50%;
  transition: .25s;
  box-shadow: var(--shadow);
}
.switch input:checked + .slider {
  background: var(--accent);
}
.switch input:checked + .slider::before {
  transform: translateX(20px);
}
.channels-card h3 {
  margin: 0 0 16px;
  font-size: 14px;
  font-weight: 600;
  color: var(--ink);
}
.channel-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
}
.channel-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.channel-field label {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--muted);
}
.notify-actions {
  display: flex;
  gap: 12px;
}
@media (max-width: 768px) {
  .channel-grid { grid-template-columns: 1fr; }
}
</style>
