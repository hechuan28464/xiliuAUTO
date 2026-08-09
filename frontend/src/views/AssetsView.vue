<script setup>
import { ref, onMounted } from "vue";

const loading = ref(true);
const refreshing = ref(false);
const rows = ref([]);
const stats = ref({ total: 0, high_risk: 0, linked_vulns: 0 });
const riskFilter = ref("");
const statusFilter = ref("");

const RISK_META = {
  critical: { label: "严重", hue: "danger" },
  high: { label: "高危", hue: "danger" },
  medium: { label: "中危", hue: "warn" },
  low: { label: "低危", hue: "info" },
};

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

async function loadStats() {
  try {
    const res = await apiFetch("/api/assets/stats");
    if (res) stats.value = { ...stats.value, ...res };
  } catch { /* keep */ }
}

async function loadList() {
  if (!rows.value.length) loading.value = true;
  else refreshing.value = true;
  try {
    const params = new URLSearchParams();
    if (riskFilter.value) params.set("risk_level", riskFilter.value);
    if (statusFilter.value) params.set("status", statusFilter.value);
    const qs = params.toString();
    const res = await apiFetch(`/api/assets${qs ? "?" + qs : ""}`);
    rows.value = Array.isArray(res) ? res : (res?.items || []);
  } catch (e) {
    alert(`加载资产失败：${e?.message || e}`);
  } finally {
    loading.value = false;
    refreshing.value = false;
  }
}

async function reload() {
  await Promise.all([loadStats(), loadList()]);
}

function riskMeta(r) {
  return RISK_META[(r || "").toLowerCase()] || { label: r || "-", hue: "ok" };
}

function techText(stack) {
  if (Array.isArray(stack)) return stack.join(", ");
  return stack || "-";
}

onMounted(reload);
</script>

<template>
  <section class="view assets-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !loading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="page-head split">
      <div>
        <h2>资产管理 <span class="intel-chip">ASSET</span></h2>
        <p class="page-sub">统一管理扫描发现的资产——域名、IP、端口、服务与技术栈，关联漏洞风险。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div class="intel-dash">
      <div class="dash-card hero">
        <span class="dash-k">资产总数</span>
        <b class="dash-v">{{ stats.total }}</b>
        <span class="dash-sub">全部已纳管资产</span>
      </div>
      <div class="dash-card danger">
        <span class="dash-icon">!</span>
        <b class="dash-v">{{ stats.high_risk }}</b>
        <span class="dash-k">高风险</span>
      </div>
      <div class="dash-card warn">
        <span class="dash-icon">⚑</span>
        <b class="dash-v">{{ stats.linked_vulns }}</b>
        <span class="dash-k">关联漏洞</span>
      </div>
    </div>

    <div class="intel-toolbar">
      <select v-model="riskFilter" @change="loadList">
        <option value="">全部风险</option>
        <option value="critical">严重</option>
        <option value="high">高危</option>
        <option value="medium">中危</option>
        <option value="low">低危</option>
      </select>
      <select v-model="statusFilter" @change="loadList">
        <option value="">全部状态</option>
        <option value="active">活跃</option>
        <option value="inactive">不活跃</option>
        <option value="archived">已归档</option>
      </select>
      <button class="btn-ghost" @click="reload" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
    </div>

    <div v-if="loading" class="intel-grid">
      <div v-for="n in 6" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      暂无资产
      <span class="hint">扫描任务发现的资产会自动汇总到这里</span>
    </div>
    <div v-else class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Host</th>
            <th>URL</th>
            <th>IP</th>
            <th>端口</th>
            <th>服务</th>
            <th>标题</th>
            <th>技术栈</th>
            <th>归属</th>
            <th>风险</th>
            <th>状态</th>
            <th>关联漏洞</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.id || row.host">
            <td>{{ row.host || "-" }}</td>
            <td class="mono">{{ row.url || "-" }}</td>
            <td class="mono">{{ row.ip || "-" }}</td>
            <td>{{ row.port || "-" }}</td>
            <td>{{ row.service || "-" }}</td>
            <td>{{ row.title || "-" }}</td>
            <td>{{ techText(row.tech_stack) }}</td>
            <td>{{ row.org || "-" }}</td>
            <td><span class="sev-badge" :class="riskMeta(row.risk_level).hue">{{ riskMeta(row.risk_level).label }}</span></td>
            <td>{{ row.status || "-" }}</td>
            <td>{{ row.linked_vulns || 0 }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border-soft);
  border-radius: 10px;
  background: var(--surface);
}
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.data-table th {
  text-align: left;
  padding: 10px 12px;
  border-bottom: 2px solid var(--border);
  color: var(--muted);
  font-weight: 600;
  white-space: nowrap;
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: .04em;
}
.data-table td {
  padding: 9px 12px;
  border-bottom: 1px solid var(--border-soft);
  vertical-align: top;
}
.data-table tr:hover td {
  background: var(--surface-2);
}
.mono {
  font-family: "IBM Plex Mono", monospace;
  font-size: 12px;
}
.sev-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
}
.sev-badge.danger { background: var(--danger-bg); color: var(--danger); }
.sev-badge.warn { background: color-mix(in oklch, var(--warn) 15%, transparent); color: var(--warn); }
.sev-badge.info { background: var(--accent-bg); color: var(--accent-ink); }
.sev-badge.ok { background: color-mix(in oklch, var(--ok) 15%, transparent); color: var(--ok); }
</style>
