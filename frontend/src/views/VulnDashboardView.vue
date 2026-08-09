<script setup>
import { ref, computed, onMounted } from "vue";
import { fmtLocalTime } from "../format.js";

const loading = ref(true);
const refreshing = ref(false);
const rows = ref([]);
const stats = ref({ total: 0, by_severity: {}, by_status: {} });

const SEV_META = {
  critical: { label: "严重", hue: "danger" },
  high: { label: "高危", hue: "danger" },
  medium: { label: "中危", hue: "warn" },
  low: { label: "低危", hue: "info" },
};

const LIFECYCLE_STAGES = [
  { id: "submitted", label: "已提交" },
  { id: "reviewed", label: "已审核" },
  { id: "accepted", label: "已确认" },
  { id: "reported", label: "已上报" },
  { id: "fixed", label: "已修复" },
  { id: "closed", label: "已关闭" },
];

const SEV_ORDER = ["critical", "high", "medium", "low"];

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
    const res = await apiFetch("/api/vulns/stats");
    if (res) stats.value = { ...stats.value, ...res };
  } catch { /* keep */ }
}

async function loadList() {
  if (!rows.value.length) loading.value = true;
  else refreshing.value = true;
  try {
    const res = await apiFetch("/api/vulns/lifecycle");
    rows.value = Array.isArray(res) ? res : (res?.items || []);
  } catch (e) {
    alert(`加载漏洞看板失败：${e?.message || e}`);
  } finally {
    loading.value = false;
    refreshing.value = false;
  }
}

async function reload() {
  await Promise.all([loadStats(), loadList()]);
}

const maxSevCount = computed(() => {
  const by = stats.value.by_severity || {};
  return Math.max(1, ...SEV_ORDER.map((s) => by[s] || 0));
});

function sevPct(s) {
  const by = stats.value.by_severity || {};
  return Math.round(((by[s] || 0) / maxSevCount.value) * 100);
}

function sevMeta(s) {
  return SEV_META[(s || "").toLowerCase()] || { label: s || "未定级", hue: "ok" };
}

function lcCount(id) {
  const by = stats.value.by_status || {};
  return by[id] || 0;
}

const fmtTime = fmtLocalTime;

onMounted(reload);
</script>

<template>
  <section class="view vuln-dashboard-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !loading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="page-head split">
      <div>
        <h2>漏洞看板 <span class="intel-chip">VULN</span></h2>
        <p class="page-sub">漏洞统计与生命周期流转——按严重程度分布、按状态阶段追踪修复进度。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div class="intel-dash">
      <div class="dash-card hero">
        <span class="dash-k">漏洞总数</span>
        <b class="dash-v">{{ stats.total }}</b>
        <span class="dash-sub">全生命周期汇总</span>
      </div>
      <div v-for="s in SEV_ORDER" :key="s" class="dash-card" :class="SEV_META[s].hue">
        <span class="dash-icon">{{ SEV_META[s].label[0] }}</span>
        <b class="dash-v">{{ stats.by_severity?.[s] || 0 }}</b>
        <span class="dash-k">{{ SEV_META[s].label }}</span>
      </div>
    </div>

    <div class="vd-charts">
      <div class="vd-chart-card">
        <h3>严重程度分布</h3>
        <div class="sev-bars">
          <div v-for="s in SEV_ORDER" :key="s" class="sev-bar">
            <span class="sev-label">{{ SEV_META[s].label }}</span>
            <div class="sev-bar-track">
              <div class="sev-bar-fill" :class="SEV_META[s].hue" :style="{ width: sevPct(s) + '%' }"></div>
            </div>
            <span class="sev-count">{{ stats.by_severity?.[s] || 0 }}</span>
          </div>
        </div>
      </div>

      <div class="vd-chart-card">
        <h3>生命周期流转</h3>
        <div class="lifecycle-flow">
          <template v-for="(stage, i) in LIFECYCLE_STAGES" :key="stage.id">
            <div class="lc-node" :class="{ on: lcCount(stage.id) > 0 }">
              <b class="lc-count">{{ lcCount(stage.id) }}</b>
              <span class="lc-label">{{ stage.label }}</span>
            </div>
            <span v-if="i < LIFECYCLE_STAGES.length - 1" class="lc-arrow">→</span>
          </template>
        </div>
      </div>
    </div>

    <div class="intel-toolbar">
      <span class="vd-list-title">漏洞列表</span>
      <button class="btn-ghost" @click="reload" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
    </div>

    <div v-if="loading" class="intel-grid">
      <div v-for="n in 6" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      暂无漏洞记录
      <span class="hint">漏洞生命周期数据会在此汇总</span>
    </div>
    <div v-else class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>标题</th>
            <th>目标 URL</th>
            <th>严重程度</th>
            <th>生命周期状态</th>
            <th>创建时间</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.id">
            <td>{{ row.title || "-" }}</td>
            <td class="mono">{{ row.target_url || "-" }}</td>
            <td><span class="sev-badge" :class="sevMeta(row.severity).hue">{{ sevMeta(row.severity).label }}</span></td>
            <td><span class="lc-status">{{ row.lifecycle_status || "-" }}</span></td>
            <td class="mono">{{ fmtTime(row.created_at) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.vd-charts {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 20px;
}
.vd-chart-card {
  border: 1px solid var(--border-soft);
  border-radius: 10px;
  background: var(--surface);
  padding: 18px;
}
.vd-chart-card h3 {
  margin: 0 0 16px;
  font-size: 14px;
  font-weight: 600;
  color: var(--ink);
}
.sev-bars {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.sev-bar {
  display: flex;
  align-items: center;
  gap: 10px;
}
.sev-label {
  width: 36px;
  font-size: 12.5px;
  color: var(--muted);
  flex-shrink: 0;
}
.sev-bar-track {
  flex: 1;
  height: 22px;
  background: var(--nav);
  border-radius: 6px;
  overflow: hidden;
}
.sev-bar-fill {
  height: 100%;
  border-radius: 6px;
  transition: width .4s ease;
  min-width: 4px;
}
.sev-bar-fill.danger { background: var(--danger); }
.sev-bar-fill.warn { background: var(--warn); }
.sev-bar-fill.info { background: var(--info); }
.sev-bar-fill.ok { background: var(--ok); }
.sev-count {
  width: 32px;
  text-align: right;
  font-size: 13px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  flex-shrink: 0;
}
.lifecycle-flow {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}
.lc-node {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 10px 14px;
  border: 1px solid var(--border-soft);
  border-radius: 8px;
  background: var(--surface-2);
  min-width: 70px;
}
.lc-node.on {
  border-color: var(--accent);
  background: var(--accent-bg);
}
.lc-count {
  font-size: 20px;
  font-weight: 800;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}
.lc-label {
  font-size: 11.5px;
  color: var(--muted);
  margin-top: 4px;
}
.lc-arrow {
  color: var(--faint);
  font-size: 14px;
}
.vd-list-title {
  font-weight: 600;
  color: var(--ink);
}
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
@media (max-width: 768px) {
  .vd-charts { grid-template-columns: 1fr; }
}
</style>
