<script setup>
import { ref, onMounted } from "vue";
import { fmtLocalTime } from "../format.js";

const loading = ref(true);
const refreshing = ref(false);
const rows = ref([]);
const actionFilter = ref("");
const usernameFilter = ref("");
const total = ref(0);
const page = ref(0);
const pageSize = 100;
const hasMore = ref(false);

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

async function loadList() {
  if (!rows.value.length) loading.value = true;
  else refreshing.value = true;
  try {
    const params = new URLSearchParams();
    params.set("limit", String(pageSize));
    params.set("offset", String(page.value * pageSize));
    if (actionFilter.value) params.set("action", actionFilter.value);
    if (usernameFilter.value) params.set("username", usernameFilter.value);
    const res = await apiFetch(`/api/audit?${params.toString()}`);
    rows.value = Array.isArray(res) ? res : (res?.items || []);
    total.value = Array.isArray(res) ? rows.value.length : (res?.total || 0);
    hasMore.value = !Array.isArray(res) && !!res?.has_more;
  } catch (e) {
    alert(`加载审计日志失败：${e?.message || e}`);
  } finally {
    loading.value = false;
    refreshing.value = false;
  }
}

async function reload() {
  page.value = 0;
  await loadList();
}

function nextPage() {
  if (!hasMore.value || refreshing.value) return;
  page.value += 1;
  loadList();
}

function prevPage() {
  if (page.value <= 0 || refreshing.value) return;
  page.value -= 1;
  loadList();
}

const fmtTime = fmtLocalTime;

onMounted(reload);
</script>

<template>
  <section class="view audit-log-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !loading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="page-head split">
      <div>
        <h2>审计日志 <span class="intel-chip">AUDIT</span></h2>
        <p class="page-sub">记录系统中的所有用户操作——登录、任务变更、漏洞处置等关键行为留痕。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div class="intel-toolbar">
      <input v-model="actionFilter" placeholder="按 action 筛选" @keyup.enter="reload" />
      <input v-model="usernameFilter" placeholder="按用户名筛选" @keyup.enter="reload" />
      <button class="btn-ghost" @click="reload" :disabled="refreshing">{{ refreshing ? "刷新中…" : "筛选" }}</button>
    </div>

    <div v-if="loading" class="intel-grid">
      <div v-for="n in 6" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      暂无审计日志
      <span class="hint">系统操作记录会自动汇总到这里</span>
    </div>
    <div v-else class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>时间</th>
            <th>用户</th>
            <th>动作</th>
            <th>资源</th>
            <th>详情</th>
            <th>IP 地址</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, i) in rows" :key="row.id || i">
            <td class="mono">{{ fmtTime(row.created_at) }}</td>
            <td>{{ row.username || "-" }}</td>
            <td><span class="action-badge">{{ row.action || "-" }}</span></td>
            <td>{{ row.resource || "-" }}</td>
            <td class="detail-cell">{{ row.detail || "-" }}</td>
            <td class="mono">{{ row.ip_address || "-" }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="!loading && total > pageSize" class="hard-pager">
      <button type="button" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
      <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }} / {{ total }}</span>
      <button type="button" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
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
  white-space: nowrap;
}
.detail-cell {
  max-width: 320px;
  word-break: break-word;
}
.action-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  background: var(--accent-bg);
  color: var(--accent-ink);
  font-family: "IBM Plex Mono", monospace;
}
</style>
