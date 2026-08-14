import { computed, createApp, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import {
  Activity,
  AlertCircle,
  ArrowUpRight,
  Check,
  CircleHelp,
  Database,
  Globe2,
  Layers3,
  Link2,
  LoaderCircle,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Route,
  Server,
  Trash2,
  X,
} from 'lucide-vue-next'
import './style.css'

const apiRoot = '/api/v1'

const unwrap = (value) => value && typeof value === 'object' && 'body' in value ? value.body : value

async function api(path, options = {}) {
  const response = await fetch(`${apiRoot}${path}`, {
    headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
    ...options,
  })
  if (response.status === 204) return null
  const payload = await response.json().catch(() => null)
  if (!response.ok) {
    throw new Error(payload?.detail || payload?.title || `请求失败 (${response.status})`)
  }
  return unwrap(payload)
}

function hexMark(value) {
  const mark = Number(value)
  return Number.isFinite(mark) ? `0x${(mark >>> 0).toString(16).padStart(4, '0')}` : '-'
}

function egressDesc(egress) {
  if (!egress) return '-'
  if (egress.type === 'tproxy') {
    const port = Number(egress.tproxy?.port) || 0
    return `${egress.tproxy?.addr || '0.0.0.0'}:${port}`
  }
  return hexMark(egress.fwmark)
}

function emptyEgress() {
  return { name: '', type: 'manual', fwmark: '', tunnel: { url: '', token: '' }, tproxy: { addr: '0.0.0.0', port: '' } }
}

function emptyDomain() {
  return { match: 'domain', domain: '', egress: '' }
}

function emptyCidr() {
  return { cidr: '', egress: '' }
}

function emptyHost() {
  return { name: '', ip: '' }
}

const viewIds = new Set(['overview', 'egresses', 'domains', 'cidrs', 'hosts', 'routes', 'dns-cache'])

function viewFromHash(hash = window.location.hash) {
  const view = hash.replace(/^#\/?/, '').split(/[/?]/, 1)[0]
  return viewIds.has(view) ? view : 'overview'
}

function hashForView(view) {
  return `#/${view}`
}

const App = {
  components: {
    Activity,
    AlertCircle,
    ArrowUpRight,
    Check,
    CircleHelp,
    Database,
    Globe2,
    Layers3,
    Link2,
    LoaderCircle,
    Network,
    Pencil,
    Plus,
    RefreshCw,
    Route,
    Server,
    Trash2,
    X,
  },
  setup() {
    const currentView = ref(viewFromHash())
    const loading = ref(true)
    const saving = ref(false)
    const error = ref('')
    const notice = ref('')
    const lastUpdated = ref(null)
    const modal = ref('')
    const editing = ref(null)
    const egressForm = reactive(emptyEgress())
    const domainForm = reactive(emptyDomain())
    const cidrForm = reactive(emptyCidr())
    const hostForm = reactive(emptyHost())
    const data = reactive({ egresses: [], domains: [], cidrs: [], hosts: [], routes: [], dnsCache: [] })

    const navItems = [
      { id: 'overview', label: '总览', icon: 'Activity' },
      { id: 'egresses', label: '出口', icon: 'Network' },
      { id: 'domains', label: '域名规则', icon: 'Globe2' },
      { id: 'cidrs', label: 'IP 规则', icon: 'Network' },
      { id: 'hosts', label: '静态 Hosts', icon: 'Server' },
      { id: 'routes', label: '生效路由', icon: 'Route' },
      { id: 'dns-cache', label: 'DNS 缓存', icon: 'Database' },
    ]

    const stats = computed(() => [
      { label: '出口配置', value: data.egresses.length, icon: Network, tone: 'teal' },
      { label: '域名规则', value: data.domains.length, icon: Globe2, tone: 'lime' },
      { label: 'IP 规则', value: data.cidrs.length, icon: Network, tone: 'indigo' },
      { label: '静态 Hosts', value: data.hosts.length, icon: Server, tone: 'amber' },
      { label: 'IPv4 路由', value: data.routes.length, icon: Route, tone: 'rose' },
    ])

    const egressByName = computed(() => new Map(data.egresses.map((item) => [item.name, item])))
    const egressByIndex = computed(() => new Map(data.egresses.map((item) => [Number(item.index), item])))
    const selectedDomainEgress = computed(() => egressByName.value.get(domainForm.egress))
    const selectedCidrEgress = computed(() => egressByName.value.get(cidrForm.egress))
    const modalTitle = computed(() => ({
      egress: editing.value ? '编辑出口' : '新建出口',
      domain: editing.value ? '编辑域名规则' : '新建域名规则',
      cidr: editing.value ? '编辑 IP 规则' : '新建 IP 规则',
      host: editing.value ? '编辑静态 Hosts' : '新建静态 Hosts',
    })[modal.value] || '')

    function clearMessage() {
      error.value = ''
      notice.value = ''
    }

    function syncViewFromHash() {
      const view = viewFromHash()
      currentView.value = view

      const expectedHash = hashForView(view)
      if (window.location.hash !== expectedHash) {
        window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${expectedHash}`)
      }
    }

    function navigate(view) {
      if (!viewIds.has(view)) return

      currentView.value = view
      const nextHash = hashForView(view)
      if (window.location.hash !== nextHash) window.location.hash = nextHash
    }

    async function refresh() {
      clearMessage()
      loading.value = true
      try {
        const [egresses, domains, cidrs, hosts, routes, dnsCache] = await Promise.all([
          api('/egresses'), api('/domains'), api('/cidrs'), api('/hosts'), api('/routes'), api('/dns/cache'),
        ])
        data.egresses = Array.isArray(egresses) ? egresses : []
        data.domains = Array.isArray(domains) ? domains : []
        data.cidrs = Array.isArray(cidrs) ? cidrs : []
        data.hosts = Array.isArray(hosts) ? hosts : []
        data.routes = Array.isArray(routes) ? routes : []
        data.dnsCache = Array.isArray(dnsCache) ? dnsCache : []
        lastUpdated.value = new Date()
      } catch (cause) {
        error.value = cause.message
      } finally {
        loading.value = false
      }
    }

    function resetForm(target, source) {
      Object.assign(target, source)
    }

    function openEgress(item) {
      editing.value = item || null
      resetForm(egressForm, item ? {
        name: item.name,
        type: item.type || 'manual',
        fwmark: item.type === 'tproxy' ? '' : item.fwmark,
        tunnel: { url: item.tunnel?.url || '', token: item.tunnel?.token || '' },
        tproxy: { addr: item.tproxy?.addr || '0.0.0.0', port: item.tproxy?.port || '' },
      } : emptyEgress())
      modal.value = 'egress'
    }

    function openDomain(item) {
      editing.value = item || null
      resetForm(domainForm, item ? {
        match: item.match || 'domain', domain: item.domain, egress: item.egress,
      } : emptyDomain())
      modal.value = 'domain'
    }

    function openCidr(item) {
      editing.value = item || null
      resetForm(cidrForm, item ? {
        cidr: item.cidr, egress: item.egress,
      } : emptyCidr())
      modal.value = 'cidr'
    }

    function openHost(item) {
      editing.value = item || null
      resetForm(hostForm, item ? { name: item.name, ip: item.ip } : emptyHost())
      modal.value = 'host'
    }

    function closeModal() {
      modal.value = ''
      editing.value = null
    }

    async function saveEgress() {
      const name = egressForm.name.trim()
      if (!name) {
        error.value = '请填写出口名称。'
        return
      }
      if (egressForm.type !== 'tproxy' && (egressForm.fwmark === '' || Number(egressForm.fwmark) < 0)) {
        error.value = '请填写有效的 fwmark。'
        return
      }
      const originalName = editing.value?.name
      const conflict = data.egresses.find((item) => item.name !== originalName
        && (item.name === name || (egressForm.type !== 'tproxy' && Number(item.fwmark) === Number(egressForm.fwmark))))
      if (conflict) {
        error.value = conflict.name === name ? '出口名称已存在。' : 'fwmark 已被其他出口使用。'
        return
      }
      saving.value = true
      clearMessage()
      try {
        await api(originalName ? `/egresses/${encodeURIComponent(originalName)}` : '/egresses', {
          method: originalName ? 'PUT' : 'POST',
          body: JSON.stringify({
            name,
            type: egressForm.type,
            fwmark: egressForm.type === 'tproxy' ? 0 : Number(egressForm.fwmark),
            tunnel: egressForm.type === 'http_tunnel'
              ? { url: egressForm.tunnel.url.trim(), token: egressForm.tunnel.token }
              : null,
            tproxy: egressForm.type === 'tproxy'
              ? { addr: egressForm.tproxy.addr.trim(), port: Number(egressForm.tproxy.port) || 0 }
              : null,
          }),
        })
        closeModal()
        notice.value = '出口配置已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    async function saveDomain() {
      const domain = domainForm.domain.trim().toLowerCase().replace(/\.+$/, '')
      const egress = selectedDomainEgress.value
      if (!domain || !egress) {
        error.value = '请填写域名并选择已有出口。'
        return
      }
      saving.value = true
      clearMessage()
      try {
        await api('/domains', {
          method: 'PUT',
          body: JSON.stringify({ match: domainForm.match, domain, egress: domainForm.egress }),
        })
        closeModal()
        notice.value = '域名规则已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    async function saveCidr() {
      const cidr = cidrForm.cidr.trim()
      const egress = selectedCidrEgress.value
      if (!cidr || !egress) {
        error.value = '请填写 CIDR 网段并选择已有出口。'
        return
      }
      saving.value = true
      clearMessage()
      try {
        await api('/cidrs', {
          method: 'PUT',
          body: JSON.stringify({ cidr, egress: cidrForm.egress }),
        })
        closeModal()
        notice.value = 'IP 规则已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    async function saveHost() {
      const name = hostForm.name.trim().toLowerCase().replace(/\.+$/, '')
      if (!name || !hostForm.ip.trim()) {
        error.value = '请填写主机名和 IP 地址。'
        return
      }
      saving.value = true
      clearMessage()
      try {
        await api('/hosts', {
          method: 'PUT',
          body: JSON.stringify({ name, ip: hostForm.ip.trim() }),
        })
        closeModal()
        notice.value = '静态 Hosts 已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    async function remove(kind, item) {
      const labels = { egress: '出口', domain: '域名规则', cidr: 'IP 规则', host: '静态 Hosts' }
      const identifier = kind === 'domain' ? item.domain : kind === 'cidr' ? item.cidr : item.name
      if (!window.confirm(`确认删除${labels[kind]}「${identifier}」？`)) return
      clearMessage()
      try {
        const path = kind === 'egress'
          ? `/egresses/${encodeURIComponent(item.name)}`
          : kind === 'domain'
            ? `/domains/${encodeURIComponent(`${item.match}:${item.domain}`)}`
            : kind === 'cidr'
              ? `/cidrs/${encodeURIComponent(item.cidr)}`
              : `/hosts/${encodeURIComponent(item.name)}`
        await api(path, { method: 'DELETE' })
        notice.value = `${labels[kind]}已删除。`
        await refresh()
      } catch (cause) {
        error.value = cause.message
      }
    }

    function addForView() {
      if (currentView.value === 'egresses') openEgress()
      if (currentView.value === 'domains') openDomain()
      if (currentView.value === 'cidrs') openCidr()
      if (currentView.value === 'hosts') openHost()
    }

    const addLabel = computed(() => ({ egresses: '新建出口', domains: '新建规则', cidrs: '新建 IP 规则', hosts: '新建 Hosts' })[currentView.value] || '')
    const canAdd = computed(() => ['egresses', 'domains', 'cidrs', 'hosts'].includes(currentView.value))

    onMounted(() => {
      syncViewFromHash()
      window.addEventListener('hashchange', syncViewFromHash)
      refresh()
    })

    onBeforeUnmount(() => window.removeEventListener('hashchange', syncViewFromHash))

    return {
      addForView, addLabel, canAdd, cidrForm, closeModal, currentView, data, domainForm, egressDesc,
      egressByIndex, egressByName, egressForm, error, hexMark, hostForm, lastUpdated, loading, modal, modalTitle, navItems, notice,
      navigate, openCidr, openDomain, openEgress, openHost, refresh, remove, saveCidr, saveDomain, saveEgress, saveHost,
      saving, selectedCidrEgress, selectedDomainEgress, stats,
    }
  },
  template: `
    <main class="shell">
      <aside class="sidebar">
        <div class="brand" aria-label="Gateway 控制台">
          <div class="brand-mark"><Layers3 :size="22" /></div>
          <div><strong>Gateway</strong><span>控制台</span></div>
        </div>
        <nav class="nav" aria-label="主导航">
          <button v-for="item in navItems" :key="item.id" class="nav-item" :class="{ active: currentView === item.id }" @click="navigate(item.id)">
            <component :is="item.icon" :size="18" />
            <span>{{ item.label }}</span>
          </button>
        </nav>
        <div class="sidebar-foot">
          <span class="status-dot"></span>
          <span>API 已连接</span>
        </div>
      </aside>

      <section class="workspace">
        <header class="topbar">
          <div>
            <p class="eyebrow">CONTROL PLANE</p>
            <h1>{{ navItems.find(item => item.id === currentView)?.label }}</h1>
          </div>
          <div class="topbar-actions">
            <span v-if="lastUpdated" class="updated">更新于 {{ lastUpdated.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }) }}</span>
            <button class="icon-button" title="刷新数据" :disabled="loading" @click="refresh"><RefreshCw :size="18" :class="{ spinning: loading }" /></button>
            <button v-if="canAdd" class="primary-button" @click="addForView"><Plus :size="18" />{{ addLabel }}</button>
          </div>
        </header>

        <div v-if="notice" class="alert alert-success"><Check :size="18" /><span>{{ notice }}</span><button title="关闭提示" @click="notice = ''"><X :size="17" /></button></div>

        <div v-if="loading && !lastUpdated" class="loading-state"><LoaderCircle :size="24" class="spinning" /><span>正在读取 Gateway 配置</span></div>

        <template v-else>
          <section v-if="currentView === 'overview'" class="view overview">
            <div class="stat-grid">
              <article v-for="stat in stats" :key="stat.label" class="stat-card" :class="stat.tone">
                <div class="stat-icon"><component :is="stat.icon" :size="20" /></div>
                <span>{{ stat.label }}</span>
                <strong>{{ stat.value }}</strong>
              </article>
            </div>
            <div class="overview-grid">
              <section class="panel-list">
                <div class="section-heading"><div><p class="eyebrow">EGRESS</p><h2>出口配置</h2></div><button class="text-button" @click="navigate('egresses')">查看全部 <ArrowUpRight :size="16" /></button></div>
                <div v-if="data.egresses.length" class="compact-list">
                  <div v-for="egress in data.egresses.slice(0, 4)" :key="egress.name" class="compact-row"><span class="row-name">{{ egress.name }}</span><span class="badge" :class="egress.type === 'http_tunnel' ? 'badge-teal' : egress.type === 'tproxy' ? 'badge-lime' : 'badge-neutral'">{{ egress.type === 'http_tunnel' ? 'HTTP 隧道' : egress.type === 'tproxy' ? '本地 TPROXY' : '手工出口' }}</span><code>{{ egressDesc(egress) }}</code></div>
                </div>
                <div v-else class="empty-inline"><Network :size="19" />尚未配置出口</div>
              </section>
              <section class="panel-list">
                <div class="section-heading"><div><p class="eyebrow">ROUTE SNAPSHOT</p><h2>最近生效路由</h2></div><button class="text-button" @click="navigate('routes')">查看全部 <ArrowUpRight :size="16" /></button></div>
                <div v-if="data.routes.length" class="compact-list">
                  <div v-for="route in data.routes.slice(0, 4)" :key="route.cidr" class="compact-row"><code>{{ route.cidr }}</code><span>egress</span><code>{{ egressByIndex.get(Number(route.value))?.name || '索引 ' + route.value }}</code></div>
                </div>
                <div v-else class="empty-inline"><Route :size="19" />尚无动态 IPv4 路由</div>
              </section>
              <section class="panel-list">
                <div class="section-heading"><div><p class="eyebrow">IP ROUTING</p><h2>最近 IP 规则</h2></div><button class="text-button" @click="navigate('cidrs')">查看全部 <ArrowUpRight :size="16" /></button></div>
                <div v-if="data.cidrs.length" class="compact-list">
                  <div v-for="cidr in data.cidrs.slice(0, 4)" :key="cidr.cidr" class="compact-row"><code>{{ cidr.cidr }}</code><span class="row-name">{{ cidr.egress }}</span></div>
                </div>
                <div v-else class="empty-inline"><Network :size="19" />尚无显式 IP 规则</div>
              </section>
            </div>
            <section class="guidance">
              <CircleHelp :size="20" />
              <p>域名规则在 DNS 响应命中后写入当前 IPv4 路由快照；IP 规则直接按 CIDR 网段生效，不依赖 DNS 解析。出口配置当前保存 fwmark 与隧道参数，策略路由和隧道生命周期由后端后续接管。</p>
            </section>
          </section>

          <section v-else-if="currentView === 'egresses'" class="view">
            <div class="section-heading"><div><p class="eyebrow">EGRESS TARGETS</p><h2>流量出口</h2></div><span class="item-count">{{ data.egresses.length }} 项</span></div>
            <div v-if="data.egresses.length" class="table-wrap"><table><thead><tr><th>名称</th><th>类型</th><th>处理方式</th><th>隧道地址</th><th></th></tr></thead><tbody><tr v-for="item in data.egresses" :key="item.name"><td class="row-name">{{ item.name }}</td><td><span class="badge" :class="item.type === 'http_tunnel' ? 'badge-teal' : item.type === 'tproxy' ? 'badge-lime' : 'badge-neutral'">{{ item.type === 'http_tunnel' ? 'HTTP 隧道' : item.type === 'tproxy' ? '本地 TPROXY' : '手工出口' }}</span></td><td><code>{{ egressDesc(item) }}</code></td><td class="muted truncate">{{ item.tunnel?.url || '-' }}</td><td class="actions"><button class="icon-button" title="编辑出口" @click="openEgress(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除出口" @click="remove('egress', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else class="empty-state"><Network :size="28" /><h2>还没有出口配置</h2><button class="primary-button" @click="openEgress()"><Plus :size="18" />新建出口</button></div>
          </section>

          <section v-else-if="currentView === 'domains'" class="view">
            <div class="section-heading"><div><p class="eyebrow">DNS ROUTING</p><h2>域名规则</h2></div><span class="item-count">{{ data.domains.length }} 项</span></div>
            <div v-if="data.domains.length" class="table-wrap"><table><thead><tr><th>域名</th><th>匹配方式</th><th>出口</th><th>出口方式</th><th></th></tr></thead><tbody><tr v-for="item in data.domains" :key="item.match + item.domain"><td class="row-name">{{ item.domain }}</td><td><span class="badge badge-lime">{{ item.match === 'full' ? '精确匹配' : '域及子域' }}</span></td><td>{{ item.egress || '-' }}</td><td><code>{{ egressDesc(egressByName.get(item.egress)) }}</code></td><td class="actions"><button class="icon-button" title="编辑规则" @click="openDomain(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除规则" @click="remove('domain', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else class="empty-state"><Globe2 :size="28" /><h2>还没有域名规则</h2><button class="primary-button" @click="openDomain()"><Plus :size="18" />新建规则</button></div>
          </section>

          <section v-else-if="currentView === 'cidrs'" class="view">
            <div class="section-heading"><div><p class="eyebrow">IP ROUTING</p><h2>IP 规则</h2></div><span class="item-count">{{ data.cidrs.length }} 项</span></div>
            <div v-if="data.cidrs.length" class="table-wrap"><table><thead><tr><th>CIDR 网段</th><th>出口</th><th>出口方式</th><th></th></tr></thead><tbody><tr v-for="item in data.cidrs" :key="item.cidr"><td class="row-name"><code>{{ item.cidr }}</code></td><td>{{ item.egress || '-' }}</td><td><code>{{ egressDesc(egressByName.get(item.egress)) }}</code></td><td class="actions"><button class="icon-button" title="编辑规则" @click="openCidr(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除规则" @click="remove('cidr', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else class="empty-state"><Network :size="28" /><h2>还没有 IP 规则</h2><button class="primary-button" @click="openCidr()"><Plus :size="18" />新建 IP 规则</button></div>
          </section>

          <section v-else-if="currentView === 'hosts'" class="view">
            <div class="section-heading"><div><p class="eyebrow">STATIC DNS</p><h2>静态 Hosts</h2></div><span class="item-count">{{ data.hosts.length }} 项</span></div>
            <div v-if="data.hosts.length" class="table-wrap"><table><thead><tr><th>主机名</th><th>IP 地址</th><th></th></tr></thead><tbody><tr v-for="item in data.hosts" :key="item.name"><td class="row-name">{{ item.name }}</td><td><code>{{ item.ip }}</code></td><td class="actions"><button class="icon-button" title="编辑 Hosts" @click="openHost(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除 Hosts" @click="remove('host', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else class="empty-state"><Server :size="28" /><h2>还没有静态 Hosts</h2><button class="primary-button" @click="openHost()"><Plus :size="18" />新建 Hosts</button></div>
          </section>

          <section v-else-if="currentView === 'routes'" class="view">
            <div class="section-heading"><div><p class="eyebrow">ACTIVE SNAPSHOT</p><h2>当前 IPv4 路由</h2></div><span class="item-count">{{ data.routes.length }} 项</span></div>
            <div v-if="data.routes.length" class="table-wrap"><table><thead><tr><th>CIDR</th><th>egress 索引</th><th>关联出口</th></tr></thead><tbody><tr v-for="item in data.routes" :key="item.cidr"><td><code>{{ item.cidr }}</code></td><td><code>{{ item.value }}</code></td><td>{{ egressByIndex.get(Number(item.value))?.name || '-' }}</td></tr></tbody></table></div>
            <div v-else class="empty-state"><Route :size="28" /><h2>当前没有动态 IPv4 路由</h2></div>
          </section>

          <section v-else-if="currentView === 'dns-cache'" class="view">
            <div class="section-heading"><div><p class="eyebrow">RESOLVER CACHE</p><h2>DNS 解析缓存</h2></div><span class="item-count">{{ data.dnsCache.length }} 项</span></div>
            <div v-if="data.dnsCache.length" class="table-wrap"><table><thead><tr><th>域名</th><th>类型</th><th>解析结果</th><th>剩余 TTL</th><th>过期时间</th></tr></thead><tbody><tr v-for="item in data.dnsCache" :key="item.name + item.type"><td class="row-name">{{ item.name }}</td><td><span class="badge badge-teal">{{ item.type }}</span></td><td class="dns-answers"><code v-for="answer in item.answers" :key="answer">{{ answer }}</code></td><td><code>{{ item.ttl }}s</code></td><td class="muted">{{ new Date(item.expiresAt).toLocaleString('zh-CN', { hour12: false }) }}</td></tr></tbody></table></div>
            <div v-else class="empty-state"><Database :size="28" /><h2>尚无有效 DNS 缓存</h2></div>
          </section>
        </template>
      </section>

      <div v-if="modal" class="modal-backdrop" @mousedown.self="closeModal">
        <form class="modal" @submit.prevent="modal === 'egress' ? saveEgress() : modal === 'domain' ? saveDomain() : modal === 'cidr' ? saveCidr() : saveHost()">
          <header><div><p class="eyebrow">CONFIGURATION</p><h2>{{ modalTitle }}</h2></div><button type="button" class="icon-button" title="关闭" @click="closeModal"><X :size="18" /></button></header>
          <div v-if="modal === 'egress'" class="form-fields">
            <label><span>名称</span><input v-model="egressForm.name" :disabled="!!editing" required placeholder="proxy-a" /></label>
            <label><span>类型</span><select v-model="egressForm.type"><option value="manual">自定义出口</option><option value="http_tunnel">HTTP 隧道</option><option value="tproxy">本地 TPROXY</option></select></label>
            <label v-if="egressForm.type !== 'tproxy'"><span>fwmark</span><input v-model.number="egressForm.fwmark" type="number" min="0" step="1" required placeholder="4097" /><small v-if="egressForm.fwmark !== ''">{{ hexMark(egressForm.fwmark) }}</small></label>
            <template v-if="egressForm.type === 'http_tunnel'"><label><span>隧道地址</span><input v-model="egressForm.tunnel.url" type="url" placeholder="https://tunnel.example/connect" /></label><label><span>访问令牌</span><input v-model="egressForm.tunnel.token" type="password" autocomplete="new-password" placeholder="token" /></label></template>
            <template v-if="egressForm.type === 'tproxy'"><label><span>监听地址</span><input v-model="egressForm.tproxy.addr" placeholder="0.0.0.0" /><small>留空或 0.0.0.0 表示按包的原目的地址查找透明监听 socket。</small></label><label><span>监听端口</span><input v-model.number="egressForm.tproxy.port" type="number" min="0" max="65535" step="1" placeholder="12345" /><small>0 表示按包的原目的端口匹配。</small></label></template>
          </div>
          <div v-else-if="modal === 'domain'" class="form-fields">
            <label><span>域名</span><input v-model="domainForm.domain" :disabled="!!editing" required placeholder="example.com" /><small v-if="editing">域名与匹配方式共同构成规则标识。</small></label>
            <label><span>匹配方式</span><select v-model="domainForm.match" :disabled="!!editing"><option value="domain">域及其子域</option><option value="full">精确域名</option></select></label>
            <label><span>关联出口</span><select v-model="domainForm.egress" required><option value="">选择出口</option><option v-for="item in data.egresses" :key="item.name" :value="item.name">{{ item.name }} · {{ egressDesc(item) }}</option></select><small v-if="selectedDomainEgress">将使用 {{ egressDesc(selectedDomainEgress) }}</small></label>
          </div>
          <div v-else-if="modal === 'cidr'" class="form-fields">
            <label><span>CIDR 网段</span><input v-model="cidrForm.cidr" :disabled="!!editing" required placeholder="203.0.113.0/24" /><small>填写 IPv4 网段，如 203.0.113.0/24，直接按最长前缀匹配，不依赖 DNS 解析。</small></label>
            <label><span>关联出口</span><select v-model="cidrForm.egress" required><option value="">选择出口</option><option v-for="item in data.egresses" :key="item.name" :value="item.name">{{ item.name }} · {{ egressDesc(item) }}</option></select><small v-if="selectedCidrEgress">将使用 {{ egressDesc(selectedCidrEgress) }}</small></label>
          </div>
          <div v-else class="form-fields"><label><span>主机名</span><input v-model="hostForm.name" :disabled="!!editing" required placeholder="internal.example.com" /></label><label><span>IP 地址</span><input v-model="hostForm.ip" required placeholder="192.0.2.10 或 2001:db8::10" /></label></div>
          <footer><button type="button" class="secondary-button" @click="closeModal">取消</button><button type="submit" class="primary-button" :disabled="saving"><LoaderCircle v-if="saving" :size="17" class="spinning" /><Check v-else :size="17" />保存</button></footer>
        </form>
      </div>

      <div v-if="error" class="error-dialog-backdrop" @mousedown.self="error = ''">
        <section class="error-dialog" role="alertdialog" aria-modal="true" aria-labelledby="error-dialog-title">
          <header>
            <div class="error-dialog-title"><AlertCircle :size="20" /><h2 id="error-dialog-title">操作失败</h2></div>
            <button type="button" class="icon-button" title="关闭错误提示" @click="error = ''"><X :size="18" /></button>
          </header>
          <p>{{ error }}</p>
          <footer><button type="button" class="primary-button" @click="error = ''">知道了</button></footer>
        </section>
      </div>
    </main>
  `,
}

createApp(App).mount('#app')
