<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import { date, daysSince, kindIcon, kindLabel, num } from '../lib/format';
  import type { AssessmentView, DirObject } from '../lib/types';
  import { findingKey, type Go } from './route';

  let { id, view, go }: { id: string; view: AssessmentView; go: Go } = $props();

  const dir = $derived(view.directory!);
  const byId = $derived(new Map(dir.objects.map((o) => [o.id, o])));
  const o = $derived(byId.get(id));
  const src = $derived(dir.sources.find((s) => s.name === o?.source));

  // Group membership, direct and nested, with how each was reached.
  const memberOf = $derived.by(() => {
    const out: { group: DirObject; how: string }[] = [];
    const seen = new Set<string>();
    const queue: { id: string; via: string | null }[] = [{ id, via: null }];
    while (queue.length) {
      const cur = queue.shift()!;
      for (const e of dir.edges) {
        if (e.kind !== 'MemberOf' || e.from !== cur.id || seen.has(e.to)) continue;
        const g = byId.get(e.to);
        if (!g) continue;
        seen.add(e.to);
        out.push({ group: g, how: cur.via ? `Through ${cur.via}` : 'Direct' });
        queue.push({ id: e.to, via: cur.via ?? g.name });
      }
    }
    return out;
  });
  const members = $derived(dir.edges.filter((e) => e.kind === 'MemberOf' && e.to === id).map((e) => byId.get(e.from)).filter(Boolean) as DirObject[]);

  // Rights this object holds, directly or through its groups.
  const holders = $derived([{ id, via: 'Direct' }, ...memberOf.map((m) => ({ id: m.group.id, via: `Through ${m.group.name}` }))]);
  const SKIP = new Set(['MemberOf', 'HasSession', 'GPLink', 'Publishes', 'SyncedTo']);
  const rights = $derived(
    holders.flatMap((h) =>
      dir.edges
        .filter((e) => e.from === h.id && !SKIP.has(e.kind))
        .map((e) => ({ kind: e.kind, target: byId.get(e.to), via: h.via, note: e.note })),
    ),
  );
  const controlledBy = $derived(
    dir.edges
      .filter((e) => e.to === id && !SKIP.has(e.kind))
      .map((e) => ({ kind: e.kind, who: byId.get(e.from), note: e.note })),
  );
  const sessions = $derived.by(() => {
    const isComputer = o?.kind === 'computer';
    return dir.edges
      .filter((e) => e.kind === 'HasSession' && (isComputer ? e.from === id : e.to === id))
      .map((e) => ({ other: byId.get(isComputer ? e.to : e.from), note: e.note }));
  });
  const links = $derived(dir.edges.filter((e) => (e.kind === 'SyncedTo' || e.kind === 'GPLink') && (e.from === id || e.to === id)));
  const findings = $derived(view.findings.filter((f) => f.status === 'failed' && f.affected.some((a) => a.object === id)));

  function ancestry(x: DirObject): string {
    const parts: string[] = [];
    let p = x.parent ? byId.get(x.parent) : undefined;
    while (p) {
      parts.unshift(p.name);
      p = p.parent ? byId.get(p.parent) : undefined;
    }
    return parts.join(' · ');
  }

  const initials = $derived(
    (o?.display_name ?? o?.name ?? '?')
      .replace(/\(.*\)/, '')
      .split(/[\s.@-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((w) => w[0]?.toUpperCase())
      .join(''),
  );
  const attrs = $derived(Object.entries(o?.attributes ?? {}).sort(([a], [b]) => a.localeCompare(b)));
  const show = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v));
</script>

{#if o}
  <div class="vhead">
    <div class="who">
      {#if o.kind === 'user'}<span class="avatar">{initials}</span>{:else}<span class="otype big" class:t0={o.tier0}><Icon name={kindIcon(o.kind)} size={28} /></span>{/if}
      <div class="names">
        <h1>{o.name}</h1>
        <span class="muted">{[o.display_name, kindLabel(o.kind), ancestry(o) || o.source].filter(Boolean).join(' · ')}</span>
      </div>
      <button class="btn" onclick={() => go({ page: 'graph', id: o.id })}><Icon name="peopleTeam" />Show in graph</button>
    </div>
    <div class="vmeta">
      {#if o.tier0}<span class="flag crit"><Icon name="shieldError" size={14} />Tier 0</span>{/if}
      {#if o.enabled === true}<span class="state ok"><Icon name="checkmarkCircle" size={16} />Enabled</span>{/if}
      {#if o.enabled === false}<span class="state neutral"><Icon name="subtractCircle" size={16} />Disabled</span>{/if}
      {#each o.flags as fl, i (i)}<span class="flag {fl.level}">{fl.text}</span>{/each}
    </div>
  </div>

  <div class="content">
    <div class="folders">
      <section class="folder">
        <div class="tabrow"><h2 class="ftab"><Icon name={kindIcon(o.kind)} size={18} />Identity</h2></div>
        <dl class="fbody fkv">
          {#if o.display_name}<div><dt>Display name</dt><dd>{o.display_name}</dd></div>{/if}
          <div><dt>Kind</dt><dd>{kindLabel(o.kind)}</dd></div>
          <div><dt>Directory</dt><dd>{o.source}</dd></div>
          {#if ancestry(o)}<div><dt>Location</dt><dd>{ancestry(o)}</dd></div>{/if}
        </dl>
      </section>
      <section class="folder sky">
        <div class="tabrow"><h2 class="ftab"><Icon name="personKey" size={18} />Account</h2></div>
        <dl class="fbody fkv">
          {#if o.enabled != null}<div><dt>State</dt><dd>{o.enabled ? 'Enabled' : 'Disabled'}</dd></div>{/if}
          {#if o.last_logon}<div><dt>Last logon</dt><dd class="num">{date(o.last_logon, true)}</dd></div>{/if}
          {#if o.password_last_set}<div><dt>Password last set</dt><dd class="num">{date(o.password_last_set)}, {num(daysSince(o.password_last_set, src?.read_at) ?? 0)} days ago</dd></div>{/if}
          <div><dt>Read from the directory</dt><dd class="num">{date(src?.read_at, true)}</dd></div>
        </dl>
      </section>
      <section class="folder lilac">
        <div class="tabrow"><h2 class="ftab"><Icon name="key" size={18} />Rights</h2></div>
        <dl class="fbody fkv">
          <div><dt>Member of</dt><dd>{num(memberOf.length)} {memberOf.length === 1 ? 'group' : 'groups'}, {num(memberOf.filter((m) => m.group.tier0).length)} Tier 0</dd></div>
          <div><dt>Rights over other objects</dt><dd>{num(rights.length)}</dd></div>
          <div><dt>Principals with rights over it</dt><dd>{num(controlledBy.length)}</dd></div>
          <div><dt>Failed checks that list it</dt><dd>{num(findings.length)}</dd></div>
        </dl>
      </section>
    </div>

    <div class="grid">
      <section class="panel s6">
        <div class="panel-h"><Icon name="warning" /><h4>Findings for this {kindLabel(o.kind).toLowerCase()}</h4></div>
        <div class="panel-b flush">
          <table class="t flat">
            <tbody>
              {#each findings as f (findingKey(f))}
                <tr>
                  <td class="pl" style="width: 128px"><SevBadge severity={f.severity} /></td>
                  <td><button class="linkbtn plain" onclick={() => go({ page: 'finding', key: findingKey(f) })}>{f.title}</button><div class="mono muted">{f.id}</div></td>
                </tr>
              {:else}
                <tr><td class="pl muted">No failed check lists this object.</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>

      {#if memberOf.length || o.kind === 'user' || o.kind === 'computer'}
        <section class="panel s6">
          <div class="panel-h"><Icon name="people" /><h4>Member of</h4><span class="muted small">{memberOf.length}, including nested</span></div>
          <div class="panel-b flush">
            <table class="t flat">
              <tbody>
                {#each memberOf as m (m.group.id)}
                  <tr>
                    <td class="pl"><span class="obj"><span class="otype" class:t0={m.group.tier0}><Icon name="people" size={16} /></span><button class="linkbtn plain" onclick={() => go({ page: 'object', id: m.group.id })}>{m.group.name}</button>{#if m.group.tier0}<span class="flag crit">Tier 0</span>{/if}</span></td>
                    <td class="muted small pr">{m.how}</td>
                  </tr>
                {:else}
                  <tr><td class="pl muted">Not a member of any group in the collected data.</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {/if}

      {#if o.kind === 'group' || o.kind === 'role'}
        <section class="panel s6">
          <div class="panel-h"><Icon name="peopleTeam" /><h4>{o.kind === 'role' ? 'Assigned to' : 'Direct members'}</h4><span class="muted small">{o.kind === 'role' ? '' : members.length}</span></div>
          <div class="panel-b flush">
            <table class="t flat">
              <tbody>
                {#each o.kind === 'role' ? controlledBy.filter((c) => c.kind === 'HasRole').map((c) => c.who).filter(Boolean) as DirObject[] : members as m (m.id)}
                  <tr><td class="pl"><span class="obj"><span class="otype" class:t0={m.tier0}><Icon name={kindIcon(m.kind)} size={16} /></span><button class="linkbtn plain" onclick={() => go({ page: 'object', id: m.id })}>{m.name}</button></span></td><td class="muted small pr">{m.display_name ?? ''}</td></tr>
                {:else}
                  <tr><td class="pl muted">None in the collected data.</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {/if}

      <section class="panel s6">
        <div class="panel-h"><Icon name="key" /><h4>Rights over other objects</h4></div>
        <div class="panel-b flush">
          <table class="t flat">
            <tbody>
              {#each rights as r, i (i)}
                <tr>
                  <td class="pl mono small strong" style="width: 150px">{r.kind}</td>
                  <td>{#if r.target}<button class="linkbtn plain" onclick={() => go({ page: 'object', id: r.target!.id })}>{r.target.name}</button>{/if}</td>
                  <td class="muted small pr">{r.via}</td>
                </tr>
              {:else}
                <tr><td class="pl muted">No rights over other objects in the collected data.</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel s6">
        <div class="panel-h"><Icon name="shieldError" /><h4>Who controls this {kindLabel(o.kind).toLowerCase()}</h4><button class="linkbtn small" onclick={() => go({ page: 'graph', id: o.id })}>Graph</button></div>
        <div class="panel-b flush">
          <table class="t flat">
            <tbody>
              {#each controlledBy as c, i (i)}
                <tr>
                  <td class="pl">{#if c.who}<button class="linkbtn plain strong" onclick={() => go({ page: 'object', id: c.who!.id })}>{c.who.name}</button>{/if}</td>
                  <td class="mono small">{c.kind}</td>
                  <td class="muted small pr">{c.note ?? ''}</td>
                </tr>
              {:else}
                <tr><td class="pl muted">No principal has rights over it in the collected data.</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>

      {#if sessions.length}
        <section class="panel s6">
          <div class="panel-h"><Icon name="clock" /><h4>{o.kind === 'computer' ? 'Signed-in accounts' : 'Signed in to'}</h4></div>
          <div class="panel-b flush">
            <table class="t flat">
              <tbody>
                {#each sessions as s, i (i)}
                  <tr>
                    <td class="pl">{#if s.other}<span class="obj"><span class="otype" class:t0={s.other.tier0}><Icon name={kindIcon(s.other.kind)} size={16} /></span><button class="linkbtn plain" onclick={() => go({ page: 'object', id: s.other!.id })}>{s.other.name}</button></span>{/if}</td>
                    <td>{#if s.other?.tier0}<span class="flag">Tier 0</span>{:else}<span class="flag warn">Not Tier 0</span>{/if}</td>
                    <td class="muted small pr">{s.note ?? ''}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {/if}

      {#if links.length}
        <section class="panel s6">
          <div class="panel-h"><Icon name="link" /><h4>Linked objects</h4></div>
          <div class="panel-b flush">
            <table class="t flat">
              <tbody>
                {#each links as l, i (i)}
                  {@const other = byId.get(l.from === id ? l.to : l.from)}
                  <tr><td class="pl mono small" style="width: 150px">{l.kind}</td><td class="pr">{#if other}<button class="linkbtn plain" onclick={() => go({ page: 'object', id: other.id })}>{other.name}</button> <span class="muted small">{other.source}</span>{/if}</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {/if}

      {#if attrs.length}
        <section class="panel s12">
          <div class="panel-h"><Icon name="document" /><h4>All attributes</h4><span class="muted small">{attrs.length}</span></div>
          <div class="panel-b">
            <dl class="kv tight wrap side">{#each attrs as [k, v] (k)}<dt>{k}</dt><dd class="mono">{show(v)}</dd>{/each}</dl>
          </div>
        </section>
      {/if}
    </div>
  </div>
{:else}
  <p class="muted pad">This object is not in the collected directory data.</p>
{/if}

<style>
  .vhead {
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 4px 28px 14px 8px;
  }

  .who {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 16px;
  }

  .names {
    display: flex;
    flex-direction: column;
    gap: 4px;
    flex: 1 1 auto;
  }

  .names h1 {
    font-size: 48px;
    font-weight: 300;
    line-height: 1.05;
    word-break: break-word;
  }

  .avatar {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 56px;
    height: 56px;
    border-radius: 18px;
    background: var(--lemon);
    color: var(--ink);
    font-weight: 600;
    font-size: 20px;
    flex: none;
  }

  .otype.big {
    width: 56px;
    height: 56px;
    border-radius: 18px;
  }

  .vmeta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px 14px;
  }

  .content {
    padding: 4px 28px 28px 8px;
    display: flex;
    flex-direction: column;
    gap: 18px;
  }

  .folders {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 18px;
  }

  .folders h2.ftab {
    margin: 0;
    font-size: 15.5px;
    font-weight: 500;
    letter-spacing: 0;
  }

  .fkv {
    margin: 0;
  }

  .fkv div {
    display: flex;
    flex-direction: column;
  }

  .fkv dt {
    font-size: 12px;
    color: rgb(20 20 20 / 0.72);
  }

  .fkv dd {
    margin: 0;
    font-size: 15.5px;
    word-break: break-word;
  }

  @media (max-width: 1100px) {
    .folders {
      grid-template-columns: minmax(0, 1fr);
    }
  }

  .side {
    grid-template-columns: 170px 1fr;
    border-top: none;
  }

  .obj {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .strong {
    font-weight: 600;
  }

  .pad {
    padding: 24px;
  }
</style>
