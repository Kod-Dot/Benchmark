<script lang="ts">
  import SevBadge from '../components/SevBadge.svelte';
  import { affectedText, date, kindLabel, num, plural, scopeText, scoreColour, SEVERITIES, severityMeta } from '../lib/format';
  import type { ExportedPage, Finding } from '../lib/types';
  import { accountSources, ageHistogram } from '../lib/ages';
  import { sourcesOf, statusText } from './util';

  let { page }: { page: ExportedPage } = $props();

  /** Objects listed per finding; the full lists are in the data exports. */
  const LISTED = 25;

  const view = $derived(page.view);
  const s = $derived(view.summary);
  const shown = $derived(
    view.findings.filter((f) => f.status === 'failed' || (f.status === 'accepted' && !page.omit_accepted)),
  );
  const passed = $derived(view.findings.filter((f) => f.status === 'passed'));
  const notAssessed = $derived(view.findings.filter((f) => f.status === 'not_assessed'));
  const accepted = $derived(view.findings.filter((f) => f.status === 'accepted'));
  const sources = $derived(sourcesOf(view.findings.filter((f) => f.status !== 'not_assessed')));
  const plan = $derived(page.plan ?? []);
  const multi = $derived(view.runs.length > 1);
  const key = (f: Finding) => `${f.run}|${f.id}`;

  // Enabled accounts only: disabled ones cannot sign in, so their ages say little.
  const ages = $derived.by(() => {
    const d = view.directory;
    if (!d) return [];
    return accountSources(d).map((src) => {
      const of = (kind: string) => d.objects.filter((o) => o.source === src.name && o.kind === kind && o.enabled !== false);
      const users = of('user');
      const computers = of('computer');
      const cols = [
        users.length ? { head: 'Users: password', bins: ageHistogram(users, 'password', src.read_at) } : null,
        users.length ? { head: 'Users: last sign-in', bins: ageHistogram(users, 'logon', src.read_at) } : null,
        computers.length ? { head: 'Computers: password', bins: ageHistogram(computers, 'password', src.read_at) } : null,
        computers.length ? { head: 'Computers: last sign-in', bins: ageHistogram(computers, 'logon', src.read_at) } : null,
      ]
        .filter((c) => c !== null)
        // A column with no recorded ages at all (a source that does not report them) says nothing.
        .filter((c) => c.bins.slice(0, -1).some((b) => b.objs.length));
      return { src, users: users.length, computers: computers.length, cols };
    }).filter((a) => a.cols.length);
  });
  // Section numbers, so the contents and headings agree.
  const sections = $derived(
    [
      ['scope', 'Scope and method'],
      ['summary', 'Results summary'],
      ['findings', `Findings (${num(shown.length)})`],
      view.paths.length ? ['paths', `Attack paths to Tier 0 (${num(view.paths.length)})`] : null,
      ages.length ? ['ages', 'Account ages'] : null,
      plan.length ? ['plan', 'Remediation plan'] : null,
    ].filter((x): x is string[] => x != null),
  );
  const no = (id: string) => sections.findIndex((x) => x[0] === id) + 1;
  const appendices = $derived(
    [
      ['passed', `Passed checks (${num(passed.length)})`],
      notAssessed.length ? ['not-assessed', `Checks not assessed (${num(notAssessed.length)})`] : null,
      accepted.length ? ['accepted', `Accepted risks (${num(accepted.length)})`] : null,
    ].filter((x): x is string[] => x != null),
  );
  const letter = (id: string) => String.fromCharCode(65 + appendices.findIndex((x) => x[0] === id));
</script>

<nav class="sec toc" aria-label="Contents">
  <h2>Contents</h2>
  <ol>
    {#each sections as [id, title], i (id)}<li><a href="#{id}"><span class="num">{i + 1}</span>{title}</a></li>{/each}
    {#each appendices as [id, title], i (id)}<li><a href="#{id}"><span>{String.fromCharCode(65 + i)}</span>Appendix: {title}</a></li>{/each}
  </ol>
</nav>

<section class="sec" id="scope">
  <h2>{no('scope')}. Scope and method</h2>
  <table class="t">
    <thead><tr><th>Assessment</th><th>Scope</th><th>Collected</th></tr></thead>
    <tbody>
      {#each view.runs as r (r.path)}
        <tr>
          <td><strong>{r.name}</strong></td>
          <td>{scopeText(r.manifest)}</td>
          <td class="num">{date(r.manifest.started_at, true)}{r.manifest.finished_at ? ` to ${date(r.manifest.finished_at, true)}` : ''}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  <dl class="kv tight wrap">
    <dt>Data sources</dt><dd>{sources.join(', ') || 'None'}</dd>
    <dt>Checks</dt><dd>{num(view.findings.length)} from check catalog {view.catalog_version}</dd>
    <dt>Collection</dt><dd>Read-only. Collectors read directory objects, configuration and logs with the permissions of the account that ran them, and change nothing.</dd>
    <dt>Severity</dt><dd>From the check catalog. CVSS 3.1 scores are estimates for the typical case and are labeled as such.</dd>
    <dt>Score</dt><dd>The share of severity weight that passed, among checks that were assessed. A critical check weighs 10, high 5, medium 2 and low 1. Accepted risks and checks that could not be assessed are left out.</dd>
  </dl>
</section>

<section class="sec" id="summary">
  <h2>{no('summary')}. Results summary</h2>
  <div class="sevrow">
    <div class="sevcell"><span class="muted small cell-label">Score</span><span class="big num">{s.score ?? '–'}</span></div>
    {#each SEVERITIES as sev (sev)}
      <div class="sevcell"><SevBadge severity={sev} /><span class="big num">{num(s.severity[sev])}</span></div>
    {/each}
  </div>
  <p class="small muted">{num(s.status.failed)} failed · {num(s.status.passed)} passed · {num(s.status.not_assessed)} not assessed · {num(s.status.accepted)} accepted risks</p>
  <table class="t">
    <thead><tr><th>Area</th><th style="width: 40%">Score</th><th class="right" style="width: 110px">Failed</th></tr></thead>
    <tbody>
      {#each s.areas as a (a.code)}
        <tr>
          <td>{a.title} <span class="mono small muted">{a.code}</span></td>
          <td>
            {#if a.score != null}
              <span class="scorebar"><span class="meter"><span style:width="{a.score}%" style:background={scoreColour(a.score)}></span></span><span class="num">{a.score}</span></span>
            {:else}<span class="muted small">Not assessed</span>{/if}
          </td>
          <td class="right num">{num(a.failed)} of {num(a.assessed)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

<section class="sec" id="findings">
  <h2>{no('findings')}. Findings</h2>
  {#if !shown.length}<p class="muted">No check failed.</p>{/if}
  {#each shown as f, i (key(f))}
    {@const d = f.detail}
    <article class="finding">
      <header class="finding-h">
        <p class="finding-meta">
          <SevBadge severity={f.severity} />
          <span class="mono">{f.id}</span>
          {#if f.cvss}<span>CVSS {f.cvss.score.toFixed(1)} <span class="muted">(estimated)</span></span>{/if}
          <span class="muted">{f.area_title}{multi ? ` · ${f.run}` : ''}</span>
          {#if f.status === 'accepted'}<span class="tag">Accepted risk</span>{/if}
        </p>
        <h3 class="finding-title">{no('findings')}.{i + 1} {f.title}</h3>
      </header>

      {#if d?.description}<p>{d.description}</p>{/if}
      {#if d?.impact}<h4>Impact</h4><p>{d.impact}</p>{/if}
      {#if d?.attack.length}
        <h4>How an attacker uses it</h4>
        <ol class="steps">{#each d.attack as step, j (j)}<li>{step}</li>{/each}</ol>
      {/if}

      <h4>Result</h4>
      <dl class="kv tight wrap">
        {#if f.expected}<dt>Expected</dt><dd>{f.expected}</dd>{/if}
        {#if f.found}<dt>Found</dt><dd>{f.found}</dd>{/if}
        {#each f.evidence as e, j (j)}<dt>{e.label}</dt><dd>{e.value}</dd>{/each}
        {#if affectedText(f)}<dt>Affected</dt><dd>{affectedText(f)}</dd>{/if}
        {#if f.note}<dt>Note</dt><dd>{f.note}</dd>{/if}
      </dl>

      {#if f.affected.length}
        <table class="t objects">
          <thead><tr><th style="width: 34%">Object</th><th>Location</th><th style="width: 34%">Why</th></tr></thead>
          <tbody>
            {#each f.affected.slice(0, LISTED) as a, j (j)}
              <tr>
                <td><strong>{a.name}</strong> <span class="muted small">{kindLabel(a.kind)}</span></td>
                <td class="mono small muted wrap">{a.location ?? ''}</td>
                <td class="small">{a.reason ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {@const total = Math.max(f.affected_count ?? 0, f.affected.length)}
        {#if total > LISTED}
          <p class="small muted">Showing {LISTED} of {num(total)}. The full list is in the Remediation plan workbook and Results.json.</p>
        {/if}
      {/if}

      {#if d?.remediation.length}
        <h4>Remediation</h4>
        <ol class="steps">{#each d.remediation as step, j (j)}<li>{step}</li>{/each}</ol>
      {/if}
      {#if d?.verify}
        <h4>Verify the fix</h4>
        <pre class="codeblock">{d.verify}</pre>
      {/if}

      {#if f.mitre.length || d?.frameworks.length}
        <dl class="kv tight wrap">
          {#if f.mitre.length}<dt>MITRE ATT&amp;CK</dt><dd>{f.mitre.map((m) => `${m.id} ${m.name} (${m.tactic})`).join('; ')}</dd>{/if}
          {#if d?.frameworks.length}<dt>Frameworks</dt><dd>{d.frameworks.join('; ')}</dd>{/if}
          {#if f.cvss}<dt>CVSS vector</dt><dd class="mono small">{f.cvss.vector}</dd>{/if}
        </dl>
      {/if}
      {#if d?.references.length}
        <h4>References</h4>
        <ul class="refs small">
          {#each d.references as r (r.url)}<li>{r.title} <a href={r.url}>{r.url}</a></li>{/each}
        </ul>
      {/if}
    </article>
  {/each}
</section>

{#if view.paths.length}
  <section class="sec" id="paths">
    <h2>{no('paths')}. Attack paths to Tier 0</h2>
    {#if view.choke_points.length}
      <p>Fixing these breaks the most paths:</p>
      <table class="t">
        <thead><tr><th>Finding</th><th class="right" style="width: 120px">Paths broken</th></tr></thead>
        <tbody>
          {#each view.choke_points as c (c.check)}
            <tr><td>{c.title} <span class="mono small muted">{c.check}</span></td><td class="right num">{num(c.paths)}</td></tr>
          {/each}
        </tbody>
      </table>
    {/if}
    {#each view.paths as p, i (i)}
      <div class="path">
        <p class="finding-meta"><SevBadge severity={p.severity} /><strong>{p.title}</strong></p>
        <ol class="path-steps">
          {#each p.steps as st, j (j)}
            <li><strong>{st.name}</strong> <span class="muted small">{kindLabel(st.kind)}</span>{#if st.via}<span class="small via">{st.via}</span>{/if}</li>
          {/each}
        </ol>
        {#if p.checks.length}<p class="small muted">Findings on this path: <span class="mono">{p.checks.join(', ')}</span></p>{/if}
      </div>
    {/each}
  </section>
{/if}

{#if ages.length}
  <section class="sec" id="ages">
    <h2>{no('ages')}. Account ages</h2>
    <p class="small muted">Enabled accounts, by how long ago the password was set and how long since the last sign-in, measured from when the directory was read. On-premises sign-in times (lastLogonTimestamp) can lag by up to 14 days, so the newest buckets are approximate.</p>
    {#each ages as a (a.src.name)}
      <h3 class="sub">{a.src.name} · {plural(a.users, 'user')}, {plural(a.computers, 'computer')}</h3>
      <table class="t">
        <thead>
          <tr><th>Age</th>{#each a.cols as c (c.head)}<th class="right">{c.head}</th>{/each}</tr>
        </thead>
        <tbody>
          {#each a.cols[0].bins as b, i (b.label)}
            <tr>
              <td>{i === a.cols[0].bins.length - 1 ? 'Never or not recorded' : b.label}</td>
              {#each a.cols as c (c.head)}<td class="right num">{num(c.bins[i].objs.length)}</td>{/each}
            </tr>
          {/each}
        </tbody>
      </table>
    {/each}
  </section>
{/if}

{#if plan.length}
  <section class="sec" id="plan">
    <h2>{no('plan')}. Remediation plan</h2>
    <p class="small muted">Ordered by when to fix: 30, 90 and 180 days, then severity, quick wins first. Effort (S, M, L) is estimated from how many objects need changing. Owners are suggestions by area.</p>
    {#each [30, 90, 180] as days (days)}
      {@const rows = plan.filter((r) => r.phase === days)}
      {#if rows.length}
        <h3 class="sub">Within {days} days · {plural(rows.length, 'finding')}</h3>
        <table class="t plan">
          <thead><tr><th style="width: 30px">#</th><th>Finding</th><th style="width: 92px">Severity</th><th style="width: 52px">Effort</th><th style="width: 30%">Owner</th></tr></thead>
          <tbody>
            {#each rows as r (r.id + r.title)}
              <tr>
                <td class="num muted">{r.order}</td>
                <td>{r.title}<div class="small muted"><span class="mono">{r.id}</span>{r.affected ? ` · ${r.affected}` : ''}{#if r.quick_win}&nbsp;· <strong class="quick">Quick win</strong>{/if}</div></td>
                <td><SevBadge severity={r.severity} /></td>
                <td class="num">{r.effort}</td>
                <td class="small">{r.owner}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    {/each}
  </section>
{/if}

<section class="sec" id="passed">
  <h2>Appendix {letter('passed')}. Passed checks</h2>
  <table class="t compact">
    <thead><tr><th style="width: 130px">Check</th><th>Title</th><th style="width: 92px">Severity</th></tr></thead>
    <tbody>
      {#each passed as f (key(f))}
        <tr><td class="mono small">{f.id}</td><td>{f.title}</td><td class="small muted">{severityMeta[f.severity].label}</td></tr>
      {:else}
        <tr><td colspan="3" class="muted">No check passed.</td></tr>
      {/each}
    </tbody>
  </table>
</section>

{#if notAssessed.length}
  <section class="sec" id="not-assessed">
    <h2>Appendix {letter('not-assessed')}. Checks not assessed</h2>
    <table class="t compact">
      <thead><tr><th style="width: 130px">Check</th><th>Title</th><th style="width: 40%">Why</th></tr></thead>
      <tbody>
        {#each notAssessed as f (key(f))}
          <tr><td class="mono small">{f.id}</td><td>{f.title}</td><td class="small">{f.note ?? statusText.not_assessed}</td></tr>
        {/each}
      </tbody>
    </table>
  </section>
{/if}

{#if accepted.length}
  <section class="sec" id="accepted">
    <h2>Appendix {letter('accepted')}. Accepted risks</h2>
    <p class="small muted">Failed checks the owner accepted as exceptions. They are not counted against the score.</p>
    <table class="t compact">
      <thead><tr><th style="width: 130px">Check</th><th>Title</th><th style="width: 92px">Severity</th><th style="width: 30%">Note</th></tr></thead>
      <tbody>
        {#each accepted as f (key(f))}
          <tr><td class="mono small">{f.id}</td><td>{f.title}</td><td><SevBadge severity={f.severity} /></td><td class="small">{f.note ?? ''}</td></tr>
        {/each}
      </tbody>
    </table>
  </section>
{/if}
