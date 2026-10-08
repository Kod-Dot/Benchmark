<script lang="ts">
  import { accountExists, inDesktopApp } from './lib/backend';
  import Login from './screens/Login.svelte';
  import Start from './screens/Start.svelte';
  import NewAssessment from './screens/NewAssessment.svelte';
  import Workspace from './results/Workspace.svelte';
  import Export from './screens/Export.svelte';
  import Settings from './screens/Settings.svelte';
  import { getCatalogSummary, getEnvironment, listAssessments, openAssessments, openBundle, pickBundle, showingExamples } from './lib/backend';
  import type { AssessmentView, CatalogSummary, Environment, Listing } from './lib/types';

  // An exported offline dashboard carries its assessment in the file and
  // shows only the results; there is no backend behind it.
  const offline = window.__DCA__?.mode === 'offline' ? window.__DCA__ : null;

  let screen = $state<'start' | 'new' | 'results' | 'export' | 'settings'>(offline ? 'results' : 'start');
  let environment = $state<Environment | null>(null);
  let catalog = $state<CatalogSummary | null>(null);
  let catalogError = $state<string | null>(null);
  let listing = $state<Listing | null>(null);
  let listingError = $state<string | null>(null);
  // Raw: the view is replaced, never changed in place, and deep reactivity on
  // hundreds of thousands of directory objects makes every read slow.
  let view = $state.raw<AssessmentView | null>(offline?.view ?? null);
  let openError = $state<string | null>(null);
  let paths = $state<string[]>([]);
  let settingsFrom = $state<'start' | 'results'>('start');

  // The sign-in gate. A browser preview and an offline exported dashboard have
  // no backend of their own, so they are never gated.
  const gated = inDesktopApp && !offline;
  let authed = $state(!gated);
  let needAccount = $state(false);
  let authReady = $state(!gated);
  if (gated) {
    accountExists()
      .then((has) => {
        needAccount = !has;
        authReady = true;
      })
      .catch(() => (authReady = true));
  }

  if (!offline) {
    getEnvironment().then((e) => (environment = e)).catch(() => {});
    getCatalogSummary()
      .then((c) => (catalog = c))
      .catch((e) => (catalogError = String(e?.message ?? e)));
    listAssessments()
      .then((l) => (listing = l))
      .catch((e) => (listingError = String(e?.message ?? e)));
  }

  /** Opens one run or combines several; returns the error to show, if any. */
  async function open(next: string[]): Promise<string | null> {
    openError = null;
    try {
      view = await openAssessments(next);
      paths = next;
      screen = 'results';
      return null;
    } catch (e) {
      return (openError = String((e as Error)?.message ?? e));
    }
  }

  /** Re-reads the open assessments, for example after a risk is accepted. */
  async function reload() {
    if (paths.length) view = await openAssessments(paths);
  }

  let importing = $state(false);

  /** Picks a bundle, imports and analyzes it, then opens it. */
  async function bundle() {
    openError = null;
    let picked: string | null;
    try {
      picked = await pickBundle();
    } catch (e) {
      openError = String((e as Error)?.message ?? e);
      return;
    }
    if (!picked) return;
    importing = true;
    try {
      const dir = await openBundle(picked);
      listAssessments().then((l) => (listing = l)).catch(() => {});
      await open([dir]);
    } catch (e) {
      openError = String((e as Error)?.message ?? e);
    } finally {
      importing = false;
    }
  }

  function settings(from: 'start' | 'results') {
    settingsFrom = from;
    screen = 'settings';
  }
</script>

{#if !authReady}
  <div class="auth-wait"></div>
{:else if !authed}
  <Login create={needAccount} onAuthed={() => (authed = true)} />
{:else if offline && view}
  <Workspace {view} listing={null} example={false} {offline} onHome={() => {}} onOpen={async () => null} />
{:else if screen === 'export' && view}
  <Export {view} {listing} example={showingExamples} onBack={() => (screen = 'results')} />
{:else if screen === 'settings'}
  <Settings
    {catalog}
    backLabel={settingsFrom === 'results' && view ? 'Results' : 'Start'}
    onBack={() => (screen = settingsFrom === 'results' && view ? 'results' : 'start')}
    onChanged={reload}
  />
{:else if screen === 'results' && view}
  {#key view.runs.map((r) => r.path).join('|')}
    <Workspace
      {view}
      {listing}
      example={showingExamples}
      onHome={() => (screen = 'start')}
      onOpen={open}
      onExport={() => (screen = 'export')}
      onReload={showingExamples ? undefined : reload}
      onSettings={() => settings('results')}
    />
  {/key}
{:else if screen === 'new'}
  <NewAssessment
    {environment}
    {catalog}
    onExit={() => (screen = 'start')}
    onOpen={open}
    onCollected={() => listAssessments().then((l) => (listing = l)).catch(() => {})}
  />
{:else}
  <Start
    {environment}
    {catalog}
    {catalogError}
    {listing}
    {listingError}
    {openError}
    onNew={() => (screen = 'new')}
    onOpen={(p) => open([p])}
    onBundle={bundle}
    {importing}
    onSettings={() => settings('start')}
  />
{/if}
