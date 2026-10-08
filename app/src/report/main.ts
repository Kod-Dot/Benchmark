// The printable reports (executive summary, technical report, changes).
// Built as its own page so each export inlines one small script; the data
// comes from window.__DCA__, which the export writes into the file.
import '@fontsource-variable/urbanist';
import '@fontsource-variable/jetbrains-mono';
import '../styles/tokens.css';
import '../styles/base.css';
import '../styles/components.css';
import './report.css';

import { mount } from 'svelte';
import Report from './Report.svelte';

export default mount(Report, { target: document.getElementById('app')! });
