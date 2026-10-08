import '@fontsource-variable/urbanist';
import '@fontsource-variable/jetbrains-mono';
import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';

import { mount } from 'svelte';
import { applyTheme, savedTheme } from './lib/theme';
import { applyMotion, applyZoom, display, watchScrolling, zoomKeys } from './lib/prefs.svelte';
import App from './App.svelte';

applyTheme(savedTheme());
applyMotion(display.motion);
if (display.zoom !== 1) applyZoom(display.zoom);
watchScrolling();
zoomKeys();

export default mount(App, { target: document.getElementById('app')! });
