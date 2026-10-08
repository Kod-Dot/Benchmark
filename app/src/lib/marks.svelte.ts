// Objects the person marked as compromised while exploring, shared by the
// relationship graph and attack paths ("paths from what is marked"). Kept
// for the open assessment only; nothing is written anywhere.

import { SvelteSet } from 'svelte/reactivity';

export const compromised = new SvelteSet<string>();
