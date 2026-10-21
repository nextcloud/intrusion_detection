<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { TabDefinition } from '../../extensions.ts'
import type { CheckRef, TrapPathList } from '../../types.ts'

import { mdiServerNetwork, mdiSignDirection } from '@mdi/js'
import { showError } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { ref } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import AdminTabs from '../AdminTabs.vue'
import CheckStateNote from '../common/CheckStateNote.vue'
import CodeBlock from '../common/CodeBlock.vue'
import ListEditor from '../common/ListEditor.vue'
import SectionCard from '../common/SectionCard.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, isCancelled, updateTrapPaths } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'

defineProps<{
	paths: TrapPathList
	check: CheckRef
}>()

const emit = defineEmits<{
	changed: [paths: TrapPathList]
}>()

const busy = ref<string | null>(null)
const error = ref<string | null>(null)
const server = ref('nginx')
const { announce } = useAnnouncer()

const serverTabs: TabDefinition[] = [
	{ id: 'nginx', name: () => 'nginx', icon: mdiServerNetwork, order: 1 },
	{ id: 'apache', name: () => 'Apache', icon: mdiServerNetwork, order: 2 },
]

/**
 * @param value - A path as typed
 */
function validate(value: string): string | null {
	if (!value.startsWith('/')) {
		return t(APP_ID, 'A path starts with /, for example /old-admin.')
	}
	if (!/^\/[\x21-\x7E]{0,199}$/.test(value)) {
		return t(APP_ID, 'A path has no spaces and at most 200 characters.')
	}
	if (/^\/(index\.php|remote\.php|public\.php|ocs|apps|core|s|login|status\.php|\.well-known)(\/|$)/.test(value)) {
		return t(APP_ID, 'Nextcloud uses this path itself, so legitimate clients would be blocked.')
	}
	return null
}

/**
 * @param key - What is saved, for the loading state
 * @param change - The change
 * @param change.add - Paths to add
 * @param change.remove - Paths to remove
 * @param change.builtinEnabled - Use the built-in list
 * @param change.autodiscover - Trap the autodiscover path
 * @param done - What to announce
 */
async function save(key: string, change: { add?: string[], remove?: string[], builtinEnabled?: boolean, autodiscover?: boolean }, done: string) {
	busy.value = key
	error.value = null
	try {
		emit('changed', await updateTrapPaths(change))
		announce(done)
	} catch (e) {
		if (!isCancelled(e)) {
			logger.error('Could not change the trap paths', { error: e })
			const message = errorMessage(e, t(APP_ID, 'The trap paths could not be saved. Please try again.'))
			if (key === 'list') {
				error.value = message
			} else {
				showError(message)
			}
			announce(message)
		}
	} finally {
		busy.value = null
	}
}
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Trap paths')" :icon="mdiSignDirection">
		<template #description>
			{{ t(APP_ID, 'Scanners look for the weak spots of other software: WordPress logins, leaked configuration files, database tools. Nextcloud has none of them, so a visitor who is not logged in and asks for one is scanning your server. Logged-in users and clients with credentials are never checked.') }}
		</template>
		<template #actions>
			<CheckStateNote :check="check" />
		</template>

		<div :class="$style.columns">
			<div :class="$style.column">
				<div :class="$style.switches">
					<NcCheckboxRadioSwitch
						type="switch"
						:modelValue="paths.builtinEnabled"
						:loading="busy === 'builtin'"
						:disabled="busy !== null"
						:description="n(APP_ID, '%n path, matched as a prefix.', '%n paths, each matched as a prefix.', paths.builtin.length)"
						@update:modelValue="save('builtin', { builtinEnabled: $event }, $event ? t(APP_ID, 'The built-in trap paths are on.') : t(APP_ID, 'The built-in trap paths are off.'))">
						{{ t(APP_ID, 'Use the built-in trap paths') }}
					</NcCheckboxRadioSwitch>
					<NcCheckboxRadioSwitch
						type="switch"
						:modelValue="paths.autodiscover"
						:loading="busy === 'autodiscover'"
						:disabled="busy !== null"
						:description="t(APP_ID, 'Some mail programs ask for {path} on any server, looking for Exchange. Only switch this on if nobody uses such a program with your domain.', { path: paths.autodiscoverPath })"
						@update:modelValue="save('autodiscover', { autodiscover: $event }, $event ? t(APP_ID, 'The autodiscover path is a trap now.') : t(APP_ID, 'The autodiscover path is no longer a trap.'))">
						{{ t(APP_ID, 'Also trap the Exchange autodiscover path') }}
					</NcCheckboxRadioSwitch>
				</div>

				<details :class="$style.builtin">
					<summary :class="$style.builtin__summary">
						{{ t(APP_ID, 'What the built-in paths are') }}
					</summary>
					<dl :class="$style.builtin__list">
						<div v-for="item in paths.builtin" :key="item.path" :class="$style.builtin__item">
							<dt><code>{{ item.path }}</code></dt>
							<dd>{{ item.text }}</dd>
						</div>
					</dl>
				</details>

				<div :class="$style.custom">
					<h4 :class="$style.subheading">
						{{ t(APP_ID, 'Your own paths') }}
					</h4>
					<ListEditor
						:items="paths.custom"
						:label="t(APP_ID, 'Add a path')"
						placeholder="/old-admin/*"
						:validate="validate"
						:normalise="(value) => value.trim().toLowerCase()"
						:emptyText="t(APP_ID, 'None yet. A path matches exactly, or as a prefix when it ends with *.')"
						:max="paths.max"
						:busy="busy === 'list'"
						:error="error"
						@add="save('list', { add: $event }, t(APP_ID, 'Added: {paths}', { paths: $event.join(', ') }, undefined, { escape: false, sanitize: false }))"
						@remove="save('list', { remove: [$event] }, t(APP_ID, 'Removed: {path}', { path: $event }, undefined, { escape: false, sanitize: false }))" />
				</div>
			</div>
			<div :class="[$style.column, $style.snippets]">
				<h4 :class="$style.subheading">
					{{ t(APP_ID, 'Route the trap paths to Nextcloud') }}
				</h4>
				<p :class="$style.text">
					{{ t(APP_ID, 'Most of these paths never reach Nextcloud: the web server answers "not found" itself, or refuses hidden files like /.env before PHP runs. Add this to your web server configuration so that it hands exactly these paths to Nextcloud, which then blocks the scanner.') }}
				</p>
				<AdminTabs v-model="server" :tabs="serverTabs" />
				<div :id="`ids-panel-${server}`" role="tabpanel" :aria-labelledby="`ids-tab-${server}`">
					<template v-for="snippet in paths.snippets" :key="snippet.id">
						<CodeBlock
							v-if="snippet.id === server"
							:content="snippet.content"
							:file="snippet.file"
							:label="server === 'nginx' ? t(APP_ID, 'nginx configuration') : t(APP_ID, 'Apache configuration')" />
					</template>
				</div>
				<NcNoteCard v-if="paths.snippetsSkipped.length > 0" type="info">
					{{ t(APP_ID, 'These paths contain characters that are not put into a web server configuration automatically: {paths}. Add them by hand if you need them.', { paths: paths.snippetsSkipped.join(' ') }, undefined, { escape: false, sanitize: false }) }}
				</NcNoteCard>
				<p :class="$style.hint">
					{{ t(APP_ID, 'The snippet changes when you change the paths above. Reload the web server after you update it.') }}
				</p>
			</div>
		</div>
	</SectionCard>
</template>

<style module>
.columns {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 420px), 1fr));
	gap: calc(var(--default-grid-baseline) * 6);
	align-items: start;
}

.column {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	min-width: 0;
}

.switches {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.builtin {
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
}

.builtin__summary {
	min-height: var(--default-clickable-area);
	padding-inline: calc(var(--default-grid-baseline) * 3);
	border-radius: var(--border-radius-large);
	font-weight: 600;
	line-height: var(--default-clickable-area);
	cursor: pointer;
}

.builtin__summary:hover {
	background-color: var(--color-background-hover);
}

.builtin__summary:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}

.builtin__list {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr));
	gap: 0 calc(var(--default-grid-baseline) * 5);
	margin: 0;
	padding: 0 calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 3);
}

.builtin__item {
	display: grid;
	grid-template-columns: minmax(0, 9em) minmax(0, 1fr);
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 2);
	border-top: 1px solid var(--color-border);
}

.builtin__item dt code {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.9em;
	overflow-wrap: anywhere;
}

.builtin__item dd {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
	line-height: 1.45;
}

.custom {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-top: calc(var(--default-grid-baseline) * 4);
	border-top: 1px solid var(--color-border);
}

.snippets {
	gap: calc(var(--default-grid-baseline) * 3);
}

.subheading {
	margin: 0;
	font-size: 1em;
	font-weight: 700;
}

.text {
	margin: 0;
	max-width: 80ch;
	line-height: 1.5;
}

.hint {
	display: flex;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

@media (max-width: 600px) {
	.builtin__item {
		grid-template-columns: minmax(0, 1fr);
		gap: calc(var(--default-grid-baseline) * 1);
	}
}
</style>
