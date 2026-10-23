<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { TabDefinition } from '../../extensions.ts'
import type { CheckRef, TrapPathList, TrapWebServer } from '../../types.ts'

import { mdiServerNetwork, mdiSignDirection } from '@mdi/js'
import { computed, ref } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import AdminTabs from '../AdminTabs.vue'
import CheckStateNote from '../common/CheckStateNote.vue'
import CodeBlock from '../common/CodeBlock.vue'
import ListEditor from '../common/ListEditor.vue'
import SectionCard from '../common/SectionCard.vue'
import ShowMore from '../common/ShowMore.vue'
import { useAction } from '../../composables/useAction.ts'
import { errorMessage } from '../../services/api.ts'
import { changeTrapPaths } from '../../stores/blocks.ts'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const props = defineProps<{
	paths: TrapPathList
	check: CheckRef
}>()

const { busy, run } = useAction()
const error = ref<string | null>(null)
const server = ref(props.paths.webServer === 'apache' || props.paths.webServer === 'apache_fpm' ? 'apache' : 'nginx')

const serverTabs: TabDefinition[] = [
	{ id: 'nginx', name: () => 'nginx', icon: mdiServerNetwork },
	{ id: 'apache', name: () => 'Apache', icon: mdiServerNetwork },
]

/**
 * @param webServer - A web server setup
 */
function serverName(webServer: TrapWebServer): string {
	return webServer === 'nginx' ? 'nginx' : (webServer === 'apache_fpm' ? t(APP_ID, 'Apache with PHP-FPM') : 'Apache')
}

/**
 * @param answeredBy - The web servers that answer a built-in path themselves
 */
function ruleNote(answeredBy: TrapPathList['builtin'][number]['answeredBy']): string {
	return t(APP_ID, 'Needs the web server rule on {servers}.', { servers: answeredBy.map(serverName).join(', ') })
}

const thisServer = computed(() => {
	const { webServer, needRule } = props.paths
	if (webServer === 'unknown') {
		return null
	}
	if (needRule.length === 0) {
		return t(APP_ID, 'On this server ({server}), your trap paths reach Nextcloud without the rule.', { server: serverName(webServer) })
	}
	return n(APP_ID, 'On this server ({server}), %n trap path reaches Nextcloud only with the rule: {paths}', 'On this server ({server}), %n trap paths reach Nextcloud only with the rule: {paths}', needRule.length, { server: serverName(webServer), paths: needRule.join(' ') })
})

/**
 * @param value - A path as typed
 */
function validate(value: string): string | null {
	if (!value.startsWith('/')) {
		return t(APP_ID, 'A path starts with /, for example /old-admin.')
	}
	const { maxLength, nextcloudSegments } = props.paths.limits
	if (value.length > maxLength || !/^\/[\x21-\x7E]*$/.test(value)) {
		return t(APP_ID, 'A path has no spaces and at most {max} characters.', { max: maxLength })
	}
	const path = value.toLowerCase().replace(/^\/index\.php(?=\/)/, '')
	if (nextcloudSegments.includes(path.slice(1).split('/')[0]!)) {
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
function save(key: string, change: { add?: string[], remove?: string[], builtinEnabled?: boolean, autodiscover?: boolean }, done: string) {
	const fallback = t(APP_ID, 'The trap paths could not be saved. Please try again.')
	error.value = null
	run(key, () => changeTrapPaths(change), {
		done,
		fallback,
		// A change of the list is shown at the list.
		handle: (e) => {
			if (key !== 'list') {
				return false
			}
			error.value = errorMessage(e, fallback)
			return true
		},
	})
}
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Trap paths')" :icon="mdiSignDirection">
		<template #description>
			{{ t(APP_ID, 'Scanners look for the weak spots of other software: WordPress logins, leaked configuration files, database tools. Nextcloud has none of them, so a visitor who is not logged in and asks for one is scanning your server. Logged-in users and clients never trip it.') }}
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

				<ShowMore
					:class="$style.builtin"
					variant="row"
					:label="t(APP_ID, 'What the built-in paths are')"
					:note="n(APP_ID, '%n path', '%n paths', paths.builtin.length)">
					<dl :class="$style.builtin__list">
						<div v-for="item in paths.builtin" :key="item.path" :class="$style.builtin__item">
							<dt><code>{{ item.path }}</code></dt>
							<dd>
								{{ item.text }}
								<span v-if="item.answeredBy.length > 0" :class="$style.builtin__rule">{{ ruleNote(item.answeredBy) }}</span>
							</dd>
						</div>
					</dl>
				</ShowMore>

				<div :class="$style.custom">
					<h4 :class="$style.subheading">
						{{ t(APP_ID, 'Your own paths') }}
					</h4>
					<ListEditor
						:items="paths.custom"
						:label="t(APP_ID, 'Add a path')"
						:placeholder="t(APP_ID, 'e.g. {example}', { example: '/old-admin/*' })"
						:validate="validate"
						:normalise="(value) => value.trim().toLowerCase()"
						:emptyText="t(APP_ID, 'None yet. A path matches exactly, or as a prefix when it ends with *.')"
						:max="paths.max"
						:busy="busy === 'list'"
						:error="error"
						@add="save('list', { add: $event }, t(APP_ID, 'Added: {paths}', { paths: $event.join(', ') }))"
						@remove="save('list', { remove: [$event] }, t(APP_ID, 'Removed: {path}', { path: $event }))" />
				</div>
			</div>
			<div :class="[$style.column, $style.snippets]">
				<h4 :class="$style.subheading">
					{{ t(APP_ID, 'Route the trap paths to Nextcloud') }}
				</h4>
				<p :class="$style.text">
					{{ t(APP_ID, 'Most trap paths reach Nextcloud on their own. Two common setups answer some of them first: nginx answers hidden paths such as /.env, and Apache with PHP-FPM answers .php paths such as /wp-login.php. This rule hands exactly the trap paths to Nextcloud, which then blocks the scanner.') }}
				</p>
				<p v-if="thisServer" :class="$style.text" data-test="trap-this-server">
					<strong>{{ thisServer }}</strong>
				</p>
				<ShowMore :label="t(APP_ID, 'Show the web server configuration')" data-test="trap-snippets">
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
						{{ t(APP_ID, 'These paths contain characters that are not put into a web server configuration automatically: {paths}. Add them by hand if you need them.', { paths: paths.snippetsSkipped.join(' ') }) }}
					</NcNoteCard>
					<p :class="$style.hint">
						{{ t(APP_ID, 'The snippet changes when you change the paths above. Reload the web server after you update it.') }}
					</p>
				</ShowMore>
			</div>
		</div>
	</SectionCard>
</template>

<style module>
.columns {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 420px), 1fr));
	gap: var(--ids-space-6);
	align-items: start;
}

.column {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
	min-width: 0;
}

.switches {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

.builtin {
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
}

.builtin__list {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr));
	gap: 0 var(--ids-space-5);
	margin: 0;
	padding: 0;
}

.builtin__item {
	display: grid;
	grid-template-columns: minmax(0, 9em) minmax(0, 1fr);
	gap: var(--ids-space-3);
	padding-block: var(--ids-space-2);
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

.builtin__rule {
	display: block;
	color: var(--color-main-text);
}

.custom {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
	padding-top: var(--ids-space-4);
	border-top: 1px solid var(--color-border);
}

.snippets {
	gap: var(--ids-space-3);
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
	composes: muted from '../../styles/shared.module.css';
	display: flex;
	gap: var(--ids-space-2);
	margin: 0;
	font-size: 0.9em;
}

@media (max-width: 600px) {
	.builtin__item {
		grid-template-columns: minmax(0, 1fr);
		gap: var(--ids-space-1);
	}
}
</style>
