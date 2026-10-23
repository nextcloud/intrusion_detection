<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { TabDefinition } from '../../extensions.ts'

import { mdiAlertCircleOutline, mdiCheckCircleOutline, mdiFire, mdiLockOutline, mdiPauseCircleOutline, mdiServerSecurity, mdiShieldOutline, mdiTimerCogOutline } from '@mdi/js'
import { computed, ref } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import AdminTabs from '../AdminTabs.vue'
import CodeBlock from '../common/CodeBlock.vue'
import SectionCard from '../common/SectionCard.vue'
import ShowMore from '../common/ShowMore.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import StateBadge from '../common/StateBadge.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { useAction } from '../../composables/useAction.ts'
import { saveSettings, state } from '../../store.ts'
import { useFirewallExport } from '../../stores/blocks.ts'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const { data: exportState, error: loadError } = useFirewallExport({ failure: () => t(APP_ID, 'The firewall export could not be loaded. Please reload the page.') })
const { busy: saving, run } = useAction()
const snippetTab = ref('nftables')

const FORMATS = [
	{ id: 'nft', file: 'bans.nft', text: () => t(APP_ID, 'An nftables script that refills the sets of table inet nextcloud_ids, each address with its remaining time.') },
	{ id: 'ipset', file: 'bans.ipset', text: () => t(APP_ID, 'For ipset restore, if your firewall uses iptables.') },
	{ id: 'log', file: 'bans.log', text: () => t(APP_ID, 'One line per block and lift, for fail2ban. Rotated at 10 MB.') },
	{ id: 'txt', file: 'bans.txt', text: () => t(APP_ID, 'One address or network per line, with its end and reference, for your own scripts.') },
]

const snippetTabs: TabDefinition[] = [
	{ id: 'nftables', name: () => 'nftables', icon: mdiShieldOutline },
	{ id: 'ipset', name: () => 'ipset', icon: mdiShieldOutline },
	{ id: 'fail2ban', name: () => 'fail2ban', icon: mdiFire },
	{ id: 'systemd', name: () => 'systemd', icon: mdiTimerCogOutline },
]

const SNIPPETS: Record<string, { ids: string[], intro: () => string }> = {
	nftables: {
		ids: ['nftables', 'nft_loader'],
		intro: () => t(APP_ID, 'Load the table once with your firewall rules. The loader fills its sets from bans.nft; it checks every line first, so the file can only ever fill these sets.'),
	},
	ipset: {
		ids: ['ipset'],
		intro: () => t(APP_ID, 'Create the sets and the iptables rules once, as the comments say, then run the loader whenever bans.ipset changes.'),
	},
	fail2ban: {
		ids: ['fail2ban_filter', 'fail2ban_jail'],
		intro: () => t(APP_ID, 'fail2ban reads bans.log and blocks each address with its own firewall rules. It uses one block duration for all addresses, here the duration of a first block.'),
	},
	systemd: {
		ids: ['systemd_path', 'systemd_service'],
		intro: () => t(APP_ID, 'A path unit runs the nftables loader as root whenever Nextcloud replaces bans.nft. Nextcloud rewrites the file in its background job, at most a minute after a block changes when cron runs every minute (otherwise at the next cron run), so blocks reach the firewall that much later than Nextcloud itself. Enable it with systemctl enable --now nextcloud-ids-firewall.path.'),
	},
}

const SNIPPET_LABELS: Record<string, () => string> = {
	nftables: () => t(APP_ID, 'nftables table'),
	nft_loader: () => t(APP_ID, 'nftables loader'),
	ipset: () => t(APP_ID, 'ipset loader'),
	fail2ban_filter: () => t(APP_ID, 'fail2ban filter'),
	fail2ban_jail: () => t(APP_ID, 'fail2ban jail'),
	systemd_path: () => t(APP_ID, 'systemd path unit'),
	systemd_service: () => t(APP_ID, 'systemd service'),
}

const shownSnippets = computed(() => (SNIPPETS[snippetTab.value]?.ids ?? [])
	.map((id) => exportState.value?.snippets.find((s) => s.id === id))
	.filter((s) => s !== undefined))

const formats = computed<string[]>(() => {
	const value = state.settings.find((s) => s.name === 'export_formats')?.value
	return Array.isArray(value) ? value : (exportState.value?.formats ?? [])
})

const status = computed(() => {
	const current = exportState.value
	if (current === null) {
		return null
	}
	if (current.directory === null) {
		return { type: 'neutral' as const, icon: mdiPauseCircleOutline, text: t(APP_ID, 'Not set up') }
	}
	if (current.error !== null) {
		return { type: 'error' as const, icon: mdiAlertCircleOutline, text: t(APP_ID, 'Not working') }
	}
	if (!current.active) {
		return { type: 'neutral' as const, icon: mdiPauseCircleOutline, text: t(APP_ID, 'No format chosen') }
	}
	return { type: 'success' as const, icon: mdiCheckCircleOutline, text: t(APP_ID, 'Writing') }
})

const configLine = computed(() => `'${exportState.value?.configKey ?? 'intrusion_detection.export_dir'}' => '${exportState.value?.exampleDirectory ?? '/var/lib/nextcloud-ids'}',`)

/**
 * Switch one format on or off.
 *
 * @param id - The format
 * @param on - Whether to write it
 */
function setFormat(id: string, on: boolean) {
	const next = on ? [...new Set([...formats.value, id])] : formats.value.filter((f) => f !== id)
	run(id, () => saveSettings({ export_formats: next }), {
		done: on ? t(APP_ID, '{file} is written from now on.', { file: `bans.${id}` }) : t(APP_ID, '{file} is no longer written.', { file: `bans.${id}` }),
		fallback: t(APP_ID, 'The formats could not be saved. Please try again.'),
	})
}
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Firewall export')" :icon="mdiServerSecurity">
		<template #description>
			{{ t(APP_ID, 'Writes the active blocks into files your firewall or fail2ban reads, so blocked addresses are dropped before they reach the web server.') }}
		</template>
		<template v-if="status" #actions>
			<StateBadge :type="status.type" :icon="status.icon">
				{{ status.text }}
			</StateBadge>
		</template>

		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="exportState === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock height="64px" />
			<SkeletonBlock height="120px" />
		</div>

		<template v-else>
			<div v-if="exportState.directory === null" :class="$style.setup" data-test="export-setup">
				<p>{{ t(APP_ID, 'To switch it on, set a directory in config.php that the web server user can write to, outside the Nextcloud folder and the data directory:') }}</p>
				<pre :class="$style.config"><code>{{ configLine }}</code></pre>
				<p :class="$style.muted">
					{{ t(APP_ID, 'This page cannot set it, so that an administrator account cannot make Nextcloud write files anywhere on the server.') }}
				</p>
			</div>

			<dl v-else :class="$style.facts">
				<div :class="$style.fact">
					<dt>{{ t(APP_ID, 'Export directory') }}</dt>
					<dd>
						<span :class="$style.path">
							<NcIconSvgWrapper
								inline
								:path="mdiLockOutline"
								:size="16"
								:name="t(APP_ID, 'Read-only')" />
							<code>{{ exportState.directory }}</code>
						</span>
						<span :class="$style.fact__hint">{{ t(APP_ID, 'Set in config.php only') }}</span>
					</dd>
				</div>
				<div :class="$style.fact">
					<dt>{{ t(APP_ID, 'Last written') }}</dt>
					<dd>
						<TimeStamp v-if="exportState.lastWriteAt" :timestamp="exportState.lastWriteAt" />
						<span v-else :class="$style.muted">{{ t(APP_ID, 'Never') }}</span>
						<span v-if="exportState.lastWriteAt" :class="$style.fact__hint">
							{{ n(APP_ID, '%n block in the files', '%n blocks in the files', exportState.entries) }}
						</span>
					</dd>
				</div>
				<div :class="$style.fact">
					<dt>{{ t(APP_ID, 'Files') }}</dt>
					<dd>
						<span v-if="exportState.files.length > 0" :class="$style.files">
							<code v-for="file in exportState.files" :key="file">{{ file }}</code>
						</span>
						<span v-else :class="$style.muted">{{ t(APP_ID, 'None') }}</span>
					</dd>
				</div>
			</dl>

			<NcNoteCard v-if="exportState.directory !== null && exportState.error" type="error">
				<p>
					<strong>{{ t(APP_ID, 'The files cannot be written.') }}</strong>
					{{ exportState.errorText }}
				</p>
				<p v-if="exportState.errorAt">
					{{ t(APP_ID, 'Since') }} <TimeStamp :timestamp="exportState.errorAt" />
				</p>
			</NcNoteCard>

			<fieldset v-if="exportState.directory !== null" :class="$style.formats">
				<legend :class="$style.formats__legend">
					{{ t(APP_ID, 'Formats') }}
				</legend>
				<div :class="$style.formats__grid">
					<div v-for="format in FORMATS" :key="format.id" :class="[$style.format, { [$style.format_on]: formats.includes(format.id) }]">
						<NcCheckboxRadioSwitch
							type="switch"
							:modelValue="formats.includes(format.id)"
							:loading="saving === format.id"
							:disabled="saving !== null"
							:description="format.text()"
							@update:modelValue="setFormat(format.id, $event)">
							<code :class="$style.format__file">{{ format.file }}</code>
						</NcCheckboxRadioSwitch>
					</div>
				</div>
			</fieldset>

			<ShowMore
				:class="$style.snippets"
				:label="t(APP_ID, 'Show the firewall setup')"
				:note="t(APP_ID, 'nftables, ipset, fail2ban, systemd')"
				data-test="firewall-setup">
				<p :class="$style.muted">
					{{ exportState.snippetsUseDirectory
						? t(APP_ID, 'Copy these files as root. They are filled in with your export directory.')
						: t(APP_ID, 'Copy these files as root. They use {dir} as an example: replace it with your export directory.', { dir: exportState.exampleDirectory }) }}
				</p>
				<AdminTabs v-model="snippetTab" :tabs="snippetTabs" />
				<div
					:id="`ids-panel-${snippetTab}`"
					role="tabpanel"
					:aria-labelledby="`ids-tab-${snippetTab}`"
					:class="$style.snippets__panel">
					<p :class="$style.snippets__intro">
						{{ SNIPPETS[snippetTab]?.intro() }}
					</p>
					<CodeBlock
						v-for="snippet in shownSnippets"
						:key="snippet.id"
						:content="snippet.content"
						:file="snippet.file"
						:label="SNIPPET_LABELS[snippet.id]?.() ?? snippet.id" />
				</div>
			</ShowMore>
		</template>
	</SectionCard>
</template>

<style module>
.skeleton {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
}

.muted {
	composes: muted from '../../styles/shared.module.css';
}

.facts {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr));
	gap: var(--ids-space-3);
	margin: 0;
}

.fact {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
	min-width: 0;
	padding: var(--ids-space-3) var(--ids-space-4);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.fact dt,
.fact dd {
	text-align: start;
}

.fact dt {
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.fact dd {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-half);
	margin: 0;
	font-weight: 600;
}

.fact__hint {
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.85em;
	font-weight: normal;
}

.path {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1-5);
	min-width: 0;
}

.path code,
.files code,
.format__file {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.95em;
	overflow-wrap: anywhere;
}

.files {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
}

.config {
	margin: var(--ids-space-2) 0;
	padding: var(--ids-space-2) var(--ids-space-3);
	overflow-x: auto;
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.9em;
}

.formats {
	min-width: 0;
	margin: 0;
	padding: 0;
	border: none;
}

.formats__legend {
	margin-bottom: var(--ids-space-2);
	padding: 0;
	font-weight: 700;
}

.formats__grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 250px), 1fr));
	gap: var(--ids-space-2);
}

.format {
	padding: var(--ids-space-2) var(--ids-space-3);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	transition: border-color 150ms ease, background-color 150ms ease;
}

.format_on {
	border-color: color-mix(in srgb, var(--color-primary-element) 45%, var(--color-border));
	background-color: color-mix(in srgb, var(--color-primary-element) 6%, var(--color-main-background));
}

.setup p {
	margin: 0;
	max-width: 80ch;
	line-height: 1.5;
}

.snippets {
	padding-top: var(--ids-space-3);
	border-top: 1px solid var(--color-border);
}

.snippets p {
	margin: 0;
	line-height: 1.5;
}

.snippets__panel {
	margin-top: var(--ids-space-3);
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

.snippets__intro {
	max-width: 80ch;
}

@media (prefers-reduced-motion: reduce) {
	.format {
		transition: none;
	}
}
</style>
