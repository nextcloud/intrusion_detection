<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban, Traps } from '../types.ts'

import { mdiLockOpenVariantOutline, mdiPlus, mdiShieldCheckOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, onActivated, onMounted, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import AddBanDialog from '../components/blocks/AddBanDialog.vue'
import BlocklistsPanel from '../components/blocks/BlocklistsPanel.vue'
import FirewallExportPanel from '../components/blocks/FirewallExportPanel.vue'
import LiftBanDialog from '../components/blocks/LiftBanDialog.vue'
import LiveSentence from '../components/checks/LiveSentence.vue'
import EmptyNote from '../components/common/EmptyNote.vue'
import ReferencePill from '../components/common/ReferencePill.vue'
import SettingsGroup from '../components/common/SettingsGroup.vue'
import SkeletonBlock from '../components/common/SkeletonBlock.vue'
import TimeStamp from '../components/common/TimeStamp.vue'
import DecoyCredentials from '../components/decoys/DecoyCredentials.vue'
import ReservedNamesCard from '../components/decoys/ReservedNamesCard.vue'
import TrapPathsCard from '../components/decoys/TrapPathsCard.vue'
import { errorMessage, fetchBans, fetchTraps } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { openDetectionId, refreshChecks, state } from '../store.ts'
import { APP_ID, formatAddress } from '../utils/format.ts'

const PAGE = 50
const bans = ref<Ban[]>([])
const hasMore = ref(false)
const activeCount = ref(0)
const showAll = ref(false)
const loading = ref(true)
const loadingMore = ref(false)
const error = ref<string | null>(null)
const liftTarget = ref<Ban | null>(null)
const adding = ref(false)

const traps = ref<Traps | null>(null)
const trapsError = ref<string | null>(null)
const decoysObserveWhileLearning = computed(() => state.status?.learning.active === true
	&& state.settings.find((s) => s.name === 'learning_decoys_act')?.value !== true)

const escalationSettings = computed(() => state.settings.filter((s) => ['ban_duration_1', 'ban_duration_2', 'ban_duration_3', 'ban_history_days', 'ban_net_after'].includes(s.name)))
const valveSettings = computed(() => state.settings.filter((s) => s.name === 'ban_shared_ip_users'))
const otherBlockSettings = computed(() => state.settings.filter((s) => s.group === 'blocks' && !escalationSettings.value.includes(s) && !valveSettings.value.includes(s)))

/**
 * Load the first page.
 */
async function load() {
	loading.value = bans.value.length === 0
	error.value = null
	try {
		const page = await fetchBans(showAll.value, PAGE, 0)
		bans.value = page.bans
		hasMore.value = page.hasMore
		activeCount.value = page.activeCount
	} catch (e) {
		logger.error('Could not load the blocks', { error: e })
		error.value = errorMessage(e, t(APP_ID, 'The blocks could not be loaded. Please reload the page.'))
	} finally {
		loading.value = false
	}
}

/**
 * Append the next page.
 */
async function loadMore() {
	loadingMore.value = true
	try {
		const page = await fetchBans(showAll.value, PAGE, bans.value.length)
		bans.value.push(...page.bans)
		hasMore.value = page.hasMore
	} catch (e) {
		logger.error('Could not load more blocks', { error: e })
	} finally {
		loadingMore.value = false
	}
}

/**
 * Load the decoys, reserved names and trap paths.
 */
async function loadTraps() {
	try {
		traps.value = await fetchTraps()
		trapsError.value = null
	} catch (e) {
		logger.error('Could not load the decoys', { error: e })
		trapsError.value = errorMessage(e, t(APP_ID, 'The decoys could not be loaded. Please reload the page.'))
	}
}

/**
 * The trap lists are also settings of their checks; keep the check cards in step.
 */
function checksChanged() {
	refreshChecks().catch((error) => logger.error('Could not reload the checks', { error }))
}

onMounted(() => {
	load()
	loadTraps()
})
onActivated(() => {
	load()
	loadTraps()
})
watch(showAll, () => {
	bans.value = []
	load()
})

/**
 * @param ban - A block
 */
function levelLabel(ban: Ban): string {
	return {
		1: t(APP_ID, 'First block'),
		2: t(APP_ID, 'Second block'),
		3: t(APP_ID, 'Repeat offender'),
	}[ban.level] ?? String(ban.level)
}

/**
 * @param ban - A block
 */
function openDetection(ban: Ban) {
	if (ban.detectionId !== null) {
		window.location.hash = `detection-${ban.detectionId}`
		openDetectionId.value = ban.detectionId
	}
}
</script>

<template>
	<div :class="$style.blocks">
		<section id="blocks-active" :class="$style.card" aria-labelledby="ids-bans-heading">
			<header :class="$style.card__head">
				<div>
					<h3 id="ids-bans-heading" :class="$style.card__heading">
						{{ showAll ? t(APP_ID, 'All blocks') : t(APP_ID, 'Active blocks') }}
					</h3>
					<p :class="$style.card__muted">
						{{ n(APP_ID, '%n address or network is blocked right now.', '%n addresses or networks are blocked right now.', activeCount) }}
					</p>
				</div>
				<div :class="$style.card__actions">
					<NcCheckboxRadioSwitch v-model="showAll" type="switch">
						{{ t(APP_ID, 'Show ended and lifted blocks') }}
					</NcCheckboxRadioSwitch>
					<NcButton variant="primary" @click="adding = true">
						<template #icon>
							<NcIconSvgWrapper :path="mdiPlus" />
						</template>
						{{ t(APP_ID, 'Block an address') }}
					</NcButton>
				</div>
			</header>

			<NcNoteCard v-if="error" type="error" :text="error" />

			<div v-if="loading" :class="$style.skeleton" aria-busy="true">
				<SkeletonBlock v-for="i in 4" :key="i" height="40px" />
			</div>

			<EmptyNote
				v-else-if="bans.length === 0 && !error"
				:name="showAll ? t(APP_ID, 'No blocks yet') : t(APP_ID, 'No address is blocked right now')"
				:description="t(APP_ID, 'Addresses that attack are blocked here automatically. You can also block one by hand.')"
				:icon="mdiShieldCheckOutline" />

			<ul v-else :class="$style.bans" :aria-label="showAll ? t(APP_ID, 'All blocks') : t(APP_ID, 'Active blocks')">
				<li
					v-for="ban in bans"
					:key="ban.id"
					:class="[$style.ban, { [$style.ban_ended]: !ban.active }]"
					data-test="ban-row">
					<div :class="$style.ban__address">
						<code :class="$style.cidr">{{ formatAddress(ban.cidr) }}</code>
						<span v-if="ban.scope === 'net'" :class="$style.tag">{{ t(APP_ID, 'network') }}</span>
					</div>
					<div :class="$style.ban__reason">
						<button
							v-if="ban.detectionId !== null"
							type="button"
							:class="$style.link"
							@click="openDetection(ban)">
							{{ ban.checkName }}
						</button>
						<span v-else>{{ ban.checkName }}</span>
						<span v-if="ban.createdBy" :class="$style.card__muted"> · {{ t(APP_ID, 'by {admin}', { admin: ban.createdBy }) }}</span>
						<span v-if="ban.note" :class="$style.note">{{ ban.note }}</span>
					</div>
					<div :class="$style.ban__until">
						<template v-if="ban.liftedAt">
							{{ t(APP_ID, 'Lifted by {admin}', { admin: ban.liftedBy ?? '' }) }}
						</template>
						<template v-else>
							<span class="hidden-visually">{{ ban.active ? t(APP_ID, 'Blocked until') : t(APP_ID, 'Ended') }}</span>
							<TimeStamp :timestamp="ban.expiresAt" short />
						</template>
						<span :class="$style.ban__level">{{ levelLabel(ban) }}</span>
					</div>
					<ReferencePill :class="$style.ban__reference" :reference="ban.reference" />
					<div :class="$style.ban__actions">
						<NcButton
							v-if="ban.active"
							variant="tertiary"
							:aria-label="t(APP_ID, 'Lift the block of {address}', { address: formatAddress(ban.cidr) })"
							:title="t(APP_ID, 'Lift block')"
							data-test="ban-lift"
							@click="liftTarget = ban">
							<template #icon>
								<NcIconSvgWrapper :path="mdiLockOpenVariantOutline" />
							</template>
						</NcButton>
					</div>
				</li>
			</ul>

			<div v-if="hasMore" :class="$style.more">
				<NcButton variant="secondary" :disabled="loadingMore" @click="loadMore">
					<template v-if="loadingMore" #icon>
						<NcLoadingIcon />
					</template>
					{{ t(APP_ID, 'Show more') }}
				</NcButton>
			</div>
		</section>

		<BlocklistsPanel id="blocks-lists" />

		<NcNoteCard v-if="decoysObserveWhileLearning" type="info">
			{{ t(APP_ID, 'While Nextcloud is learning, decoys only observe.') }}
		</NcNoteCard>
		<NcNoteCard v-if="trapsError" type="error" :text="trapsError" />
		<div v-else-if="traps === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock v-for="i in 2" :key="i" height="160px" />
		</div>
		<template v-else>
			<DecoyCredentials
				id="blocks-decoys"
				:decoys="traps.decoys"
				:check="traps.decoyCheck"
				:collisions="traps.decoyCollisions"
				@changed="traps.decoys = $event" />
			<ReservedNamesCard
				id="blocks-reserved"
				:reserved="traps.reservedNames"
				:check="traps.reservedCheck"
				@changed="traps.reservedNames = $event; checksChanged()" />
			<TrapPathsCard
				id="blocks-trap-paths"
				:paths="traps.trapPaths"
				:check="traps.trapCheck"
				@changed="traps.trapPaths = $event; checksChanged()" />
		</template>

		<FirewallExportPanel id="blocks-firewall" />

		<div id="blocks-escalation" :class="$style.blocks__explain">
			<section :class="$style.card" aria-labelledby="ids-escalation-heading">
				<h3 id="ids-escalation-heading" :class="$style.card__heading">
					{{ t(APP_ID, 'How blocks escalate') }}
				</h3>
				<SettingsGroup :settings="escalationSettings" :collapsedLabel="t(APP_ID, 'Change the durations')">
					<template #default="{ fill, changed }">
						<p :class="$style.card__text">
							<LiveSentence :segments="fill(state.templates.escalation ?? '')" :changed="changed" />
						</p>
					</template>
				</SettingsGroup>
			</section>

			<section :class="$style.card" aria-labelledby="ids-valve-heading">
				<h3 id="ids-valve-heading" :class="$style.card__heading">
					{{ t(APP_ID, 'Addresses that are never blocked') }}
				</h3>
				<SettingsGroup :settings="valveSettings">
					<template #default="{ fill, changed }">
						<p :class="$style.card__text">
							<LiveSentence
								:segments="fill(Number(state.settings.find((s) => s.name === 'ban_shared_ip_users')?.value) === 0 ? (state.templates.safetyValveOff ?? '') : (state.templates.safetyValve ?? ''))"
								:changed="changed" />
						</p>
						<p :class="$style.card__text">
							{{ state.templates.neverBlocked }}
							<a v-if="state.bruteForceSettingsUrl" :href="state.bruteForceSettingsUrl">{{ t(APP_ID, 'Edit the brute-force allowlist') }}</a>
						</p>
					</template>
				</SettingsGroup>
			</section>

			<section v-if="otherBlockSettings.length > 0" :class="$style.card" aria-labelledby="ids-flag-heading">
				<h3 id="ids-flag-heading" :class="$style.card__heading">
					{{ t(APP_ID, 'After an attack') }}
				</h3>
				<SettingsGroup :settings="otherBlockSettings" />
			</section>

			<NcNoteCard type="info">
				<p>
					<strong>{{ t(APP_ID, 'Locked yourself out?') }}</strong>
					{{ t(APP_ID, 'Run occ intrusion:bans:lift with the address or the reference. To turn off every check of requests at once, set intrusion_detection.disable_guards to true in config.php.') }}
				</p>
			</NcNoteCard>
		</div>

		<LiftBanDialog :ban="liftTarget" @close="liftTarget = null" @lifted="load" />
		<AddBanDialog v-model:open="adding" @added="load" />
	</div>
</template>

<style module>
.blocks {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.blocks__explain {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 380px), 1fr));
	gap: calc(var(--default-grid-baseline) * 5);
	align-items: start;
}

.card {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	min-width: 0;
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.card__head {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 3);
}

.card__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.card__muted {
	margin: calc(var(--default-grid-baseline) * 1) 0 0;
	color: var(--color-text-maxcontrast);
}

.card__text {
	margin: 0;
	line-height: 1.6;
}

.card__actions {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
}

/* One row per block. The columns line up across rows, and Lift always stays in view. */
.bans {
	display: flex;
	flex-direction: column;
	margin: 0;
	padding: 0;
	list-style: none;
	container-type: inline-size;
}

.ban {
	display: grid;
	grid-template-columns: minmax(11em, 1fr) minmax(0, 2fr) minmax(8em, auto) auto var(--default-clickable-area);
	grid-template-areas: 'address reason until reference actions';
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 4);
	padding-block: calc(var(--default-grid-baseline) * 2);
	border-bottom: 1px solid var(--color-border);
}

.ban:last-child {
	border-bottom: none;
}

.ban__address {
	grid-area: address;
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 2);
	min-width: 0;
}

.ban__reason {
	grid-area: reason;
	min-width: 0;
	overflow-wrap: anywhere;
}

.ban__until {
	grid-area: until;
	display: flex;
	flex-direction: column;
	font-variant-numeric: tabular-nums;
}

.ban__level {
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
}

.ban__reference {
	grid-area: reference;
	justify-self: start;
}

.ban__actions {
	grid-area: actions;
	display: flex;
	justify-content: flex-end;
}

.ban_ended {
	color: var(--color-text-maxcontrast);
}

/* Narrow: two compact lines, the address and the time first, Lift on the right */
@container (max-width: 720px) {
	.ban {
		grid-template-columns: minmax(0, 1fr) auto var(--default-clickable-area);
		grid-template-areas:
			'address until actions'
			'reason reference actions';
		gap: calc(var(--default-grid-baseline) / 2) calc(var(--default-grid-baseline) * 3);
		padding-block: calc(var(--default-grid-baseline) * 1.5);
	}

	.ban__until {
		align-items: flex-end;
		font-size: 0.9em;
	}

	.ban__level {
		display: none;
	}

	.ban__reason {
		overflow: hidden;
		color: var(--color-text-maxcontrast);
		font-size: 0.9em;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.ban__reason .note {
		display: inline;
	}

	.ban__reason .note::before {
		content: ' · ';
	}
}

.card__text a {
	color: var(--color-main-text);
	text-decoration: underline;
	text-underline-offset: 3px;
}

.cidr {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	white-space: nowrap;
}

.tag {
	margin-inline-start: calc(var(--default-grid-baseline) * 2);
	padding-inline: calc(var(--default-grid-baseline) * 1.5);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
}

.note {
	display: block;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.ban__reason button.link {
	margin: 0;
	text-align: start;
	white-space: normal;
	padding: 0;
	min-height: 0;
	border: none;
	background: none;
	color: var(--color-main-text);
	font-weight: normal;
	text-decoration: underline;
	text-decoration-color: var(--color-border-dark, var(--color-border));
	text-underline-offset: 3px;
	cursor: pointer;
}

.ban__reason button.link:hover,
.ban__reason button.link:focus-visible {
	text-decoration-color: currentColor;
}

.more {
	display: flex;
	justify-content: center;
}

@media (max-width: 600px) {
	.card {
		padding: calc(var(--default-grid-baseline) * 3);
	}
}
</style>
