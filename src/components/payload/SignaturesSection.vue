<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Check, Signature, Signatures } from '../../types.ts'

import { mdiClose, mdiPlus, mdiRegex } from '@mdi/js'
import { showError } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, onMounted, ref, useId, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import StateBadge from '../common/StateBadge.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { ApiError, checkSignatures, errorMessage, fetchSignatures, isCancelled, updateCheck } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { replaceCheck } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	check: Check
}>()

const id = useId()
const catalog = ref<Signatures | null>(null)
const loadError = ref<string | null>(null)
const busy = ref<string | null>(null)
const weight = ref(3)
const pattern = ref('')
const patternError = ref<string | null>(null)
const { announce } = useAnnouncer()

/**
 * Load the signatures.
 */
async function load() {
	try {
		catalog.value = await fetchSignatures()
		loadError.value = null
	} catch (error) {
		logger.error('Could not load the signatures', { error })
		loadError.value = errorMessage(error, t(APP_ID, 'The signatures could not be loaded.'))
	}
}

onMounted(load)
watch(() => props.check, load)
watch(pattern, () => {
	patternError.value = null
})

const groups = computed(() => {
	const signatures = catalog.value?.signatures ?? []
	return [
		{ id: 'sql', name: t(APP_ID, 'SQL injection'), signatures: signatures.filter((s) => s.group === 'sql') },
		{ id: 'payload', name: t(APP_ID, 'Attack code'), signatures: signatures.filter((s) => s.group === 'payload') },
	]
})
const disabledCount = computed(() => catalog.value?.signatures.filter((s) => !s.enabled).length ?? 0)
const customEntries = computed(() => catalog.value?.custom.map((c) => c.entry) ?? [])
const localProblem = computed(() => {
	const value = pattern.value.trim()
	if (value === '') {
		return null
	}
	// eslint-disable-next-line no-control-regex
	if (/[\u0000-\u001F\u007F]/.test(value)) {
		return t(APP_ID, 'The pattern must be one line.')
	}
	if (value.length + 2 > (catalog.value?.maxLength ?? 300)) {
		return t(APP_ID, 'The pattern is too long.')
	}
	return null
})

/**
 * Save new values of the check's signature settings.
 *
 * @param key - What is saved, for the loading state
 * @param params - The new values
 */
async function save(key: string, params: Record<string, string[]>): Promise<boolean> {
	busy.value = key
	try {
		replaceCheck(await updateCheck(props.check.id, { params }))
		return true
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not save the signatures', { error })
			if (key === 'add' && error instanceof ApiError) {
				patternError.value = error.message
			} else {
				showError(errorMessage(error, t(APP_ID, 'The signatures could not be saved. Please try again.')))
			}
		}
		return false
	} finally {
		busy.value = null
	}
}

/**
 * @param signature - The signature
 * @param on - Whether it counts
 */
async function toggle(signature: Signature, on: boolean) {
	const disabled = (catalog.value?.signatures ?? []).filter((s) => !s.enabled && s.id !== signature.id).map((s) => s.id)
	if (!on) {
		disabled.push(signature.id)
	}
	if (await save(signature.id, { disabled_signatures: disabled })) {
		announce(on ? t(APP_ID, 'Signature {id} is on.', { id: signature.id }) : t(APP_ID, 'Signature {id} is off.', { id: signature.id }))
	}
}

/**
 * Check the new signature on the server, then add it.
 */
async function add() {
	const body = pattern.value.trim()
	if (body === '' || localProblem.value !== null) {
		return
	}
	const entry = weight.value === catalog.value?.defaultWeight ? body : `${weight.value}:${body}`
	if (customEntries.value.includes(entry)) {
		patternError.value = t(APP_ID, 'This signature exists already.')
		return
	}
	busy.value = 'add'
	try {
		const [checked] = (await checkSignatures([entry])).entries
		if (checked?.problemText) {
			patternError.value = checked.problemText
			return
		}
	} catch (error) {
		patternError.value = errorMessage(error, t(APP_ID, 'The signature could not be checked. Please try again.'))
		return
	} finally {
		busy.value = null
	}
	if (await save('add', { custom_signatures: [...customEntries.value, entry] })) {
		pattern.value = ''
		announce(t(APP_ID, 'Your signature was added.'))
	}
}

/**
 * @param entry - The custom signature to remove
 */
async function remove(entry: string) {
	if (await save('remove:' + entry, { custom_signatures: customEntries.value.filter((e) => e !== entry) })) {
		announce(t(APP_ID, 'The signature was removed.'))
	}
}
</script>

<template>
	<section :class="$style.sigs" :aria-labelledby="`${id}-heading`">
		<div :class="$style.sigs__head">
			<h5 :id="`${id}-heading`" :class="$style.sigs__heading">
				<NcIconSvgWrapper inline :path="mdiRegex" :size="18" />
				{{ t(APP_ID, 'Signatures') }}
			</h5>
			<span v-if="catalog" :class="$style.muted">
				{{ t(APP_ID, 'Version {version}', { version: catalog.version }) }}
				<template v-if="disabledCount > 0"> · {{ n(APP_ID, '%n turned off', '%n turned off', disabledCount) }}</template>
			</span>
		</div>
		<p :class="$style.sigs__text">
			{{ t(APP_ID, 'Each signature adds its weight when it matches. A value fires when the weights add up to at least {weight}. Turn a signature off if an app on your server legitimately sends what it looks for.', { weight: catalog?.minWeight ?? 3 }) }}
		</p>

		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="catalog === null" :class="$style.skeleton">
			<SkeletonBlock v-for="i in 4" :key="i" height="36px" />
		</div>

		<template v-else>
			<details v-for="group in groups" :key="group.id" :class="$style.group">
				<summary :class="$style.group__summary">
					<span>{{ group.name }}</span>
					<span :class="$style.muted">{{ n(APP_ID, '%n signature', '%n signatures', group.signatures.length) }}</span>
				</summary>
				<ul :class="$style.list">
					<li v-for="signature in group.signatures" :key="signature.id" :class="[$style.sig, { [$style.sig_off]: !signature.enabled }]">
						<NcCheckboxRadioSwitch
							type="switch"
							:modelValue="signature.enabled"
							:loading="busy === signature.id"
							:disabled="busy !== null"
							@update:modelValue="toggle(signature, $event)">
							<span class="hidden-visually">{{ t(APP_ID, 'Use signature {id}', { id: signature.id }) }}</span>
						</NcCheckboxRadioSwitch>
						<span :class="$style.sig__text">
							<span>{{ signature.description }}</span>
							<span :class="$style.sig__meta">
								<code>{{ signature.id }}</code>
								<StateBadge v-if="signature.scope === 'encoded'" type="info">{{ t(APP_ID, 'only in base64') }}</StateBadge>
								<StateBadge v-if="signature.requiresOther">{{ t(APP_ID, 'only with another match') }}</StateBadge>
							</span>
						</span>
						<span :class="$style.weight" :title="t(APP_ID, 'Weight')">
							<span class="hidden-visually">{{ t(APP_ID, 'Weight') }}</span>
							{{ signature.weight }}
						</span>
					</li>
				</ul>
			</details>

			<div :class="$style.custom">
				<h6 :class="$style.custom__heading">
					{{ t(APP_ID, 'Your own signatures') }}
				</h6>
				<ul v-if="catalog.custom.length > 0" :class="$style.list">
					<li v-for="custom in catalog.custom" :key="custom.entry" :class="$style.sig">
						<span :class="$style.sig__text">
							<code :class="$style.pattern">{{ custom.pattern }}</code>
							<span v-if="custom.problemText" :class="$style.problem">{{ custom.problemText }} {{ t(APP_ID, 'It is skipped.') }}</span>
						</span>
						<span :class="$style.weight" :title="t(APP_ID, 'Weight')">
							<span class="hidden-visually">{{ t(APP_ID, 'Weight') }}</span>
							{{ custom.weight }}
						</span>
						<NcButton
							variant="tertiary"
							:aria-label="t(APP_ID, 'Remove signature {pattern}', { pattern: custom.pattern }, undefined, { escape: false, sanitize: false })"
							:disabled="busy !== null"
							@click="remove(custom.entry)">
							<template #icon>
								<NcLoadingIcon v-if="busy === 'remove:' + custom.entry" />
								<NcIconSvgWrapper v-else :path="mdiClose" />
							</template>
						</NcButton>
					</li>
				</ul>
				<p v-else :class="$style.muted">
					{{ t(APP_ID, 'None yet. Add a regular expression for attacks the built-in signatures miss; it runs on the normalised, lower-cased value.') }}
				</p>

				<form :class="$style.custom__form" @submit.prevent="add">
					<label :class="$style.custom__weight">
						<span>{{ t(APP_ID, 'Weight') }}</span>
						<select v-model.number="weight" :disabled="busy !== null">
							<option v-for="w in 9" :key="w" :value="w">{{ w }}</option>
						</select>
					</label>
					<label :class="$style.custom__pattern">
						<span>{{ t(APP_ID, 'Regular expression') }}</span>
						<input
							v-model="pattern"
							type="text"
							spellcheck="false"
							autocomplete="off"
							placeholder="union\s+distinct\s+select"
							:maxlength="catalog.maxLength"
							:disabled="busy !== null"
							:aria-invalid="(patternError ?? localProblem) ? 'true' : undefined"
							:aria-describedby="`${id}-pattern-hint`"
							data-test="signature-pattern">
					</label>
					<NcButton type="submit" variant="secondary" :disabled="busy !== null || pattern.trim() === '' || localProblem !== null">
						<template #icon>
							<NcLoadingIcon v-if="busy === 'add'" />
							<NcIconSvgWrapper v-else :path="mdiPlus" />
						</template>
						{{ t(APP_ID, 'Add') }}
					</NcButton>
					<p :id="`${id}-pattern-hint`" :class="[$style.custom__hint, { [$style.problem]: patternError ?? localProblem }]" data-test="signature-hint">
						{{ patternError ?? localProblem ?? t(APP_ID, 'Without delimiters. It is tested against long input before it is saved, so a slow pattern cannot overload the server.') }}
					</p>
				</form>
			</div>
		</template>
	</section>
</template>

<style module>
.sigs {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
}

.sigs__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
}

.sigs__heading {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1.5);
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.sigs__text {
	margin: 0;
	line-height: 1.6;
}

.muted {
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
}

.group {
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
}

.group__summary {
	display: flex;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
	min-height: var(--default-clickable-area);
	padding-inline: calc(var(--default-grid-baseline) * 3);
	border-radius: var(--border-radius-large);
	font-weight: 600;
	cursor: pointer;
}

.group__summary:hover {
	background-color: var(--color-background-hover);
}

.group__summary:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}

.list {
	display: flex;
	flex-direction: column;
	margin: 0;
	padding: 0 calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 2);
	list-style: none;
}

.sig {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-block: calc(var(--default-grid-baseline) * 1);
	border-top: 1px solid var(--color-border);
}

.custom .sig {
	padding-inline: calc(var(--default-grid-baseline) * 2);
}

.sig_off .sig__text {
	color: var(--color-text-maxcontrast);
}

.sig__text {
	display: flex;
	flex: 1 1 auto;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) / 2);
	min-width: 0;
	line-height: 1.45;
}

.sig__meta {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1.5);
}

.sig__meta code,
.pattern {
	color: var(--color-text-maxcontrast);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.8em;
	overflow-wrap: anywhere;
}

.pattern {
	color: var(--color-main-text);
	font-size: 0.9em;
}

.weight {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	min-width: 28px;
	height: 24px;
	border-radius: var(--border-radius-pill, 100px);
	background-color: var(--color-background-dark);
	font-size: 0.85em;
	font-weight: 700;
	font-variant-numeric: tabular-nums;
}

.custom {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-top: calc(var(--default-grid-baseline) * 2);
}

.custom__heading {
	margin: 0;
	font-size: 1em;
	font-weight: 700;
}

.custom .list {
	padding: 0;
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
}

.custom .list .sig:first-child {
	border-top: none;
}

.custom__form {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-end;
	gap: calc(var(--default-grid-baseline) * 2);
}

.custom__form label {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	font-weight: 600;
}

.custom__weight select {
	width: 5em;
	margin: 0;
}

.custom__pattern {
	flex: 1 1 220px;
}

.custom__pattern input {
	width: 100%;
	margin: 0;
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
}

.custom__hint {
	flex: 1 0 100%;
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.problem {
	color: var(--color-error-text);
	font-weight: 600;
}
</style>
