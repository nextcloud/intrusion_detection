<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Check, Signature } from '../../types.ts'

import { mdiClose, mdiPlus, mdiRegex } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, useId, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import SelectField from '../common/SelectField.vue'
import ShowMore from '../common/ShowMore.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import StateBadge from '../common/StateBadge.vue'
import { useAction } from '../../composables/useAction.ts'
import { ApiError, checkSignatures, errorMessage } from '../../services/api.ts'
import { saveCheck } from '../../store.ts'
import { useSignatures } from '../../stores/settings.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	check: Check
}>()

const id = useId()
const { data: catalog, error: loadError } = useSignatures({ failure: () => t(APP_ID, 'The signatures could not be loaded.') })
const { busy, run } = useAction()
const weight = ref(3)
const pattern = ref('')
const patternError = ref<string | null>(null)

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
 * @param done - What to announce when it worked
 * @param before - Runs first, e.g. a check of the new value
 */
function save(key: string, params: Record<string, string[]>, done: string, before?: () => Promise<void>): Promise<boolean> {
	return run(key, async () => {
		await before?.()
		await saveCheck(props.check.id, { params })
	}, {
		done,
		fallback: t(APP_ID, 'The signatures could not be saved. Please try again.'),
		handle: (error) => {
			if (key === 'add' && error instanceof ApiError) {
				patternError.value = error.message
				return true
			}
			return false
		},
	})
}

/**
 * @param signature - The signature
 * @param on - Whether it counts
 */
function toggle(signature: Signature, on: boolean) {
	const disabled = (catalog.value?.signatures ?? []).filter((s) => !s.enabled && s.id !== signature.id).map((s) => s.id)
	if (!on) {
		disabled.push(signature.id)
	}
	save(signature.id, { disabled_signatures: disabled }, on ? t(APP_ID, 'Signature {id} is on.', { id: signature.id }) : t(APP_ID, 'Signature {id} is off.', { id: signature.id }))
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
	const added = await save('add', { custom_signatures: [...customEntries.value, entry] }, t(APP_ID, 'Your signature was added.'), async () => {
		let checked
		try {
			[checked] = (await checkSignatures([entry])).entries
		} catch (error) {
			throw new ApiError(errorMessage(error, t(APP_ID, 'The signature could not be checked. Please try again.')), null, { cause: error })
		}
		if (checked?.problemText) {
			throw new ApiError(checked.problemText)
		}
	})
	if (added) {
		pattern.value = ''
	}
}

/**
 * @param entry - The custom signature to remove
 */
function remove(entry: string) {
	save('remove:' + entry, { custom_signatures: customEntries.value.filter((e) => e !== entry) }, t(APP_ID, 'The signature was removed.'))
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
			<ShowMore
				v-for="group in groups"
				:key="group.id"
				:class="$style.group"
				variant="row"
				:label="group.name"
				:note="n(APP_ID, '%n signature', '%n signatures', group.signatures.length)">
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
			</ShowMore>

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
					<SelectField
						v-model="weight"
						:class="$style.custom__weight"
						:label="t(APP_ID, 'Weight')"
						:options="[1, 2, 3, 4, 5, 6, 7, 8, 9].map((w) => ({ value: w, label: String(w) }))"
						:disabled="busy !== null" />
					<NcTextField
						v-model="pattern"
						:class="$style.custom__pattern"
						:label="t(APP_ID, 'Regular expression')"
						spellcheck="false"
						autocomplete="off"
						:placeholder="t(APP_ID, 'e.g. {example}', { example: 'union\\s+distinct\\s+select' }, undefined, { escape: false, sanitize: false })"
						:maxlength="catalog.maxLength"
						:disabled="busy !== null"
						:error="(patternError ?? localProblem) !== null"
						:aria-describedby="`${id}-pattern-hint`"
						data-test="signature-pattern" />
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
	gap: var(--ids-space-2);
}

.sigs__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-2);
}

.sigs__heading {
	composes: eyebrow from '../../styles/shared.module.css';
	display: flex;
	align-items: center;
	gap: var(--ids-space-1-5);
	margin: 0;
}

.sigs__text {
	margin: 0;
	line-height: 1.6;
}

.muted {
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.9em;
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
}

.group {
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
}

.list {
	display: flex;
	flex-direction: column;
	margin: 0;
	padding: 0 var(--ids-space-2) var(--ids-space-2);
	list-style: none;
}

.sig {
	display: flex;
	align-items: center;
	gap: var(--ids-space-2);
	padding-block: var(--ids-space-1);
	border-top: 1px solid var(--color-border);
}

.custom .sig {
	padding-inline: var(--ids-space-2);
}

.sig_off .sig__text {
	color: var(--color-text-maxcontrast);
}

.sig__text {
	display: flex;
	flex: 1 1 auto;
	flex-direction: column;
	gap: var(--ids-space-half);
	min-width: 0;
	line-height: 1.45;
}

.sig__meta {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-1-5);
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
	gap: var(--ids-space-2);
	padding-top: var(--ids-space-2);
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
	gap: var(--ids-space-2);
}

.custom__form .custom__weight {
	flex: 0 0 110px;
}

.custom__form .custom__pattern {
	flex: 1 1 220px;
	margin: 0;
}

.custom__pattern :global(input) {
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
