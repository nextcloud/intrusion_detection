<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Check, ParamValue } from '../../types.ts'

import { mdiFilterVariant, mdiFlaskOutline, mdiOpenInNew, mdiRestore } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, inject, reactive, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import LiveSentence from './LiveSentence.vue'
import ParamField from './ParamField.vue'
import SimulationDialog from './SimulationDialog.vue'
import { useAction } from '../../composables/useAction.ts'
import { checkSections } from '../../extensions.ts'
import { ApiError } from '../../services/api.ts'
import { detectionFilters, globalTypes, globalValues, resetCheckToDefaults, saveCheck, state } from '../../store.ts'
import { APP_ID, fillTemplate } from '../../utils/format.ts'
import { validateParam } from '../../utils/validate.ts'

const props = defineProps<{
	check: Check
}>()

const showTab = inject<(tab: string) => void>('ids-show-tab', () => {})

const missingRequirement = computed(() => props.check.requirements.find((r) => !r.met) ?? null)

/* Settings and responses: edited as a draft and saved together. */

const draft = reactive<Record<string, unknown>>({})
const selected = ref<string[]>([])
const serverErrors = reactive<Record<string, string>>({})
const { busy, run } = useAction()
const saving = computed(() => busy.value === 'save')
const resetOpen = ref(false)

const savedResponses = computed(() => props.check.responses.filter((r) => r.selected).map((r) => r.type))

watch(() => props.check, (check, old) => {
	for (const param of check.params) {
		const before = old?.params.find((p) => p.name === param.name)
		// Edits the admin has not saved yet survive a reload of the check (e.g. after a mode change).
		if (before === undefined || !(param.name in draft) || same(draft[param.name], before.value)) {
			draft[param.name] = param.value
		}
	}
	if (old === undefined || sameList(selected.value, old.responses.filter((r) => r.selected).map((r) => r.type))) {
		selected.value = check.responses.filter((r) => r.selected).map((r) => r.type)
	}
}, { immediate: true })

const validation = computed(() => Object.fromEntries(props.check.params.map((param) => [param.name, validateParam(param, draft[param.name])])))

const errors = computed<Record<string, string | null>>(() => Object.fromEntries(props.check.params.map((param) => [
	param.name,
	validation.value[param.name]?.error ?? serverErrors[param.name] ?? null,
])))

const changedParams = computed(() => props.check.params
	.filter((param) => {
		const value = validation.value[param.name]?.value
		return value !== undefined && !same(value, param.value)
	})
	.map((param) => param.name))

const responsesChanged = computed(() => !sameList(selected.value, savedResponses.value))
const hasErrors = computed(() => props.check.params.some((param) => validation.value[param.name]?.error))
const dirty = computed(() => changedParams.value.length > 0 || responsesChanged.value || hasErrors.value)

/** The live values: what is typed where valid, the saved value elsewhere */
const values = computed<Record<string, ParamValue>>(() => ({
	...globalValues.value,
	...Object.fromEntries(props.check.params.map((param) => [param.name, validation.value[param.name]?.value ?? param.value])),
}))
const types = computed(() => ({ ...globalTypes.value, ...Object.fromEntries(props.check.params.map((p) => [p.name, p.type])) }))

const decides = computed(() => fillTemplate(props.check.decidesTemplate, values.value, types.value))
const happens = computed(() => props.check.responses
	.filter((r) => selected.value.includes(r.type))
	.sort((a, b) => a.order - b.order)
	.map((r) => ({ type: r.type, segments: fillTemplate(r.happens, values.value, types.value) })))

/**
 * Save the changed settings and responses.
 */
async function save() {
	if (hasErrors.value) {
		return
	}
	Object.keys(serverErrors).forEach((key) => delete serverErrors[key])
	const params = Object.fromEntries(changedParams.value.map((name) => [name, validation.value[name]!.value!]))
	await run('save', async () => {
		const updated = await saveCheck(props.check.id, {
			params,
			responses: responsesChanged.value ? [...selected.value] : undefined,
		})
		takeSaved(updated)
	}, {
		done: t(APP_ID, 'Saved: {check}', { check: props.check.texts.name }),
		fallback: t(APP_ID, 'The changes could not be saved. Please try again.'),
		handle: (error) => {
			if (error instanceof ApiError && error.param !== null && props.check.params.some((p) => p.name === error.param)) {
				serverErrors[error.param] = error.message
				return true
			}
			return false
		},
	})
}

/**
 * Take the check as saved into the form.
 *
 * @param updated - The check as the server returned it
 */
function takeSaved(updated: Check) {
	for (const param of updated.params) {
		draft[param.name] = param.value
	}
	selected.value = updated.responses.filter((r) => r.selected).map((r) => r.type)
}

/**
 * Throw away the unsaved changes.
 */
function discard() {
	for (const param of props.check.params) {
		draft[param.name] = param.value
	}
	selected.value = [...savedResponses.value]
	Object.keys(serverErrors).forEach((key) => delete serverErrors[key])
}

/**
 * Put the check back to its defaults, after the confirmation.
 */
async function reset() {
	const done = await run('reset', async () => takeSaved(await resetCheckToDefaults(props.check.id)), {
		done: t(APP_ID, '{check} is back to its defaults.', { check: props.check.texts.name }),
		fallback: t(APP_ID, 'The check could not be reset. Please try again.'),
	})
	if (done) {
		resetOpen.value = false
	}
}

/**
 * "Show recent detections": the overview, filtered to this check.
 */
function showDetections() {
	Object.assign(detectionFilters, { check: props.check.id, severity: '', user: '', address: '', mode: '' })
	showTab('overview')
}

/** Settings that a card section edits itself are left out of the settings form */
const formParams = computed(() => {
	const replaced = checkSections
		.filter((section) => section.checks.length === 0 || section.checks.includes(props.check.id))
		.flatMap((section) => section.replacesParams ?? [])
	return props.check.params.filter((param) => !replaced.includes(param.name))
})

const simulating = ref(false)

const sectionsAfter = (after: string) => checkSections.filter((section) => section.after === after && (section.checks.length === 0 || section.checks.includes(props.check.id)))

const learnMoreUrl = computed(() => state.docUrl ? `${state.docUrl}#check-${props.check.id}` : '')

/**
 * @param a - A value
 * @param b - Another value
 */
function same(a: unknown, b: unknown): boolean {
	return Array.isArray(a) && Array.isArray(b) ? sameList(a.map(String), b.map(String)) : a === b
}

/**
 * @param a - A list
 * @param b - Another list
 */
function sameList(a: string[], b: string[]): boolean {
	return a.length === b.length && a.every((item) => b.includes(item))
}
</script>

<template>
	<article
		:class="$style.card"
		:aria-label="t(APP_ID, 'Customise {check}', { check: check.texts.name })">
		<div :class="$style.card__inner">
			<NcNoteCard v-if="missingRequirement" type="warning">
				{{ missingRequirement.text }} {{ t(APP_ID, 'Until then it stays off, and only Off can be chosen.') }}
			</NcNoteCard>

			<div :class="$style.card__body">
				<div :class="$style.card__explain">
					<section :class="$style.section">
						<h5 :class="$style.section__heading">
							{{ t(APP_ID, 'What it detects') }}
						</h5>
						<p>{{ check.texts.detects }}</p>
					</section>
					<component
						:is="section.component"
						v-for="section in sectionsAfter('detects')"
						:key="section.id"
						:check="check" />

					<section :class="$style.section">
						<h5 :class="$style.section__heading">
							{{ t(APP_ID, 'How it decides') }}
						</h5>
						<p data-test="decides">
							<LiveSentence :segments="decides" :changed="changedParams" />
						</p>
					</section>
					<component
						:is="section.component"
						v-for="section in sectionsAfter('decides')"
						:key="section.id"
						:check="check" />

					<section :class="$style.section">
						<h5 :class="$style.section__heading">
							{{ check.mode.effective === 'protect' ? t(APP_ID, 'What happens') : t(APP_ID, 'What would happen in Protect mode') }}
						</h5>
						<ul v-if="happens.length > 0" :class="$style.section__list" data-test="happens">
							<li v-for="item in happens" :key="item.type">
								<LiveSentence :segments="item.segments" :changed="changedParams" />
							</li>
						</ul>
						<p v-else>
							{{ t(APP_ID, 'Nothing is done; detections are only recorded.') }}
						</p>
					</section>
					<component
						:is="section.component"
						v-for="section in sectionsAfter('happens')"
						:key="section.id"
						:check="check" />

					<section :class="$style.section">
						<h5 :class="$style.section__heading">
							{{ t(APP_ID, 'When it may be wrong') }}
						</h5>
						<p>{{ check.texts.wrong }}</p>
					</section>
					<component
						:is="section.component"
						v-for="section in sectionsAfter('wrong')"
						:key="section.id"
						:check="check" />

					<div :class="$style.card__facts">
						<section :class="$style.section">
							<h5 :class="$style.section__heading">
								{{ t(APP_ID, 'Cost') }}
							</h5>
							<p>{{ check.cost.text }}</p>
						</section>
						<section :class="$style.section">
							<h5 :class="$style.section__heading">
								{{ t(APP_ID, 'Data') }}
							</h5>
							<p>{{ check.texts.data }}</p>
							<p v-if="check.sendsData" :class="$style.section__warning">
								{{ t(APP_ID, 'This check contacts an external service.') }}
							</p>
						</section>
					</div>
					<component
						:is="section.component"
						v-for="section in [...sectionsAfter('cost'), ...sectionsAfter('data')]"
						:key="section.id"
						:check="check" />
				</div>

				<form :class="$style.card__configure" @submit.prevent="save">
					<fieldset v-if="check.responses.length > 0" :class="$style.fieldset">
						<legend :class="$style.fieldset__legend">
							{{ t(APP_ID, 'Responses') }}
						</legend>
						<NcCheckboxRadioSwitch
							v-for="response in check.responses"
							:key="response.type"
							v-model="selected"
							:value="response.type"
							:disabled="saving"
							type="checkbox">
							{{ response.label }}
						</NcCheckboxRadioSwitch>
					</fieldset>

					<fieldset v-if="formParams.length > 0" :class="$style.fieldset">
						<legend :class="$style.fieldset__legend">
							{{ t(APP_ID, 'Settings') }}
						</legend>
						<ParamField
							v-for="param in formParams"
							:key="param.name"
							v-model="draft[param.name]"
							:param="param"
							:error="errors[param.name]"
							:disabled="saving" />
					</fieldset>
					<component
						:is="section.component"
						v-for="section in sectionsAfter('settings')"
						:key="section.id"
						:check="check" />

					<div :class="$style.card__save">
						<NcButton type="submit" variant="primary" :disabled="!dirty || hasErrors || saving">
							<template v-if="saving" #icon>
								<NcLoadingIcon />
							</template>
							{{ t(APP_ID, 'Save changes') }}
						</NcButton>
						<NcButton
							v-if="dirty"
							variant="tertiary"
							:disabled="saving"
							@click="discard">
							{{ t(APP_ID, 'Discard') }}
						</NcButton>
					</div>
				</form>
			</div>

			<div :class="$style.card__footer">
				<NcButton variant="secondary" @click="showDetections">
					<template #icon>
						<NcIconSvgWrapper :path="mdiFilterVariant" />
					</template>
					{{ t(APP_ID, 'Show recent detections') }}
				</NcButton>
				<NcButton v-if="check.simulatable" variant="secondary" @click="simulating = true">
					<template #icon>
						<NcIconSvgWrapper :path="mdiFlaskOutline" />
					</template>
					{{ t(APP_ID, 'Simulate') }}
				</NcButton>
				<NcButton variant="tertiary" @click="resetOpen = true">
					<template #icon>
						<NcIconSvgWrapper :path="mdiRestore" />
					</template>
					{{ t(APP_ID, 'Reset to defaults') }}
				</NcButton>
				<NcButton
					v-if="learnMoreUrl"
					variant="tertiary"
					:href="learnMoreUrl"
					target="_blank"
					rel="noreferrer noopener">
					<template #icon>
						<NcIconSvgWrapper :path="mdiOpenInNew" />
					</template>
					{{ t(APP_ID, 'Learn more') }}
				</NcButton>
			</div>
		</div>

		<SimulationDialog v-if="check.simulatable" v-model:open="simulating" :check="check" />

		<NcDialog
			v-model:open="resetOpen"
			:name="t(APP_ID, 'Reset {check}?', { check: check.texts.name })"
			:message="t(APP_ID, 'Its mode, responses and settings go back to the defaults. Detections and blocks stay as they are.')"
			:buttons="[
				{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
				{ label: t(APP_ID, 'Reset to defaults'), variant: 'error', callback: () => { reset(); return false } },
			]" />
	</article>
</template>

<style module>
.card {
	min-width: 0;
	padding-top: calc(var(--default-grid-baseline) * 4);
	border-top: 1px solid var(--color-border);
}

.card__inner {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	min-width: 0;
}

.card__body {
	display: grid;
	grid-template-columns: minmax(0, 3fr) minmax(280px, 2fr);
	gap: calc(var(--default-grid-baseline) * 6);
	padding-top: calc(var(--default-grid-baseline) * 2);
}

.card__explain {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	min-width: 0;
}

.card__facts {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
	gap: calc(var(--default-grid-baseline) * 4);
}

.section p {
	margin: 0;
	line-height: 1.6;
}

.section__heading {
	margin: 0 0 calc(var(--default-grid-baseline) * 1);
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.section__list {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
	margin: 0;
	padding-inline-start: calc(var(--default-grid-baseline) * 5);
	list-style: disc;
	line-height: 1.6;
}

.section__warning {
	margin-top: calc(var(--default-grid-baseline) * 1) !important;
	color: var(--color-warning-text);
	font-weight: 600;
}

.card__configure {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
	align-self: start;
	padding: calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.fieldset {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	min-width: 0;
	margin: 0;
	padding: 0;
	border: none;
}

.fieldset__legend {
	margin-bottom: calc(var(--default-grid-baseline) * 2);
	padding: 0;
	font-size: 1em;
	font-weight: 700;
}

.card__save {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
}

.card__footer {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-top: calc(var(--default-grid-baseline) * 3);
	border-top: 1px solid var(--color-border);
}

@media (max-width: 900px) {
	.card__body {
		grid-template-columns: minmax(0, 1fr);
	}
}

</style>
