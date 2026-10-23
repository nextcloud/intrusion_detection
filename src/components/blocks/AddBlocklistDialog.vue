<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Blocklist, ListPurpose } from '../../types.ts'

import { t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import SelectField from '../common/SelectField.vue'
import { useAction } from '../../composables/useAction.ts'
import { ApiError } from '../../services/api.ts'
import { modeLabel } from '../../store.ts'
import { addBlocklist } from '../../stores/blocks.ts'
import { APP_ID } from '../../utils/format.ts'
import { httpsUrlProblem, listIdProblem } from '../../utils/validate.ts'

const open = defineModel<boolean>('open', { required: true })

const props = defineProps<{
	/** Names in use */
	existing: string[]
	formats: string[]
}>()

const name = ref('')
const address = ref('')
const purpose = ref<ListPurpose>('deny')
const mode = ref<'observe' | 'protect'>('observe')
const format = ref('cidr')
const touched = ref({ name: false, address: false })
const serverErrors = ref<Record<string, string>>({})
const { busy, error, run } = useAction()

watch(open, (value) => {
	if (value) {
		name.value = ''
		address.value = ''
		purpose.value = 'deny'
		mode.value = 'observe'
		format.value = 'cidr'
		touched.value = { name: false, address: false }
		serverErrors.value = {}
		error.value = null
	}
})
/**
 * A refusal from the server is about the value it was given; a new value gets a fresh chance.
 *
 * @param field - The field that was edited
 */
function edited(field: 'name' | 'address') {
	touched.value[field] = true
	delete serverErrors.value[field === 'name' ? 'id' : 'url']
}

const nameError = computed(() => {
	const value = name.value.trim()
	if (!touched.value.name) {
		return null
	}
	if (props.existing.includes(value)) {
		return t(APP_ID, 'A list with this name exists already.')
	}
	return listIdProblem(value) ?? serverErrors.value.id ?? null
})
const addressError = computed(() => (touched.value.address ? httpsUrlProblem(address.value) : null) ?? serverErrors.value.url ?? null)
const valid = computed(() => listIdProblem(name.value.trim()) === null && !props.existing.includes(name.value.trim()) && httpsUrlProblem(address.value) === null)

const PURPOSES: { value: ListPurpose, label: () => string, text: () => string }[] = [
	{ value: 'deny', label: () => t(APP_ID, 'Blocklist'), text: () => t(APP_ID, 'Addresses known for attacks. They are counted, or refused in Protect mode.') },
	{ value: 'hosting', label: () => t(APP_ID, 'Hosting networks'), text: () => t(APP_ID, 'Networks of a cloud or hosting provider without an official list. They are marked, never blocked.') },
	{ value: 'tor', label: () => t(APP_ID, 'Tor network'), text: () => t(APP_ID, 'Exit nodes of the Tor network. They are marked, never blocked.') },
]

const FORMAT_LABELS: Record<string, () => string> = {
	cidr: () => t(APP_ID, 'Plain text: one address or range per line, # starts a comment'),
	spamhaus_json: () => t(APP_ID, 'Spamhaus DROP (JSON lines)'),
	aws_json: () => t(APP_ID, 'Amazon Web Services ip-ranges.json'),
	google_json: () => t(APP_ID, 'Google Cloud cloud.json'),
	oracle_json: () => t(APP_ID, 'Oracle Cloud public_ip_ranges.json'),
	geofeed_csv: () => t(APP_ID, 'Geofeed CSV (RFC 8805)'),
}

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Add list'), variant: 'primary' as const, type: 'submit' as const, disabled: !valid.value || busy.value !== null, callback: () => false },
])

/**
 * Add the list.
 */
async function submit() {
	touched.value = { name: true, address: true }
	if (!valid.value) {
		return
	}
	serverErrors.value = {}
	const added = await run('add', () => addBlocklist({ id: name.value.trim(), url: address.value.trim(), purpose: purpose.value, format: format.value, mode: mode.value }), {
		done: (list: Blocklist) => t(APP_ID, '{list} was added and is downloaded within the next minutes.', { list: list.name }),
		fallback: t(APP_ID, 'The list could not be added. Please try again.'),
		inline: true,
		handle: (e) => {
			if (e instanceof ApiError && (e.param === 'id' || e.param === 'url')) {
				serverErrors.value = { [e.param]: e.message }
				return true
			}
			return false
		},
	})
	if (added) {
		open.value = false
	}
}
</script>

<template>
	<NcDialog
		v-model:open="open"
		:name="t(APP_ID, 'Add a list')"
		isForm
		:buttons="buttons"
		size="normal"
		@submit="submit">
		<div :class="$style.dialog" @keydown.esc="open = false">
			<p>{{ t(APP_ID, 'Any list of addresses published over https can be used, for example one your provider or your security team maintains. Nextcloud downloads it regularly and never sends anything about your users.') }}</p>

			<fieldset :class="$style.dialog__fieldset">
				<legend :class="$style.dialog__legend">
					{{ t(APP_ID, 'What the list contains') }}
				</legend>
				<NcCheckboxRadioSwitch
					v-for="option in PURPOSES"
					:key="option.value"
					v-model="purpose"
					type="radio"
					:value="option.value"
					name="ids-list-purpose"
					:description="option.text()">
					{{ option.label() }}
				</NcCheckboxRadioSwitch>
			</fieldset>

			<NcTextField
				v-model="address"
				:label="t(APP_ID, 'Address of the list')"
				:placeholder="t(APP_ID, 'e.g. {example}', { example: 'https://example.org/blocklist.txt' }, undefined, { escape: false, sanitize: false })"
				type="url"
				autocomplete="off"
				spellcheck="false"
				:error="addressError !== null"
				:helperText="addressError ?? t(APP_ID, 'https:// only, and not in your local network.')"
				data-test="list-url"
				required
				@update:modelValue="edited('address')" />

			<NcTextField
				v-model="name"
				:label="t(APP_ID, 'Short name')"
				:placeholder="t(APP_ID, 'e.g. {example}', { example: 'my_provider' })"
				autocomplete="off"
				spellcheck="false"
				:error="nameError !== null"
				:helperText="nameError ?? t(APP_ID, 'Lower-case letters, digits and underscores. Shown in the list and in occ.')"
				data-test="list-name"
				required
				@update:modelValue="edited('name')" />

			<div :class="$style.dialog__field">
				<SelectField
					v-model="format"
					:class="$style.dialog__select"
					:label="t(APP_ID, 'Format')"
					:options="formats.map((value) => ({ value, label: FORMAT_LABELS[value]?.() ?? value }))" />
			</div>

			<fieldset v-if="purpose === 'deny'" :class="$style.dialog__fieldset">
				<legend :class="$style.dialog__legend">
					{{ t(APP_ID, 'What a match does') }}
				</legend>
				<NcCheckboxRadioSwitch
					v-model="mode"
					type="radio"
					value="observe"
					name="ids-list-mode"
					:description="t(APP_ID, 'Recommended at first: matches are only counted, so you can see what the list would block.')">
					{{ modeLabel('observe') }}
				</NcCheckboxRadioSwitch>
				<NcCheckboxRadioSwitch
					v-model="mode"
					type="radio"
					value="protect"
					name="ids-list-mode"
					:description="t(APP_ID, 'Requests from listed addresses get an error page with a reference.')">
					{{ modeLabel('protect') }}
				</NcCheckboxRadioSwitch>
			</fieldset>

			<NcNoteCard v-if="error" type="error" :text="error" />
		</div>
	</NcDialog>
</template>

<style module>
.dialog {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
	padding-bottom: var(--ids-space-2);
}

.dialog p {
	margin: 0;
	line-height: 1.5;
}

.dialog__fieldset {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
	margin: 0;
	padding: 0;
	border: none;
}

.dialog__field {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
}

.dialog__legend {
	margin-bottom: var(--ids-space-1);
	padding: 0;
	font-weight: 600;
}

.dialog__select {
	width: 100%;
	margin: 0;
}
</style>
