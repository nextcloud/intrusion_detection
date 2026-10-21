<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { DecoyFormat, NewDecoy } from '../../types.ts'

import { t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import { ApiError, createDecoy, errorMessage, isCancelled } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'

const open = defineModel<boolean>('open', { required: true })

const emit = defineEmits<{
	created: [created: NewDecoy]
}>()

const label = ref('')
const loginName = ref('')
const format = ref<DecoyFormat>('app-password')
const serverErrors = ref<Record<string, string>>({})
const error = ref<string | null>(null)
const busy = ref(false)

watch(open, (value) => {
	if (value) {
		label.value = ''
		loginName.value = ''
		format.value = 'app-password'
		serverErrors.value = {}
		error.value = null
	}
})

const labelError = computed(() => {
	if (label.value.length > 200) {
		return t(APP_ID, 'The label can have at most 200 characters.')
	}
	return serverErrors.value.label ?? null
})

const loginNameError = computed(() => {
	const value = loginName.value.trim()
	// eslint-disable-next-line no-control-regex
	if (value !== '' && !/^[^\s\u0000-\u001F\u007F]{1,64}$/u.test(value)) {
		return t(APP_ID, 'A login name has no spaces and at most 64 characters.')
	}
	return serverErrors.value.login_name ?? null
})

const valid = computed(() => label.value.trim() !== '' && labelError.value === null && loginNameError.value === null)

const FORMATS: { value: DecoyFormat, label: () => string, text: () => string }[] = [
	{ value: 'app-password', label: () => t(APP_ID, 'Looks like an app password'), text: () => t(APP_ID, 'Five groups of five characters, like the app passwords of the security settings.') },
	{ value: 'token', label: () => t(APP_ID, 'Looks like a token'), text: () => t(APP_ID, '72 letters and digits, like a token of a login flow or of occ.') },
]

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Create decoy'), variant: 'primary' as const, type: 'submit' as const, disabled: !valid.value || busy.value, callback: () => false },
])

/**
 * Create the decoy and hand its secret to the parent, once.
 */
async function submit() {
	if (!valid.value) {
		return
	}
	busy.value = true
	serverErrors.value = {}
	error.value = null
	try {
		const created = await createDecoy({ label: label.value.trim(), loginName: loginName.value.trim(), format: format.value })
		open.value = false
		emit('created', created)
	} catch (e) {
		if (isCancelled(e)) {
			return
		}
		logger.error('Could not create the decoy', { error: e })
		if (e instanceof ApiError && (e.param === 'label' || e.param === 'login_name')) {
			serverErrors.value = { [e.param]: e.message }
		} else {
			error.value = errorMessage(e, t(APP_ID, 'The decoy could not be created. Please try again.'))
		}
	} finally {
		busy.value = false
	}
}
</script>

<template>
	<NcDialog
		v-model:open="open"
		:name="t(APP_ID, 'Create a decoy credential')"
		isForm
		:buttons="buttons"
		size="normal"
		@submit="submit">
		<div :class="$style.dialog" @keydown.esc="open = false">
			<p>{{ t(APP_ID, 'Nextcloud makes up a secret that looks like a real credential. Nobody needs it, so anyone who uses it found it where you planted it.') }}</p>
			<NcTextField
				v-model="label"
				:label="t(APP_ID, 'Where you will plant it')"
				:placeholder="t(APP_ID, 'Old backup script on nas01')"
				:error="labelError !== null"
				:helperText="labelError ?? t(APP_ID, 'Shown in the alert, so you know at once where it was found.')"
				data-test="decoy-label"
				required
				@update:modelValue="delete serverErrors.label" />
			<NcTextField
				v-model="loginName"
				:label="t(APP_ID, 'Login name (optional)')"
				placeholder="backup-svc"
				autocomplete="off"
				spellcheck="false"
				:error="loginNameError !== null"
				:helperText="loginNameError ?? t(APP_ID, 'Planted next to the secret. It must not be an account. A login attempt with this name alone also counts, as a weaker sign.')"
				data-test="decoy-login"
				@update:modelValue="delete serverErrors.login_name" />
			<fieldset :class="$style.dialog__fieldset">
				<legend :class="$style.dialog__legend">
					{{ t(APP_ID, 'What the secret looks like') }}
				</legend>
				<NcCheckboxRadioSwitch
					v-for="option in FORMATS"
					:key="option.value"
					v-model="format"
					type="radio"
					name="ids-decoy-format"
					:value="option.value"
					:description="option.text()">
					{{ option.label() }}
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
	gap: calc(var(--default-grid-baseline) * 4);
	padding-bottom: calc(var(--default-grid-baseline) * 2);
}

.dialog p {
	margin: 0;
	line-height: 1.5;
}

.dialog__fieldset {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	margin: 0;
	padding: 0;
	border: none;
}

.dialog__legend {
	margin-bottom: calc(var(--default-grid-baseline) * 1);
	padding: 0;
	font-weight: 600;
}
</style>
