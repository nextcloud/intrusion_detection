<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Check, PayloadTest } from '../../types.ts'

import { mdiTestTube } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { ref, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import PayloadResult from './PayloadResult.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, testPayload } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'

defineProps<{
	check: Check
}>()

const id = useId()
const input = ref('')
const result = ref<PayloadTest | null>(null)
const error = ref<string | null>(null)
const busy = ref(false)
const { announce } = useAnnouncer()

const EXAMPLES = [
	{ label: () => t(APP_ID, 'Classic SQL injection'), value: "/index.php/apps/files/?id=1' OR '1'='1" },
	{ label: () => t(APP_ID, 'Hidden in base64'), value: '/index.php/apps/files/?data=JyBPUiAnMSc9JzE=' },
	{ label: () => t(APP_ID, 'A harmless file name'), value: "/remote.php/dav/files/alice/Bob's union select notes.txt" },
]

/**
 * Run the test on the server.
 */
async function test() {
	if (input.value.trim() === '') {
		error.value = t(APP_ID, 'Paste a web address or a value to test.')
		return
	}
	busy.value = true
	error.value = null
	try {
		result.value = await testPayload(input.value)
		announce(result.value.fires ? t(APP_ID, 'Result: would fire.') : t(APP_ID, 'Result: would not fire.'))
	} catch (e) {
		logger.error('Could not test the value', { error: e })
		error.value = errorMessage(e, t(APP_ID, 'The test did not work. Please try again.'))
		result.value = null
	} finally {
		busy.value = false
	}
}

/**
 * @param value - An example to test
 */
function tryExample(value: string) {
	input.value = value
	test()
}
</script>

<template>
	<section :class="$style.tester" :aria-labelledby="`${id}-heading`">
		<h5 :id="`${id}-heading`" :class="$style.tester__heading">
			<NcIconSvgWrapper inline :path="mdiTestTube" :size="18" />
			{{ t(APP_ID, 'Test a URL') }}
		</h5>
		<p :class="$style.tester__text">
			{{ t(APP_ID, 'Paste a web address from your logs, or a single value, and see exactly what the check does with it. Nothing is sent to that address and nothing is recorded.') }}
		</p>
		<form :class="$style.tester__form" @submit.prevent="test">
			<label :for="`${id}-input`" class="hidden-visually">{{ t(APP_ID, 'Web address or value to test with {check}', { check: check.texts.name }) }}</label>
			<textarea
				:id="`${id}-input`"
				v-model="input"
				:class="$style.tester__input"
				rows="2"
				spellcheck="false"
				autocomplete="off"
				:placeholder="t(APP_ID, 'https://cloud.example.com/index.php/apps/foo/?id=1 UNION SELECT 1')"
				data-test="payload-input"
				@keydown.enter.exact.prevent="test" />
			<NcButton type="submit" variant="primary" :disabled="busy">
				<template #icon>
					<NcLoadingIcon v-if="busy" />
					<NcIconSvgWrapper v-else :path="mdiTestTube" />
				</template>
				{{ t(APP_ID, 'Test') }}
			</NcButton>
		</form>
		<div :class="$style.tester__examples">
			<span>{{ t(APP_ID, 'Try:') }}</span>
			<button
				v-for="example in EXAMPLES"
				:key="example.value"
				type="button"
				:class="$style.example"
				:title="example.value"
				@click="tryExample(example.value)">
				{{ example.label() }}
			</button>
		</div>

		<NcNoteCard v-if="error" type="error" :text="error" />
		<div aria-live="polite">
			<PayloadResult v-if="result" :result="result" />
		</div>
	</section>
</template>

<style module>
.tester {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding: calc(var(--default-grid-baseline) * 4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.tester__heading {
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

.tester__text {
	margin: 0;
	line-height: 1.6;
}

.tester__form {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 2);
}

.tester__input {
	flex: 1 1 260px;
	min-height: 44px;
	margin: 0;
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.9em;
	resize: vertical;
}

.tester__examples {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1.5);
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.tester__examples button.example {
	min-height: 28px;
	margin: 0;
	padding-block: 0;
	padding-inline: calc(var(--default-grid-baseline) * 2.5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-pill, 100px);
	background-color: var(--color-main-background);
	color: var(--color-main-text);
	font-size: 1em;
	font-weight: normal;
	cursor: pointer;
}

.tester__examples button.example:hover,
.tester__examples button.example:focus-visible {
	border-color: var(--color-primary-element);
	color: var(--color-primary-element-text-dark, var(--color-main-text));
}

.tester__examples button.example:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: 2px;
}
</style>
