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
import NcTextArea from '@nextcloud/vue/components/NcTextArea'
import PayloadResult from './PayloadResult.vue'
import { useAction } from '../../composables/useAction.ts'
import { testPayload } from '../../services/api.ts'
import { APP_ID } from '../../utils/format.ts'

defineProps<{
	check: Check
}>()

const id = useId()
const input = ref('')
const result = ref<PayloadTest | null>(null)
const { busy, error, run } = useAction()

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
	const tested = await run('test', async () => {
		result.value = await testPayload(input.value)
		return result.value
	}, {
		done: (outcome: PayloadTest) => outcome.fires ? t(APP_ID, 'Result: would fire.') : t(APP_ID, 'Result: would not fire.'),
		fallback: t(APP_ID, 'The test did not work. Please try again.'),
		inline: true,
	})
	if (!tested) {
		result.value = null
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
			<NcTextArea
				v-model="input"
				:class="$style.tester__input"
				:label="t(APP_ID, 'Web address or value to test with {check}', { check: check.texts.name })"
				rows="2"
				resize="vertical"
				spellcheck="false"
				autocomplete="off"
				:placeholder="t(APP_ID, 'e.g. {example}', { example: 'https://cloud.example.com/index.php/apps/foo/?id=1 UNION SELECT 1' }, undefined, { escape: false, sanitize: false })"
				data-test="payload-input"
				@keydown.enter.exact.prevent="test" />
			<NcButton type="submit" variant="primary" :disabled="busy !== null">
				<template #icon>
					<NcLoadingIcon v-if="busy !== null" />
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
	gap: var(--ids-space-2);
	padding: var(--ids-space-4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.tester__heading {
	composes: eyebrow from '../../styles/shared.module.css';
	display: flex;
	align-items: center;
	gap: var(--ids-space-1-5);
	margin: 0;
}

.tester__text {
	margin: 0;
	line-height: 1.6;
}

.tester__form {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	gap: var(--ids-space-2);
}

.tester__form .tester__input {
	flex: 1 1 260px;
	margin: 0;
}

.tester__input :global(textarea) {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.9em;
}

.tester__examples {
	composes: muted from '../../styles/shared.module.css';
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-1-5);
	font-size: 0.9em;
}

.tester__examples button.example {
	min-height: 28px;
	margin: 0;
	padding-block: 0;
	padding-inline: var(--ids-space-2-5);
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
	outline: var(--ids-focus-ring);
	outline-offset: 2px;
}
</style>
