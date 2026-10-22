<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Check } from '../../types.ts'

import { mdiArrowRight } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SettingsGroup from '../common/SettingsGroup.vue'
import { state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	check: Check
}>()

const checkOff = computed(() => props.check.mode.effective === 'off')

const settings = computed(() => state.settings.filter((s) => s.group === 'risky_network'))
</script>

<template>
	<fieldset :class="$style.section" data-test="risky-network-settings">
		<legend :class="$style.section__legend">
			{{ t(APP_ID, 'Networks and people that are never affected') }}
		</legend>
		<SettingsGroup v-if="settings.length > 0" :settings="settings" />
		<p v-if="checkOff" :class="$style.section__text">
			{{ t(APP_ID, 'This check is off. The trusted networks still lower the risk score of their addresses.') }}
		</p>
		<p :class="$style.section__text">
			{{ t(APP_ID, 'Which hosting providers and Tor exit nodes count is set by the network lists. They are all off until you switch one on.') }}
		</p>
		<div>
			<NcButton variant="secondary" href="#blocks-lists">
				<template #icon>
					<NcIconSvgWrapper :path="mdiArrowRight" />
				</template>
				{{ t(APP_ID, 'Choose the network lists on the Blocks tab') }}
			</NcButton>
		</div>
	</fieldset>
</template>

<style module>
.section {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	min-width: 0;
	margin: 0;
	padding: 0;
	border: none;
}

.section__legend {
	margin-bottom: calc(var(--default-grid-baseline) * 2);
	padding: 0;
	font-weight: 700;
}

.section__text {
	margin: 0;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}
</style>
