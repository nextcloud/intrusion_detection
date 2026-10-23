<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiCheck, mdiClose, mdiGauge } from '@mdi/js'
import { computed } from 'vue'
import SectionCard from '../common/SectionCard.vue'
import SettingsGroup from '../common/SettingsGroup.vue'
import StateBadge from '../common/StateBadge.vue'
import { state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'

const settings = computed(() => state.settings.filter((s) => s.group === 'risk'))
const enabled = computed(() => state.settings.find((s) => s.name === 'risk_enabled')?.value !== false)
</script>

<template>
	<SectionCard
		v-if="settings.length > 0"
		:heading="t(APP_ID, 'Address risk score')"
		:icon="mdiGauge"
		data-test="risk-score">
		<template #description>
			{{ t(APP_ID, 'Some addresses are more suspicious than others. Nextcloud adds points for what it already knows about an address, and uses the score wherever it decides about one: a suspicious address meets lower limits, and a very suspicious one must confirm every password login. Nothing is looked up for it on normal requests.') }}
		</template>
		<template #actions>
			<StateBadge :type="enabled ? 'success' : 'warning'" :icon="enabled ? mdiCheck : mdiClose">
				{{ enabled ? t(APP_ID, 'On') : t(APP_ID, 'Off') }}
			</StateBadge>
		</template>

		<SettingsGroup :settings="settings">
			<p :class="$style.explanation" data-test="risk-points">
				{{ state.templates.riskPoints }}
			</p>
			<p :class="$style.explanation" data-test="risk-tiers">
				{{ state.templates.riskTiers }}
			</p>
		</SettingsGroup>
	</SectionCard>
</template>

<style module>
.explanation {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
	line-height: 1.5;
}
</style>
