<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { TrustedNetwork } from '../types.ts'

import { mdiDeleteOutline, mdiLanConnect } from '@mdi/js'
import { computed } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import SectionCard from '../../components/common/SectionCard.vue'
import LoadError from './LoadError.vue'
import SkeletonRows from './SkeletonRows.vue'
import { useAction } from '../../composables/useAction.ts'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'
import { forgetNetwork, personal, useTrustedNetworks } from '../store.ts'
import { date } from '../time.ts'

const { data: networks, error, reload: load } = useTrustedNetworks({ failure: () => t(APP_ID, 'Your trusted networks could not be loaded. Please try again.') })
const { busy, run } = useAction()
const timeZone = computed(() => personal.overview?.timezone)
/** Shown while loading, and while there is a network or an error */
const shown = computed(() => networks.value === null || networks.value.length > 0 || error.value !== null)

/**
 * Stop trusting one network.
 *
 * @param network - The entry
 */
function remove(network: TrustedNetwork) {
	run(network.id, () => forgetNetwork(network.id), {
		done: t(APP_ID, 'The network {network} is no longer trusted.', { network: network.network }),
		toast: true,
		fallback: t(APP_ID, 'The network could not be removed. Please try again.'),
	})
}
</script>

<template>
	<SectionCard
		v-if="shown"
		:heading="t(APP_ID, 'Trusted networks')"
		:icon="mdiLanConnect"
		level="h4"
		data-test="trusted-networks">
		<template #description>
			{{ t(APP_ID, 'Networks you confirmed with "Yes, it was me". Logins from them are asked fewer questions for a while.') }}
		</template>

		<LoadError v-if="error" :text="error" @retry="load" />
		<SkeletonRows v-else-if="networks === null" :rows="2" />
		<ul v-else :class="$style.list">
			<li
				v-for="network in networks"
				:key="network.id"
				:class="$style.network"
				:data-test="`network-${network.id}`">
				<span :class="$style.network__icon" aria-hidden="true">
					<NcIconSvgWrapper :path="mdiLanConnect" :size="20" />
				</span>
				<div :class="$style.network__main">
					<p :class="$style.network__name">
						{{ network.network }}
					</p>
					<p :class="$style.network__meta">
						{{ t(APP_ID, 'Trusted since {since}, until {until}', { since: date(network.createdAt, timeZone), until: date(network.expiresAt, timeZone) }) }}
					</p>
				</div>
				<NcButton
					variant="tertiary"
					:aria-label="t(APP_ID, 'Stop trusting {network}', { network: network.network })"
					:title="t(APP_ID, 'Remove')"
					:disabled="busy !== null"
					data-test="remove-network"
					@click="remove(network)">
					<template #icon>
						<NcLoadingIcon v-if="busy === network.id" :size="20" />
						<NcIconSvgWrapper v-else :path="mdiDeleteOutline" />
					</template>
				</NcButton>
			</li>
		</ul>
	</SectionCard>
</template>

<style module>
.list {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
}

.network {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-3);
	padding-block: var(--ids-space-3);
	border-block-start: 1px solid var(--color-border);
}

.network:first-child {
	padding-block-start: 0;
	border-block-start: none;
}

.network__icon {
	composes: muted from '../../styles/shared.module.css';
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 36px;
	height: 36px;
	border-radius: 50%;
	background-color: var(--color-background-dark);
}

.network__main {
	display: flex;
	flex: 1 1 auto;
	flex-direction: column;
	gap: var(--ids-space-half);
	min-width: 0;
}

.network__name {
	margin: 0;
	font-family: var(--font-face-monospace, monospace);
	font-weight: 600;
	overflow-wrap: anywhere;
}

.network__meta {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
	font-size: 0.92em;
	line-height: 1.5;
}
</style>
