/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import axios from '@nextcloud/axios'
import { addPasswordConfirmationInterceptors } from '@nextcloud/password-confirmation'
import { createApp } from 'vue'
import AdminSettings from './views/AdminSettings.vue'

import 'vite/modulepreload-polyfill'
import './styles/tokens.css'

addPasswordConfirmationInterceptors(axios)

createApp(AdminSettings).mount('#intrusion_detection-admin-settings')
