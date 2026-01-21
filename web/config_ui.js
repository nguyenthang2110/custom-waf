// Configuration UI rendering method
function renderConfiguration() {
    return `
        <div class="space-y-6">
            <!-- Backend Configuration -->
            <div class="bg-gray-800 rounded-lg border border-gray-700 p-6">
                <div class="mb-6">
                    <h3 class="text-2xl font-bold mb-2">Backend Server Configuration</h3>
                    <p class="text-sm text-gray-400">Configure the upstream web server that WAF will protect</p>
                </div>

                <!-- Current Backend -->
                <div class="bg-gray-700 rounded-lg p-4 mb-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <div class="text-sm text-gray-400 mb-1">Current Backend Server</div>
                            <div class="text-lg font-mono text-cyan-400">${this.backendURL}</div>
                        </div>
                        <svg class="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M12 5l7 7-7 7" />
                        </svg>
                    </div>
                </div>

                <!-- Update Form -->
                <form onsubmit="dashboard.updateBackend(event)" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium mb-2">New Backend URL</label>
                        <input 
                            type="text" 
                            name="backend_url" 
                            placeholder="http://localhost:8000" 
                            value="${this.backendURL !== 'Loading...' && this.backendURL !== 'Error loading' && this.backendURL !== 'Unknown' ? this.backendURL : ''}" 
                            required
                            class="w-full px-4 py-3 rounded-lg bg-gray-700 border border-gray-600 text-white focus:outline-none focus:border-cyan-400 font-mono"
                        >
                        <p class="text-xs text-gray-400 mt-2">Example: http://localhost:8000, https://example.com</p>
                    </div>

                    <button 
                        type="submit" 
                        class="w-full px-6 py-3 bg-cyan-600 hover:bg-cyan-700 rounded-lg font-semibold transition flex items-center justify-center gap-2">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                        Update Backend Server
                    </button>
                </form>

                <!-- Info Box -->
                <div class="mt-6 p-4 bg-blue-900/30 border border-blue-700 rounded-lg">
                    <div class="flex items-start gap-3">
                        <svg class="w-5 h-5 text-blue-400 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <div class="text-sm">
                            <p class="font-semibold text-blue-400 mb-1">Dynamic Configuration</p>
                            <p class="text-gray-300">The backend server can be updated without restarting the WAF. All future requests will be proxied to the new backend immediately.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- System Information -->
            <div class="bg-gray-800 rounded-lg border border-gray-700 p-6">
                <h3 class="text-xl font-bold mb-4">System Information</h3>
                <div class="grid md:grid-cols-2 gap-4">
                    <div class="bg-gray-700 rounded-lg p-4">
                        <div class="text-sm text-gray-400 mb-1">WAF Status</div>
                        <div class="flex items-center gap-2">
                            <div class="w-2 h-2 bg-green-400 rounded-full status-dot"></div>
                            <span class="text-lg font-bold text-green-400">Active</span>
                        </div>
                    </div>
                    <div class="bg-gray-700 rounded-lg p-4">
                        <div class="text-sm text-gray-400 mb-1">Total Rules Loaded</div>
                        <div class="text-lg font-bold text-cyan-400">${this.stats.rules_loaded || 0}</div>
                    </div>
                    <div class="bg-gray-700 rounded-lg p-4">
                        <div class="text-sm text-gray-400 mb-1">Total Requests</div>
                        <div class="text-lg font-bold">${this.stats.total_requests || 0}</div>
                    </div>
                    <div class="bg-gray-700 rounded-lg p-4">
                        <div class="text-sm text-gray-400 mb-1">Uptime</div>
                        <div class="text-lg font-bold">${this.stats.uptime || '0s'}</div>
                    </div>
                </div>
            </div>
        </div>
    `;
}
