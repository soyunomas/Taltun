package com.soyunomas.taltun.android.config

import android.content.Context

class ConfigStore(context: Context) {
    private val preferences = context.getSharedPreferences("taltun_config", Context.MODE_PRIVATE)

    fun load(): TaltunConfig = TaltunConfig(
        profileName = preferences.getString("profile_name", "Taltun") ?: "Taltun",
        localVip = preferences.getString("local_vip", "10.0.0.2") ?: "10.0.0.2",
        privateKeyHex = preferences.getString("private_key", "") ?: "",
        peerVip = preferences.getString("peer_vip", "10.0.0.1") ?: "10.0.0.1",
        peerPublicKeyHex = preferences.getString("peer_public_key", "") ?: "",
        endpoint = preferences.getString("endpoint", "") ?: "",
        routes = TaltunConfig.splitList(preferences.getString("routes", "10.0.0.0/24") ?: ""),
        allowedSources = TaltunConfig.splitList(preferences.getString("allowed_sources", "10.0.0.0/24") ?: ""),
        dnsServers = TaltunConfig.splitList(preferences.getString("dns_servers", "") ?: ""),
        mtu = preferences.getInt("mtu", 1380),
    )

    fun save(config: TaltunConfig) {
        preferences.edit()
            .putString("profile_name", config.profileName)
            .putString("local_vip", config.localVip)
            .putString("private_key", config.privateKeyHex.lowercase())
            .putString("peer_vip", config.peerVip)
            .putString("peer_public_key", config.peerPublicKeyHex.lowercase())
            .putString("endpoint", config.endpoint)
            .putString("routes", config.routes.joinToString(","))
            .putString("allowed_sources", config.allowedSources.joinToString(","))
            .putString("dns_servers", config.dnsServers.joinToString(","))
            .putInt("mtu", config.mtu)
            .apply()
    }
}
