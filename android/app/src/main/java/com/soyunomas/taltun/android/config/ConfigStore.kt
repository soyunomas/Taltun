package com.soyunomas.taltun.android.config

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

class ConfigStore(context: Context) {
    data class StoredProfile(
        val id: String,
        val config: TaltunConfig,
    )

    companion object {
        private const val PREFS = "taltun_config"
        private const val KEY_PROFILES = "profiles_v2"
        private const val KEY_SELECTED = "selected_profile_id"
    }

    private val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    @Synchronized
    fun listProfiles(): List<StoredProfile> {
        ensureMigrated()
        return readProfiles()
    }

    @Synchronized
    fun selectedProfileId(): String? {
        ensureMigrated()
        val selected = preferences.getString(KEY_SELECTED, null)
        return selected?.takeIf { id -> readProfiles().any { it.id == id } }
    }

    @Synchronized
    fun select(profileId: String): Boolean {
        ensureMigrated()
        if (readProfiles().none { it.id == profileId }) return false
        return preferences.edit().putString(KEY_SELECTED, profileId).commit()
    }

    /** Compatibility entry point used by the VPN service. */
    @Synchronized
    fun load(): TaltunConfig {
        ensureMigrated()
        val profiles = readProfiles()
        val selected = preferences.getString(KEY_SELECTED, null)
        return profiles.firstOrNull { it.id == selected }?.config
            ?: profiles.firstOrNull()?.config
            ?: TaltunConfig()
    }

    @Synchronized
    fun loadProfile(profileId: String): TaltunConfig? {
        ensureMigrated()
        return readProfiles().firstOrNull { it.id == profileId }?.config
    }

    /** Compatibility save: updates the selected profile or creates one. */
    @Synchronized
    fun save(config: TaltunConfig) {
        ensureMigrated()
        val profiles = readProfiles().toMutableList()
        val selected = preferences.getString(KEY_SELECTED, null)
        val index = profiles.indexOfFirst { it.id == selected }
        if (index >= 0) {
            profiles[index] = profiles[index].copy(config = normalized(config))
            writeProfiles(profiles, profiles[index].id)
        } else {
            val id = UUID.randomUUID().toString()
            profiles += StoredProfile(id, normalized(config))
            writeProfiles(profiles, id)
        }
    }

    @Synchronized
    fun saveProfile(profileId: String?, config: TaltunConfig): String {
        ensureMigrated()
        val profiles = readProfiles().toMutableList()
        val normalized = normalized(config)
        val id = profileId ?: UUID.randomUUID().toString()
        val index = profiles.indexOfFirst { it.id == id }
        if (index >= 0) profiles[index] = StoredProfile(id, normalized)
        else profiles += StoredProfile(id, normalized)
        writeProfiles(profiles, preferences.getString(KEY_SELECTED, null) ?: id)
        return id
    }

    @Synchronized
    fun duplicateProfile(profileId: String): String? {
        ensureMigrated()
        val profiles = readProfiles().toMutableList()
        val source = profiles.firstOrNull { it.id == profileId } ?: return null
        val existingNames = profiles.map { it.config.profileName }.toSet()
        val base = source.config.profileName.ifBlank { "Perfil" }
        var name = "$base (copia)"
        var suffix = 2
        while (name in existingNames) {
            name = "$base (copia $suffix)"
            suffix++
        }
        val id = UUID.randomUUID().toString()
        profiles += StoredProfile(id, source.config.copy(profileName = name))
        writeProfiles(profiles, preferences.getString(KEY_SELECTED, null))
        return id
    }

    @Synchronized
    fun deleteProfile(profileId: String): Boolean {
        ensureMigrated()
        val profiles = readProfiles().toMutableList()
        if (!profiles.removeAll { it.id == profileId }) return false
        val currentSelected = preferences.getString(KEY_SELECTED, null)
        val newSelected = if (currentSelected == profileId) profiles.firstOrNull()?.id else currentSelected
        writeProfiles(profiles, newSelected)
        return true
    }

    private fun ensureMigrated() {
        if (preferences.contains(KEY_PROFILES)) return

        val legacy = loadLegacy()
        val id = UUID.randomUUID().toString()
        writeProfiles(listOf(StoredProfile(id, normalized(legacy))), id)
    }

    private fun loadLegacy(): TaltunConfig = TaltunConfig(
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

    private fun normalized(config: TaltunConfig): TaltunConfig = config.copy(
        profileName = config.profileName.trim(),
        localVip = config.localVip.trim(),
        privateKeyHex = config.privateKeyHex.trim().lowercase(),
        peerVip = config.peerVip.trim(),
        peerPublicKeyHex = config.peerPublicKeyHex.trim().lowercase(),
        endpoint = config.endpoint.trim(),
        routes = config.routes.map(String::trim).filter(String::isNotEmpty).distinct(),
        allowedSources = config.allowedSources.map(String::trim).filter(String::isNotEmpty).distinct(),
        dnsServers = config.dnsServers.map(String::trim).filter(String::isNotEmpty).distinct(),
    )

    private fun readProfiles(): List<StoredProfile> {
        val raw = preferences.getString(KEY_PROFILES, "[]") ?: "[]"
        return runCatching {
            val array = JSONArray(raw)
            buildList {
                for (index in 0 until array.length()) {
                    val item = array.getJSONObject(index)
                    add(StoredProfile(item.getString("id"), configFromJson(item.getJSONObject("config"))))
                }
            }
        }.getOrElse { emptyList() }
    }

    private fun writeProfiles(profiles: List<StoredProfile>, selectedId: String?) {
        val array = JSONArray()
        profiles.forEach { profile ->
            array.put(
                JSONObject()
                    .put("id", profile.id)
                    .put("config", configToJson(profile.config)),
            )
        }
        val editor = preferences.edit().putString(KEY_PROFILES, array.toString())
        if (selectedId != null && profiles.any { it.id == selectedId }) {
            editor.putString(KEY_SELECTED, selectedId)
        } else {
            editor.remove(KEY_SELECTED)
        }
        check(editor.commit()) { "No se pudieron guardar los perfiles" }
    }

    private fun configToJson(config: TaltunConfig): JSONObject = JSONObject()
        .put("profile_name", config.profileName)
        .put("local_vip", config.localVip)
        .put("private_key", config.privateKeyHex)
        .put("peer_vip", config.peerVip)
        .put("peer_public_key", config.peerPublicKeyHex)
        .put("endpoint", config.endpoint)
        .put("routes", JSONArray(config.routes))
        .put("allowed_sources", JSONArray(config.allowedSources))
        .put("dns_servers", JSONArray(config.dnsServers))
        .put("mtu", config.mtu)

    private fun configFromJson(json: JSONObject): TaltunConfig = TaltunConfig(
        profileName = json.optString("profile_name", "Taltun"),
        localVip = json.optString("local_vip", "10.0.0.2"),
        privateKeyHex = json.optString("private_key", ""),
        peerVip = json.optString("peer_vip", "10.0.0.1"),
        peerPublicKeyHex = json.optString("peer_public_key", ""),
        endpoint = json.optString("endpoint", ""),
        routes = json.optStringList("routes", listOf("10.0.0.0/24")),
        allowedSources = json.optStringList("allowed_sources", listOf("10.0.0.0/24")),
        dnsServers = json.optStringList("dns_servers", emptyList()),
        mtu = json.optInt("mtu", 1380),
    )

    private fun JSONObject.optStringList(name: String, fallback: List<String>): List<String> {
        val array = optJSONArray(name) ?: return fallback
        return buildList {
            for (index in 0 until array.length()) {
                val value = array.optString(index).trim()
                if (value.isNotEmpty()) add(value)
            }
        }.distinct()
    }
}
