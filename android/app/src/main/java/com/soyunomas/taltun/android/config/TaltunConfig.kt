package com.soyunomas.taltun.android.config

import com.soyunomas.taltun.android.core.Hex
import com.soyunomas.taltun.android.core.Ipv4
import com.soyunomas.taltun.android.core.TaltunCrypto

data class TaltunConfig(
    val profileName: String = "Taltun",
    val localVip: String = "10.0.0.2",
    val privateKeyHex: String = "",
    val peerVip: String = "10.0.0.1",
    val peerPublicKeyHex: String = "",
    val endpoint: String = "",
    val routes: List<String> = listOf("10.0.0.0/24"),
    val allowedSources: List<String> = listOf("10.0.0.0/24"),
    val dnsServers: List<String> = emptyList(),
    val mtu: Int = 1380,
) {
    data class Endpoint(val host: String, val port: Int)

    fun validate(): List<String> {
        val errors = mutableListOf<String>()
        runCatching { Ipv4.parse(localVip) }.onFailure { errors += "VIP local inválida" }
        runCatching { Ipv4.parse(peerVip) }.onFailure { errors += "VIP del peer inválida" }
        if (localVip.trim() == peerVip.trim()) errors += "La VIP local y la del peer deben ser distintas"

        validateKey(privateKeyHex, "Clave privada", errors)
        validateKey(peerPublicKeyHex, "Clave pública del peer", errors)
        runCatching { parseEndpoint(endpoint) }.onFailure { errors += "Endpoint inválido; usa host:puerto" }

        if (routes.isEmpty()) errors += "Configura al menos una ruta"
        routes.forEach { route ->
            runCatching { Ipv4.parsePrefix(route) }.onFailure { errors += "Ruta IPv4 inválida: $route" }
        }
        allowedSources.forEach { prefix ->
            runCatching { Ipv4.parsePrefix(prefix) }.onFailure { errors += "Allowed source inválido: $prefix" }
        }
        dnsServers.forEach { dns ->
            runCatching { Ipv4.parse(dns) }.onFailure { errors += "DNS IPv4 inválido: $dns" }
        }
        if (mtu !in 576..2007) errors += "MTU fuera de rango (576..2007)"
        if (profileName.isBlank()) errors += "El nombre del perfil no puede estar vacío"
        return errors.distinct()
    }

    fun localVipInt(): Int = Ipv4.parse(localVip)
    fun peerVipInt(): Int = Ipv4.parse(peerVip)
    fun privateKey(): ByteArray = Hex.decode(privateKeyHex).also { require(it.size == TaltunCrypto.KEY_SIZE) }
    fun peerPublicKey(): ByteArray = Hex.decode(peerPublicKeyHex).also { require(it.size == TaltunCrypto.KEY_SIZE) }
    fun endpointParts(): Endpoint = parseEndpoint(endpoint)

    fun sourcePrefixes(): List<Ipv4.Prefix> {
        val all = ArrayList<Ipv4.Prefix>(allowedSources.size + 1)
        all += Ipv4.parsePrefix("${peerVip.trim()}/32")
        allowedSources.forEach { all += Ipv4.parsePrefix(it) }
        return all.distinct()
    }

    companion object {
        fun splitList(value: String): List<String> = value
            .split(',', '\n', ';', ' ', '\t')
            .map(String::trim)
            .filter(String::isNotEmpty)
            .distinct()

        fun parseEndpoint(value: String): Endpoint {
            val trimmed = value.trim()
            val index = trimmed.lastIndexOf(':')
            require(index > 0 && index < trimmed.lastIndex) { "invalid endpoint" }
            val host = trimmed.substring(0, index).trim()
            val port = trimmed.substring(index + 1).toInt()
            require(host.isNotEmpty() && port in 1..65535)
            require(!host.contains(':')) { "IPv6 endpoints are not supported" }
            return Endpoint(host, port)
        }

        private fun validateKey(value: String, label: String, errors: MutableList<String>) {
            val key = runCatching { Hex.decode(value) }.getOrNull()
            if (key == null || key.size != TaltunCrypto.KEY_SIZE) {
                errors += "$label debe tener 32 bytes (64 caracteres hex)"
            }
        }
    }
}
