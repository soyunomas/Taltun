package com.soyunomas.taltun.android

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.soyunomas.taltun.android.config.ConfigStore
import com.soyunomas.taltun.android.config.TaltunConfig
import com.soyunomas.taltun.android.core.Hex
import com.soyunomas.taltun.android.core.TaltunCrypto

class MainActivity : Activity() {
    private val vpnRequest = 7001
    private lateinit var profile: EditText
    private lateinit var vip: EditText
    private lateinit var privateKey: EditText
    private lateinit var peerVip: EditText
    private lateinit var peerKey: EditText
    private lateinit var endpoint: EditText
    private lateinit var routes: EditText
    private lateinit var allowed: EditText
    private lateinit var dns: EditText
    private lateinit var mtu: EditText
    private lateinit var publicKey: TextView
    private lateinit var status: TextView
    private lateinit var stats: TextView
    private lateinit var connect: Button
    private val handler = Handler(Looper.getMainLooper())
    private val poll = object : Runnable {
        override fun run() {
            refreshState()
            handler.postDelayed(this, 500)
        }
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(buildUi())
        load()
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 7002)
        }
    }

    override fun onResume() { super.onResume(); handler.post(poll) }
    override fun onPause() { handler.removeCallbacks(poll); super.onPause() }

    @Deprecated("Legacy callback avoids AndroidX dependency")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequest && resultCode == RESULT_OK) startVpn()
    }

    private fun buildUi(): ScrollView {
        val scroll = ScrollView(this)
        scroll.setBackgroundColor(Color.rgb(246, 248, 251))
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(32))
        }
        scroll.addView(root)
        root.addView(TextView(this).apply {
            text = "Taltun"
            textSize = 30f
            setTypeface(typeface, Typeface.BOLD)
        })
        root.addView(TextView(this).apply {
            text = "Cliente Android · protocolo v2"
            setPadding(0, 0, 0, dp(16))
        })
        status = TextView(this).apply { textSize = 17f; setPadding(dp(12), dp(10), dp(12), dp(4)) }
        stats = TextView(this).apply { setPadding(dp(12), 0, dp(12), dp(12)) }
        root.addView(status); root.addView(stats)

        title(root, "Identidad local")
        profile = field(root, "Nombre del perfil")
        vip = field(root, "VIP local · 10.0.0.2")
        privateKey = field(root, "Clave privada X25519 · 64 hex", password = true)
        val keys = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        keys.addView(Button(this).apply { text = "Generar"; setOnClickListener { generateIdentity() } },
            LinearLayout.LayoutParams(0, dp(48), 1f))
        keys.addView(Button(this).apply { text = "Copiar pública"; setOnClickListener { copyPublic() } },
            LinearLayout.LayoutParams(0, dp(48), 1f))
        root.addView(keys)
        publicKey = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(dp(8), dp(8), dp(8), dp(14))
        }
        root.addView(publicKey)

        title(root, "Servidor / Lighthouse")
        peerVip = field(root, "VIP peer · 10.0.0.1")
        peerKey = field(root, "Clave pública X25519 del peer · 64 hex")
        endpoint = field(root, "Endpoint · vpn.example.com:9000")

        title(root, "Túnel")
        routes = field(root, "Rutas · 10.0.0.0/24")
        allowed = field(root, "Allowed sources · 10.0.0.0/24")
        dns = field(root, "DNS opcional")
        mtu = field(root, "MTU · 1380", numeric = true)

        root.addView(TextView(this).apply {
            text = "Full tunnel: usa 0.0.0.0/0. El socket UDP exterior se excluye mediante VpnService.protect()."
            textSize = 12f
            setPadding(0, 4, 0, dp(12))
        })
        root.addView(Button(this).apply {
            text = "Guardar configuración"
            setOnClickListener { save(true) }
        })
        connect = Button(this).apply {
            text = "Conectar"
            setOnClickListener {
                if (VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTED ||
                    VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTING) disconnect() else requestConnect()
            }
        }
        root.addView(connect)
        return scroll
    }

    private fun field(root: LinearLayout, hint: String, password: Boolean = false, numeric: Boolean = false): EditText {
        val e = EditText(this).apply {
            this.hint = hint
            setSingleLine(true)
            if (password) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            if (numeric) inputType = InputType.TYPE_CLASS_NUMBER
        }
        root.addView(e, LinearLayout.LayoutParams(-1, dp(54)))
        return e
    }

    private fun title(root: LinearLayout, value: String) {
        root.addView(TextView(this).apply {
            text = value
            textSize = 18f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(14), 0, dp(4))
        })
    }

    private fun config() = TaltunConfig(
        profileName = profile.text.toString().trim(),
        localVip = vip.text.toString().trim(),
        privateKeyHex = privateKey.text.toString().trim(),
        peerVip = peerVip.text.toString().trim(),
        peerPublicKeyHex = peerKey.text.toString().trim(),
        endpoint = endpoint.text.toString().trim(),
        routes = TaltunConfig.splitList(routes.text.toString()),
        allowedSources = TaltunConfig.splitList(allowed.text.toString()),
        dnsServers = TaltunConfig.splitList(dns.text.toString()),
        mtu = mtu.text.toString().toIntOrNull() ?: 1380
    )

    private fun load() {
        val c = ConfigStore(this).load()
        profile.setText(c.profileName); vip.setText(c.localVip); privateKey.setText(c.privateKeyHex)
        peerVip.setText(c.peerVip); peerKey.setText(c.peerPublicKeyHex); endpoint.setText(c.endpoint)
        routes.setText(c.routes.joinToString(", ")); allowed.setText(c.allowedSources.joinToString(", "))
        dns.setText(c.dnsServers.joinToString(", ")); mtu.setText(c.mtu.toString())
        refreshPublic()
    }

    private fun save(show: Boolean): Boolean {
        val c = config()
        val errors = c.validate()
        if (errors.isNotEmpty()) {
            Toast.makeText(this, errors.joinToString("\n"), Toast.LENGTH_LONG).show()
            return false
        }
        ConfigStore(this).save(c)
        refreshPublic()
        if (show) Toast.makeText(this, "Configuración guardada", Toast.LENGTH_SHORT).show()
        return true
    }

    private fun generateIdentity() {
        runCatching { TaltunCrypto.generateKeyPair() }.onSuccess {
            privateKey.setText(Hex.encode(it.privateKey))
            publicKey.text = "Clave pública: " + Hex.encode(it.publicKey)
        }.onFailure {
            Toast.makeText(this, "Error generando identidad: " + it.message, Toast.LENGTH_LONG).show()
        }
    }

    private fun refreshPublic() {
        val value = runCatching {
            val raw = Hex.decode(privateKey.text.toString())
            require(raw.size == 32)
            Hex.encode(TaltunCrypto.publicFromPrivate(raw))
        }.getOrNull()
        publicKey.text = "Clave pública: " + (value ?: "—")
    }

    private fun copyPublic() {
        val value = publicKey.text.toString().substringAfter("Clave pública: ")
        if (value == "—") return
        val cb = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cb.setPrimaryClip(ClipData.newPlainText("Taltun public key", value))
        Toast.makeText(this, "Clave pública copiada", Toast.LENGTH_SHORT).show()
    }

    private fun requestConnect() {
        if (!save(false)) return
        val permission = VpnService.prepare(this)
        if (permission == null) startVpn() else startActivityForResult(permission, vpnRequest)
    }

    private fun startVpn() {
        startForegroundService(Intent(this, TaltunVpnService::class.java).setAction(TaltunVpnService.ACTION_CONNECT))
    }

    private fun disconnect() {
        startService(Intent(this, TaltunVpnService::class.java).setAction(TaltunVpnService.ACTION_DISCONNECT))
    }

    private fun refreshState() {
        status.text = VpnRuntimeState.status.name + " · " + VpnRuntimeState.detail
        stats.text =
            "Datos TX " + bytes(VpnRuntimeState.txBytes.get()) +
            " · RX " + bytes(VpnRuntimeState.rxBytes.get()) +
            "\nUDP TX " + VpnRuntimeState.udpTxPackets.get() +
            " · RX " + VpnRuntimeState.udpRxPackets.get() +
            " · HS TX " + VpnRuntimeState.handshakeTx.get() +
            " · RX " + VpnRuntimeState.handshakeRx.get() +
            " · TUN descartados " + VpnRuntimeState.tunDroppedPackets.get() +
            "\nRed " + VpnRuntimeState.underlyingNetwork +
            " · local " + VpnRuntimeState.udpLocal +
            " · remoto " + VpnRuntimeState.udpRemote
        connect.text = if (VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTED ||
            VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTING) "Desconectar" else "Conectar"
    }

    private fun bytes(v: Long): String = when {
        v >= 1_000_000L -> String.format("%.2f MB", v / 1_000_000.0)
        v >= 1_000L -> String.format("%.1f KB", v / 1_000.0)
        else -> v.toString() + " B"
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}
