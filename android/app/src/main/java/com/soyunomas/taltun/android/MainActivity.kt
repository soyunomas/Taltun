package com.soyunomas.taltun.android

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.ViewGroup
import android.view.WindowInsets
import android.widget.Button
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.soyunomas.taltun.android.config.ConfigStore
import com.soyunomas.taltun.android.core.Hex
import com.soyunomas.taltun.android.core.TaltunCrypto

class MainActivity : Activity() {
    private val vpnRequest = 7001
    private lateinit var store: ConfigStore
    private lateinit var status: TextView
    private lateinit var stats: TextView
    private lateinit var profilesContainer: LinearLayout
    private var pendingProfileId: String? = null
    private var lastCardState: String? = null

    private val handler = Handler(Looper.getMainLooper())
    private val poll = object : Runnable {
        override fun run() {
            refreshState()
            handler.postDelayed(this, 500)
        }
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        store = ConfigStore(this)
        window.setDecorFitsSystemWindows(false)
        setContentView(buildUi())
        renderProfiles()

        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 7002)
        }
    }

    override fun onResume() {
        super.onResume()
        renderProfiles()
        handler.post(poll)
    }

    override fun onPause() {
        handler.removeCallbacks(poll)
        super.onPause()
    }

    @Deprecated("Legacy callback avoids AndroidX dependency")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequest) {
            val id = pendingProfileId
            pendingProfileId = null
            if (resultCode == RESULT_OK && id != null) startVpn(id)
        }
    }

    private fun buildUi(): ScrollView {
        val scroll = ScrollView(this).apply {
            setBackgroundColor(getColor(R.color.taltun_background))
            clipToPadding = false
            isFillViewport = true
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(36))
        }
        scroll.addView(root)
        applySystemBarInsets(scroll, root, 20, 20, 20, 36)

        root.addView(TextView(this).apply {
            text = "Taltun"
            textSize = 30f
            setTypeface(typeface, Typeface.BOLD)
        })
        root.addView(TextView(this).apply {
            text = "Perfiles VPN · protocolo v2"
            textSize = 14f
            setTextColor(getColor(R.color.taltun_text_secondary))
            setPadding(0, 0, 0, dp(12))
        })

        status = TextView(this).apply {
            textSize = 17f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(dp(14), dp(12), dp(14), dp(4))
        }
        stats = TextView(this).apply {
            textSize = 12f
            setTextColor(getColor(R.color.taltun_text_secondary))
            setPadding(dp(14), 0, dp(14), dp(14))
        }
        root.addView(status)
        root.addView(stats)

        val heading = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(12), 0, dp(8))
        }
        heading.addView(TextView(this).apply {
            text = "Perfiles"
            textSize = 20f
            setTypeface(typeface, Typeface.BOLD)
        }, LinearLayout.LayoutParams(0, -2, 1f))
        heading.addView(Button(this).apply {
            text = "+ Nuevo"
            isAllCaps = false
            minHeight = dp(52)
            setOnClickListener { openEditor(null) }
        })
        root.addView(heading)

        profilesContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        root.addView(profilesContainer)
        return scroll
    }

    private fun renderProfiles() {
        if (!::profilesContainer.isInitialized) return
        profilesContainer.removeAllViews()

        val profiles = store.listProfiles()
        val selected = store.selectedProfileId()
        if (profiles.isEmpty()) {
            profilesContainer.addView(TextView(this).apply {
                text = "Todavía no hay perfiles. Crea uno para configurar tu primera conexión."
                textSize = 15f
                setTextColor(getColor(R.color.taltun_text_secondary))
                setPadding(dp(8), dp(24), dp(8), dp(24))
            })
            return
        }

        profiles.forEach { stored ->
            val config = stored.config
            val active = VpnRuntimeState.activeProfileId == stored.id
            val isRunning = active && (
                VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTED ||
                    VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTING
                )
            val validationErrors = config.validate()

            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(16), dp(14), dp(12), dp(12))
                background = GradientDrawable().apply {
                    setColor(getColor(R.color.taltun_surface))
                    cornerRadius = dp(14).toFloat()
                    setStroke(dp(1), getColor(R.color.taltun_border))
                }
            }

            val titleRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            titleRow.addView(TextView(this).apply {
                text = config.profileName
                textSize = 18f
                setTypeface(typeface, Typeface.BOLD)
            }, LinearLayout.LayoutParams(0, -2, 1f))

            val badge = when {
                active && VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTED -> "CONECTADO"
                active && VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTING -> "CONECTANDO"
                active && VpnRuntimeState.status == VpnRuntimeState.Status.ERROR -> "ERROR"
                selected == stored.id -> "ÚLTIMO USADO"
                else -> null
            }
            if (badge != null) {
                titleRow.addView(TextView(this).apply {
                    text = badge
                    textSize = 11f
                    setTypeface(typeface, Typeface.BOLD)
                    setPadding(dp(8), dp(4), dp(8), dp(4))
                    background = GradientDrawable().apply {
                        setColor(getColor(R.color.taltun_surface_muted))
                        cornerRadius = dp(10).toFloat()
                    }
                })
            }
            card.addView(titleRow)

            card.addView(TextView(this).apply {
                text = if (config.endpoint.isBlank()) "Endpoint sin configurar" else config.endpoint
                textSize = 14f
                setPadding(0, dp(7), 0, 0)
            })
            card.addView(TextView(this).apply {
                text = config.localVip + " → " + config.peerVip +
                    "   ·   " + if (config.routes.isEmpty()) "sin rutas" else config.routes.joinToString(", ")
                textSize = 12f
                setTextColor(getColor(R.color.taltun_text_secondary))
                setPadding(0, dp(3), 0, dp(8))
            })

            if (validationErrors.isNotEmpty()) {
                card.addView(TextView(this).apply {
                    text = "Configuración incompleta · " + validationErrors.first()
                    textSize = 12f
                    setPadding(0, 0, 0, dp(6))
                })
            }

            val actions = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }

            actions.addView(Button(this).apply {
                text = if (isRunning) "Desconectar" else "Conectar"
                isAllCaps = false
                minHeight = dp(52)
                isEnabled = isRunning || validationErrors.isEmpty()
                setOnClickListener {
                    if (isRunning) disconnect() else requestConnect(stored.id)
                }
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

            actions.addView(Button(this).apply {
                text = "Editar"
                isAllCaps = false
                minHeight = dp(52)
                setOnClickListener { openEditor(stored.id) }
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

            val more = Button(this).apply {
                text = "⋮"
                isAllCaps = false
                minHeight = dp(52)
                contentDescription = "Más opciones para " + config.profileName
                setOnClickListener { showProfileMenu(this, stored.id) }
            }
            actions.addView(more, LinearLayout.LayoutParams(dp(56), ViewGroup.LayoutParams.WRAP_CONTENT))
            card.addView(actions)

            profilesContainer.addView(
                card,
                LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) },
            )
        }
        lastCardState = cardStateKey()
    }

    private fun showProfileMenu(anchor: Button, profileId: String) {
        val profile = store.loadProfile(profileId) ?: return
        PopupMenu(this, anchor).apply {
            menu.add("Copiar clave pública")
            menu.add("Duplicar")
            menu.add("Eliminar")
            setOnMenuItemClickListener { item ->
                when (item.title.toString()) {
                    "Copiar clave pública" -> copyPublicKey(profile.privateKeyHex)
                    "Duplicar" -> {
                        val newId = store.duplicateProfile(profileId)
                        renderProfiles()
                        if (newId != null) openEditor(newId)
                    }
                    "Eliminar" -> confirmDelete(profileId, profile.profileName)
                }
                true
            }
            show()
        }
    }

    private fun confirmDelete(profileId: String, name: String) {
        val isActive = VpnRuntimeState.activeProfileId == profileId &&
            (VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTED ||
                VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTING)
        if (isActive) {
            Toast.makeText(this, "Desconecta este perfil antes de eliminarlo", Toast.LENGTH_LONG).show()
            return
        }

        AlertDialog.Builder(this)
            .setTitle("Eliminar perfil")
            .setMessage("Se eliminará “${name}” y su clave privada de este dispositivo.")
            .setNegativeButton("Cancelar", null)
            .setPositiveButton("Eliminar") { _, _ ->
                store.deleteProfile(profileId)
                renderProfiles()
            }
            .show()
    }

    private fun copyPublicKey(privateKeyHex: String) {
        val value = runCatching {
            val raw = Hex.decode(privateKeyHex)
            require(raw.size == 32)
            Hex.encode(TaltunCrypto.publicFromPrivate(raw))
        }.getOrNull()

        if (value == null) {
            Toast.makeText(this, "Este perfil no tiene una identidad válida", Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Taltun public key", value))
        Toast.makeText(this, "Clave pública copiada", Toast.LENGTH_SHORT).show()
    }

    private fun requestConnect(profileId: String) {
        val config = store.loadProfile(profileId) ?: return
        val errors = config.validate()
        if (errors.isNotEmpty()) {
            Toast.makeText(this, errors.joinToString("\n"), Toast.LENGTH_LONG).show()
            openEditor(profileId)
            return
        }

        val otherRunning = VpnRuntimeState.activeProfileId != null &&
            VpnRuntimeState.activeProfileId != profileId &&
            (VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTED ||
                VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTING)

        if (otherRunning) {
            val current = VpnRuntimeState.activeProfileName ?: "el perfil actual"
            AlertDialog.Builder(this)
                .setTitle("Cambiar de perfil")
                .setMessage("Se desconectará “${current}” y se conectará “${config.profileName}”.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Cambiar") { _, _ -> requestVpnPermission(profileId) }
                .show()
        } else {
            requestVpnPermission(profileId)
        }
    }

    private fun requestVpnPermission(profileId: String) {
        store.select(profileId)
        val permission = VpnService.prepare(this)
        if (permission == null) {
            startVpn(profileId)
        } else {
            pendingProfileId = profileId
            startActivityForResult(permission, vpnRequest)
        }
    }

    private fun startVpn(profileId: String) {
        startForegroundService(
            Intent(this, TaltunVpnService::class.java)
                .setAction(TaltunVpnService.ACTION_CONNECT)
                .putExtra(TaltunVpnService.EXTRA_PROFILE_ID, profileId),
        )
    }

    private fun disconnect() {
        startService(
            Intent(this, TaltunVpnService::class.java)
                .setAction(TaltunVpnService.ACTION_DISCONNECT),
        )
    }

    private fun openEditor(profileId: String?) {
        startActivity(
            Intent(this, ProfileEditorActivity::class.java).apply {
                if (profileId != null) putExtra(ProfileEditorActivity.EXTRA_PROFILE_ID, profileId)
            },
        )
    }

    private fun refreshState() {
        val name = VpnRuntimeState.activeProfileName
        status.text = when (VpnRuntimeState.status) {
            VpnRuntimeState.Status.DISCONNECTED -> "Sin conexión"
            VpnRuntimeState.Status.CONNECTING -> "Conectando" + (name?.let { " · $it" } ?: "")
            VpnRuntimeState.Status.CONNECTED -> "Conectado" + (name?.let { " · $it" } ?: "")
            VpnRuntimeState.Status.ERROR -> "Error" + (name?.let { " · $it" } ?: "")
        }

        stats.text = when (VpnRuntimeState.status) {
            VpnRuntimeState.Status.DISCONNECTED -> "Selecciona un perfil para conectar."
            else -> VpnRuntimeState.detail +
                "\nDatos TX " + bytes(VpnRuntimeState.txBytes.get()) +
                " · RX " + bytes(VpnRuntimeState.rxBytes.get()) +
                "   ·   UDP " + VpnRuntimeState.udpTxPackets.get() + "/" + VpnRuntimeState.udpRxPackets.get()
        }

        val key = cardStateKey()
        if (key != lastCardState) renderProfiles()
    }

    private fun cardStateKey(): String =
        VpnRuntimeState.status.name + "|" +
            (VpnRuntimeState.activeProfileId ?: "") + "|" +
            (store.selectedProfileId() ?: "")

    private fun bytes(value: Long): String = when {
        value >= 1_000_000L -> String.format("%.2f MB", value / 1_000_000.0)
        value >= 1_000L -> String.format("%.1f KB", value / 1_000.0)
        else -> "$value B"
    }


    private fun applySystemBarInsets(
        scroll: ScrollView,
        root: LinearLayout,
        leftDp: Int,
        topDp: Int,
        rightDp: Int,
        bottomDp: Int,
    ) {
        scroll.setOnApplyWindowInsetsListener { _, insets ->
            val bars = insets.getInsets(
                WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout(),
            )
            root.setPadding(
                dp(leftDp) + bars.left,
                dp(topDp) + bars.top,
                dp(rightDp) + bars.right,
                dp(bottomDp) + bars.bottom,
            )
            insets
        }
        scroll.requestApplyInsets()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
