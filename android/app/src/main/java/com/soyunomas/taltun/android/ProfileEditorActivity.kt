package com.soyunomas.taltun.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.view.Gravity
import android.view.ViewGroup
import android.view.WindowInsets
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.soyunomas.taltun.android.config.ConfigStore
import com.soyunomas.taltun.android.config.TaltunConfig
import com.soyunomas.taltun.android.core.Hex
import com.soyunomas.taltun.android.core.TaltunCrypto

class ProfileEditorActivity : Activity() {
    companion object {
        const val EXTRA_PROFILE_ID = "profile_id"
    }

    private lateinit var store: ConfigStore
    private var profileId: String? = null
    private var baseline: TaltunConfig? = null

    private lateinit var name: EditText
    private lateinit var vip: EditText
    private lateinit var privateKey: EditText
    private lateinit var publicKey: TextView
    private lateinit var peerVip: EditText
    private lateinit var peerKey: EditText
    private lateinit var endpoint: EditText
    private lateinit var routes: EditText
    private lateinit var allowed: EditText
    private lateinit var dns: EditText
    private lateinit var mtu: EditText

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        store = ConfigStore(this)
        window.setDecorFitsSystemWindows(false)
        profileId = intent.getStringExtra(EXTRA_PROFILE_ID)

        val initial = profileId?.let(store::loadProfile) ?: newDefaultConfig()
        baseline = initial
        setContentView(buildUi(initial))
    }

    @Deprecated("Legacy callback keeps the app free of AndroidX dependencies")
    override fun onBackPressed() {
        if (baseline != null && configFromFields() != baseline) {
            AlertDialog.Builder(this)
                .setTitle("Descartar cambios")
                .setMessage("Hay cambios sin guardar en este perfil.")
                .setNegativeButton("Seguir editando", null)
                .setPositiveButton("Descartar") { _, _ -> super.onBackPressed() }
                .show()
        } else {
            super.onBackPressed()
        }
    }

    private fun buildUi(initial: TaltunConfig): ScrollView {
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
        applySystemBarInsets(scroll, root, 20, 20, 20, 40)

        val top = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        top.addView(Button(this).apply {
            text = "‹"
            contentDescription = "Volver"
            setOnClickListener { onBackPressed() }
        }, LinearLayout.LayoutParams(dp(52), dp(48)))
        top.addView(TextView(this).apply {
            text = if (profileId == null) "Nuevo perfil" else "Editar perfil"
            textSize = 26f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(dp(10), 0, 0, 0)
        }, LinearLayout.LayoutParams(0, -2, 1f))
        root.addView(top)

        section(root, "Perfil")
        name = labeledField(root, "Nombre", "Casa, Oficina, VPS…")
        name.setText(initial.profileName)

        section(root, "Identidad local")
        vip = labeledField(root, "VIP local", "10.0.0.2")
        vip.setText(initial.localVip)

        privateKey = labeledField(root, "Clave privada X25519", "64 caracteres hex", password = true)
        privateKey.setText(initial.privateKeyHex)

        val keyActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        keyActions.addView(Button(this).apply {
            text = "Generar clave"
            isAllCaps = false
            minHeight = dp(56)
            setSingleLine(true)
            setOnClickListener { confirmGenerateIdentity() }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginEnd = dp(4)
        })
        keyActions.addView(Button(this).apply {
            text = "Copiar pública"
            isAllCaps = false
            minHeight = dp(56)
            setSingleLine(true)
            setOnClickListener { copyPublicKey() }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginStart = dp(4)
        })
        root.addView(keyActions)

        root.addView(CheckBox(this).apply {
            text = "Mostrar clave privada"
            setOnCheckedChangeListener { _, checked ->
                privateKey.transformationMethod = if (checked) null else PasswordTransformationMethod.getInstance()
                privateKey.setSelection(privateKey.text.length)
            }
        })

        publicKey = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(dp(10), dp(8), dp(10), dp(12))
        }
        root.addView(publicKey)
        refreshPublicKey()

        section(root, "Servidor")
        peerVip = labeledField(root, "VIP del servidor / peer", "10.0.0.1")
        peerVip.setText(initial.peerVip)
        peerKey = labeledField(root, "Clave pública X25519 del servidor", "64 caracteres hex")
        peerKey.setText(initial.peerPublicKeyHex)
        endpoint = labeledField(root, "Endpoint", "192.168.24.119:9000")
        endpoint.setText(initial.endpoint)

        section(root, "Enrutamiento")
        routes = labeledField(root, "Rutas por Taltun", "10.0.0.0/24", multiline = true)
        routes.setText(initial.routes.joinToString(", "))
        helper(root, "Para túnel completo usa 0.0.0.0/0. El socket exterior queda ligado a la red física.")

        allowed = labeledField(root, "Orígenes permitidos desde el peer", "10.0.0.0/24", multiline = true)
        allowed.setText(initial.allowedSources.joinToString(", "))
        dns = labeledField(root, "DNS opcional", "1.1.1.1, 8.8.8.8", multiline = true)
        dns.setText(initial.dnsServers.joinToString(", "))
        mtu = labeledField(root, "MTU", "1380", numeric = true)
        mtu.setText(initial.mtu.toString())

        root.addView(Button(this).apply {
            text = "Guardar perfil"
            isAllCaps = false
            minHeight = dp(56)
            setOnClickListener { saveAndClose() }
        }, LinearLayout.LayoutParams(-1, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(22)
        })

        root.addView(Button(this).apply {
            text = "Cancelar"
            isAllCaps = false
            minHeight = dp(56)
            setOnClickListener { onBackPressed() }
        }, LinearLayout.LayoutParams(-1, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(8)
            bottomMargin = dp(8)
        })

        return scroll
    }

    private fun section(root: LinearLayout, title: String) {
        root.addView(TextView(this).apply {
            text = title
            textSize = 18f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(20), 0, dp(8))
        })
    }

    private fun helper(root: LinearLayout, value: String) {
        root.addView(TextView(this).apply {
            text = value
            textSize = 12f
            setTextColor(getColor(R.color.taltun_text_secondary))
            setPadding(0, 0, 0, dp(8))
        })
    }

    private fun labeledField(
        root: LinearLayout,
        label: String,
        hint: String,
        password: Boolean = false,
        numeric: Boolean = false,
        multiline: Boolean = false,
    ): EditText {
        root.addView(TextView(this).apply {
            text = label
            textSize = 13f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(6), 0, 0)
        })
        val field = EditText(this).apply {
            this.hint = hint
            if (multiline) {
                setSingleLine(false)
                minLines = 2
                maxLines = 4
                gravity = Gravity.TOP
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            } else {
                setSingleLine(true)
            }
            if (password) {
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                transformationMethod = PasswordTransformationMethod.getInstance()
            }
            if (numeric) inputType = InputType.TYPE_CLASS_NUMBER
        }
        root.addView(field, LinearLayout.LayoutParams(-1, if (multiline) dp(78) else dp(54)))
        return field
    }

    private fun newDefaultConfig(): TaltunConfig {
        val privateHex = runCatching {
            Hex.encode(TaltunCrypto.generateKeyPair().privateKey)
        }.getOrDefault("")
        return TaltunConfig(
            profileName = "Nuevo perfil",
            privateKeyHex = privateHex,
        )
    }

    private fun configFromFields(): TaltunConfig = TaltunConfig(
        profileName = name.text.toString().trim(),
        localVip = vip.text.toString().trim(),
        privateKeyHex = privateKey.text.toString().trim(),
        peerVip = peerVip.text.toString().trim(),
        peerPublicKeyHex = peerKey.text.toString().trim(),
        endpoint = endpoint.text.toString().trim(),
        routes = TaltunConfig.splitList(routes.text.toString()),
        allowedSources = TaltunConfig.splitList(allowed.text.toString()),
        dnsServers = TaltunConfig.splitList(dns.text.toString()),
        mtu = mtu.text.toString().toIntOrNull() ?: 1380,
    )

    private fun saveAndClose() {
        val config = configFromFields()
        val errors = config.validate()
        if (errors.isNotEmpty()) {
            Toast.makeText(this, errors.joinToString("\n"), Toast.LENGTH_LONG).show()
            return
        }

        val id = store.saveProfile(profileId, config)
        profileId = id
        baseline = config
        if (
            VpnRuntimeState.activeProfileId == id &&
            (VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTED ||
                VpnRuntimeState.status == VpnRuntimeState.Status.CONNECTING)
        ) {
            Toast.makeText(this, "Guardado. Reconecta para aplicar los cambios.", Toast.LENGTH_LONG).show()
        } else {
            Toast.makeText(this, "Perfil guardado", Toast.LENGTH_SHORT).show()
        }
        finish()
    }

    private fun confirmGenerateIdentity() {
        val action = {
            runCatching { TaltunCrypto.generateKeyPair() }
                .onSuccess {
                    privateKey.setText(Hex.encode(it.privateKey))
                    refreshPublicKey()
                }
                .onFailure {
                    Toast.makeText(this, "No se pudo generar la identidad: " + it.message, Toast.LENGTH_LONG).show()
                }
        }

        if (privateKey.text.toString().isBlank()) {
            action()
        } else {
            AlertDialog.Builder(this)
                .setTitle("Regenerar identidad")
                .setMessage("Cambiará la clave pública de este perfil. Tendrás que actualizarla también en el servidor.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Regenerar") { _, _ -> action() }
                .show()
        }
    }

    private fun refreshPublicKey(): String? {
        val value = runCatching {
            val raw = Hex.decode(privateKey.text.toString().trim())
            require(raw.size == 32)
            Hex.encode(TaltunCrypto.publicFromPrivate(raw))
        }.getOrNull()
        publicKey.text = "Pública: " + (value ?: "—")
        return value
    }

    private fun copyPublicKey() {
        val value = refreshPublicKey() ?: run {
            Toast.makeText(this, "La clave privada no es válida", Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Taltun public key", value))
        Toast.makeText(this, "Clave pública copiada", Toast.LENGTH_SHORT).show()
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
