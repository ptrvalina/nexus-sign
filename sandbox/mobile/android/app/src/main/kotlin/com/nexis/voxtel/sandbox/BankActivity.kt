package com.nexis.voxtel.sandbox

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.nexis.nexussign.NEXUSSignConfig
import com.nexis.nexussign.NEXUSSignSDK
import com.nexis.nexussign.NEXUSVerificationOutcome
import com.nexis.nexussign.NexusAuthorization
import com.nexis.nexussign.NexusDeclineReason
import com.nexis.nexussign.NexusPromptLabels
import com.nexis.nexussign.NexusSignedTransaction
import java.util.UUID
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * VoxTel Demo Bank (sandbox). One activity; screens are built in code.
 * The NEXUS-SIGN SDK runs inside the bank app: the customer installs nothing else.
 */
class BankActivity : AppCompatActivity() {

    private companion object {
        const val PREFS = "voxtel-sandbox"
        val ACCENT = Color.rgb(61, 191, 168)
        val ACCENT_SOFT = Color.rgb(219, 242, 237)
        val DEEP = Color.rgb(30, 90, 90)
        val BG = Color.rgb(247, 250, 250)
        val INK = Color.rgb(20, 31, 36)
        val MUTED = Color.rgb(115, 128, 135)
        val NEGATIVE = Color.rgb(224, 92, 69)
        val POSITIVE = Color.rgb(33, 158, 120)
    }

    private var api: BankApi? = null
    private var sdk: NEXUSSignSDK? = null
    private var bankName = "VoxTel Demo Bank"
    private var profile: Profile? = null
    private var accounts = listOf<Account>()
    private var cards = listOf<Card>()
    private var transactions = listOf<BankTransaction>()
    private var favorites = listOf<Favorite>()
    private var products = listOf<Product>()
    private var notifications = listOf<BankNotification>()

    private var tab = "home"
    /** True while a tab's top screen is shown (nothing typed there, safe to redraw). */
    private var onTab = false
    private val backStack = ArrayDeque<() -> Unit>()
    private var dialogOpen = false
    private var busy = false
    private val dismissed = mutableSetOf<String>()

    private lateinit var content: FrameLayout
    private lateinit var nav: LinearLayout

    private val prefs by lazy { getSharedPreferences(PREFS, Context.MODE_PRIVATE) }
    private val dp = { v: Int -> (v * resources.displayMetrics.density).toInt() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(BG) }
        content = FrameLayout(this)
        nav = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setBackgroundColor(Color.WHITE); setPadding(0, dp(6), 0, dp(10)) }
        root.addView(content, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        root.addView(nav, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        setContentView(root)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (backStack.isNotEmpty()) backStack.removeLast().invoke() else finish()
            }
        })
        showLogin()
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                var tick = 0
                while (true) {
                    poll(tick % 5 == 0)
                    tick++
                    delay(3_000)
                }
            }
        }
    }

    // ---- Session -------------------------------------------------------------

    private fun connect(address: String): Boolean {
        val url = address.trim().trimEnd('/')
        val api = BankApi(url)
        val sdk = try {
            NEXUSSignSDK(
                this,
                NEXUSSignConfig(
                    bankId = "voxtel-sandbox",
                    baseUrl = url,
                    sessionTokenProvider = { _ -> api.bootstrapToken() },
                    promptTitle = "Подтвердите операцию",
                    promptCancelText = "Отмена",
                    recoverySetupPromptText = "Подтвердите новую фразу восстановления",
                    allowEmulatorHostHttp = true,
                    promptLabels = NexusPromptLabels(iban = "IBAN", account = "Счёт", accountNumber = "Номер счёта", name = "Получатель", bic = "BIC"),
                ),
            )
        } catch (e: IllegalArgumentException) {
            alert("Адрес банка: https://… по Wi‑Fi, или http://127.0.0.1:8191 через USB (adb reverse), или http://10.0.2.2:8191 в эмуляторе.")
            return false
        }
        this.api = api
        this.sdk = sdk
        return true
    }

    private val deviceRegistered get() = (sdk?.isRegistered() ?: false) && (profile?.deviceEnrolled ?: false)

    private fun login(address: String, login: String, password: String) = launchBusy {
        if (!connect(address)) return@launchBusy
        prefs.edit().putString("server", address).apply()
        val api = api ?: return@launchBusy
        bankName = runCatching { api.bankName() }.getOrDefault(bankName)
        profile = api.login(login.trim().lowercase(), password)
        refresh()
        if (deviceRegistered) showTab("home") else showEnrol()
    }

    private fun logout() = lifecycleScope.launch {
        api?.logout()
        profile = null
        accounts = emptyList(); transactions = emptyList()
        backStack.clear()
        showLogin()
    }

    private fun enrol() = launchBusy {
        val sdk = sdk ?: return@launchBusy
        val registration = sdk.bootstrap()
        profile = api?.completeEnrolment(registration.credentialId)
        alert("Телефон подключён к NEXUS-SIGN. Операции подтверждаются ключом этого телефона.")
        showTab("home")
    }

    private suspend fun refresh() {
        val api = api ?: return
        try {
            accounts = api.accounts()
            cards = api.cards()
            transactions = api.transactions()
            favorites = api.favorites()
            products = api.products()
            notifications = api.notifications()
        } catch (e: Exception) {
            if (!dialogOpen) toastError(e)
        }
    }

    private suspend fun poll(refreshData: Boolean) {
        val sdk = sdk ?: return
        if (profile == null) return
        val delivery = runCatching { sdk.submitPendingOfflineSignatures() }.getOrNull()
        if (delivery != null && delivery.delivered > 0) alert("Подпись офлайн-подтверждения отправлена в банк.")
        if (delivery != null && delivery.refused > 0) alert("Банк не принял подпись офлайн-подтверждения: операция не будет выполнена.")
        if (refreshData && onTab && backStack.isEmpty() && !dialogOpen && deviceRegistered) { refresh(); showTab(tab) }
        if (dialogOpen || busy || !deviceRegistered) return
        val waiting = runCatching { api?.pendingAuthorization() }.getOrNull() ?: return
        if (waiting.id !in dismissed) runCatching { presentConfirmation(waiting) }
    }

    // ---- Payments ------------------------------------------------------------

    private fun submit(order: JSONObject, key: String) = launchBusy {
        val t = api!!.create(order, key)
        if (t.state != "AUTHORIZATION_PENDING") { showResult(t); return@launchBusy }
        presentConfirmation(t)
    }

    /** "Подтвердите перевод": the terms come from the bytes the SDK signs. */
    private suspend fun presentConfirmation(t: BankTransaction) {
        val sdk = sdk ?: return
        val authorization = sdk.fetchAuthorization(t.authorizationId ?: return)
        val signed = authorization.signedTransaction()
        dialogOpen = true
        val box = column(dp(20)).apply {
            addView(text("${signed.formattedAmount()} ${signed.currency}", 28f, bold = true, center = true))
            signed.beneficiary["name"]?.let { addView(row("Получатель", it)) }
            signed.beneficiary["iban"]?.let { addView(row("IBAN", it)) }
            signed.beneficiary["fee"]?.let { addView(row("Комиссия", it)) }
            addView(row("Референс", signed.transactionReference))
            addView(text("Данные прочитаны из того, что подписывает ключ телефона. Если они отличаются от вашего заказа — не подтверждайте.", 12f, color = MUTED).padTop(12))
        }
        var dialog: AlertDialog? = null
        box.addView(primary("Подтвердить") { dialog?.dismiss(); approve(t, authorization) }.padTop(16))
        box.addView(link("Нет интернета? Код для банка") { dialog?.dismiss(); offline(t, signed) })
        box.addView(secondary("Это не я") { dialog?.dismiss(); decline(t, authorization) }.padTop(8))
        box.addView(secondary("Позже") { dismissed += t.id; dialog?.dismiss() }.padTop(8))
        val created = AlertDialog.Builder(this)
            .setTitle("Подтвердите ${if (signed.operationType == "transfer") "перевод" else "платёж"} в $bankName")
            .setView(ScrollView(this).apply { addView(box) })
            .setCancelable(false)
            .create()
        dialog = created
        created.setOnDismissListener { dialogOpen = false }
        created.show()
    }

    private fun approve(t: BankTransaction, authorization: NexusAuthorization) = launchBusy {
        when (sdk!!.approve(authorization, this@BankActivity)) {
            NEXUSVerificationOutcome.VERIFIED -> follow(t.id)
            NEXUSVerificationOutcome.FAILED -> alert("Auth Core не принял подпись.")
            NEXUSVerificationOutcome.EXPIRED -> alert("Срок подтверждения истёк.")
        }
    }

    private fun decline(t: BankTransaction, authorization: NexusAuthorization) = launchBusy {
        dismissed += t.id
        sdk!!.decline(authorization, NexusDeclineReason.NOT_ME)
        follow(t.id)
    }

    /** Online: the QR content; offline: the SDK makes the 8-digit code, the signature waits for the network. */
    private fun offline(t: BankTransaction, signed: NexusSignedTransaction) = launchBusy {
        dismissed += t.id
        val sdk = sdk!!
        val challenge = sdk.readOfflineChallenge(api!!.offlineChallenge(t.id))
        val code = sdk.confirmOffline(challenge, this@BankActivity)
        AlertDialog.Builder(this@BankActivity)
            .setTitle("Код подтверждения")
            .setMessage("${code.take(4)} ${code.takeLast(4)}\n\nОперация ${signed.transactionReference}.\n\nНазовите код сотруднику банка (в песочнице — введите его в консоли банка на странице операции). Банк исполнит операцию только когда получит и подпись телефона: она отправится сама, как только появится интернет.")
            .setPositiveButton("Готово", null)
            .show()
    }

    /** Follows the transaction at the bank until it is executed or refused. */
    private suspend fun follow(id: String) {
        showWaiting()
        repeat(60) {
            val t = runCatching { api!!.transaction(id) }.getOrNull()
            if (t != null && t.isFinal) { refresh(); showResult(t); return }
            delay(1_000)
        }
        refresh()
        showTab("history")
    }

    // ---- Screens -------------------------------------------------------------

    private fun setScreen(view: View, showNav: Boolean) {
        content.removeAllViews()
        content.addView(view)
        nav.visibility = if (showNav) View.VISIBLE else View.GONE
        onTab = showNav
        if (showNav) renderNav()
    }

    private fun push(current: () -> Unit, next: () -> Unit) { backStack.addLast(current); next() }

    private fun showLogin() {
        val serverField = edit("Адрес банка", prefs.getString("server", "http://127.0.0.1:8191") ?: "")
        val loginField = edit("Email/логин", "")
        val passwordField = edit("Пароль", "", password = true)
        val screen = column(dp(24)).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            addView(logo().padTop(40))
            addView(text("Вход", 30f, bold = true, center = true).padTop(28))
            addView(loginField.padTop(24)); addView(passwordField.padTop(12)); addView(serverField.padTop(12))
            addView(text("Через USB: http://127.0.0.1:8191 (adb reverse). По Wi‑Fi: https://<IP компьютера>:8191.", 12f, color = MUTED).padTop(6))
            addView(primary("Продолжить") { login(serverField.text.toString(), loginField.text.toString(), passwordField.text.toString()) }.padTop(28))
            addView(text("Демонстрационный банк: тестовые средства, вымышленные клиенты.", 12f, color = MUTED, center = true).padTop(12))
        }
        setScreen(scroll(screen), false)
    }

    private fun showEnrol() {
        setScreen(scroll(column(dp(24)).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            addView(logo().padTop(60))
            addView(text("Подключите этот телефон", 22f, bold = true, center = true).padTop(20))
            addView(text("Операции подтверждаются ключом, который создаётся в аппаратном хранилище этого телефона (StrongBox / TEE) и никогда его не покидает. Понадобится отпечаток или распознавание лица.", 14f, color = MUTED, center = true).padTop(12))
            addView(primary("Подключить телефон") { enrol() }.padTop(36))
            addView(secondary("Выйти") { logout() }.padTop(10))
        }), false)
    }

    private fun showTab(name: String) {
        tab = name
        backStack.clear()
        when (name) {
            "home" -> showHome()
            "payments" -> showPayments()
            "history" -> showHistory()
            "products" -> showProducts()
            else -> showMore()
        }
    }

    private fun renderNav() {
        nav.removeAllViews()
        for ((id, label) in listOf("home" to "Главная", "payments" to "Платежи", "history" to "История", "products" to "Продукты", "more" to "Ещё")) {
            nav.addView(TextView(this).apply {
                text = label
                textSize = 12f
                gravity = Gravity.CENTER
                setTextColor(if (id == tab) ACCENT else MUTED)
                setTypeface(null, if (id == tab) Typeface.BOLD else Typeface.NORMAL)
                setPadding(0, dp(10), 0, dp(10))
                setOnClickListener { showTab(id) }
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }
    }

    private fun showHome() {
        val screen = column(dp(16)).apply {
            addView(text(profile?.displayName ?: "", 20f, bold = true))
            addView(text("Всего на счетах: ${Money.format(accounts.sumOf { it.balanceMinor }, accounts.firstOrNull()?.currency ?: "MDL")}", 14f, color = MUTED).padTop(4))
            addView(section("Мои продукты"))
            val strip = LinearLayout(this@BankActivity)
            accounts.forEach { a -> strip.addView(accountCard(a).apply { setOnClickListener { push(::showHome) { showAccount(a) } } }, LinearLayout.LayoutParams(dp(280), dp(160)).apply { marginEnd = dp(10) }) }
            addView(HorizontalScrollView(this@BankActivity).apply { isHorizontalScrollBarEnabled = false; addView(strip) })
            addView(section("Быстрые действия"))
            val quick = LinearLayout(this@BankActivity)
            quick.addView(tile("Новый платёж") { push(::showHome) { showTransfer(own = false) } })
            quick.addView(tile("Между своими счетами") { push(::showHome) { showTransfer(own = true) } })
            favorites.forEach { f -> quick.addView(tile(f.name) { push(::showHome) { showTransfer(own = false, name = f.name, iban = f.iban) } }) }
            addView(HorizontalScrollView(this@BankActivity).apply { isHorizontalScrollBarEnabled = false; addView(quick) })
            addView(section("Транзакции"))
            addView(transactionList(transactions.take(4)) { t -> push(::showHome) { showTransaction(t) } })
            if (notifications.any { it.state != "READ" }) addView(text("Новых уведомлений: ${notifications.count { it.state != "READ" }} (вкладка «Ещё»)", 13f, color = ACCENT).padTop(12))
        }
        setScreen(scroll(screen), true)
    }

    private fun showPayments() {
        val screen = column(dp(16)).apply {
            addView(text("Платежи", 24f, bold = true))
            addView(section("Избранное"))
            val fav = LinearLayout(this@BankActivity)
            favorites.forEach { f -> fav.addView(tile(f.name) { push(::showPayments) { showTransfer(own = false, name = f.name, iban = f.iban) } }) }
            if (favorites.isEmpty()) fav.addView(text("Сохраните получателя после перевода.", 13f, color = MUTED))
            addView(HorizontalScrollView(this@BankActivity).apply { addView(fav) })
            addView(section("Платежи"))
            addView(LinearLayout(this@BankActivity).apply {
                addView(tile("Новый платёж") { push(::showPayments) { showTransfer(own = false) } })
                addView(tile("Платёж в бюджет") { push(::showPayments) { showTransfer(own = false, name = "Казначейство (тест)", iban = "MD65RN000000000000000555") } })
            })
            addView(section("Переводы"))
            addView(LinearLayout(this@BankActivity).apply {
                addView(tile("Между своими счетами") { push(::showPayments) { showTransfer(own = true) } })
                addView(tile("По номеру счёта (IBAN)") { push(::showPayments) { showTransfer(own = false) } })
            })
        }
        setScreen(scroll(screen), true)
    }

    private fun showTransfer(own: Boolean, name: String = "", iban: String = "") {
        var source = accounts.firstOrNull()?.id ?: ""
        var destination = accounts.firstOrNull { it.id != source }?.id ?: ""
        val nameField = edit("Имя получателя", name)
        val ibanField = edit("IBAN получателя", iban).apply { inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS }
        val amount = edit("Сумма перевода, ${accounts.firstOrNull()?.currency ?: "MDL"}", "").apply { inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL }
        val note = edit("Назначение (необязательно)", "")
        val error = text("", 13f, color = NEGATIVE)
        val screen = column(dp(16)).apply {
            addView(text(if (own) "Между своими счетами" else "Перевод по IBAN", 22f, bold = true))
            addView(text("Отправитель", 13f, color = MUTED).padTop(16))
            addView(picker(accounts) { source = it })
            addView(text("Получатель", 13f, color = MUTED).padTop(16))
            if (own) addView(picker(accounts) { destination = it }) else { addView(nameField.padTop(4)); addView(ibanField.padTop(10)) }
            addView(amount.padTop(16)); addView(note.padTop(10)); addView(error.padTop(8))
            addView(primary("Оплатить") {
                val minor = Money.minor(amount.text.toString()) ?: run { error.text = "Введите сумму, например 50 или 50.25"; return@primary }
                val order = JSONObject().put("sourceAccountId", source).put("amountMinor", minor)
                if (note.text.isNotBlank()) order.put("description", note.text.toString())
                if (own) {
                    if (destination == source) { error.text = "Выберите другой счёт зачисления"; return@primary }
                    order.put("destinationAccountId", destination)
                } else {
                    order.put("beneficiaryName", nameField.text.toString().trim()).put("beneficiaryIban", ibanField.text.toString().replace(" ", "").uppercase())
                }
                launchBusy {
                    try {
                        val quote = api!!.quote(order)
                        push({ showTransfer(own, nameField.text.toString(), ibanField.text.toString()) }) { showReview(order, quote) }
                    } catch (e: BankApiException) { error.text = e.message }
                }
            }.padTop(16))
        }
        setScreen(scroll(screen), false)
    }

    private fun showReview(order: JSONObject, quote: Quote) {
        val key = UUID.randomUUID().toString()
        val source = accounts.firstOrNull { it.id == order.getString("sourceAccountId") }
        setScreen(scroll(column(dp(16)).apply {
            addView(text(Money.format(quote.amountMinor, quote.currency), 32f, bold = true, center = true).padTop(16))
            addView(box().apply {
                addView(row("Отправитель", "${source?.name ?: ""} (${source?.shortNumber ?: ""})"))
                addView(row("Получатель", "${quote.beneficiaryName} (**** ${quote.beneficiaryIban.takeLast(4)})"))
                addView(row("Сумма перевода", Money.format(quote.amountMinor, quote.currency)))
                addView(row("Комиссия", Money.format(quote.feeMinor, quote.currency)))
                addView(row("Итоговая сумма", Money.format(quote.totalMinor, quote.currency)))
            }.padTop(16))
            addView(text("После нажатия банк попросит подтвердить операцию ключом этого телефона.", 13f, color = MUTED, center = true).padTop(12))
            addView(primary("Подтвердить") { submit(order, key) }.padTop(24))
        }), false)
    }

    private fun showWaiting() {
        setScreen(column(dp(24)).apply {
            gravity = Gravity.CENTER
            addView(ProgressBar(this@BankActivity))
            addView(text("Ожидание подтверждения", 22f, bold = true, center = true).padTop(16))
            addView(text("Банк проверяет подпись и доказательство…", 14f, color = MUTED, center = true).padTop(8))
        }, false)
    }

    private fun showResult(t: BankTransaction) {
        val ok = t.state == "EXECUTED"
        backStack.clear()
        setScreen(scroll(column(dp(24)).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            addView(text(if (ok) "✓" else "✕", 44f, bold = true, center = true, color = Color.WHITE).apply {
                background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(if (ok) ACCENT else DEEP) }
                layoutParams = LinearLayout.LayoutParams(dp(88), dp(88)).apply { topMargin = dp(60) }
                gravity = Gravity.CENTER
            })
            addView(text(if (ok) "Переведено успешно" else t.stateTitle, 18f, center = true).padTop(18))
            addView(text(t.amount, 32f, bold = true, center = true).padTop(6))
            addView(text(if (ok) "На счёт **** ${t.beneficiaryIban.takeLast(4)}" else (t.failureReason ?: "Операция не выполнена."), 14f, color = MUTED, center = true).padTop(6))
            if (ok) {
                addView(secondary("Квитанция") { showReceipt(t) }.padTop(24))
                addView(secondary("Сохранить в избранное") { lifecycleScope.launch { runCatching { api!!.addFavorite(t.beneficiaryName, t.beneficiaryIban) }; refresh(); alert("Сохранено в избранное.") } }.padTop(8))
            }
            addView(primary("Готово") { showTab("home") }.padTop(24))
        }), false)
    }

    private fun showReceipt(t: BankTransaction) = lifecycleScope.launch {
        val r = runCatching { api!!.receipt(t.id) }.getOrElse { toastError(it); return@launch }
        val to = r.getJSONObject("to")
        val c = r.getJSONObject("confirmation")
        AlertDialog.Builder(this@BankActivity).setTitle("Квитанция ${r.getString("reference")}")
            .setMessage(
                "${r.getString("bank")}\nИсполнено: ${r.getString("executedAt")}\nСо счёта: ${r.getString("from")}\nПолучатель: ${to.getString("name")}\nIBAN: ${to.getString("iban")}\n" +
                    "Сумма: ${r.getString("amount")}\nКомиссия: ${r.getString("fee")}\nИтого: ${r.getString("total")}\n\nПодтверждение NEXUS-SIGN: ${c.getString("method")}\n" +
                    "Доказательство: ${c.getString("evidenceHash").take(24)}…\n\n${r.getString("notice")}",
            )
            .setPositiveButton("Готово", null).show()
    }

    private fun showHistory() {
        setScreen(scroll(column(dp(16)).apply {
            addView(text("История", 24f, bold = true))
            addView(transactionList(transactions) { t -> push(::showHistory) { showTransaction(t) } }.padTop(12))
        }), true)
    }

    private fun showTransaction(t: BankTransaction) {
        setScreen(scroll(column(dp(16)).apply {
            addView(text(t.total, 30f, bold = true))
            addView(text(t.stateTitle, 14f, color = stateColor(t)).padTop(4))
            addView(box().apply {
                addView(row("Получатель", t.beneficiaryName)); addView(row("IBAN", t.beneficiaryIban))
                addView(row("Сумма", t.amount)); addView(row("Комиссия", t.fee)); addView(row("Референс", t.reference))
                addView(row("Создана", t.createdAt.take(16).replace('T', ' ')))
                if (t.description.isNotEmpty()) addView(row("Назначение", t.description))
                t.failureReason?.let { addView(row("Причина", it)) }
            }.padTop(12))
            if (t.state == "EXECUTED") addView(secondary("Квитанция") { showReceipt(t) }.padTop(16))
            if (t.state == "AUTHORIZATION_PENDING") {
                addView(primary("Подтвердить сейчас") { dismissed -= t.id; launchBusy { presentConfirmation(t) } }.padTop(16))
                addView(secondary("Отменить операцию") { launchBusy { api!!.cancel(t.id); refresh(); showTab("history") } }.padTop(8))
            }
        }), false)
    }

    private fun showAccount(a: Account) {
        val card = cards.firstOrNull { it.accountId == a.id }
        setScreen(scroll(column(dp(16)).apply {
            addView(accountCard(a), LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(170)))
            if (card != null) {
                addView(text("Карта ${card.brand} **** ${card.last4}: ${when (card.status) { "FROZEN" -> "заморожена"; "BLOCKED" -> "заблокирована"; else -> "активна" }}", 14f).padTop(14))
                if (card.status != "BLOCKED") {
                    addView(secondary(if (card.status == "FROZEN") "Разморозить" else "Заморозить") {
                        launchBusy { api!!.cardAction(card.id, if (card.status == "FROZEN") "unfreeze" else "freeze"); refresh(); showAccount(a) }
                    }.padTop(8))
                    addView(secondary("Блокировать") { launchBusy { api!!.cardAction(card.id, "block"); refresh(); showAccount(a) } }.padTop(8))
                }
            }
            addView(section("Реквизиты"))
            addView(box().apply { addView(row("Получатель", profile?.displayName ?: "")); addView(row("IBAN", a.iban)); addView(row("Банк", bankName)) })
            addView(primary("Новый платёж/перевод") { push({ showAccount(a) }) { showTransfer(own = false) } }.padTop(16))
        }), false)
    }

    private fun showProducts() {
        setScreen(scroll(column(dp(16)).apply {
            addView(text("Продукты", 24f, bold = true))
            addView(section("Счета"))
            accounts.forEach { a -> addView(box().apply { addView(row(a.name + "  " + a.shortNumber, a.balance)); setOnClickListener { push(::showProducts) { showAccount(a) } } }.padTop(8)) }
            addView(section("Каталог"))
            products.forEach { p -> addView(box().apply { addView(text(p.title, 15f, bold = true)); addView(text(p.summary, 13f, color = MUTED).padTop(4)) }.padTop(8)) }
        }), true)
    }

    private fun showMore() {
        setScreen(scroll(column(dp(16)).apply {
            addView(box().apply { addView(text(profile?.displayName ?: "", 17f, bold = true)); addView(text("Ваш личный аккаунт · ${profile?.login ?: ""}", 13f, color = MUTED)) })
            addView(section("Уведомления"))
            addView(box().apply {
                if (notifications.isEmpty()) addView(text("Уведомлений нет", 13f, color = MUTED))
                notifications.take(10).forEach { addView(row(it.title, it.createdAt.take(16).replace('T', ' '))); addView(text(it.body, 12f, color = MUTED)) }
            })
            addView(section("Безопасность (NEXUS-SIGN)"))
            addView(box().apply {
                addView(row("Состояние", if (deviceRegistered) "Подключён" else "Не подключён"))
                addView(row("NEXUS ID", profile?.nexusId ?: "—"))
                addView(text("Ключ подписи хранится в аппаратном хранилище телефона и не покидает его.", 12f, color = MUTED))
            })
            addView(secondary("Подключить телефон заново") { enrol() }.padTop(8))
            addView(section("Служба поддержки"))
            addView(text("Демонстрационная поддержка: support@demo-bank.invalid", 13f, color = MUTED))
            addView(text("Демонстрационный банк. Тестовые средства, вымышленные клиенты.", 12f, color = MUTED).padTop(16))
            addView(secondary("Выход") { logout() }.padTop(16))
        }), true)
    }

    // ---- Small UI kit ----------------------------------------------------------

    private fun launchBusy(block: suspend () -> Unit) = lifecycleScope.launch {
        if (busy) return@launch
        busy = true
        try { block() } catch (e: Exception) { toastError(e) } finally { busy = false }
    }

    private fun toastError(e: Throwable) = alert(e.message ?: e.toString())
    private fun alert(message: String) { AlertDialog.Builder(this).setTitle(bankName).setMessage(message).setPositiveButton("OK", null).show() }

    private fun View.padTop(v: Int): View = apply { setPadding(paddingLeft, paddingTop + dp(v), paddingRight, paddingBottom) }
    private fun column(pad: Int) = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }
    private fun scroll(v: View) = ScrollView(this).apply { addView(v) }
    private fun rounded(color: Int, radius: Int = 16) = GradientDrawable().apply { setColor(color); cornerRadius = dp(radius).toFloat() }

    private fun text(value: String, size: Float, bold: Boolean = false, center: Boolean = false, color: Int = INK) = TextView(this).apply {
        text = value; textSize = size; setTextColor(color)
        if (bold) setTypeface(null, Typeface.BOLD)
        if (center) gravity = Gravity.CENTER_HORIZONTAL
    }

    private fun edit(hint: String, value: String, password: Boolean = false) = EditText(this).apply {
        this.hint = hint; setText(value); setSingleLine()
        background = rounded(Color.WHITE, 12); setPadding(dp(14), dp(14), dp(14), dp(14))
        if (password) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    }

    private fun primary(title: String, run: () -> Unit) = Button(this).apply {
        text = title; isAllCaps = false; setTextColor(Color.WHITE); textSize = 16f
        background = rounded(ACCENT, 14); minHeight = dp(52); setOnClickListener { run() }
    }

    private fun secondary(title: String, run: () -> Unit) = Button(this).apply {
        text = title; isAllCaps = false; setTextColor(DEEP); textSize = 15f
        background = rounded(ACCENT_SOFT, 14); minHeight = dp(48); setOnClickListener { run() }
    }

    private fun link(title: String, run: () -> Unit) = text(title, 14f, color = ACCENT, center = true).apply { setPadding(0, dp(12), 0, dp(4)); setOnClickListener { run() } }
    private fun section(title: String) = text(title, 19f, bold = true).padTop(22).also { it.setPadding(it.paddingLeft, it.paddingTop, 0, dp(8)) }
    private fun box() = column(dp(14)).apply { background = rounded(Color.WHITE) }
    private fun logo() = text("✓", 30f, bold = true, center = true, color = Color.WHITE).apply {
        gravity = Gravity.CENTER
        background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(ACCENT) }
        layoutParams = LinearLayout.LayoutParams(dp(60), dp(60))
    }

    private fun row(key: String, value: String) = LinearLayout(this).apply {
        setPadding(0, dp(9), 0, dp(9))
        addView(text(key, 14f), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        addView(text(value, 14f, color = MUTED).apply { gravity = Gravity.END }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.3f))
    }

    private fun tile(title: String, run: () -> Unit) = text(title, 13f, bold = true, color = INK).apply {
        background = rounded(ACCENT_SOFT); setPadding(dp(12), dp(40), dp(12), dp(12))
        layoutParams = LinearLayout.LayoutParams(dp(112), dp(112)).apply { marginEnd = dp(10) }
        setOnClickListener { run() }
    }

    private fun accountCard(a: Account): View {
        val card = cards.firstOrNull { it.accountId == a.id }
        return column(dp(18)).apply {
            background = GradientDrawable(GradientDrawable.Orientation.TL_BR, intArrayOf(DEEP, Color.rgb(46, 140, 133), ACCENT)).apply { cornerRadius = dp(18).toFloat() }
            addView(text(a.name, 14f, color = Color.WHITE))
            addView(text(a.balance, 26f, bold = true, color = Color.WHITE).padTop(30))
            addView(text(card?.let { "${it.brand}  **** ${it.last4}  ${it.expires}" } ?: a.shortNumber, 13f, color = Color.WHITE).padTop(10))
        }
    }

    private fun picker(list: List<Account>, onPick: (String) -> Unit): View {
        val strip = LinearLayout(this)
        val views = mutableListOf<View>()
        list.forEachIndexed { i, a ->
            val v = column(dp(12)).apply {
                background = rounded(Color.WHITE, 14)
                addView(text(a.name, 14f, bold = true)); addView(text("${a.shortNumber} · ${a.balance}", 12f, color = MUTED))
            }
            views += v
            v.setOnClickListener {
                views.forEach { it.alpha = 0.55f }; v.alpha = 1f; onPick(a.id)
            }
            v.alpha = if (i == 0) 1f else 0.55f
            strip.addView(v, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = dp(8) })
        }
        return HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false; addView(strip) }
    }

    private fun stateColor(t: BankTransaction) = when (t.state) {
        "EXECUTED" -> POSITIVE
        "AUTHORIZATION_PENDING", "OFFLINE_PROVISIONAL", "AUTHORIZING" -> Color.rgb(200, 130, 0)
        "CANCELLED" -> MUTED
        else -> NEGATIVE
    }

    private fun transactionList(list: List<BankTransaction>, open: (BankTransaction) -> Unit) = box().apply {
        if (list.isEmpty()) addView(text("Операций пока нет.", 13f, color = MUTED))
        list.forEach { t ->
            addView(LinearLayout(this@BankActivity).apply {
                setPadding(0, dp(8), 0, dp(8))
                addView(column(0).apply {
                    addView(text(t.beneficiaryName, 14f, bold = true))
                    addView(text("**** ${t.beneficiaryIban.takeLast(4)} · ${t.createdAt.take(16).replace('T', ' ')}", 12f, color = MUTED))
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(column(0).apply {
                    gravity = Gravity.END
                    addView(text("- ${t.total}", 14f, bold = true, color = if (t.state == "EXECUTED") NEGATIVE else MUTED))
                    addView(text(t.stateTitle, 12f, color = stateColor(t)))
                })
                setOnClickListener { open(t) }
            })
        }
    }
}
