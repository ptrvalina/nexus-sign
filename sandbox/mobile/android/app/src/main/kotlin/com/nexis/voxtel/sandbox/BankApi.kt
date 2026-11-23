package com.nexis.voxtel.sandbox

import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * Client of the sandbox bank's app API (/app/v1/*, sandbox/bank/src/appApi.mjs).
 * Everything the app shows comes from here; a payment is shown as done only
 * when the bank reports the transaction as EXECUTED.
 */
class BankApiException(val status: Int, val code: String, message: String) : Exception(message)

data class Account(val id: String, val name: String, val iban: String, val currency: String, val balanceMinor: Long, val balance: String) {
    val shortNumber get() = "**** " + iban.takeLast(4)
}

data class Card(val id: String, val accountId: String, val last4: String, val brand: String, val expires: String, val status: String)

data class BankTransaction(
    val id: String, val reference: String, val kind: String, val state: String,
    val beneficiaryName: String, val beneficiaryIban: String,
    val amount: String, val fee: String, val total: String, val amountMinor: Long,
    val authorizationId: String?, val failureReason: String?, val createdAt: String, val description: String,
) {
    val isFinal get() = state in setOf("EXECUTED", "REJECTED", "EXPIRED", "CANCELLED", "FAILED")
    val stateTitle get() = when (state) {
        "EXECUTED" -> "Выполнено"
        "AUTHORIZATION_PENDING" -> "Ждёт подтверждения"
        "OFFLINE_PROVISIONAL" -> "Код принят, ждём подпись"
        "AUTHORIZING" -> "Проверяется банком"
        "REJECTED" -> "Отклонено вами"
        "EXPIRED" -> "Срок истёк"
        "CANCELLED" -> "Отменено"
        "FAILED" -> "Отказ банка"
        else -> "Создано"
    }
}

data class Quote(val kind: String, val amountMinor: Long, val feeMinor: Long, val totalMinor: Long, val currency: String, val beneficiaryName: String, val beneficiaryIban: String)
data class Favorite(val id: String, val name: String, val iban: String)
data class Product(val id: String, val kind: String, val title: String, val summary: String)
data class BankNotification(val id: String, val title: String, val body: String, val state: String, val createdAt: String)
data class Profile(val displayName: String, val login: String, val nexusId: String?, val credentialId: String?, val deviceEnrolled: Boolean)

class BankApi(val baseUrl: String) {
    @Volatile var token: String? = null

    private suspend fun call(method: String, path: String, body: JSONObject? = null, headers: Map<String, String> = emptyMap()): String = withContext(Dispatchers.IO) {
        val connection = try {
            (URL(baseUrl.trimEnd('/') + path).openConnection() as HttpURLConnection)
        } catch (e: Exception) {
            throw BankApiException(0, "BAD_ADDRESS", "Неверный адрес банка: ${e.message}")
        }
        connection.requestMethod = method
        connection.connectTimeout = 8_000
        connection.readTimeout = 15_000
        token?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
        headers.forEach { (k, v) -> connection.setRequestProperty(k, v) }
        try {
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (code !in 200..299) {
                val json = runCatching { JSONObject(text) }.getOrNull()
                throw BankApiException(code, json?.optString("code") ?: "HTTP_$code", json?.optString("error")?.ifEmpty { null } ?: "Банк ответил HTTP $code")
            }
            text
        } catch (e: BankApiException) {
            throw e
        } catch (e: Exception) {
            throw BankApiException(0, "NETWORK", "Нет связи с банком: ${e.message}")
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun obj(method: String, path: String, body: JSONObject? = null, headers: Map<String, String> = emptyMap()) = JSONObject(call(method, path, body, headers))
    private suspend fun arr(path: String) = JSONArray(call("GET", path))
    private fun <T> JSONArray.map(f: (JSONObject) -> T): List<T> = (0 until length()).map { f(getJSONObject(it)) }
    private fun JSONObject.str(name: String): String? = if (isNull(name)) null else optString(name).ifEmpty { null }

    suspend fun bankName(): String = obj("GET", "/app/v1/bank").getJSONObject("branding").getString("name")
    suspend fun login(login: String, password: String): Profile {
        val answer = obj("POST", "/app/v1/session", JSONObject().put("login", login).put("password", password))
        token = answer.getString("token")
        return parseProfile(answer.getJSONObject("customer"))
    }
    suspend fun logout() { runCatching { call("DELETE", "/app/v1/session") } }
    suspend fun profile(): Profile = parseProfile(obj("GET", "/app/v1/profile"))
    private fun parseProfile(j: JSONObject) = Profile(j.getString("displayName"), j.getString("login"), j.str("nexusId"), j.str("credentialId"), j.optBoolean("deviceEnrolled"))
    suspend fun bootstrapToken(): String = obj("POST", "/app/v1/enrolment/bootstrap-token", JSONObject()).getString("token")
    suspend fun completeEnrolment(credentialId: String): Profile = parseProfile(obj("POST", "/app/v1/enrolment/complete", JSONObject().put("credentialId", credentialId)))
    suspend fun accounts(): List<Account> = arr("/app/v1/accounts").map { Account(it.getString("id"), it.getString("name"), it.getString("iban"), it.getString("currency"), it.getLong("balanceMinor"), it.getString("balance")) }
    suspend fun cards(): List<Card> = arr("/app/v1/cards").map { Card(it.getString("id"), it.getString("accountId"), it.getString("last4"), it.getString("brand"), it.getString("expires"), it.getString("status")) }
    suspend fun cardAction(cardId: String, action: String) { obj("POST", "/app/v1/cards/$cardId/$action", JSONObject()) }
    suspend fun favorites(): List<Favorite> = arr("/app/v1/favorites").map { Favorite(it.getString("id"), it.getString("name"), it.getString("iban")) }
    suspend fun addFavorite(name: String, iban: String) { obj("POST", "/app/v1/favorites", JSONObject().put("name", name).put("iban", iban)) }
    suspend fun products(): List<Product> = arr("/app/v1/products").map { Product(it.getString("id"), it.getString("kind"), it.getString("title"), it.getString("summary")) }
    suspend fun notifications(): List<BankNotification> = arr("/app/v1/notifications").map { BankNotification(it.getString("id"), it.getString("title"), it.getString("body"), it.getString("state"), it.getString("createdAt")) }
    suspend fun transactions(): List<BankTransaction> = arr("/app/v1/transactions").map(::parseTransaction)
    suspend fun transaction(id: String): BankTransaction = parseTransaction(obj("GET", "/app/v1/transactions/$id"))
    suspend fun cancel(id: String): BankTransaction = parseTransaction(obj("POST", "/app/v1/transactions/$id/cancel", JSONObject()))
    suspend fun receipt(id: String): JSONObject = obj("GET", "/app/v1/transactions/$id/receipt")
    suspend fun offlineChallenge(id: String): String = obj("GET", "/app/v1/transactions/$id/offline-challenge").getString("qrPayload")
    suspend fun pendingAuthorization(): BankTransaction? = obj("GET", "/app/v1/pending-authorization").optJSONObject("transaction")?.let(::parseTransaction)
    suspend fun quote(order: JSONObject): Quote = obj("POST", "/app/v1/transactions/quote", order).let {
        Quote(it.getString("kind"), it.getLong("amountMinor"), it.getLong("feeMinor"), it.getLong("totalMinor"), it.getString("currency"), it.getString("beneficiaryName"), it.getString("beneficiaryIban"))
    }
    suspend fun create(order: JSONObject, idempotencyKey: String): BankTransaction =
        parseTransaction(obj("POST", "/app/v1/transactions", order, mapOf("Idempotency-Key" to idempotencyKey)))

    private fun parseTransaction(j: JSONObject) = BankTransaction(
        j.getString("id"), j.getString("reference"), j.getString("kind"), j.getString("state"),
        j.getString("beneficiaryName"), j.getString("beneficiaryIban"), j.getString("amount"), j.getString("fee"), j.getString("total"),
        j.getLong("amountMinor"), j.str("authorizationId"), j.str("failureReason"), j.getString("createdAt"), j.optString("description"),
    )
}

object Money {
    /** "50", "50.5", "50,50" → 5050 minor units; null when not a valid positive amount. */
    fun minor(text: String): Long? {
        val cleaned = text.replace(" ", "").replace(',', '.')
        val match = Regex("^(\\d{1,9})(?:\\.(\\d{1,2}))?$").find(cleaned) ?: return null
        val whole = match.groupValues[1].toLong()
        val cents = match.groupValues[2].padEnd(2, '0').ifEmpty { "00" }.toLong()
        return (whole * 100 + cents).takeIf { it > 0 }
    }

    fun format(minor: Long, currency: String): String {
        val sign = if (minor < 0) "-" else ""
        val v = kotlin.math.abs(minor)
        val whole = (v / 100).toString().reversed().chunked(3).joinToString(" ").reversed()
        return "$sign$whole.${(v % 100).toString().padStart(2, '0')} $currency"
    }
}
