package com.example.myapp.telemetry

import android.content.Context
import android.content.res.Configuration
import android.os.BatteryManager
import android.os.Build
import android.util.DisplayMetrics
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import okhttp3.*
import org.json.JSONObject
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.TimeUnit

object TelemetryManager {
    private const val PREFS_NAME = "TelemetryPrefs"
    private const val PREF_DEVICE_UUID = "device_uuid"
    private const val PREF_FIRST_LAUNCH = "first_launch"
    private const val SERVER_URL = "https://your-server.com/telemetry" // Replace with your server endpoint
    private var sessionStartTime: Long = 0

    // Initialize telemetry and check for first launch
    fun initialize(context: Context, webView: WebView? = null) {
        sessionStartTime = System.currentTimeMillis()
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (prefs.getBoolean(PREF_FIRST_LAUNCH, true)) {
            sendTelemetry(context, collectTelemetryData(context, webView))
            prefs.edit().putBoolean(PREF_FIRST_LAUNCH, false).apply()
        }
    }

    // Set up WebView to detect link clicks and send telemetry
    fun setupWebViewTelemetry(context: Context, webView: WebView, targetLink: String) {
        webView.settings.javaScriptEnabled = true // Required for network type and local storage
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (request.url.toString() == targetLink) {
                    sendTelemetry(context, collectTelemetryData(context, webView))
                    return false // Allow normal link navigation
                }
                return super.shouldOverrideUrlLoading(view, request)
            }
        }
        // Inject JavaScript for error tracking
        webView.loadUrl("javascript:window.onerror = function(message, source, lineno) {" +
                "window._lastError = message + ' at ' + source + ':' + lineno;};")
    }

    // Collect all telemetry data
    private fun collectTelemetryData(context: Context, webView: WebView?): JSONObject {
        val telemetry = JSONObject()

        // 1️⃣ System & Device Info
        val deviceInfo = JSONObject().apply {
            put("device_model", Build.MODEL)
            put("manufacturer", Build.MANUFACTURER)
            put("android_version", Build.VERSION.RELEASE)
            put("sdk_int", Build.VERSION.SDK_INT)
            put("device_name", Build.DEVICE)
            put("brand", Build.BRAND)
            put("hardware", Build.HARDWARE)
            put("cpu_abi", Build.SUPPORTED_ABIS.joinToString())
            put("locale", Locale.getDefault().toString())
            put("timezone", TimeZone.getDefault().ID)
        }
        telemetry.put("device_info", deviceInfo)

        // 2️⃣ Network Info (Basic)
        val networkInfo = JSONObject().apply {
            webView?.evaluateJavascript(
                "(function() { return navigator.connection ? navigator.connection.type : 'unknown'; })()"
            ) { result ->
                put("network_type", result?.replace("\"", "") ?: "unknown")
            }
            put("ip_address", "logged_server_side")
            put("proxy", System.getProperty("http.proxyHost") ?: "none")
        }
        telemetry.put("network_info", networkInfo)

        // 3️⃣ App Info
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val deviceUuid = prefs.getString(PREF_DEVICE_UUID, null) ?: run {
            val newUuid = UUID.randomUUID().toString()
            prefs.edit().putString(PREF_DEVICE_UUID, newUuid).apply()
            newUuid
        }
        val appInfo = JSONObject().apply {
            put("app_version", context.packageManager.getPackageInfo(context.packageName, 0).versionName)
            put("version_code", context.packageManager.getPackageInfo(context.packageName, 0).versionCode)
            put("package_name", context.packageName)
            put("first_launch", prefs.getBoolean(PREF_FIRST_LAUNCH, true))
            put("device_uuid", deviceUuid)
        }
        telemetry.put("app_info", appInfo)

        // 4️⃣ Usage Data (Basic Analytics)
        val usageData = JSONObject().apply {
            put("timestamp", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
            }.format(Date()))
            put("session_duration", (System.currentTimeMillis() - sessionStartTime) / 1000)
            put("screen_view", getCurrentScreen(context))
            put("event", if (webView != null) "link_clicked" else "app_first_launch")
            webView?.evaluateJavascript(
                "(function() { return window._lastError || 'none'; })()"
            ) { result ->
                put("js_error", result?.replace("\"", "") ?: "none")
            }
        }
        telemetry.put("usage_data", usageData)

        // 5️⃣ Local Storage (WebView)
        val localStorage = JSONObject()
        webView?.evaluateJavascript(
            "(function() { return JSON.stringify(localStorage); })()"
        ) { result ->
            if (result != null && result != "null") {
                localStorage.put("local_storage", JSONObject(result))
            }
        }
        webView?.evaluateJavascript(
            "(function() { return document.cookie; })()"
        ) { result ->
            if (result != null && result != "null") {
                localStorage.put("cookies", result)
            }
        }
        telemetry.put("webview_storage", localStorage)

        // 6️⃣ Device Capabilities
        val displayMetrics = context.resources.displayMetrics
        val configuration = context.resources.configuration
        val batteryManager = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val deviceCapabilities = JSONObject().apply {
            put("orientation", if (configuration.orientation == Configuration.ORIENTATION_PORTRAIT) "portrait" else "landscape")
            put("screen_width", displayMetrics.widthPixels)
            put("screen_height", displayMetrics.heightPixels)
            put("density", displayMetrics.density)
            put("dark_mode", (configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES)
            put("battery_level", batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY))
        }
        telemetry.put("device_capabilities", deviceCapabilities)

        return telemetry
    }

    // Send telemetry to server
    private fun sendTelemetry(context: Context, telemetry: JSONObject) {
        val client = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

        val requestBody = RequestBody.create(
            MediaType.parse("application/json; charset=utf-8"),
            telemetry.toString()
        )

        val request = Request.Builder()
            .url(SERVER_URL)
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                // Log failure (e.g., to local storage or analytics)
                e.printStackTrace()
            }

            override fun onResponse(call: Call, response: Response) {
                response.close() // Ensure resources are released
            }
        })
    }

    private fun getCurrentScreen(context: Context): String {
        return (context as? AppCompatActivity)?.javaClass?.simpleName ?: "unknown"
    }
}
