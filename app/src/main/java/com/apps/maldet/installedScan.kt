package com.apps.maldet

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.apps.maldet.ml.MlpModel
import com.apps.maldet.ml.SatuModel
import dalvik.system.DexFile
import kotlinx.coroutines.*
import org.tensorflow.lite.DataType
import org.tensorflow.lite.support.tensorbuffer.TensorBuffer
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

class installedScan : AppCompatActivity() {
    private lateinit var malwareQuantity: TextView
    private lateinit var goToHome: ImageView
    private lateinit var scanList: RecyclerView
    private lateinit var scanButton: Button

    private val scanResults = mutableListOf<ScanResult>()
    private lateinit var scanAdapter: ScanAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_installed_scan)

        malwareQuantity = findViewById(R.id.quantity)
        goToHome = findViewById(R.id.home)
        scanList = findViewById(R.id.scanList)
        scanButton = findViewById(R.id.scanButton)

        scanAdapter = ScanAdapter(scanResults)
        scanList.layoutManager = LinearLayoutManager(this)
        scanList.adapter = scanAdapter

        goToHome.setOnClickListener {
            startActivity(Intent(this, home::class.java))
        }

        scanButton.setOnClickListener {
            scanButton.isEnabled = false
            scanButton.text = "Scanning..."
            scanResults.clear()
            scanAdapter.notifyDataSetChanged()

            CoroutineScope(Dispatchers.IO).launch {
                runScan()

                withContext(Dispatchers.Main) {
                    scanButton.isEnabled = true
                    scanButton.text = "Scan Again"
                    Toast.makeText(this@installedScan, "Scan Completed", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private suspend fun runScan() {
        val pm = packageManager
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)

        val model = SatuModel.newInstance(this)

        var malwareCount = 0

        for (app in apps) {
            if ((app.flags and ApplicationInfo.FLAG_SYSTEM) != 0) continue

            val appName = app.loadLabel(pm).toString()
            val packageName = app.packageName
            val icon = app.loadIcon(pm)
            val apkPath = app.sourceDir

            val permissions = try {
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS).requestedPermissions?.toSet() ?: emptySet()
            } catch (e: Exception) {
                emptySet()
            }

            val dexKeywords = try {
                val zip = java.util.zip.ZipFile(apkPath)
                zip.entries().asSequence()
                    .filter { it.name.endsWith(".dex") }
                    .flatMap { entry ->
                        val dexBytes = zip.getInputStream(entry).readBytes()
                        String(dexBytes)
                            .split(Regex("[^\\x20-\\x7E]+"))
                            .filter { it.length in 3..100 && it.contains('.') }
                    }.toSet()
            } catch (e: Exception) {
                Log.e("DEX", "DEX parse error in $packageName: ${e.message}")
                emptySet()
            }


            val vector = FloatArray(215) { i ->
                val keyword = FeatureList.feature[i]
                if (permissions.any { it.contains(keyword, ignoreCase = true) } ||
                    dexKeywords.any { it.contains(keyword, ignoreCase = true) }
                ) 1f else 0f
            }

            val inputBuffer = ByteBuffer.allocateDirect(4 * 215).apply {
                order(ByteOrder.nativeOrder())
                vector.forEach { putFloat(it) }
            }

            val input = TensorBuffer.createFixedSize(intArrayOf(1, 215), DataType.FLOAT32)
            input.loadBuffer(inputBuffer)

            val output = model.process(input)
            val score = output.outputFeature0AsTensorBuffer.floatArray[0]

            val label = when {
                score >= 0.1f -> "MALWARE"
                score >= 0.05f -> "SUSPICIOUS"
                else -> "BENIGN"
            }

// Collect triggered features
            val matchedFeatures = mutableListOf<String>()
            FeatureList.feature.forEachIndexed { index, keyword ->
                if (vector[index] == 1f) matchedFeatures.add(keyword)
            }

            if (label == "MALWARE") malwareCount++


            val result = ScanResult(icon, appName, packageName, score, label)

            withContext(Dispatchers.Main) {
                scanResults.add(result)
                scanAdapter.notifyItemInserted(scanResults.size - 1)
                malwareQuantity.text = malwareCount.toString()

                if (label == "MALWARE") {
                    val featureSummary = if (matchedFeatures.isNotEmpty()) {
                        matchedFeatures.joinToString(separator = "\n- ", prefix = "\n\n⚠️ Dangerous Features Detected:\n- ")
                    } else {
                        "\n\n(No specific features matched)"
                    }

                    AlertDialog.Builder(this@installedScan)
                        .setTitle("Malware Detected")
                        .setMessage("App: $appName\nDetected Score: $score$featureSummary\n\nDo you want to uninstall it?")
                        .setPositiveButton("Uninstall") { _, _ ->
                            val intent = Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName"))
                            startActivity(intent)
                        }
                        .setNegativeButton("Cancel", null)
                        .show()
                }

                if (label == "SUSPICIOUS") {
                    val featureSummary = if (matchedFeatures.isNotEmpty()) {
                        matchedFeatures.joinToString(separator = "\n- ", prefix = "\n\n⚠️ Potentially Dangerous Features:\n- ")
                    } else {
                        "\n\n(No specific features matched)"
                    }

                    AlertDialog.Builder(this@installedScan)
                        .setTitle("Suspicious App Detected")
                        .setMessage("App: $appName\nDetected Score: $score$featureSummary")
                        .setPositiveButton("OK", null)
                        .show()
                }

            }

            yield()
        }

        model.close()
    }

    data class ScanResult(
        val icon: Drawable,
        val appName: String,
        val packageName: String,
        val score: Float,
        val label: String
    )

    object FeatureList {
        val feature = listOf(
            "transact",
            "onServiceConnected",
            "bindService",
            "attachInterface",
            "ServiceConnection",
            "android.os.Binder",
            "SEND_SMS",
            "Ljava.lang.Class.getCanonicalName",
            "Ljava.lang.Class.getMethods",
            "Ljava.lang.Class.cast",
            "Ljava.net.URLDecoder",
            "android.content.pm.Signature", "android.telephony.SmsManager", "READ_PHONE_STATE", "getBinder", "ClassLoader", "Landroid.content.Context.registerReceiver", "Ljava.lang.Class.getField", "Landroid.content.Context.unregisterReceiver", "GET_ACCOUNTS", "RECEIVE_SMS", "Ljava.lang.Class.getDeclaredField", "READ_SMS", "getCallingUid", "Ljavax.crypto.spec.SecretKeySpec", "android.intent.action.BOOT_COMPLETED", "USE_CREDENTIALS", "MANAGE_ACCOUNTS", "android.content.pm.PackageInfo", "KeySpec", "TelephonyManager.getLine1Number", "DexClassLoader", "HttpGet.init", "SecretKey", "Ljava.lang.Class.getMethod", "System.loadLibrary", "android.intent.action.SEND", "Ljavax.crypto.Cipher", "WRITE_SMS", "READ_SYNC_SETTINGS", "AUTHENTICATE_ACCOUNTS", "android.telephony.gsm.SmsManager", "WRITE_HISTORY_BOOKMARKS", "TelephonyManager.getSubscriberId", "mount", "INSTALL_PACKAGES", "Runtime.getRuntime", "CAMERA", "Ljava.lang.Object.getClass", "WRITE_SYNC_SETTINGS", "READ_HISTORY_BOOKMARKS", "Ljava.lang.Class.forName", "INTERNET", "android.intent.action.PACKAGE_REPLACED", "Binder", "android.intent.action.SEND_MULTIPLE", "RECORD_AUDIO", "IBinder", "android.os.IBinder", "createSubprocess", "NFC", "ACCESS_LOCATION_EXTRA_COMMANDS", "URLClassLoader", "WRITE_APN_SETTINGS", "abortBroadcast", "BIND_REMOTEVIEWS", "android.intent.action.TIME_SET", "READ_PROFILE", "TelephonyManager.getDeviceId", "MODIFY_AUDIO_SETTINGS", "getCallingPid", "READ_SYNC_STATS", "BROADCAST_STICKY", "android.intent.action.PACKAGE_REMOVED", "android.intent.action.TIMEZONE_CHANGED", "WAKE_LOCK", "RECEIVE_BOOT_COMPLETED", "RESTART_PACKAGES", "Ljava.lang.Class.getPackage", "chmod", "Ljava.lang.Class.getDeclaredClasses", "android.intent.action.ACTION_POWER_DISCONNECTED", "android.intent.action.PACKAGE_ADDED", "PathClassLoader", "TelephonyManager.getSimSerialNumber", "Runtime.load", "TelephonyManager.getCallState", "BLUETOOTH", "READ_CALENDAR", "READ_CALL_LOG", "SUBSCRIBED_FEEDS_WRITE", "READ_EXTERNAL_STORAGE", "TelephonyManager.getSimCountryIso", "sendMultipartTextMessage", "PackageInstaller", "VIBRATE", "remount", "android.intent.action.ACTION_SHUTDOWN", "sendDataMessage", "ACCESS_NETWORK_STATE", "chown", "HttpPost.init", "Ljava.lang.Class.getClasses", "SUBSCRIBED_FEEDS_READ", "TelephonyManager.isNetworkRoaming", "CHANGE_WIFI_MULTICAST_STATE", "WRITE_CALENDAR", "android.intent.action.PACKAGE_DATA_CLEARED", "MASTER_CLEAR", "HttpUriRequest", "UPDATE_DEVICE_STATS", "WRITE_CALL_LOG", "DELETE_PACKAGES", "GET_TASKS", "GLOBAL_SEARCH", "DELETE_CACHE_FILES", "WRITE_USER_DICTIONARY", "android.intent.action.PACKAGE_CHANGED", "android.intent.action.NEW_OUTGOING_CALL", "REORDER_TASKS", "WRITE_PROFILE", "SET_WALLPAPER", "BIND_INPUT_METHOD", "divideMessage", "READ_SOCIAL_STREAM", "READ_USER_DICTIONARY", "PROCESS_OUTGOING_CALLS", "CALL_PRIVILEGED", "Runtime.exec", "BIND_WALLPAPER", "RECEIVE_WAP_PUSH", "DUMP", "BATTERY_STATS", "ACCESS_COARSE_LOCATION", "SET_TIME", "android.intent.action.SENDTO", "WRITE_SOCIAL_STREAM", "WRITE_SETTINGS", "REBOOT", "BLUETOOTH_ADMIN", "TelephonyManager.getNetworkOperator", "/system/bin", "MessengerService", "BIND_DEVICE_ADMIN", "WRITE_GSERVICES", "IRemoteService", "KILL_BACKGROUND_PROCESSES", "SET_ALARM", "ACCOUNT_MANAGER", "/system/app", "android.intent.action.CALL", "STATUS_BAR", "TelephonyManager.getSimOperator", "PERSISTENT_ACTIVITY", "CHANGE_NETWORK_STATE", "onBind", "Process.start", "android.intent.action.SCREEN_ON", "Context.bindService", "RECEIVE_MMS", "SET_TIME_ZONE", "android.intent.action.BATTERY_OKAY", "CONTROL_LOCATION_UPDATES", "BROADCAST_WAP_PUSH", "BIND_ACCESSIBILITY_SERVICE", "ADD_VOICEMAIL", "CALL_PHONE", "ProcessBuilder", "BIND_APPWIDGET", "FLASHLIGHT", "READ_LOGS", "Ljava.lang.Class.getResource", "defineClass", "SET_PROCESS_LIMIT", "android.intent.action.PACKAGE_RESTARTED", "MOUNT_UNMOUNT_FILESYSTEMS", "BIND_TEXT_SERVICE", "INSTALL_LOCATION_PROVIDER", "android.intent.action.CALL_BUTTON", "android.intent.action.SCREEN_OFF", "findClass", "SYSTEM_ALERT_WINDOW", "MOUNT_FORMAT_FILESYSTEMS", "CHANGE_CONFIGURATION", "CLEAR_APP_USER_DATA", "intent.action.RUN", "android.intent.action.SET_WALLPAPER", "CHANGE_WIFI_STATE", "READ_FRAME_BUFFER", "ACCESS_SURFACE_FLINGER", "Runtime.loadLibrary", "BROADCAST_SMS", "EXPAND_STATUS_BAR", "INTERNAL_SYSTEM_WINDOW", "android.intent.action.BATTERY_LOW", "SET_ACTIVITY_WATCHER", "WRITE_CONTACTS", "android.intent.action.ACTION_POWER_CONNECTED", "BIND_VPN_SERVICE", "DISABLE_KEYGUARD", "ACCESS_MOCK_LOCATION", "GET_PACKAGE_SIZE", "MODIFY_PHONE_STATE", "CHANGE_COMPONENT_ENABLED_STATE", "CLEAR_APP_CACHE", "SET_ORIENTATION", "READ_CONTACTS", "DEVICE_POWER", "HARDWARE_TEST", "ACCESS_WIFI_STATE", "WRITE_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION", "SET_WALLPAPER_HINTS", "SET_PREFERRED_APPLICATIONS", "WRITE_SECURE_SETTINGS"

        )
    }
}
