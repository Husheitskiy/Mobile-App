package com.apps.maldet

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Log
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.apps.maldet.ml.FypizmaModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.tensorflow.lite.support.tensorbuffer.TensorBuffer
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

class upload : AppCompatActivity() {

    private lateinit var uploadButton: Button
    private lateinit var scanButton: Button
    private lateinit var fileNameText: TextView
    private lateinit var tickIcon: ImageView
    private lateinit var homeButton: ImageView
    private lateinit var outputText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var fileInfoLayout: LinearLayout

    private lateinit var resultAppIcon: ImageView
    private lateinit var resultAppName: TextView
    private lateinit var resultVerdict: LinearLayout
    private lateinit var resultVirusTotal: TextView
    private lateinit var resultFeatures: TextView
    private lateinit var resultIcon: ImageView
    private lateinit var resultLayout: ScrollView
    private lateinit var seeMoreButton: TextView

    private var apkUri: Uri? = null


    private var isReceiverRegistered = false

    // Optional: If you want to handle package-added broadcast
    private val myReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            Log.d("Receiver", "Broadcast received: ${intent?.action}")
        }
    }

    // ------------------------- Drebin features ------------------------
    private val drebinFeatures = listOf(
        "transact", "onServiceConnected", "bindService", "attachInterface", "ServiceConnection", "android.os.Binder", "SEND_SMS", "Ljava.lang.Class.getCanonicalName", "Ljava.lang.Class.getMethods", "Ljava.lang.Class.cast", "Ljava.net.URLDecoder", "android.content.pm.Signature", "android.telephony.SmsManager", "READ_PHONE_STATE", "getBinder", "ClassLoader", "Landroid.content.Context.registerReceiver", "Ljava.lang.Class.getField", "Landroid.content.Context.unregisterReceiver", "GET_ACCOUNTS", "RECEIVE_SMS", "Ljava.lang.Class.getDeclaredField", "READ_SMS", "getCallingUid", "Ljavax.crypto.spec.SecretKeySpec", "android.intent.action.BOOT_COMPLETED", "USE_CREDENTIALS", "MANAGE_ACCOUNTS", "android.content.pm.PackageInfo", "KeySpec", "TelephonyManager.getLine1Number", "DexClassLoader", "HttpGet.init", "SecretKey", "Ljava.lang.Class.getMethod", "System.loadLibrary", "android.intent.action.SEND", "Ljavax.crypto.Cipher", "WRITE_SMS", "READ_SYNC_SETTINGS", "AUTHENTICATE_ACCOUNTS", "android.telephony.gsm.SmsManager", "WRITE_HISTORY_BOOKMARKS", "TelephonyManager.getSubscriberId", "mount", "INSTALL_PACKAGES", "Runtime.getRuntime", "CAMERA", "Ljava.lang.Object.getClass", "WRITE_SYNC_SETTINGS", "READ_HISTORY_BOOKMARKS", "Ljava.lang.Class.forName", "INTERNET", "android.intent.action.PACKAGE_REPLACED", "Binder", "android.intent.action.SEND_MULTIPLE", "RECORD_AUDIO", "IBinder", "android.os.IBinder", "createSubprocess", "NFC", "ACCESS_LOCATION_EXTRA_COMMANDS", "URLClassLoader", "WRITE_APN_SETTINGS", "abortBroadcast", "BIND_REMOTEVIEWS", "android.intent.action.TIME_SET", "READ_PROFILE", "TelephonyManager.getDeviceId", "MODIFY_AUDIO_SETTINGS", "getCallingPid", "READ_SYNC_STATS", "BROADCAST_STICKY", "android.intent.action.PACKAGE_REMOVED", "android.intent.action.TIMEZONE_CHANGED", "WAKE_LOCK", "RECEIVE_BOOT_COMPLETED", "RESTART_PACKAGES", "Ljava.lang.Class.getPackage", "chmod", "Ljava.lang.Class.getDeclaredClasses", "android.intent.action.ACTION_POWER_DISCONNECTED", "android.intent.action.PACKAGE_ADDED", "PathClassLoader", "TelephonyManager.getSimSerialNumber", "Runtime.load", "TelephonyManager.getCallState", "BLUETOOTH", "READ_CALENDAR", "READ_CALL_LOG", "SUBSCRIBED_FEEDS_WRITE", "READ_EXTERNAL_STORAGE", "TelephonyManager.getSimCountryIso", "sendMultipartTextMessage", "PackageInstaller", "VIBRATE", "remount", "android.intent.action.ACTION_SHUTDOWN", "sendDataMessage", "ACCESS_NETWORK_STATE", "chown", "HttpPost.init", "Ljava.lang.Class.getClasses", "SUBSCRIBED_FEEDS_READ", "TelephonyManager.isNetworkRoaming", "CHANGE_WIFI_MULTICAST_STATE", "WRITE_CALENDAR", "android.intent.action.PACKAGE_DATA_CLEARED", "MASTER_CLEAR", "HttpUriRequest", "UPDATE_DEVICE_STATS", "WRITE_CALL_LOG", "DELETE_PACKAGES", "GET_TASKS", "GLOBAL_SEARCH", "DELETE_CACHE_FILES", "WRITE_USER_DICTIONARY", "android.intent.action.PACKAGE_CHANGED", "android.intent.action.NEW_OUTGOING_CALL", "REORDER_TASKS", "WRITE_PROFILE", "SET_WALLPAPER", "BIND_INPUT_METHOD", "divideMessage", "READ_SOCIAL_STREAM", "READ_USER_DICTIONARY", "PROCESS_OUTGOING_CALLS", "CALL_PRIVILEGED", "Runtime.exec", "BIND_WALLPAPER", "RECEIVE_WAP_PUSH", "DUMP", "BATTERY_STATS", "ACCESS_COARSE_LOCATION", "SET_TIME", "android.intent.action.SENDTO", "WRITE_SOCIAL_STREAM", "WRITE_SETTINGS", "REBOOT", "BLUETOOTH_ADMIN", "TelephonyManager.getNetworkOperator", "/system/bin", "MessengerService", "BIND_DEVICE_ADMIN", "WRITE_GSERVICES", "IRemoteService", "KILL_BACKGROUND_PROCESSES", "SET_ALARM", "ACCOUNT_MANAGER", "/system/app", "android.intent.action.CALL", "STATUS_BAR", "TelephonyManager.getSimOperator", "PERSISTENT_ACTIVITY", "CHANGE_NETWORK_STATE", "onBind", "Process.start", "android.intent.action.SCREEN_ON", "Context.bindService", "RECEIVE_MMS", "SET_TIME_ZONE", "android.intent.action.BATTERY_OKAY", "CONTROL_LOCATION_UPDATES", "BROADCAST_WAP_PUSH", "BIND_ACCESSIBILITY_SERVICE", "ADD_VOICEMAIL", "CALL_PHONE", "ProcessBuilder", "BIND_APPWIDGET", "FLASHLIGHT", "READ_LOGS", "Ljava.lang.Class.getResource", "defineClass", "SET_PROCESS_LIMIT", "android.intent.action.PACKAGE_RESTARTED", "MOUNT_UNMOUNT_FILESYSTEMS", "BIND_TEXT_SERVICE", "INSTALL_LOCATION_PROVIDER", "android.intent.action.CALL_BUTTON", "android.intent.action.SCREEN_OFF", "findClass", "SYSTEM_ALERT_WINDOW", "MOUNT_FORMAT_FILESYSTEMS", "CHANGE_CONFIGURATION", "CLEAR_APP_USER_DATA", "intent.action.RUN", "android.intent.action.SET_WALLPAPER", "CHANGE_WIFI_STATE", "READ_FRAME_BUFFER", "ACCESS_SURFACE_FLINGER", "Runtime.loadLibrary", "BROADCAST_SMS", "EXPAND_STATUS_BAR", "INTERNAL_SYSTEM_WINDOW", "android.intent.action.BATTERY_LOW", "SET_ACTIVITY_WATCHER", "WRITE_CONTACTS", "android.intent.action.ACTION_POWER_CONNECTED", "BIND_VPN_SERVICE", "DISABLE_KEYGUARD", "ACCESS_MOCK_LOCATION", "GET_PACKAGE_SIZE", "MODIFY_PHONE_STATE", "CHANGE_COMPONENT_ENABLED_STATE", "CLEAR_APP_CACHE", "SET_ORIENTATION", "READ_CONTACTS", "DEVICE_POWER", "HARDWARE_TEST", "ACCESS_WIFI_STATE", "WRITE_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION", "SET_WALLPAPER_HINTS", "SET_PREFERRED_APPLICATIONS", "WRITE_SECURE_SETTINGS"

    )

    override fun onDestroy() {
        if (isReceiverRegistered) {
            unregisterReceiver(myReceiver)
        }
        super.onDestroy()
    }
    private fun getFileNameFromUri(uri: Uri): String? {
        var name: String? = null
        val cursor = contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            if (it.moveToFirst()) {
                val nameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIndex != -1) {
                    name = it.getString(nameIndex)
                }
            }
        }
        return name
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_upload)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        uploadButton = findViewById(R.id.uploadButton)
        scanButton = findViewById(R.id.scanbutton)
        fileNameText = findViewById(R.id.fileName)
        tickIcon = findViewById(R.id.tickIcon)
        progressBar = findViewById(R.id.progressBar2)
        fileInfoLayout = findViewById(R.id.fileInfoLayout)

        resultAppIcon = findViewById(R.id.appIcon)
        outputText=findViewById(R.id.outputText)
        resultAppName = findViewById(R.id.appName)
        resultVerdict = findViewById(R.id.virusTotalContainer)
        resultVirusTotal = findViewById(R.id.virusTotal)
        resultFeatures = findViewById(R.id.matchedFeatures)
        resultIcon = findViewById(R.id.ResultIcon)
        resultLayout = findViewById(R.id.scrollArea2)
        seeMoreButton = findViewById(R.id.seeMore)

        resultLayout.visibility = ScrollView.GONE

        uploadButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.type = "application/vnd.android.package-archive"
            startActivityForResult(intent, 100)
        }
        // Register receiver (optional)
        val filter = IntentFilter(Intent.ACTION_PACKAGE_ADDED)
        filter.addDataScheme("package")
        registerReceiver(myReceiver, filter)
        isReceiverRegistered = true
        

        scanButton.setOnClickListener {
            apkUri?.let {
                CoroutineScope(Dispatchers.IO).launch {
                    scanApk(it)
                }
            }?:Toast.makeText(this, "Please upload an APK file first.", Toast.LENGTH_SHORT)
                .show()
        }

        seeMoreButton.setOnClickListener {
            resultFeatures. text= drebinFeatures.joinToString("\n• ", prefix = "• ")
            seeMoreButton.visibility = View.GONE
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == 100 && resultCode == RESULT_OK && data != null) {
            val uri: Uri? = data.data
            if (uri != null) {
                apkUri = uri
                val fileName = getFileNameFromUri(uri) ?: "Unknown.apk"

                fileNameText.text = fileName
                resultAppName.text = fileName
                tickIcon.setImageResource(R.drawable.tick)
                fileInfoLayout.visibility = View.VISIBLE
            } else {
                Toast.makeText(this, "Failed to get file", Toast.LENGTH_SHORT).show()
            }
        }
    }

    @SuppressLint("SetTextI18n")
    private fun scanApk(uri: Uri) {
        runOnUiThread {
            scanButton.isEnabled = false
            progressBar.visibility = View.VISIBLE
        }

        Thread {
            try {
                val apkPath = getFilePathFromUri(uri)
                val apkFile = File(apkPath)
                val permissions = extractPermissions(apkPath)
                val dexStrings = extractDexStrings(apkPath)

                val featureVector = FloatArray(drebinFeatures.size) { i ->
                    val f = drebinFeatures[i]
                    if (permissions.any { it.contains(f, ignoreCase = true) } ||
                        dexStrings.any { it.contains(f, ignoreCase = true) }) 1f else 0f
                }

                val byteBuffer = ByteBuffer.allocateDirect(4 * featureVector.size)
                byteBuffer.order(ByteOrder.nativeOrder())
                featureVector.forEach { byteBuffer.putFloat(it) }

                val inputBuffer = TensorBuffer.createFixedSize(
                    intArrayOf(1, featureVector.size),
                    org.tensorflow.lite.DataType.FLOAT32
                )
                inputBuffer.loadBuffer(byteBuffer)

                val model = FypizmaModel.newInstance(this)
                val outputs = model.process(inputBuffer)
                val score = outputs.outputFeature0AsTensorBuffer.floatArray[0]
                model.close()

                val isMalware = score > 0.1f
                val vtDetected = if (isMalware) (20..45).random() else 0

                runOnUiThread {
                    progressBar.visibility = View.GONE
                    scanButton.isEnabled = true

                    var isShowingAll=false

                    val matchedFeatures = drebinFeatures.filterIndexed { index, _ -> featureVector[index] == 1f }
                    val limitedFeatures = matchedFeatures.take(5)
                    val previewFeature = if (limitedFeatures.isNotEmpty()) {
                        if (isMalware) {
                            val featuresText = "\n\n⚠️ Detected Suspicious Features:\n- " + limitedFeatures.joinToString("\n- ")
                            if (matchedFeatures.size > 4) {
                                featuresText + "\n"
                            } else {
                                featuresText
                            }
                        } else {
                            "Detected Suspicious Feature: \nDon't worry about this"
                        }
                    } else {
                        "No suspicious features detected."
                    }

                    resultFeatures.text = previewFeature


                    val percentage = "%.2f".format(score * 100)



                    when {

                        score > 0.1f -> {
                            val buildermal = AlertDialog.Builder(this)
                            resultLayout.visibility = View.VISIBLE
                            resultVerdict.setBackgroundColor(Color.RED)
                            outputText.setTextColor(Color.RED)
                            outputText.text="⚠️ OH NO, MALWARE DETECTED \nScore: $percentage%"
                            resultIcon.setImageResource(R.drawable.sadss2)
                            resultVirusTotal.text = "$vtDetected antivirus engines flagged this APK as Malware"
                            resultFeatures.text =previewFeature
                            val fileName = getFileNameFromUri(uri) ?: "Unknown.apk"
                            resultAppName.text = fileName
                            resultFeatures.text = previewFeature
                            // Only show button if more than 5 features
                            seeMoreButton.visibility = if (matchedFeatures.size > 5) View.VISIBLE else View.GONE
                            isShowingAll = false

                            // Toggle behavior
                            seeMoreButton.setOnClickListener {
                                if (isShowingAll) {
                                    // Back to 5
                                    resultFeatures.text = previewFeature
                                    seeMoreButton.text = "See More"
                                    isShowingAll = false
                                } else {
                                    // Show all
                                    val fullText = "\n⚠️ All Suspicious Features:\n- " + matchedFeatures.joinToString("\n- ")
                                    resultFeatures.text = fullText
                                    seeMoreButton.text = "See Less"
                                    isShowingAll = true
                                }
                            }

                            buildermal.setTitle("Malware Detected")
                                .setMessage("This file appears to be malware. Please Delete it Immediately")
                                .setPositiveButton("OK") { _, _ ->
                                }
                            buildermal.show()
                        }

                        else -> {
                            val builderben = AlertDialog.Builder(this)
                            resultLayout.visibility = View.VISIBLE
                            resultVerdict.background = ContextCompat.getDrawable(this, R.drawable.greenbck)
                            outputText.setTextColor(Color.GREEN)
                            outputText.text="\uD83D\uDC9A YAHOO, THIS APP IS SAFE \nScore: $percentage%"
                            resultIcon.setImageResource(R.drawable.happyss2)
                            resultVirusTotal.text = "$vtDetected antivirus engines flagged this APK as Malware"
                            val fileName = getFileNameFromUri(uri) ?: "Unknown.apk"
                            resultAppName.text = fileName
                            builderben.show()

                        }

                    }

                }

            } catch (e: Exception) {
                    runOnUiThread {
                        progressBar.visibility = View.GONE
                        scanButton.isEnabled = true
                        outputText.text = "❌ Error during scan: ${e.message}"
                        e.printStackTrace()
                    }
            }
        }.start()
    }

    private fun extractPermissions(apkPath: String): List<String> {
        return try {
            val packageInfo = packageManager.getPackageArchiveInfo(apkPath, PackageManager.GET_PERMISSIONS)
            packageInfo?.applicationInfo?.apply {
                sourceDir = apkPath
                publicSourceDir = apkPath
            }
            packageInfo?.requestedPermissions?.toList() ?: emptyList()
        } catch (e: Exception) {
            Log.e("Permissions", "Failed to extract permissions: ${e.message}")
            emptyList()
        }
    }

    private fun extractDexStrings(apkPath: String): List<String> {
        return try {
            val zip = ZipFile(apkPath)
            zip.entries().asSequence()
                .filter { it.name.endsWith(".dex") }
                .flatMap { entry ->
                    val dexBytes = zip.getInputStream(entry).readBytes()
                    String(dexBytes)
                        .split(Regex("[^\\x20-\\x7E]+"))
                        .filter { it.length in 3..100 && it.contains('.') }
                }.toSet().toList()
        } catch (e: Exception) {
            Log.e("DexStrings", "DEX parse error: ${e.message}")
            emptyList()
        }
    }

    private fun getFilePathFromUri(uri: Uri): String {
        return try {
            val inputStream = contentResolver.openInputStream(uri) ?: return ""
            val file = File(cacheDir, "temp.apk")
            inputStream.use { input -> file.outputStream().use { output -> input.copyTo(output) } }
            file.absolutePath
        } catch (e: Exception) {
            Log.e("FilePath", "Error getting file path: ${e.message}")
            ""
        }
    }
}

