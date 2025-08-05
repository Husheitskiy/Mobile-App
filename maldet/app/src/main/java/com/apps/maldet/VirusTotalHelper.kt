package com.apps.maldet

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject


object VirusTotalHelper {
    private const val API_KEY = "51ce1251a09ff21698584f5dd41235eea3cc3623171f20fc41c913dcb646bf76"
    private val client = OkHttpClient()

    fun checkHash(hash: String, onResult: (Int, Boolean) -> Unit) {
        val url = "https://www.virustotal.com/api/v3/files/$hash"

        val request = Request.Builder()
            .url(url)
            .addHeader("x-apikey", API_KEY)
            .build()

        Thread {
            try {
                client.newCall(request).execute().use { response ->
                    if (response.isSuccessful) {
                        val body = response.body?.string()
                        val json = JSONObject(body!!)
                        val data = json.getJSONObject("data")
                        val attributes = data.getJSONObject("attributes")
                        val stats = attributes.getJSONObject("last_analysis_stats")

                        val malicious = stats.getInt("malicious")
                        val harmless = stats.getInt("harmless")

                        onResult(malicious, malicious > 0)
                    } else {
                        onResult(0, false)
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                onResult(0, false)
            }
        }.start()

    }

}
