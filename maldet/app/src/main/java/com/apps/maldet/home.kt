package com.apps.maldet

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.ImageView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class home : AppCompatActivity() {

    private lateinit var _fon: Button
    private lateinit var _file: Button
    private lateinit var _infophone: ImageView
    private lateinit var _infofile: ImageView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_home)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        _fon=findViewById(R.id.btnScanPhone)
        _file=findViewById(R.id.btnScanFile)
        _infophone=findViewById(R.id.infofon)
        _infofile=findViewById(R.id.infofile)

        //Tekan button ni dia ke page detect Install Fon
        _fon.setOnClickListener{
            startActivity(Intent(this,installedScan::class.java))
        }

        //Tekan button ni dia ke page detect Scanned File
        _file.setOnClickListener{
            startActivity(Intent(this,upload::class.java))
        }

        _infophone.setOnClickListener{
            val builder = android.app.AlertDialog.Builder(this)
            builder.setTitle("Scan Phone")
            builder.setMessage("This page scans all installed apps on your Android device to detect any potential malware. It analyzes each app's behavior and code patterns to ensure your phone stays protected from harmful or suspicious applications.")
            builder.setPositiveButton("OK") { dialog, _ ->
                dialog.dismiss()
            }
            builder.show()
        }

        _infofile.setOnClickListener{
            val builder = android.app.AlertDialog.Builder(this)
            builder.setTitle("Scan APK File")
            builder.setMessage("This page allows you to upload and scan an APK file to detect if it contains malware. The system uses intelligent analysis based on permissions and DEX code to determine if the file is safe or malicious before installation.")
            builder.setPositiveButton("OK") { dialog, _ ->
                dialog.dismiss()
            }
            builder.show()
        }

    }
}