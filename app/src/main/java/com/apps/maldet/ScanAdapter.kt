package com.apps.maldet

import android.graphics.drawable.Drawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class ScanAdapter(private val scanResults: List<installedScan.ScanResult>) :
    RecyclerView.Adapter<ScanAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val appIcon: ImageView = view.findViewById(R.id.icon)
        val appName: TextView = view.findViewById(R.id.appName)
        val packageName: TextView = view.findViewById(R.id.packageName)
        val score: TextView = view.findViewById(R.id.score)
        val label: TextView = view.findViewById(R.id.label)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.scan_item, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount() = scanResults.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val result = scanResults[position]
        holder.appIcon.setImageDrawable(result.icon)
        holder.appName.text = result.appName
        holder.packageName.text = result.packageName
        holder.score.text = "Score: %.2f".format(result.score)
        holder.label.text = result.label
        holder.label.setTextColor(
            if (result.label == "MALWARE") 0xFFFF4444.toInt() else 0xFF66BB6A.toInt()
        )
    }
}
