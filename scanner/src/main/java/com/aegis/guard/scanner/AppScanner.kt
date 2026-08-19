package com.aegis.guard.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

enum class ThreatLevel {
    SAFE, SUSPICIOUS, DANGEROUS
}

data class ScanResult(
    val packageName: String,
    val appName: String,
    val isSystemApp: Boolean,
    val score: Int,
    val threatLevel: ThreatLevel,
    val malwareProbability: Float = 0.0f,
    val topReasons: List<String> = emptyList()
)

@Singleton
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val featureExtractor: AppFeatureExtractor,
    private val malwareModel: OnDeviceMalwareModel
) {
    init {
        malwareModel.loadModel(context)
    }

    fun scanApps(): List<ScanResult> {
        val packageManager = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS

        val packages = packageManager.getInstalledPackages(flags)
        val results = mutableListOf<ScanResult>()

        for (pkg in packages) {
            val appInfo = pkg.applicationInfo
            val isSystemApp = appInfo?.let { (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 } ?: false
            val appName = appInfo?.loadLabel(packageManager)?.toString() ?: pkg.packageName

            // Extract 80-dimensional feature vector
            val features = featureExtractor.extractFeatures(context, pkg)

            // Run on-device ML model inference
            val prediction = malwareModel.predict(features)

            results.add(
                ScanResult(
                    packageName = pkg.packageName,
                    appName = appName,
                    isSystemApp = isSystemApp,
                    score = prediction.riskScore,
                    threatLevel = prediction.threatLevel,
                    malwareProbability = prediction.probability,
                    topReasons = prediction.topReasons
                )
            )
        }

        return results
    }

    /**
     * Scans a single installed package or APK file.
     */
    fun scanSinglePackage(packageName: String): ScanResult? {
        val packageManager = context.packageManager
        return try {
            val flags = PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_ACTIVITIES or
                    PackageManager.GET_SERVICES or
                    PackageManager.GET_RECEIVERS
            val pkg = packageManager.getPackageInfo(packageName, flags)
            val appInfo = pkg.applicationInfo
            val isSystemApp = appInfo?.let { (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 } ?: false
            val appName = appInfo?.loadLabel(packageManager)?.toString() ?: pkg.packageName

            val features = featureExtractor.extractFeatures(context, pkg)
            val prediction = malwareModel.predict(features)

            ScanResult(
                packageName = pkg.packageName,
                appName = appName,
                isSystemApp = isSystemApp,
                score = prediction.riskScore,
                threatLevel = prediction.threatLevel,
                malwareProbability = prediction.probability,
                topReasons = prediction.topReasons
            )
        } catch (e: Exception) {
            null
        }
    }
}