package com.aegis.guard.scanner
 
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import javax.inject.Inject
import javax.inject.Singleton
 
enum class ScanStatus {
    SUCCESS, FAILED
}
 
data class ScanResult(
    val packageName: String,
    val appName: String,
    val isSystemApp: Boolean,
    val score: Int,
    val threatLevel: ThreatLevel,
    val malwareProbability: Float = 0.0f,
    val topReasons: List<String> = emptyList(),
    val status: ScanStatus = ScanStatus.SUCCESS,
    val errorMessage: String? = null
)
 
@Singleton
class AppScanner @Inject constructor(
    private val context: Context,
    private val featureExtractor: AppFeatureExtractor = AppFeatureExtractor(),
    private val malwareModel: OnDeviceMalwareModel = OnDeviceMalwareModel()
) {
    init {
        try {
            malwareModel.loadModel(context)
        } catch (e: Exception) {
            // Log model initialization failure - subsequent scan will report explicit UNKNOWN/FAILED
        }
    }

    /**
     * Scans all installed packages on device using the AEGIS 92-Feature On-Device ML Model.
     */
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

            try {
                // Extract comprehensive 92-dimensional feature vector
                val features = featureExtractor.extractFeatures(context, pkg)

                // Pure on-device ML inference (Evaluates calibrated tree ensemble over 92 features)
                val prediction = malwareModel.predict(features)

                results.add(
                    ScanResult(
                        packageName = pkg.packageName,
                        appName = appName,
                        isSystemApp = isSystemApp,
                        score = prediction.riskScore,
                        threatLevel = prediction.threatLevel,
                        malwareProbability = prediction.probability,
                        topReasons = prediction.topReasons,
                        status = ScanStatus.SUCCESS
                    )
                )
            } catch (e: Exception) {
                // EXPLICIT ERROR REPORTING: Never return SAFE on model or extraction failure
                results.add(
                    ScanResult(
                        packageName = pkg.packageName,
                        appName = appName,
                        isSystemApp = isSystemApp,
                        score = -1,
                        threatLevel = ThreatLevel.UNKNOWN,
                        malwareProbability = -1.0f,
                        topReasons = listOf("Scanning error: ${e.message}"),
                        status = ScanStatus.FAILED,
                        errorMessage = e.message
                    )
                )
            }
        }

        return results
    }

    /**
     * Scans a single installed package or APK file.
     */
    fun scanSinglePackage(packageName: String): ScanResult {
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
                topReasons = prediction.topReasons,
                status = ScanStatus.SUCCESS
            )
        } catch (e: Exception) {
            ScanResult(
                packageName = packageName,
                appName = packageName,
                isSystemApp = false,
                score = -1,
                threatLevel = ThreatLevel.UNKNOWN,
                malwareProbability = -1.0f,
                topReasons = listOf("Package scanning error: ${e.message}"),
                status = ScanStatus.FAILED,
                errorMessage = e.message
            )
        }
    }
}