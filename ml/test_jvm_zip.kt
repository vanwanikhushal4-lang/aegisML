import java.io.File
import java.util.zip.ZipFile

fun main() {
    val apkPath = """C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"""
    val file = File(apkPath)
    println("Testing Java ZipFile on: $apkPath")
    
    var errorCount = 0
    var successCount = 0
    
    ZipFile(file).use { zip ->
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
            val e = entries.nextElement()
            try {
                zip.getInputStream(e).use { s ->
                    val b = ByteArray(1024)
                    val r = s.read(b)
                    successCount++
                }
            } catch (ex: Exception) {
                errorCount++
                if (errorCount <= 3) {
                    println("  Exception reading ${e.name}: $ex")
                }
            }
        }
    }
    println("Result: $successCount succeeded, $errorCount failed due to ZipException")
}
main()