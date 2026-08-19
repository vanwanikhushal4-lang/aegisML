package com.aegis.guard.scanner

class NativeEngine {
    init {
        System.loadLibrary("aegis-scanner")
    }

    external fun hashFile(filePath: String): String
}
