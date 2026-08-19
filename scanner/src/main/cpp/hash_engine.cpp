#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_com_aegis_guard_scanner_NativeEngine_hashFile(
        JNIEnv* env,
        jobject /* this */,
        jstring filePath) {
    // Basic hardcoded mock hash for testing the JNI bridge
    std::string hardcoded_hash = "d41d8cd98f00b204e9800998ecf8427e";
    return env->NewStringUTF(hardcoded_hash.c_str());
}
