/*
 * artmethod.c —— JNI 助手：拿 ArtMethod* 并 dump 它的内存布局
 *
 * 为什么需要它：
 *   1. Android 11+ 的 hidden API 限制让"反射读 Method 的私有 long
 *      字段"这条路失效。ART 里 jmethodID 本身就是 ArtMethod*，
 *      用 FromReflectedMethod 可以干净地拿到。
 *   2. 各版本 ArtMethod 的字段偏移不同（Android 13 与 8~11 就不一样），
 *      所以这里直接按 8 字节步长把前 0x40 字节打出来，
 *      再配合"哪个字段指向可执行页"来判定 entry_point_ 的真实偏移。
 */
#include <jni.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Java: static native long getArtMethod(Method m) */
JNIEXPORT jlong JNICALL
Java_pte_javatest_ArtMethodHelper_getArtMethod(JNIEnv *env, jclass cls,
                                               jobject method)
{
    jmethodID mid = (*env)->FromReflectedMethod(env, method);
    (void)cls;
    return (jlong)(intptr_t)mid;
}

/* Java: static native int isStatic(Method m) —— 1=static，0=实例，-1=失败 */
JNIEXPORT jint JNICALL
Java_pte_javatest_ArtMethodHelper_isStatic(JNIEnv *env, jclass cls,
                                           jobject method)
{
    jclass mcls;
    jmethodID getMod;
    jint mod;

    (void)cls;
    if (!(*env)->FromReflectedMethod(env, method))
        return -1;
    mcls = (*env)->GetObjectClass(env, method);
    getMod = (*env)->GetMethodID(env, mcls, "getModifiers", "()I");
    mod = (*env)->CallIntMethod(env, method, getMod);
    return (mod & 0x0008) ? 1 : 0;   /* Modifier.STATIC */
}

/*
 * Java: static native String dumpArtMethod(Method m, int bytes)
 *
 * 把 ArtMethod 起始的 bytes 字节按 8 字节一行打出来（hex）。
 * 用于人工判断各字段含义，不参与内核模块逻辑。
 */
JNIEXPORT jstring JNICALL
Java_pte_javatest_ArtMethodHelper_dumpArtMethod(JNIEnv *env, jclass cls,
                                                jobject method, jint bytes)
{
    jmethodID mid = (*env)->FromReflectedMethod(env, method);
    const uint8_t *p = (const uint8_t *)(intptr_t)mid;
    char buf[2048];
    int off = 0, i;

    (void)cls;
    if (!p)
        return (*env)->NewStringUTF(env, "(null ArtMethod)");
    if (bytes <= 0 || bytes > 0x100)
        bytes = 0x40;

    off += snprintf(buf + off, sizeof(buf) - off, "ArtMethod* = %p\n", (void *)p);
    for (i = 0; i < bytes && off < (int)sizeof(buf) - 64; i += 8) {
        uint64_t v;
        memcpy(&v, p + i, 8);
        off += snprintf(buf + off, sizeof(buf) - off,
                        "  +0x%02x: 0x%016llx\n", i,
                        (unsigned long long)v);
    }
    return (*env)->NewStringUTF(env, buf);
}
