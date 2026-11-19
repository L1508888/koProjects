/*
 * ArtMethodHelper.java —— 通过 JNI 拿 ArtMethod*
 *
 * 为什么不能纯 Java 拿：
 *   Android 11+ 的 hidden API 限制让"反射读 java.lang.reflect.Method
 *   的私有 long 字段"这条路失效（getDeclaredFields 看不到，或者
 *   setAccessible 被拦）。
 *
 * 正确做法：ART 里 jmethodID **本身**就是 ArtMethod*，
 * 用 JNI 的 FromReflectedMethod 可以干净地拿到它。
 *
 * 这个类的 native 实现在 artmethod.c，加载方式：
 *   System.load("/data/local/tmp/libartmethod.so");
 */
package pte.javatest;

import java.lang.reflect.Method;

public final class ArtMethodHelper {

    private ArtMethodHelper() {}

    /** 返回 ArtMethod*（目标进程内的用户态地址）；失败返回 0 */
    public static native long getArtMethod(Method m);

    /** 1 = static（x0 是 ArtMethod*），0 = 实例方法（x0 是 receiver） */
    public static native int isStatic(Method m);

    /** 把 ArtMethod 起始 bytes 字节按 8 字节一行打成 hex，人工看布局用 */
    public static native String dumpArtMethod(Method m, int bytes);
}
