/*
 * JavaHookTest.java —— Java 层 hook 的验证程序（Android）
 *
 * 作用：造几个方法，把它们的 ArtMethod 地址打印出来，然后循环调用，
 * 方便配合 /proc/pte_java 观察 hook 是否生效。
 *
 * 拿 ArtMethod 用 JNI（ArtMethodHelper），因为 Android 11+ 的
 * hidden API 限制让反射读 Method 的私有字段不可行。
 *
 * 编译见 test/readme.md 或 tools/build_java_test.sh。
 */

package pte.javatest;

import java.lang.reflect.Method;

public class JavaHookTest {

    /** 被测方法：整数相加。命中 hook 时观察 x1/x2 是否为 3/4。 */
    public int add(int a, int b) {
        return a + b;
    }

    /** 被测静态方法。静态方法 x0 = ArtMethod*，第一个真实参数在 x1。 */
    public static String greet(String name) {
        return "hello, " + name;
    }

    /** 被测方法：无参数，便于观察调用频次。 */
    public long tick() {
        return System.nanoTime();
    }

    /**
     * 强循环方法：让 ART 尽快把它 JIT 起来。
     *
     * 这点很关键：方法还没被编译时，ArtMethod.entry_point_ 指向的是
     * libart.so 里的共享跳板，所有方法共用同一个地址，此时 hook 入口
     * 意义不大。调用足够多次之后 ART 会 JIT，入口变成该方法独享的
     * 匿名可执行页，hook 就精确了。
     */
    /**
     * 简单乘法，返回值好判断（6*7=42）。
     * 保持短小，便于一眼看出"改参数/改返回值"是否生效。
     */
    public int hot(int a, int b) {
        return a * b;
    }

    public static void main(String[] args) throws Exception {
        System.load("/data/local/tmp/libartmethod.so");

        JavaHookTest obj = new JavaHookTest();

        Method add = JavaHookTest.class.getMethod("add", int.class, int.class);
        Method greet = JavaHookTest.class.getMethod("greet", String.class);
        Method tick = JavaHookTest.class.getMethod("tick");
        Method hot = JavaHookTest.class.getMethod("hot", int.class, int.class);

        int pid = android.os.Process.myPid();
        System.out.println("pid = " + pid);

        printInfo("add", add);
        printInfo("greet", greet);
        printInfo("tick", tick);
        printInfo("hot", hot);

        /* dump ArtMethod 内存布局：用来确定 entry_point_ 的真实偏移 */
        System.out.println("---- ArtMethod layout (add) ----");
        System.out.println(ArtMethodHelper.dumpArtMethod(add, 0x20));
        System.out.println("---- ArtMethod layout (greet/static) ----");
        System.out.println(ArtMethodHelper.dumpArtMethod(greet, 0x20));

        /* 先把 hot() 打热，让 ART JIT 它 */
        System.out.println("---- warming up hot() ----");
        int sink = 0;
        for (int i = 0; i < 200000; i++)
            sink += obj.hot(i & 0xff, 3);
        System.out.println("warmup done, sink=" + sink);
        printInfo("hot(jitted)", hot);
        System.out.println("---- ArtMethod layout (hot, after JIT) ----");
        System.out.println(ArtMethodHelper.dumpArtMethod(hot, 0x20));
        System.out.println("---- 用上面的地址去 /proc/pte_java 装 hook ----");

        /*
         * 用反射调用 hot()。
         *
         * 为什么不用 obj.hot(...)：JIT 会把短小的热方法**内联**到调用者，
         * 内联后调用点直接执行展开的代码，完全不经过 ArtMethod.entry_point_，
         * 于是改 entry_point_ 的 hook 就"看不到"这次调用（实测踩过）。
         * 反射调用必然走 ART 的方法入口，不可能被内联，所以用它做验证。
         */
        Method hotM = JavaHookTest.class.getMethod("hot", int.class, int.class);

        for (int i = 0; i < 100000; i++) {
            int r = obj.add(3, 4);
            String s = greet("world");
            long t = obj.tick();

            /* 反射调用 hot：必然经过 entry_point_ */
            int h = 0;
            for (int k = 0; k < 20; k++)
                h = (Integer) hotM.invoke(obj, 6, 7);

            if (i % 50 == 0)
                System.out.println("iter " + i + " add(3,4)=" + r
                        + " greet=" + s + " tick=" + t + " hot(6,7)=" + h);

            Thread.sleep(10);
        }
        System.out.println("done");
    }

    private static void printInfo(String name, Method m) {
        long am = ArtMethodHelper.getArtMethod(m);
        int st = ArtMethodHelper.isStatic(m);
        System.out.println(name + " ArtMethod = 0x" + Long.toHexString(am)
                + (st == 1 ? "  [static]" : (st == 0 ? "  [instance]" : "")));
    }
}
