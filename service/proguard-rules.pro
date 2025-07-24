# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
-keepclasseswithmembers class io.github.a13e300.tricky_store.MainKt {
    public static void main(java.lang.String[]);
}

-assumenosideeffects class io.github.a13e300.tricky_store.Logger {
    public static void d(java.lang.String);
}

# keep these or bouncycastle will not work
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-dontwarn javax.naming.**

# Keep `Companion` object fields of serializable classes.
# This avoids serializer lookup through `getDeclaredClasses` as done for named companion objects.
-if @kotlinx.serialization.Serializable class **
-keepclassmembers class <1> {
   static <1>$Companion Companion;
}

# Keep `serializer()` on companion objects (both default and named) of serializable classes.
-if @kotlinx.serialization.Serializable class ** {
   static **$* *;
}
-keepclassmembers class <2>$<3> {
   kotlinx.serialization.KSerializer serializer(...);
}

# Keep `INSTANCE.serializer()` of serializable objects.
-if @kotlinx.serialization.Serializable class ** {
   public static ** INSTANCE;
}
-keepclassmembers class <1> {
   public static <1> INSTANCE;
   kotlinx.serialization.KSerializer serializer(...);
}

# Keep all fields and methods in SecurityLevelInterceptor
-keep class io.github.a13e300.tricky_store.SecurityLevelInterceptor {
    *;
}

# Keep Key and Info inner classes used in maps
-keepclassmembers class io.github.a13e300.tricky_store.SecurityLevelInterceptor$Key {
    *;
}
-keepclassmembers class io.github.a13e300.tricky_store.SecurityLevelInterceptor$Info {
    *;
}

# Keep Parcelable CREATOR fields
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

-repackageclasses
-allowaccessmodification
-overloadaggressively
-keepattributes SourceFile,LineNumberTable,LocalVariableTable
-renamesourcefileattribute
-obfuscationdictionary          proguard-dic.txt
-classobfuscationdictionary     proguard-dic.txt
-packageobfuscationdictionary   proguard-dic.txt
