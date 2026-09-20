# 保留行号与源文件信息，便于排查
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Play Integrity / GMS 相关
-keep class com.google.android.gms.** { *; }
-dontwarn com.google.android.gms.**
