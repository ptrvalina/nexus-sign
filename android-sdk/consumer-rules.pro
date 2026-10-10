# kotlinx.serialization requires its generated serializer classes to
# survive minification in the host app; this module's own consumer
# rules keep them intact without the integrating bank having to know
# that detail.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

-keep,includedescriptorclasses class com.nexis.nexussign.**$$serializer { *; }
-keepclassmembers class com.nexis.nexussign.** {
    *** Companion;
}
-keepclasseswithmembers class com.nexis.nexussign.** {
    kotlinx.serialization.KSerializer serializer(...);
}
