
# My config #####################################################################################

# This ProGuard configuration file illustrates how to process Android
# applications.
# Usage:
#     java -jar proguard.jar @android.pro
#
# If you're using the Android SDK, the Ant release build and Eclipse export
# already take care of the proper settings. You only need to enable ProGuard
# by commenting in the corresponding line in project.properties. You can still
# add project-specific configuration in proguard-project.txt.
#
# This configuration file is for custom, stand-alone builds.

# Specify the input jars, output jars, and library jars.
# Note that ProGuard works with Java bytecode (.class),
# before the dex compiler converts it into Dalvik code (.dex).

#-injars bin/classes
-injars xxx

#-outjars proguard-obf-classes.jar


#-libraryjars /data/xiezifan/OptTPL/libs/android.jar

# Save the obfuscation mapping to a file, so you can de-obfuscate any stack
# traces later on.

-printmapping mapping.txt

# You can print out the seeds that are matching the keep options below.

-printseeds seeds.txt

-printusage usage.txt
#-dontobfuscate
#-dontoptimize
#-dontshrink

-dontpreverify
-ignorewarnings
-dontnote

-dontwarn org.xmlpull.v1.**
-dontwarn org.kxml2.io.**
-dontwarn android.content.res.**
-dontwarn org.slf4j.impl.StaticLoggerBinder

-keep class org.xmlpull.** { *; }
-dontwarn org.xml.sax.**
-dontwarn org.xml.sax.ext.**
-keep class org.xml.sax.Locator { *; }
-keepclassmembers class org.xml.sax.Locator { *; }
-keepclassmembers class org.xmlpull.** { *; }

-keep class org.xml.sax.Locator { *; }
-keepclassmembers class org.xml.sax.Locator { *; }

-keep class android.view.animation.BaseInterpolator { *; }
-keepclassmembers class android.view.animation.BaseInterpolator { *; }
-keep class android.graphics.drawable.AnimatedVectorDrawable { *; }
-keepclassmembers class android.graphics.drawable.AnimatedVectorDrawable { *; }
-keep class android.graphics.drawable.Animatable2 { *; }
-keepclassmembers class android.graphics.drawable.Animatable2 { *; }

-keep public class android.support.v7.preference.** { *; }
-dontwarn org.ietf.jgss.*
-dontwarn com.jcraft.jzlib.ZStream
# strip debug and trace (verbose) logging
-assumenosideeffects class org.slf4j.Logger {
    public void debug(...);
    public void trace(...);
}
-dontwarn org.slf4j.impl.StaticMDCBinder
-dontwarn org.slf4j.impl.StaticMarkerBinder
-dontwarn org.slf4j.impl.StaticLoggerBinder

-keepclassmembers class ** {
    public void onEvent*(**);
}

# https://github.com/Kotlin/kotlinx.serialization#android
-dontnote kotlinx.serialization.SerializationKt
-keep,includedescriptorclasses class com.ubergeek42.weechat.**$$serializer { *; }
-keepclassmembers class com.ubergeek42.weechat.** {
    *** Companion;
}
-keepclasseswithmembers class com.ubergeek42.weechat.** {
    kotlinx.serialization.KSerializer serializer(...);
}



# proguard-android-optimize.txt-8.1.0 ###################################################################

-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*
-optimizationpasses 5
-allowaccessmodification

-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# Preserve some attributes that may be required for reflection.
-keepattributes AnnotationDefault,
                EnclosingMethod,
                InnerClasses,
                RuntimeVisibleAnnotations,
                RuntimeVisibleParameterAnnotations,
                RuntimeVisibleTypeAnnotations,
                Signature

-keep public class com.google.vending.licensing.ILicensingService
-keep public class com.android.vending.licensing.ILicensingService
-keep public class com.google.android.vending.licensing.ILicensingService
-dontnote com.android.vending.licensing.ILicensingService
-dontnote com.google.vending.licensing.ILicensingService
-dontnote com.google.android.vending.licensing.ILicensingService

# For native methods, see http://proguard.sourceforge.net/manual/examples.html#native
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# Keep setters in Views so that animations can still work.
-keepclassmembers public class * extends android.view.View {
    void set*(***);
    *** get*();
}

# We want to keep methods in Activity that could be used in the XML attribute onClick.
-keepclassmembers class * extends android.app.Activity {
    public void *(android.view.View);
}

# For enumeration classes, see http://proguard.sourceforge.net/manual/examples.html#enumerations
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# Preserve annotated Javascript interface methods.
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# The support libraries contains references to newer platform versions.
# Don't warn about those in case this app is linking against an older
# platform version. We know about them, and they are safe.
-dontnote android.support.**
-dontnote androidx.**
-dontwarn android.support.**
-dontwarn androidx.**

# This class is deprecated, but remains for backward compatibility.
-dontwarn android.util.FloatMath

# Understand the @Keep support annotation.
-keep class android.support.annotation.Keep
-keep class androidx.annotation.Keep

-keep @android.support.annotation.Keep class * {*;}
-keep @androidx.annotation.Keep class * {*;}

-keepclasseswithmembers class * {
    @android.support.annotation.Keep <methods>;
}

-keepclasseswithmembers class * {
    @androidx.annotation.Keep <methods>;
}

-keepclasseswithmembers class * {
    @android.support.annotation.Keep <fields>;
}

-keepclasseswithmembers class * {
    @androidx.annotation.Keep <fields>;
}

-keepclasseswithmembers class * {
    @android.support.annotation.Keep <init>(...);
}

-keepclasseswithmembers class * {
    @androidx.annotation.Keep <init>(...);
}

# These classes are duplicated between android.jar and org.apache.http.legacy.jar.
-dontnote org.apache.http.**
-dontnote android.net.http.**

# These classes are duplicated between android.jar and core-lambda-stubs.jar.
-dontnote java.lang.invoke.**

# aapt_rules.txt ##################################################################################
#-todo_aapt_rules

-keep class android.support.v4.widget.NestedScrollView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.app.AlertController$RecycleListView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.PreferenceImageView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.preference.UnPressableLinearLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.view.menu.ActionMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.view.menu.ExpandedMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.view.menu.ListMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.ActionBarContainer { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.ActionBarContextView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.ActionBarOverlayLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.ActionMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.ActivityChooserView$InnerLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.AlertDialogLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.ButtonBarLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.ContentFrameLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.DialogTitle { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.FitWindowsFrameLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.FitWindowsLinearLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.RecyclerView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.SearchView$SearchAutoComplete { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.SwitchCompat { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.Toolbar { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.ViewStubCompat { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.widget.Space { <init>(android.content.Context, android.util.AttributeSet); }

-keepclassmembers class * { *** enter(android.view.View); }

-keepclassmembers class * { *** menuButtonClicked(android.view.View); }

-keepclassmembers class * { *** nextButtonClicked(android.view.View); }

-keepclassmembers class * { *** noteButtonClicked(android.view.View); }

-keepclassmembers class * { *** opennotebook(android.view.View); }

-keepclassmembers class * { *** playButtonClicked(android.view.View); }

-keepclassmembers class * { *** previousButtonClicked(android.view.View); }

-keep class android.widget.Button { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.widget.Space { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.app.AlertController$RecycleListView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.view.menu.ActionMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.view.menu.ExpandedMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.view.menu.ListMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.ActionBarContainer { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.ActionBarContextView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.ActionBarOverlayLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.ActionMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.ActivityChooserView$InnerLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.AlertDialogLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.AppCompatButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.AppCompatCheckBox { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.AppCompatImageButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.AppCompatRadioButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.AppCompatTextView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.ButtonBarLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.ContentFrameLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.DialogTitle { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.FitWindowsFrameLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.FitWindowsLinearLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.SearchView { <init>(android.content.Context); }

-keep class androidx.appcompat.widget.SearchView$SearchAutoComplete { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.SwitchCompat { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.Toolbar { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.appcompat.widget.ViewStubCompat { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.browser.browseractions.BrowserActionsFallbackMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.constraintlayout.widget.Barrier { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.constraintlayout.widget.ConstraintLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.constraintlayout.widget.Guideline { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.coordinatorlayout.widget.CoordinatorLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.core.widget.NestedScrollView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.drawerlayout.widget.ClosableDrawerLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.preference.UnPressableLinearLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.preference.internal.PreferenceImageView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.recyclerview.widget.RecyclerView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.swiperefreshlayout.widget.SwipeRefreshLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.viewpager2.widget.ViewPager2 { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.afollestad.materialdialogs.internal.MDButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.afollestad.materialdialogs.internal.MDRootLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.canhub.cropper.CropImageView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.canhub.cropper.CropOverlayView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.appbar.MaterialToolbar { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.bottomnavigation.BottomNavigationView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.button.MaterialButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.button.MaterialButtonToggleGroup { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.chip.Chip { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.chip.ChipGroup { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.datepicker.MaterialCalendarGridView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.floatingactionbutton.FloatingActionButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.BaselineLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.CheckableImageButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.NavigationMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.NavigationMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.navigation.NavigationView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.snackbar.Snackbar$SnackbarLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.snackbar.SnackbarContentLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.tabs.TabLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.textfield.TextInputEditText { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.textfield.TextInputLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.textview.MaterialTextView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.ChipTextInputComboView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.ClockFaceView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.ClockHandView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.TimePickerView { <init>(android.content.Context, android.util.AttributeSet); }


-keep class androidx.constraintlayout.widget.Barrier { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.constraintlayout.widget.ConstraintLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.constraintlayout.widget.Guideline { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.coordinatorlayout.widget.CoordinatorLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.core.widget.NestedScrollView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.drawerlayout.widget.DrawerLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.fragment.app.FragmentContainerView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.recyclerview.widget.RecyclerView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.swiperefreshlayout.widget.SwipeRefreshLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.viewpager.widget.ViewPager { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.blikoon.qrcodescanner.view.QrCodeFinderView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.elyeproj.loaderviewlibrary.LoaderImageView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.elyeproj.loaderviewlibrary.LoaderTextView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.github.chrisbanes.photoview.PhotoView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.exoplayer2.ui.AspectRatioFrameLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.exoplayer2.ui.StyledPlayerView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.exoplayer2.ui.SubtitleView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.exoplayer2.ui.TrackSelectionView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.appbar.AppBarLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.appbar.MaterialToolbar { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.button.MaterialButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.button.MaterialButtonToggleGroup { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.card.MaterialCardView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.chip.Chip { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.chip.ChipGroup { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.datepicker.MaterialCalendarGridView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.floatingactionbutton.FloatingActionButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.BaselineLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.CheckableImageButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.NavigationMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.NavigationMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.navigation.NavigationView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.snackbar.Snackbar$SnackbarLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.snackbar.SnackbarContentLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.tabs.TabLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.textfield.TextInputEditText { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.textfield.TextInputLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.textview.MaterialTextView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.ChipTextInputComboView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.ClockFaceView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.ClockHandView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.TimePickerView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.nextcloud.ui.SquareLoaderImageView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class androidx.viewpager2.widget.ViewPager2 { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.adonai.manman.views.PassiveSlidingPane { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.appbar.AppBarLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.appbar.MaterialToolbar { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.button.MaterialButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.button.MaterialButtonToggleGroup { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.chip.Chip { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.chip.ChipGroup { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.datepicker.MaterialCalendarGridView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.BaselineLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.CheckableImageButton { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.NavigationMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.internal.NavigationMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.snackbar.Snackbar$SnackbarLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.snackbar.SnackbarContentLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.tabs.TabLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.textfield.TextInputEditText { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.textfield.TextInputLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.textview.MaterialTextView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.ChipTextInputComboView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.ClockFaceView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.ClockHandView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class com.google.android.material.timepicker.TimePickerView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.design.internal.NavigationMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.design.internal.NavigationMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.design.widget.NavigationView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.design.widget.Snackbar$SnackbarLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v4.widget.DrawerLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v4.widget.Space { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v4.widget.SwipeRefreshLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.view.menu.ActionMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.view.menu.ExpandedMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.view.menu.ListMenuItemView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.ActionBarContainer { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.ActionBarContextView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.ActionBarOverlayLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.ActivityChooserView$InnerLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.ContentFrameLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.DialogTitle { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.FitWindowsFrameLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.FitWindowsLinearLayout { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.TintImageView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.internal.widget.ViewStubCompat { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.ActionMenuView { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.SearchView$SearchAutoComplete { <init>(android.content.Context, android.util.AttributeSet); }

-keep class android.support.v7.widget.Toolbar { <init>(android.content.Context, android.util.AttributeSet); }

-keepclassmembers class * { *** onOpenFacebookClick(android.view.View); }

-keepclassmembers class * { *** onOpenFeedbackClick(android.view.View); }

-keepclassmembers class * { *** onOpenGithubClick(android.view.View); }

-keepclassmembers class * { *** onOpenGoogleplusClick(android.view.View); }

-keepclassmembers class * { *** onOpenTwitterClick(android.view.View); }


# recyclerview-v7-28.0.0\proguard.txt ###############################################################
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# When layoutManager xml attribute is used, RecyclerView inflates
#LayoutManagers' constructors using reflection.
-keep public class * extends android.support.v7.widget.RecyclerView$LayoutManager {
    public <init>(android.content.Context, android.util.AttributeSet, int, int);
    public <init>();
}

# jetified-AndroidFastScroll-v1.1.5\proguard.txt #####################################################
# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
-keepclassmembers class fqcn.of.javascript.interface.for.webview {
   public *;
}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# recyclerview-1.2.1\proguard.txt ###################################################################
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# When layoutManager xml attribute is used, RecyclerView inflates
#LayoutManagers' constructors using reflection.
-keep public class * extends androidx.recyclerview.widget.RecyclerView$LayoutManager {
    public <init>(android.content.Context, android.util.AttributeSet, int, int);
    public <init>();
}

-keepclassmembers class androidx.recyclerview.widget.RecyclerView {
    public void suppressLayout(boolean);
    public boolean isLayoutSuppressed();
}

# jetified-floatingactionbutton-1.10.1\proguard.txt #################################################
# keep getters/setters in RotatingDrawable so that animations can still work.
-keepclassmembers class com.getbase.floatingactionbutton.FloatingActionsMenu$RotatingDrawable {
   void set*(***);
   *** get*();
}
# fragment-1.3.6\proguard.txt ########################################################################
# Copyright (C) 2020 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The default FragmentFactory creates Fragment instances using reflection
-if public class ** extends androidx.fragment.app.Fragment
-keepclasseswithmembers,allowobfuscation public class <1> {
    public <init>();
}

# jetified-exoplayer-ui-2.15.1\proguard.txt #########################################################
# Proguard rules specific to the UI module.

# Constructor method accessed via reflection in StyledPlayerView and PlayerView
-dontnote com.google.android.exoplayer2.video.spherical.SphericalGLSurfaceView
-keepclassmembers class com.google.android.exoplayer2.video.spherical.SphericalGLSurfaceView {
  <init>(android.content.Context);
}
-dontnote com.google.android.exoplayer2.video.VideoDecoderGLSurfaceView
-keepclassmembers class com.google.android.exoplayer2.video.VideoDecoderGLSurfaceView {
  <init>(android.content.Context);
}

# Constructor method accessed via reflection in TrackSelectionDialogBuilder
-dontnote androidx.appcompat.app.AlertDialog.Builder
-keepclassmembers class androidx.appcompat.app.AlertDialog$Builder {
  <init>(android.content.Context, int);
  public android.content.Context getContext();
  public androidx.appcompat.app.AlertDialog$Builder setTitle(java.lang.CharSequence);
  public androidx.appcompat.app.AlertDialog$Builder setView(android.view.View);
  public androidx.appcompat.app.AlertDialog$Builder setPositiveButton(int, android.content.DialogInterface$OnClickListener);
  public androidx.appcompat.app.AlertDialog$Builder setNegativeButton(int, android.content.DialogInterface$OnClickListener);
  public androidx.appcompat.app.AlertDialog create();
}
# Equivalent methods needed when the library is de-jetified.
-dontnote androidx.appcompat.app.AlertDialog.Builder
-keepclassmembers class androidx.appcompat.app.AlertDialog$Builder {
  <init>(android.content.Context, int);
  public android.content.Context getContext();
  public androidx.appcompat.app.AlertDialog$Builder setTitle(java.lang.CharSequence);
  public androidx.appcompat.app.AlertDialog$Builder setView(android.view.View);
  public androidx.appcompat.app.AlertDialog$Builder setPositiveButton(int, android.content.DialogInterface$OnClickListener);
  public androidx.appcompat.app.AlertDialog$Builder setNegativeButton(int, android.content.DialogInterface$OnClickListener);
  public androidx.appcompat.app.AlertDialog create();
}

# Don't warn about checkerframework and Kotlin annotations
-dontwarn org.checkerframework.**
-dontwarn kotlin.annotations.jvm.**
-dontwarn javax.annotation.**


# databinding-runtime-7.0.2\proguard.txt #############################################################
-dontwarn androidx.databinding.ViewDataBinding
-dontwarn androidx.databinding.ViewDataBinding$LiveDataListener

# instant apps load these via reflection so we need to keep them.
-keep public class * extends androidx.databinding.DataBinderMapper

# material-1.4.0\proguard.txt ########################################################################
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# CoordinatorLayout resolves the behaviors of its child components with reflection.
-keep public class * extends androidx.coordinatorlayout.widget.CoordinatorLayout$Behavior {
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>();
}

# Make sure we keep annotations for CoordinatorLayout's DefaultBehavior
-keepattributes RuntimeVisible*Annotation*

# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# AppCompatViewInflater reads the viewInflaterClass theme attribute which then
# reflectively instantiates MaterialComponentsViewInflater using the no-argument
# constructor. We only need to keep this constructor and the class name if
# AppCompatViewInflater is also being kept.
-if class androidx.appcompat.app.AppCompatViewInflater
-keep class com.google.android.material.theme.MaterialComponentsViewInflater {
    <init>();
}

# jetified-lifecycle-process-2.4.1\proguard.txt #####################################################
# this rule is need to work properly when app is compiled with api 28, see b/142778206
-keepclassmembers class * extends androidx.lifecycle.EmptyActivityLifecycleCallbacks { *; }

# transition-1.2.0\proguard.txt #####################################################################
# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Keep a field in transition that is used to keep a reference to weakly-referenced object
-keepclassmembers class androidx.transition.ChangeBounds$* extends android.animation.AnimatorListenerAdapter {
  androidx.transition.ChangeBounds$ViewBounds mViewBounds;
}

# jetified-savedstate-1.1.0\proguard.txt ###########################################################
# Copyright (C) 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

-keepclassmembers,allowobfuscation class * implements androidx.savedstate.SavedStateRegistry$AutoRecreated {
    <init>();
}


# jetified-lifecycle-viewmodel-savedstate-2.3.1\proguard.txt #########################################
-keepclassmembers,allowobfuscation class * extends androidx.lifecycle.ViewModel {
    <init>(androidx.lifecycle.SavedStateHandle);
}

-keepclassmembers,allowobfuscation class * extends androidx.lifecycle.AndroidViewModel {
    <init>(android.app.Application,androidx.lifecycle.SavedStateHandle);
}

# jetified-acra-core-5.7.0\proguard.txt #############################################################
#ACRA specifics
# Restore some Source file names and restore approximate line numbers in the stack traces,
# otherwise the stack traces are pretty useless
-keepattributes SourceFile,LineNumberTable

# ACRA needs "annotations" so add this...
# Note: This may already be defined in the default "proguard-android-optimize.txt"
# file in the SDK. If it is, then you don't need to duplicate it. See your
# "project.properties" file to get the path to the default "proguard-android-optimize.txt".
-keepattributes *Annotation*

# ACRA loads Plugins using reflection, so we need to keep all Plugin classes
-keep class * implements org.acra.plugins.Plugin {*;}

# ACRA uses enum fields in annotations, so we have to keep those
-keep enum org.acra.** {*;}

-dontwarn android.support.**

# okhttp3.pro #####################################################################################
# JSR 305 annotations are for embedding nullability information.
-dontwarn javax.annotation.**

# A resource is loaded with a relative path so the package of this class must be preserved.
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# Animal Sniffer compileOnly dependency to ensure APIs are compatible with older versions of Java.
-dontwarn org.codehaus.mojo.animal_sniffer.*

# OkHttp platform used only on JVM and when Conscrypt dependency is available.
-dontwarn okhttp3.internal.platform.ConscryptPlatform

# jetified-drawer-1.0.3\proguard.txt ################################################################
-keepclassmembernames class androidx.drawerlayout.widget.DrawerLayout {
    private java.util.List mListeners;
    void moveDrawerToOffset(android.view.View, float);
}

# r8-from-1.6.0\coroutines.pro #####################################################################
# Allow R8 to optimize away the FastServiceLoader.
# Together with ServiceLoader optimization in R8
# this results in direct instantiation when loading Dispatchers.Main
-assumenosideeffects class kotlinx.coroutines.internal.MainDispatcherLoader {
    boolean FAST_SERVICE_LOADER_ENABLED return false;
}

-assumenosideeffects class kotlinx.coroutines.internal.FastServiceLoaderKt {
    boolean ANDROID_DETECTED return true;
}

-keep class kotlinx.coroutines.android.AndroidDispatcherFactory {*;}

# Disable support for "Missing Main Dispatcher", since we always have Android main dispatcher
-assumenosideeffects class kotlinx.coroutines.internal.MainDispatchersKt {
    boolean SUPPORT_MISSING return false;
}

# Statically turn off all debugging facilities and assertions
-assumenosideeffects class kotlinx.coroutines.DebugKt {
    boolean getASSERTIONS_ENABLED() return false;
    boolean getDEBUG() return false;
    boolean getRECOVER_STACK_TRACES() return false;
}

# webkit-1.4.0\proguard.txt #########################################################################
# Copyright 2018 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# We need to avoid obfuscating the support library boundary interface because
# this API is shared with the Android Support Library.
# Note that we only 'keep' the package org.chromium.support_lib_boundary itself,
# any sub-packages of that package can still be obfuscated.
-keep public class org.chromium.support_lib_boundary.* { public *; }

# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Prevent WebViewClientCompat from being renamed, since chromium depends on this name.
-keepnames public class androidx.webkit.WebViewClientCompat


# retrofit2.pro ###################################################################################
# Retrofit does reflection on generic parameters. InnerClasses is required to use Signature and
# EnclosingMethod is required to use InnerClasses.
-keepattributes Signature, InnerClasses, EnclosingMethod

# Retain service method parameters when optimizing.
-keepclassmembers,allowshrinking,allowobfuscation interface * {
    @retrofit2.http.* <methods>;
}

# Ignore annotation used for build tooling.
-dontwarn org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement

# Ignore JSR 305 annotations for embedding nullability information.
-dontwarn javax.annotation.**

# Guarded by a NoClassDefFoundError try/catch and only used when on the classpath.
-dontwarn kotlin.Unit

# Top-level functions that can only be used by Kotlin.
-dontwarn retrofit2.-KotlinExtensions

# appcompat-1.2.0\proguard.txt #####################################################################
# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# aapt is not able to read app::actionViewClass and app:actionProviderClass to produce proguard
# keep rules. Add a commonly used SearchView to the keep list until b/109831488 is resolved.
-keep class androidx.appcompat.widget.SearchView { <init>(...); }

# Never inline methods, but allow shrinking and obfuscation.
-keepclassmembernames,allowobfuscation,allowshrinking class androidx.appcompat.widget.AppCompatTextViewAutoSizeHelper$Impl* {
  <methods>;
}

# appcompat-v7-28.0.0\proguard.txt
# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Ensure that reflectively-loaded inflater is not obfuscated. This can be
# removed when we stop supporting AAPT1 builds.
-keepnames class android.support.v7.app.AppCompatViewInflater

# aapt is not able to read app::actionViewClass and app:actionProviderClass to produce proguard
# keep rules. Add a commonly used SearchView to the keep list until b/109831488 is resolved.
-keep class android.support.v7.widget.SearchView { <init>(...); }

# support-media-compat-28.0.0\proguard.txt ##########################################################
# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Prevent Parcelable objects from being removed or renamed.
-keep class android.support.v4.media.** implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# Prevent Parcelable objects from being removed or renamed.
-keep class android.support.mediacompat.** implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}
-keep class android.support.v4.media.Audio* implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}
-keep class android.support.v4.media.MediaBrowserCompatUtils* implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}
-keep class android.support.v4.media.MediaBrowserProtocol* implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}
-keep class android.support.v4.media.MediaBrowserService* implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}
-keep class android.support.v4.media.Volume* implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}
-keep class android.support.v4.media.app.** implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}
-keep class android.support.v4.media.session.MediaButton* implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}


# animated-vector-drawable-28.0.0\proguard.txt
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# keep setters in VectorDrawables so that animations can still work.
-keepclassmembers class android.support.graphics.drawable.VectorDrawableCompat$* {
   void set*(***);
   *** get*();
}

# com.android.tools\r8-from-1.6.0\coroutines.pro #####################################################
# Allow R8 to optimize away the FastServiceLoader.
# Together with ServiceLoader optimization in R8
# this results in direct instantiation when loading Dispatchers.Main
-assumenosideeffects class kotlinx.coroutines.internal.MainDispatcherLoader {
    boolean FAST_SERVICE_LOADER_ENABLED return false;
}

-assumenosideeffects class kotlinx.coroutines.internal.FastServiceLoaderKt {
    boolean ANDROID_DETECTED return true;
}

-keep class kotlinx.coroutines.android.AndroidDispatcherFactory {*;}

# Disable support for "Missing Main Dispatcher", since we always have Android main dispatcher
-assumenosideeffects class kotlinx.coroutines.internal.MainDispatchersKt {
    boolean SUPPORT_MISSING return false;
}

# Statically turn off all debugging facilities and assertions
-assumenosideeffects class kotlinx.coroutines.DebugKt {
    boolean getASSERTIONS_ENABLED() return false;
    boolean getDEBUG() return false;
    boolean getRECOVER_STACK_TRACES() return false;
}


# vectordrawable-animated-1.1.0\proguard.txt #########################################################
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# keep setters in VectorDrawables so that animations can still work.
-keepclassmembers class androidx.vectordrawable.graphics.drawable.VectorDrawableCompat$* {
   void set*(***);
   *** get*();
}

# coordinatorlayout-1.0.0\proguard.txt ###############################################################
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# CoordinatorLayout resolves the behaviors of its child components with reflection.
-keep public class * extends androidx.coordinatorlayout.widget.CoordinatorLayout$Behavior {
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>();
}

# Make sure we keep annotations for CoordinatorLayout's DefaultBehavior and ViewPager's DecorView
-keepattributes *Annotation*


# support-compat-28.0.0\proguard.txt
# aapt2 is not (yet) keeping FQCNs defined in the appComponentFactory <application> attribute
-keep class android.support.v4.app.CoreComponentFactory


# media-1.2.0\proguard.txt ##########################################################################
# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Prevent Parcelable objects from being removed or renamed.
-keep class android.support.v4.media.** implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# Prevent Parcelable objects from being removed or renamed.
-keep class androidx.media.** implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# proguard\coroutines.pro ###########################################################################
# ServiceLoader support
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# Most of volatile fields are updated with AFU and should not be mangled
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# Same story for the standard library's SafeContinuation that also uses AtomicReferenceFieldUpdater
-keepclassmembers class kotlin.coroutines.SafeContinuation {
    volatile <fields>;
}

# These classes are only required by kotlinx.coroutines.debug.AgentPremain, which is only loaded when
# kotlinx-coroutines-core is used as a Java agent, so these are not needed in contexts where ProGuard is used.
-dontwarn java.lang.instrument.ClassFileTransformer
-dontwarn sun.misc.SignalHandler
-dontwarn java.lang.instrument.Instrumentation
-dontwarn sun.misc.Signal

# runtime-1.1.1\proguard.txt
-keepattributes *Annotation*

-keepclassmembers enum android.arch.lifecycle.Lifecycle$Event {
    <fields>;
}

-keep class * implements android.arch.lifecycle.LifecycleObserver {
}

-keep class * implements android.arch.lifecycle.GeneratedAdapter {
    <init>(...);
}

-keepclassmembers class ** {
    @android.arch.lifecycle.OnLifecycleEvent *;
}

# work-runtime-2.7.1\proguard.txt #####################################################################
-keep class * extends androidx.work.Worker
-keep class * extends androidx.work.InputMerger
# Keep all constructors on ListenableWorker, Worker (also marked with @Keep)
-keep public class * extends androidx.work.ListenableWorker {
    public <init>(...);
}
# We need to keep WorkerParameters for the ListenableWorker constructor
-keep class androidx.work.WorkerParameters


# core-1.7.0\proguard.txt ###########################################################################
# Never inline methods, but allow shrinking and obfuscation.
-keepclassmembernames,allowobfuscation,allowshrinking class androidx.core.view.ViewCompat$Api* {
  <methods>;
}
-keepclassmembernames,allowobfuscation,allowshrinking class androidx.core.view.WindowInsetsCompat$*Impl* {
  <methods>;
}
-keepclassmembernames,allowobfuscation,allowshrinking class androidx.core.app.NotificationCompat$*$Api*Impl {
  <methods>;
}
-keepclassmembernames,allowobfuscation,allowshrinking class androidx.core.os.UserHandleCompat$Api*Impl {
  <methods>;
}
-keepclassmembernames,allowobfuscation,allowshrinking class androidx.core.widget.EdgeEffectCompat$Api*Impl {
  <methods>;
}

# jetified-flexbox-2.0.1\proguard.txt ##############################################################
#
# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# The FlexboxLayoutManager may be set from a layout xml, in that situation the RecyclerView
# tries to instantiate the layout manager using reflection.
# This is to prevent the layout manager from being obfuscated.
-keepnames public class com.google.android.flexbox.FlexboxLayoutManager
# End of content from D:\java_tools\gradle_respository\caches\transforms-3\8d68b62dc0c52d85b52bdd80a533c5f3\transformed\jetified-flexbox-2.0.1\proguard.txt


# lifecycle-viewmodel-2.1.0\proguard.txt #############################################################
-keepclassmembers,allowobfuscation class * extends androidx.lifecycle.ViewModel {
    <init>();
}

-keepclassmembers,allowobfuscation class * extends androidx.lifecycle.AndroidViewModel {
    <init>(android.app.Application);
}

# jetified-android.joda-2.10.14-release\proguard.txt ################################################
# All the resources are retrieved via reflection, so we need to make sure we keep them
-keep class net.danlew.android.joda.R$raw { *; }

# These aren't necessary if including joda-convert, but
# most people aren't, so it's helpful to include it.
-dontwarn org.joda.convert.FromString
-dontwarn org.joda.convert.ToString

# Joda classes use the writeObject special method for Serializable, so
# if it's stripped, we'll run into NotSerializableExceptions.
# https://www.guardsquare.com/en/products/proguard/manual/examples#serializable
-keepnames class org.joda.** implements java.io.Serializable
-keepclassmembers class org.joda.** implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    !static !transient <fields>;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# lifecycle-runtime-2.3.1\proguard.txt ################################################################
-keepattributes *Annotation*

-keepclassmembers enum androidx.lifecycle.Lifecycle$Event {
    <fields>;
}

-keep !interface * implements androidx.lifecycle.LifecycleObserver {
}

-keep class * implements androidx.lifecycle.GeneratedAdapter {
    <init>(...);
}

-keepclassmembers class ** {
    @androidx.lifecycle.OnLifecycleEvent *;
}

# this rule is need to work properly when app is compiled with api 28, see b/142778206
# Also this rule prevents registerIn from being inlined.
-keepclassmembers class androidx.lifecycle.ReportFragment$LifecycleCallbacks { *; }

# okio.pro #########################################################################################
# Animal Sniffer compileOnly dependency to ensure APIs are compatible with older versions of Java.
-dontwarn org.codehaus.mojo.animal_sniffer.*


# jetified-glide-4.13.2\proguard.txt #################################################################
-keep public class * implements com.bumptech.glide.module.GlideModule
-keep class * extends com.bumptech.glide.module.AppGlideModule {
 <init>(...);
}
-keep public enum com.bumptech.glide.load.ImageHeaderParser$** {
  **[] $VALUES;
  public *;
}
-keep class com.bumptech.glide.load.data.ParcelFileDescriptorRewinder$InternalRewinder {
  *** rewind();
}

# Uncomment for DexGuard only
#-keepresourcexmlelements manifest/application/meta-data@value=GlideModule

# End of content from D:\java_tools\gradle_respository\caches\transforms-3\df3c7e29f69c1ff9720cda26ac8cf84e\transformed\jetified-glide-4.13.2\proguard.txt

# moshi.pro #######################################################################################
# JSR 305 annotations are for embedding nullability information.
-dontwarn javax.annotation.**

-keepclasseswithmembers class * {
    @com.squareup.moshi.* <methods>;
}

-keep @com.squareup.moshi.JsonQualifier interface *

# Enum field names are used by the integrated EnumJsonAdapter.
# values() is synthesized by the Kotlin compiler and is used by EnumJsonAdapter indirectly
# Annotate enums with @JsonClass(generateAdapter = false) to use them with Moshi.
-keepclassmembers @com.squareup.moshi.JsonClass class * extends java.lang.Enum {
    <fields>;
    **[] values();
}

# Keep helper method to avoid R8 optimisation that would keep all Kotlin Metadata when unwanted
-keepclassmembers class com.squareup.moshi.internal.Util {
    private static java.lang.String getKotlinMetadataClassName();
}

# jetified-savedstate-1.0.0\proguard.txt #############################################################
# Copyright (C) 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

-keepclassmembers,allowobfuscation class * implements androidx.savedstate.SavedStateRegistry$AutoRecreated {
    <init>();
}

# versionedparcelable-1.1.1\proguard.txt #############################################################
-keep class * implements androidx.versionedparcelable.VersionedParcelable
-keep public class android.support.**Parcelizer { *; }
-keep public class androidx.**Parcelizer { *; }
-keep public class androidx.versionedparcelable.ParcelImpl


# jetified-startup-runtime-1.0.0\proguard.txt #########################################################
# This Proguard rule ensures that ComponentInitializers are are neither shrunk nor obfuscated.
# This is because they are discovered and instantiated during application initialization.
-keep class * extends androidx.startup.Initializer {
    # Keep the public no-argument constructor while allowing other methods to be optimized.
    <init>();
}

-assumenosideeffects class androidx.startup.StartupLogger


# jetified-library-1.4.2\proguard.txt ################################################################
# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in /opt/android-sdk/tools/proguard/proguard-android.txt
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Add any project specific keep options here:

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

-keep class me.zhanghai.android.materialprogressbar.** { *; }

# preference-v7-28.0.0\proguard.txt #################################################################
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Preference objects are inflated via reflection
-keep public class android.support.v7.preference.Preference {
    public <init>(android.content.Context, android.util.AttributeSet);
}
-keep public class * extends android.support.v7.preference.Preference {
    public <init>(android.content.Context, android.util.AttributeSet);
}

# jetified-window-1.0.0\proguard.txt #################################################################
# Copyright (C) 2020 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# A rule that will keep classes that implement SidecarInterface$SidecarCallback if Sidecar seems
# be used. See b/157286362 and b/165268619 for details.
# TODO(b/208543178) investigate how to pass header jar to R8 so we don't need this rule
-if class androidx.window.layout.SidecarCompat {
  public setExtensionCallback(androidx.window.layout.ExtensionInterfaceCompat$ExtensionCallbackInterface);
}
-keep class androidx.window.layout.SidecarCompat$TranslatingCallback,
 androidx.window.layout.SidecarCompat$DistinctSidecarElementCallback {
  public onDeviceStateChanged(androidx.window.sidecar.SidecarDeviceState);
  public onWindowLayoutChanged(android.os.IBinder, androidx.window.sidecar.SidecarWindowLayoutInfo);
}




# jetified-SimpleDialogFragments-1028602dd618032aacfb8d486a3c506dd7cb2ed5\proguard.txt ###############
# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in C:\Android\sdk/tools/proguard/proguard-android.txt
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Add any project specific keep options here:

# Keep TAG field, so it can be found by the SimpleDialog.show() method
-keepclassmembers class * extends eltos.simpledialogfragment.SimpleDialog {
    public static final java.lang.String TAG;
}

# room-runtime-2.2.5\proguard.txt #####################################################################
-keep class * extends androidx.room.RoomDatabase
-dontwarn androidx.room.paging.**

# End of content from D:\java_tools\gradle_respository\caches\transforms-3\6a6843984c4943d355d072ab9db16e1b\transformed\room-runtime-2.2.5\proguard.txt

# jetified-eventbus-3.3.1\proguard.txt ###############################################################
-keepattributes *Annotation*
-keepclassmembers class * {
    @org.greenrobot.eventbus.Subscribe <methods>;
}
-keep enum org.greenrobot.eventbus.ThreadMode { *; }

# If using AsyncExecutord, keep required constructor of default event used.
# Adjust the class name if a custom failure event type is used.
-keepclassmembers class org.greenrobot.eventbus.util.ThrowableFailureEvent {
    <init>(java.lang.Throwable);
}

# Accessed via reflection, avoid renaming or removal
-keep class org.greenrobot.eventbus.android.AndroidComponentsImpl



# androidx-annotations.pro #########################################################################
-keep,allowobfuscation @interface androidx.annotation.Keep
-keep @androidx.annotation.Keep class * {*;}

-keepclasseswithmembers class * {
    @androidx.annotation.Keep <methods>;
}

-keepclasseswithmembers class * {
    @androidx.annotation.Keep <fields>;
}

-keepclasseswithmembers class * {
    @androidx.annotation.Keep <init>(...);
}

-keepclassmembers,allowobfuscation class * {
  @androidx.annotation.DoNotInline <methods>;
}

# jetified-conscrypt-android-2.5.2\proguard.txt #####################################################
# Add project specific ProGuard rules here.
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Many of the Conscrypt classes are referenced indirectly via JNI or
# reflection.
# This could probably be tightened up, but this will get it building for now.
# TODO(kroot): Need anything special to prevent obfuscation?
-keep class org.conscrypt.** { *; }

# Backward compatibility code.
-dontnote libcore.io.Libcore
-dontnote org.apache.harmony.xnet.provider.jsse.OpenSSLRSAPrivateKey
-dontnote org.apache.harmony.security.utils.AlgNameMapper
-dontnote sun.security.x509.AlgorithmId

-dontwarn dalvik.system.BlockGuard
-dontwarn dalvik.system.BlockGuard$Policy
-dontwarn dalvik.system.CloseGuard
-dontwarn com.android.org.conscrypt.AbstractConscryptSocket
-dontwarn com.android.org.conscrypt.ConscryptFileDescriptorSocket
-dontwarn com.android.org.conscrypt.OpenSSLSocketImpl
-dontwarn org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl


# okhttp3.pro #####################################################################################
# JSR 305 annotations are for embedding nullability information.
-dontwarn javax.annotation.**

# A resource is loaded with a relative path so the package of this class must be preserved.
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# Animal Sniffer compileOnly dependency to ensure APIs are compatible with older versions of Java.
-dontwarn org.codehaus.mojo.animal_sniffer.*

# OkHttp platform used only on JVM and when Conscrypt dependency is available.
-dontwarn okhttp3.internal.platform.ConscryptPlatform



# jetified-annotation-experimental-1.1.0\proguard.txt  ################################################
# Copyright (C) 2020 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Ignore missing Kotlin meta-annotations so that this library can be used
# without adding a compileOnly dependency on the Kotlin standard library.
-dontwarn kotlin.Deprecated
-dontwarn kotlin.Metadata
-dontwarn kotlin.ReplaceWith
-dontwarn kotlin.annotation.AnnotationRetention
-dontwarn kotlin.annotation.AnnotationTarget
-dontwarn kotlin.annotation.Retention
-dontwarn kotlin.annotation.Target



# vulnerability functions ############################################################################

-keep,allowobfuscation class  org.bouncycastle.jce.spec.IESParameterSpec {
*;}
-keep,allowobfuscation class  org.bouncycastle.jce.spec.IESParameterSpec$* {
*;}
-keep,allowobfuscation class  org.apache.commons.compress.archivers.zip.X0017_StrongEncryptionHeader {
*;}
-keep,allowobfuscation class  org.apache.commons.compress.archivers.zip.X0017_StrongEncryptionHeader$* {
*;}
-keep,allowobfuscation class  com.itextpdf.testutils.CompareTool {
*;}
-keep,allowobfuscation class  com.itextpdf.testutils.CompareTool$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.util.BadBlockException {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.util.BadBlockException$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey$* {
*;}
-keep,allowobfuscation class  org.apache.http.conn.ssl.SSLSocketFactory {
*;}
-keep,allowobfuscation class  org.apache.http.conn.ssl.SSLSocketFactory$* {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.xml.DomUtil {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.xml.DomUtil$* {
*;}
-keep,allowobfuscation class  okhttp3.internal.tls.TrustRootIndex {
*;}
-keep,allowobfuscation class  okhttp3.internal.tls.TrustRootIndex$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPrivateKey {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPrivateKey$* {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.microsoft.xml.AbstractXML2003Parser {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.microsoft.xml.AbstractXML2003Parser$* {
*;}
-keep,allowobfuscation class  com.github.junrar.Archive {
*;}
-keep,allowobfuscation class  com.github.junrar.Archive$* {
*;}
-keep,allowobfuscation class  okhttp3.internal.tls.AndroidTrustRootIndex {
*;}
-keep,allowobfuscation class  okhttp3.internal.tls.AndroidTrustRootIndex$* {
*;}
-keep,allowobfuscation class  org.apache.http.impl.client.HttpClientBuilder {
*;}
-keep,allowobfuscation class  org.apache.http.impl.client.HttpClientBuilder$* {
*;}
-keep,allowobfuscation class  org.apache.commons.compress.archivers.examples.Expander {
*;}
-keep,allowobfuscation class  org.apache.commons.compress.archivers.examples.Expander$* {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.pkg.StreamingZipContainerDetector {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.pkg.StreamingZipContainerDetector$* {
*;}
-keep,allowobfuscation class  okhttp3.internal.tls.CertificateChainCleaner {
*;}
-keep,allowobfuscation class  okhttp3.internal.tls.CertificateChainCleaner$* {
*;}
-keep,allowobfuscation class  com.itextpdf.text.xml.xmp.XmpReader {
*;}
-keep,allowobfuscation class  com.itextpdf.text.xml.xmp.XmpReader$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters$* {
*;}
-keep,allowobfuscation class  com.tom_roush.pdfbox.pdmodel.interactive.form.PDXFAResource {
*;}
-keep,allowobfuscation class  com.tom_roush.pdfbox.pdmodel.interactive.form.PDXFAResource$* {
*;}
-keep,allowobfuscation class  org.conscrypt.ConscryptEngine {
*;}
-keep,allowobfuscation class  org.conscrypt.ConscryptEngine$* {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.spi2davex.PostMethod {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.spi2davex.PostMethod$* {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.DavResource {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.DavResource$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat160 {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat160$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.ExplicitTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.ExplicitTypePermission$* {
*;}
-keep,allowobfuscation class  io.netty.handler.ssl.OpenSslEngine {
*;}
-keep,allowobfuscation class  io.netty.handler.ssl.OpenSslEngine$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.XStream {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.XStream$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.NoPermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.NoPermission$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.params.DHPublicKeyParameters {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.params.DHPublicKeyParameters$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.ForbiddenClassException {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.ForbiddenClassException$* {
*;}
-keep,allowobfuscation class  ch.qos.logback.classic.net.SimpleSocketServer {
*;}
-keep,allowobfuscation class  ch.qos.logback.classic.net.SimpleSocketServer$* {
*;}
-keep,allowobfuscation class  com.itextpdf.text.pdf.XfaForm {
*;}
-keep,allowobfuscation class  com.itextpdf.text.pdf.XfaForm$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat256 {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat256$* {
*;}
-keep,allowobfuscation class  com.fasterxml.jackson.databind.deser.BeanDeserializerFactory {
*;}
-keep,allowobfuscation class  com.fasterxml.jackson.databind.deser.BeanDeserializerFactory$* {
*;}
-keep,allowobfuscation class  org.apache.commons.compress.archivers.zip.ZipArchiveInputStream {
*;}
-keep,allowobfuscation class  org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.WildcardTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.WildcardTypePermission$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi$* {
*;}
-keep,allowobfuscation class  org.jivesoftware.smack.AbstractXMPPConnection {
*;}
-keep,allowobfuscation class  org.jivesoftware.smack.AbstractXMPPConnection$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyPairGeneratorSpi {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyPairGeneratorSpi$* {
*;}
-keep,allowobfuscation class  org.apache.http.client.utils.URIBuilder {
*;}
-keep,allowobfuscation class  org.apache.http.client.utils.URIBuilder$* {
*;}
-keep,allowobfuscation class  retrofit2.converter.jaxb.JaxbResponseConverter {
*;}
-keep,allowobfuscation class  retrofit2.converter.jaxb.JaxbResponseConverter$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat192 {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat192$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat224 {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat224$* {
*;}
-keep,allowobfuscation class  ch.qos.logback.classic.net.server.LogbackClassicSerializationHelper {
*;}
-keep,allowobfuscation class  ch.qos.logback.classic.net.server.LogbackClassicSerializationHelper$* {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.Platform {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.Platform$* {
*;}
-keep,allowobfuscation class  okhttp3.internal.tls.RealTrustRootIndex {
*;}
-keep,allowobfuscation class  okhttp3.internal.tls.RealTrustRootIndex$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters$* {
*;}
-keep,allowobfuscation class  org.codehaus.groovy.runtime.MethodClosure {
*;}
-keep,allowobfuscation class  org.codehaus.groovy.runtime.MethodClosure$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.generators.RSAKeyPairGenerator {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.generators.RSAKeyPairGenerator$* {
*;}
-keep,allowobfuscation class  com.google.common.collect.CompoundOrdering_CustomFieldSerializer {
*;}
-keep,allowobfuscation class  com.google.common.collect.CompoundOrdering_CustomFieldSerializer$* {
*;}
-keep,allowobfuscation class  com.tom_roush.pdfbox.pdmodel.fdf.XMLUtil {
*;}
-keep,allowobfuscation class  com.tom_roush.pdfbox.pdmodel.fdf.XMLUtil$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.RegExpTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.RegExpTypePermission$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.TypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.TypePermission$* {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.util.CSRFUtil {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.util.CSRFUtil$* {
*;}
-keep,allowobfuscation class  com.fasterxml.jackson.databind.jsontype.impl.SubTypeValidator {
*;}
-keep,allowobfuscation class  com.fasterxml.jackson.databind.jsontype.impl.SubTypeValidator$* {
*;}
-keep,allowobfuscation class  okhttp3.internal.Platform {
*;}
-keep,allowobfuscation class  okhttp3.internal.Platform$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.rainbow.RainbowParameters {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.rainbow.RainbowParameters$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.mapper.SecurityMapper {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.mapper.SecurityMapper$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.PrimitiveTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.PrimitiveTypePermission$* {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.server.AbstractWebdavServlet {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.server.AbstractWebdavServlet$* {
*;}
-keep,allowobfuscation class  io.netty.handler.codec.http.websocketx.WebSocket08FrameDecoder {
*;}
-keep,allowobfuscation class  io.netty.handler.codec.http.websocketx.WebSocket08FrameDecoder$* {
*;}
-keep,allowobfuscation class  okhttp3.CertificatePinner {
*;}
-keep,allowobfuscation class  okhttp3.CertificatePinner$* {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.mat.MatParser {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.mat.MatParser$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.asn1.ASN1Enumerated {
*;}
-keep,allowobfuscation class  org.bouncycastle.asn1.ASN1Enumerated$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.engines.IESEngine {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.engines.IESEngine$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.xmss.XMSSUtil {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.xmss.XMSSUtil$* {
*;}
-keep,allowobfuscation class  org.apache.http.client.protocol.RequestProxyAuthentication {
*;}
-keep,allowobfuscation class  org.apache.http.client.protocol.RequestProxyAuthentication$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.hibernate.security.HibernateProxyTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.hibernate.security.HibernateProxyTypePermission$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.DH {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.DH$* {
*;}
-keep,allowobfuscation class  com.google.common.util.concurrent.AtomicDoubleArray {
*;}
-keep,allowobfuscation class  com.google.common.util.concurrent.AtomicDoubleArray$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.dsa.DSASigner {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.dsa.DSASigner$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.AnyTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.AnyTypePermission$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.math.linearalgebra.GF2nField {
*;}
-keep,allowobfuscation class  org.bouncycastle.pqc.math.linearalgebra.GF2nField$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.ies.AlgorithmParametersSpi {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.ies.AlgorithmParametersSpi$* {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.tls.TrustRootIndex {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.tls.TrustRootIndex$* {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.CertificatePinner {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.CertificatePinner$* {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.iptc.IptcAnpaParser {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.iptc.IptcAnpaParser$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.CGLIBProxyTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.CGLIBProxyTypePermission$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.asn1.ASN1Integer {
*;}
-keep,allowobfuscation class  org.bouncycastle.asn1.ASN1Integer$* {
*;}
-keep,allowobfuscation class  okhttp3.OkHttpClient {
*;}
-keep,allowobfuscation class  okhttp3.OkHttpClient$* {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.xml.DavDocumentBuilderFactory {
*;}
-keep,allowobfuscation class  org.apache.jackrabbit.webdav.xml.DavDocumentBuilderFactory$* {
*;}
-keep,allowobfuscation class  org.apache.tika.utils.XMLReaderUtils {
*;}
-keep,allowobfuscation class  org.apache.tika.utils.XMLReaderUtils$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.converters.reflection.SunLimitedUnsafeReflectionProvider {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.converters.reflection.SunLimitedUnsafeReflectionProvider$* {
*;}
-keep,allowobfuscation class  org.apache.http.conn.ssl.AbstractVerifier {
*;}
-keep,allowobfuscation class  org.apache.http.conn.ssl.AbstractVerifier$* {
*;}
-keep,allowobfuscation class  org.jsoup.parser.TokeniserState {
*;}
-keep,allowobfuscation class  org.jsoup.parser.TokeniserState$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.mapper.CachingMapper {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.mapper.CachingMapper$* {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.microsoft.ooxml.xwpf.ml2006.Word2006MLParser {
*;}
-keep,allowobfuscation class  org.apache.tika.parser.microsoft.ooxml.xwpf.ml2006.Word2006MLParser$* {
*;}
-keep,allowobfuscation class  retrofit2.RequestBuilder {
*;}
-keep,allowobfuscation class  retrofit2.RequestBuilder$* {
*;}
-keep,allowobfuscation class  com.itextpdf.text.zugferd.InvoiceDOM {
*;}
-keep,allowobfuscation class  com.itextpdf.text.zugferd.InvoiceDOM$* {
*;}
-keep,allowobfuscation class  org.apache.http.conn.ssl.SSLConnectionSocketFactory {
*;}
-keep,allowobfuscation class  org.apache.http.conn.ssl.SSLConnectionSocketFactory$* {
*;}
-keep,allowobfuscation class  org.jivesoftware.smack.tcp.XMPPTCPConnection {
*;}
-keep,allowobfuscation class  org.jivesoftware.smack.tcp.XMPPTCPConnection$* {
*;}
-keep,allowobfuscation class  com.google.gson.internal.StringMap {
*;}
-keep,allowobfuscation class  com.google.gson.internal.StringMap$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.agreement.DHAgreement {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.agreement.DHAgreement$* {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.tls.AndroidTrustRootIndex {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.tls.AndroidTrustRootIndex$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.NoTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.NoTypePermission$* {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.tls.RealTrustRootIndex {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.tls.RealTrustRootIndex$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.ProxyTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.ProxyTypePermission$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.signers.DSASigner {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.signers.DSASigner$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.NullPermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.NullPermission$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.dh.IESCipher {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.dh.IESCipher$* {
*;}
-keep,allowobfuscation class  io.netty.handler.codec.http.websocketx.ContinuationWebSocketFrame {
*;}
-keep,allowobfuscation class  io.netty.handler.codec.http.websocketx.ContinuationWebSocketFrame$* {
*;}
-keep,allowobfuscation class  com.caverock.androidsvg.SVGParser {
*;}
-keep,allowobfuscation class  com.caverock.androidsvg.SVGParser$* {
*;}
-keep,allowobfuscation class  ch.qos.logback.core.net.HardenedObjectInputStream {
*;}
-keep,allowobfuscation class  ch.qos.logback.core.net.HardenedObjectInputStream$* {
*;}
-keep,allowobfuscation class  io.netty.handler.codec.http.websocketx.Utf8Validator {
*;}
-keep,allowobfuscation class  io.netty.handler.codec.http.websocketx.Utf8Validator$* {
*;}
-keep,allowobfuscation class  com.tom_roush.pdfbox.pdfparser.COSParser {
*;}
-keep,allowobfuscation class  com.tom_roush.pdfbox.pdfparser.COSParser$* {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.io.RealConnection {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.io.RealConnection$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.EC {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.EC$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat128 {
*;}
-keep,allowobfuscation class  org.bouncycastle.math.raw.Nat128$* {
*;}
-keep,allowobfuscation class  src.com.google.common.util.concurrent.AtomicDoubleArray {
*;}
-keep,allowobfuscation class  src.com.google.common.util.concurrent.AtomicDoubleArray$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher {
*;}
-keep,allowobfuscation class  org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher$* {
*;}
-keep,allowobfuscation class  org.zeroturnaround.zip.ZipUtil {
*;}
-keep,allowobfuscation class  org.zeroturnaround.zip.ZipUtil$* {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.ArrayTypePermission {
*;}
-keep,allowobfuscation class  com.thoughtworks.xstream.security.ArrayTypePermission$* {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.agreement.DHBasicAgreement {
*;}
-keep,allowobfuscation class  org.bouncycastle.crypto.agreement.DHBasicAgreement$* {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.tls.CertificateChainCleaner {
*;}
-keep,allowobfuscation class  com.squareup.okhttp.internal.tls.CertificateChainCleaner$* {
*;}
-keep,allowobfuscation class  com.itextpdf.text.pdf.XfaXmlLocator {
*;}
-keep,allowobfuscation class  com.itextpdf.text.pdf.XfaXmlLocator$* {
*;}
-keep,allowobfuscation class org.jasypt.digest.StandardByteDigester {
*;}
-keep,allowobfuscation class org.jasypt.digest.StandardByteDigester$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.ClientCookieDecoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.ClientCookieDecoder$* {
*;}
-keep,allowobfuscation class org.bouncycastle.jcajce.provider.asymmetric.dsa.DSASigner {
*;}
-keep,allowobfuscation class org.bouncycastle.jcajce.provider.asymmetric.dsa.DSASigner$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.ResourceContentFactory {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.ResourceContentFactory$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.servlet.DefaultServlet {
*;}
-keep,allowobfuscation class org.eclipse.jetty.servlet.DefaultServlet$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.HttpResponse {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.HttpResponse$* {
*;}
-keep,allowobfuscation class test.java.org.apache.commons.beanutils2.bugs.Jira520TestCase {
*;}
-keep,allowobfuscation class test.java.org.apache.commons.beanutils2.bugs.Jira520TestCase$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.package-info {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.package-info$* {
*;}
-keep,allowobfuscation class org.acra.annotation.ReportsCrashes {
*;}
-keep,allowobfuscation class org.acra.annotation.ReportsCrashes$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.DefaultCookie {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.DefaultCookie$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.URIUtil {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.URIUtil$* {
*;}
-keep,allowobfuscation class org.dom4j.DocumentHelper {
*;}
-keep,allowobfuscation class org.dom4j.DocumentHelper$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.ClientCookieEncoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.ClientCookieEncoder$* {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.fdf.FDFDocument {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.fdf.FDFDocument$* {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.net.server.TcpSocketServer {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.net.server.TcpSocketServer$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.CookieEncoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.CookieEncoder$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.resource.ResourceCollators {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.resource.ResourceCollators$* {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.DistinguishedNameParser {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.DistinguishedNameParser$* {
*;}
-keep,allowobfuscation class org.apache.cordova.CordovaWebViewImpl {
*;}
-keep,allowobfuscation class org.apache.cordova.CordovaWebViewImpl$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.CookieUtil {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.CookieUtil$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.resource.Resource {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.resource.Resource$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.HttpObjectDecoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.HttpObjectDecoder$* {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.OkHostnameVerifier {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.OkHostnameVerifier$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.UrlEncoded {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.UrlEncoded$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.Cookie {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.Cookie$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.session.FileSessionDataStore {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.session.FileSessionDataStore$* {
*;}
-keep,allowobfuscation class com.liulishuo.filedownloader.util.FileDownloadUtils {
*;}
-keep,allowobfuscation class com.liulishuo.filedownloader.util.FileDownloadUtils$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.resource.FileResource {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.resource.FileResource$* {
*;}
-keep,allowobfuscation class org.dom4j.Namespace {
*;}
-keep,allowobfuscation class org.dom4j.Namespace$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.handler.ResourceHandler {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.handler.ResourceHandler$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.Request {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.Request$* {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.net.server.AbstractSocketServer {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.net.server.AbstractSocketServer$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.security.Password {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.security.Password$* {
*;}
-keep,allowobfuscation class org.acra.util.HttpRequest {
*;}
-keep,allowobfuscation class org.acra.util.HttpRequest$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.handler.AllowSymLinkAliasChecker {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.handler.AllowSymLinkAliasChecker$* {
*;}
-keep,allowobfuscation class org.acra.ACRAConstants {
*;}
-keep,allowobfuscation class org.acra.ACRAConstants$* {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.interactive.form.PDXFAResource {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.interactive.form.PDXFAResource$* {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.ASN1Integer {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.ASN1Integer$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.HttpChannel {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.HttpChannel$* {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.ASN1Enumerated {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.ASN1Enumerated$* {
*;}
-keep,allowobfuscation class org.apache.openjpa.kernel.AbstractBrokerFactory {
*;}
-keep,allowobfuscation class org.apache.openjpa.kernel.AbstractBrokerFactory$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.security.authentication.DigestAuthenticator {
*;}
-keep,allowobfuscation class org.eclipse.jetty.security.authentication.DigestAuthenticator$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.http.HttpParser {
*;}
-keep,allowobfuscation class org.eclipse.jetty.http.HttpParser$* {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.fdf.XMLUtil {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.fdf.XMLUtil$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.security.jaspi.modules.DigestAuthModule {
*;}
-keep,allowobfuscation class org.eclipse.jetty.security.jaspi.modules.DigestAuthModule$* {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.util.FilteredObjectInputStream {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.util.FilteredObjectInputStream$* {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.StreamUtil {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.StreamUtil$* {
*;}
-keep,allowobfuscation class org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi {
*;}
-keep,allowobfuscation class org.bouncycastle.jcajce.provider.asymmetric.ec.SignatureSpi$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.HttpRequest {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.HttpRequest$* {
*;}
-keep,allowobfuscation class org.apache.commons.compress.compressors.bzip2.BlockSort {
*;}
-keep,allowobfuscation class org.apache.commons.compress.compressors.bzip2.BlockSort$* {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.LimitedInputStream {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.LimitedInputStream$* {
*;}
-keep,allowobfuscation class org.apache.cordova.CordovaBridge {
*;}
-keep,allowobfuscation class org.apache.cordova.CordovaBridge$* {
*;}
-keep,allowobfuscation class org.apache.commons.beanutils2.PropertyUtilsBean {
*;}
-keep,allowobfuscation class org.apache.commons.beanutils2.PropertyUtilsBean$* {
*;}
-keep,allowobfuscation class test.java.org.apache.commons.beanutils2.BeanIntrospectionDataTestCase {
*;}
-keep,allowobfuscation class test.java.org.apache.commons.beanutils2.BeanIntrospectionDataTestCase$* {
*;}
-keep,allowobfuscation class test.java.org.apache.commons.compress.compressors.bzip2.BlockSortTest {
*;}
-keep,allowobfuscation class test.java.org.apache.commons.compress.compressors.bzip2.BlockSortTest$* {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.IndefiniteLengthInputStream {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.IndefiniteLengthInputStream$* {
*;}
-keep,allowobfuscation class com.unboundid.ldap.sdk.SimpleBindRequest {
*;}
-keep,allowobfuscation class com.unboundid.ldap.sdk.SimpleBindRequest$* {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.DefiniteLengthInputStream {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.DefiniteLengthInputStream$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.Cookie {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.Cookie$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.handler.DefaultHandler {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.handler.DefaultHandler$* {
*;}
-keep,allowobfuscation class test.java.com.fasterxml.jackson.dataformat.xml.failing.SupportDTDDefaultsTest {
*;}
-keep,allowobfuscation class test.java.com.fasterxml.jackson.dataformat.xml.failing.SupportDTDDefaultsTest$* {
*;}
-keep,allowobfuscation class test.java.org.apache.commons.beanutils2.bugs.Jira157TestCase {
*;}
-keep,allowobfuscation class test.java.org.apache.commons.beanutils2.bugs.Jira157TestCase$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.embedded.FastFileServer {
*;}
-keep,allowobfuscation class org.eclipse.jetty.embedded.FastFileServer$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.CookieDecoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.CookieDecoder$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.HttpHeaderDateFormat {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.HttpHeaderDateFormat$* {
*;}
-keep,allowobfuscation class test.java.org.dom4j.AllowedCharsTest {
*;}
-keep,allowobfuscation class test.java.org.dom4j.AllowedCharsTest$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.CookieDecoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.CookieDecoder$* {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.ASN1StreamParser {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.ASN1StreamParser$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.handler.ContextHandler {
*;}
-keep,allowobfuscation class org.eclipse.jetty.server.handler.ContextHandler$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.CookieUtil {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.CookieUtil$* {
*;}
-keep,allowobfuscation class org.apache.openjpa.lib.conf.PluginValue {
*;}
-keep,allowobfuscation class org.apache.openjpa.lib.conf.PluginValue$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.CookieHeaderNames {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.CookieHeaderNames$* {
*;}
-keep,allowobfuscation class com.fasterxml.jackson.dataformat.xml.XmlFactory {
*;}
-keep,allowobfuscation class com.fasterxml.jackson.dataformat.xml.XmlFactory$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.ServerCookieEncoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.ServerCookieEncoder$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.DefaultCookie {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.DefaultCookie$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.ServerCookieEncoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.ServerCookieEncoder$* {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.ProxyHandshaker {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.ProxyHandshaker$* {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.SocketConnector {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.SocketConnector$* {
*;}
-keep,allowobfuscation class org.acra.ACRAConfiguration {
*;}
-keep,allowobfuscation class org.acra.ACRAConfiguration$* {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.Address {
*;}
-keep,allowobfuscation class com.neovisionaries.ws.client.Address$* {
*;}
-keep,allowobfuscation class org.dom4j.io.SAXReader {
*;}
-keep,allowobfuscation class org.dom4j.io.SAXReader$* {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.ASN1InputStream {
*;}
-keep,allowobfuscation class org.bouncycastle.asn1.ASN1InputStream$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.ClientCookieEncoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.ClientCookieEncoder$* {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.fdf.FDFAnnotationStamp {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.fdf.FDFAnnotationStamp$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.resource.PathResource {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.resource.PathResource$* {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.net.server.ObjectInputStreamLogEventBridge {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.net.server.ObjectInputStreamLogEventBridge$* {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.net.server.UdpSocketServer {
*;}
-keep,allowobfuscation class org.apache.logging.log4j.core.net.server.UdpSocketServer$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.BufferUtil {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.BufferUtil$* {
*;}
-keep,allowobfuscation class org.dom4j.tree.QNameCache {
*;}
-keep,allowobfuscation class org.dom4j.tree.QNameCache$* {
*;}
-keep,allowobfuscation class org.apache.pdfbox.util.XMLUtil {
*;}
-keep,allowobfuscation class org.apache.pdfbox.util.XMLUtil$* {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.ServerCookieDecoder {
*;}
-keep,allowobfuscation class io.netty.handler.codec.http.cookie.ServerCookieDecoder$* {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.fdf.FDFField {
*;}
-keep,allowobfuscation class org.apache.pdfbox.pdmodel.fdf.FDFField$* {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.security.Credential {
*;}
-keep,allowobfuscation class org.eclipse.jetty.util.security.Credential$* {
*;}
-keep,allowobfuscation class org.dom4j.io.SAXHelper {
*;}
-keep,allowobfuscation class org.dom4j.io.SAXHelper$* {
*;}
-keep,allowobfuscation class org.dom4j.QName {
*;}
-keep,allowobfuscation class org.dom4j.QName$* {
*;}
