
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

-libraryjars /data/xiezifan/OptTPL/libs/android.jar

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

# proguard-android-optimize.txt-8.1.0 ###################################################################

-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*
-optimizationpasses 5
-allowaccessmodification

-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

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

