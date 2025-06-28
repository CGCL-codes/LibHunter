# Correction

## Critical Bug Fix

We've discovered a **critical bug in our previously uploaded code**, thanks to a helpful scholar who appreciates our
work. This bug led to a very high false positive rate for detected TPLs.

We accidentally uploaded an internal development version instead of the final code used in our experiments, which made
it impossible to reproduce our paper's results.
After a thorough review, we found the main issue was in the `pre_match` stage. Previous code only matched method fuzz
signatures, **missing the crucial field fuzz signatures** as we outlined in our paper (section 4.1). This oversight
incorrectly matched many TPLs to target APKs.

Given the severity of this problem, **we've re-uploaded the corrected code**. We're very grateful for the scholar's
alert and apologize to anyone who encountered issues with the previous code.

## Script for Code Optimization Research

To help researchers study how code optimization affects TPL detection, we've
added [Scripts/post_obfuscate_apk.py](Scripts/post_obfuscate_apk.py).
This script use R8 to post obfuscate/optimize an APK file, even without the source code. It also exports the obfuscation
mapping file, which can help understand the obfuscated/optimized app. For example, when R8 performs function inlining to
combine multiple functions into one, the inlining information is recorded in the mapping file.

However, we've noticed that R8 performs more aggressive obfuscation and optimization when the app's source code is
available. So, we still recommend obfuscating or optimizing apps from source whenever possible.

# LibHunter

Detect TPL versions for Android apps against optimization, obfuscation and shrinking

## Tool and Dataset

### Dataset Link

You can access the dataset via the following here: [Dataset](https://doi.org/10.6084/m9.figshare.27623457.v1)

### **LibHunter Usage**

```
# Step1: parpare the tpls_jar and apks
# Put the candidate TPLs in LibHunter/tpls_jar
# Put the target APKs in LibHunter/apks
```

```
# Step2:
cd LibHunter
python3 LibHunter.py detect_all -o outputs -af apks -lf tpls_jar -ld tpls_dex
```

```
# Step3: Check the results in outputs folder
```

For the example, the version ``com.squareup.okhttp3.okhttp_3.12.0.dex'' is the correct version of the target APK.

## **Optimization Strategies**

- ``Inlining``: This optimization involves replacing a function call with the actual code of the function itself. It can
  increase the optimization scope by optimizing the callee and caller collectively.
[groundtruth_1220.txt](../OptTPL/groundtruth_1220.txt)
- ``ClassInlining``: This optimization removes classes that are only used in one place, integrating their functionality
  directly into the using class. It can reduce the overall application size and improve runtime performance.

- ``Devirtualization``: This optimization enhances performance by converting virtual method calls into direct method
  calls when the exact type of the object is known at compile-time, avoiding dynamic dispatch.

- ``EnumValueOptimization``: This optimization reduces memory usage and possibly improves lookup speed by replacing the
  use of enum values with their ordinal or other constant values where possible.

- ``Outlining``: This optimization reduces code size by moving frequently repeated code patterns into separate methods,
  eliminating redundant code sequences. It is particularly useful in a constrained environment like Android.

- ``InitializedClassesAnalysis``: This optimization allows the compiler to optimize away class initialization checks
  under certain conditions by analyzing and determining which classes are definitely initialized at certain program
  points.

- ``CallSiteOptimization``: This optimization reduces the overhead of method calls by optimizing call sites, possibly by
  inlining, devirtualizing, or other means, depending on the context of each call site.

- ``HorizontalClassMerger``: This optimization merges classes that are not part of a hierarchy but share similar methods
  or fields. It can reduce the number of classes and method implementations, improving runtime performance and reducing
  memory usage.

- ``NameReflection``: This optimization reduces the metadata related to reflection usage by possibly renaming methods
  and fields that are not accessed through reflection, or by optimizing reflection access patterns themselves.

- ``VerticalClassMerger``: This optimization merges subclasses with their superclasses where possible, reducing the
  complexity of the class hierarchy and potentially leading to more efficient execution and reduced memory usage.

- ``StringConcatenation``: This optimization improves performance and significantly reduces garbage collection pressure
  by optimizing string concatenations using more efficient methods or by avoiding intermediate string objects.

- ``EnumUnboxing``: This optimization improves performance and reduces memory overhead by converting enum types into
  primitive types where they are used simply as integers or other simple values.

- ``SideEffectAnalysis``: This optimization enhances the potential for further optimizations by analyzing and
  understanding the side effects of methods to determine whether calls to these methods can be safely removed or
  modified without changing the program’s behavior.

## **Vulnerable TPL information**

We analyzed 4,151 open-source apps from F-Droid, an archive for open-source Android software. By examining the Gradle
build files, we identified all the libraries each app utilized. Subsequently, we queried the National Vulnerability
Database (NVD) to gather information on reported vulnerabilities and their respective affected library versions. This
meticulous process helped us identify 94 CVEs impacting 31 unique library categories (considering different versions of
org.eclipse.jetty
as a single category). This study involved significant manual effort. The CVEs selected for this research are detailed
below.

| library (group:artifact)                    | CVE                                                                                                                                                                                                                                                                                        |
|---------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| com.neovisionaries:nv-websocket-client      | CVE-2017-1000209                                                                                                                                                                                                                                                                           |
| FasterXML:jackson-dataformat-xml            | CVE-2016-3720                                                                                                                                                                                                                                                                              |
| org.jsoup:jsoup                             | CVE-2015-6748                                                                                                                                                                                                                                                                              |
| org.apache.groovy:groovy                    | CVE-2015-3253, CVE-2016-6814                                                                                                                                                                                                                                                               |
| org.igniterealtime.smack:smack-core         | CVE-2016-10027                                                                                                                                                                                                                                                                             |
| com.thoughtworks.xstream:xstream            | CVE-2013-7285, CVE-2017-7957                                                                                                                                                                                                                                                               |
| org.apache.commons:commons-compress         | CVE-2018-11771, CVE-2019-12402<br>CVE-2018-1324,CVE-2012-2098                                                                                                                                                                                                                              |
| com.squareup.okhttp3:okhttp                 | CVE-2021-0341                                                                                                                                                                                                                                                                              |
| org.apache.httpcomponents:httpclient        | CVE-2015-5262, CVE-2014-3577                                                                                                                                                                                                                                                               |
| com.itextpdf:itextpdf                       | CVE-2017-9096                                                                                                                                                                                                                                                                              |
| com.github.junrar:junrar                    | CVE-2018-12418                                                                                                                                                                                                                                                                             |
| com.google.guava:guava                      | CVE-2018-10237                                                                                                                                                                                                                                                                             |
| com.caverock:androidsvg                     | CVE-2017-1000498                                                                                                                                                                                                                                                                           |
| io.netty:netty                              | CVE-2018-12418, CVE-2014-0193<br>CVE-2016-4970, CVE-2014-3488                                                                                                                                                                                                                              |
| com.squareup.retrofit2:retrofit             | CVE-2018-1000850                                                                                                                                                                                                                                                                           |
| org.zeroturnaround:zt-zip                   | CVE-2018-1002201                                                                                                                                                                                                                                                                           |
| ch.qos.logback:logback-core                 | CVE-2017-5929                                                                                                                                                                                                                                                                              |
| org.apache.jackrabbit:jackrabbit-webdav     | CVE-2015-1833, CVE-2016-6801                                                                                                                                                                                                                                                               |
| org.conscrypt:conscrypt-android             | CVE-2017-13309                                                                                                                                                                                                                                                                             |
| org.apache.logging.log4j:log4j-core         | CVE-2021-44228, CVE-2021-45046<br>CVE-2017-5645                                                                                                                                                                                                                                            |
| org.apache.pdfbox:pdfbox                    | CVE-2016-2175, CVE-2018-8036<br>CVE-2018-11797,CVE-2019-0228                                                                                                                                                                                                                               |
| com.fasterxml.jackson.core:jackson-databind | CVE-2019-17267, CVE-2020-8840<br>CVE-2021-20190, CVE-2019-14439<br>CVE-2018-11307, CVE-2019-14892<br>CVE-2020-36182, CVE-2018-19362<br>CVE-2018-19360, CVE-2019-14893<br>CVE-2017-17485, CVE-2018-5968<br>CVE-2019-12086, CVE-2018-12022<br>CVE-2018-19361,CVE-2020-9546<br>CVE-2019-12814 |
 org.bouncycastle:bcprov-jdk15on             | CVE-2016-1000344, CVE-2016-1000341<br>CVE-2020-26939, CVE-2016-1000343<br>CVE-2018-1000613, CVE-2016-1000352<br>CVE-2016-1000345, CVE-2018-1000180<br>CVE-2020-28052, CVE-2016-1000346 <br>CVE-2019-17359, CVE-2017-13098 <br>CVE-2016-1000342,CVE-2015-6644<br>CVE-2016-1000339           |
| org.eclipse.jetty:jetty-server              | CVE-2011-4461, CVE-2016-4800 <br>CVE-2018-12538,CVE-2019-17632<br>CVE-2019-10247,CVE-2019-10241                                                                                                                                                                                            |
| org.eclipse.jetty:jetty-servlet             | CVE-2019-10246                                                                                                                                                                                                                                                                             |
| org.eclipse.jetty:jetty-security            | CVE-2017-9735                                                                                                                                                                                                                                                                              |
| org.eclipse.jetty:jetty-http                | CVE-2015-2080,CVE-2017-7656<br>CVE-2017-7657                                                                                                                                                                                                                                               |
| dom4j:dom4j                                 | CVE-2020-10683,CVE-2018-1000632                                                                                                                                                                                                                                                            |
| io.netty:netty-all                          | CVE-2019-16869,CVE-2015-2156<br>CVE-2019-20444                                                                                                                                                                                                                                             |
| org.apache.openjpa:openjpa-lib              | CVE-2013-1768                                                                                                                                                                                                                                                                              |
| com.unboundid:unboundid-ldapsdk             | CVE-2018-1000134                                                                                                                                                                                                                                                                           |
| commons-beanutils:commons-beanutils         | CVE-2019-10086                                                                                                                                                                                                                                                                             |
| org.apache.cordova:framework                | CVE-2015-5256,CVE-2015-8320                                                                                                                                                                                                                                                                |
| com.liulishuo.filedownloader:library        | CVE-2018-11248                                                                                                                                                                                                                                                                             |
| com.google.gson:gson                        | CVE-2022-25647                                                                                                                                                                                                                                                                             |
