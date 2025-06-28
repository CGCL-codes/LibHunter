from xml.etree import ElementTree
from multiprocessing import Pool

import zipfile, os, shutil, sys

# for file in origin/*.apk; do       folder=$(basename "$file" .apk)  ;     mkdir "dataset/$folder"  ;     cp "$file" "dataset/$folder/"  ; done

# mkdir -p dataset_R8_option  # 预先创建目标目录以避免重复创建
# find origin -type f -name '*.apk' | shuf | head -n 50 | while IFS= read -r file; do
#     folder=$(basename "$file" .apk)
#     mkdir -p "dataset_R8_option/$folder"
#     cp "$file" "dataset_R8_option/$folder/"
# done


dataset = './dataset'
dataset = './dataset_R8_option'
final_dataset = './final_dataset'
frameworkDir = '.'
errorFileName = 'proguarderror'



libDir = os.path.join(frameworkDir,'libs')
R8_OneOp_dir = os.path.join(frameworkDir,'R8_OneOption')
R8_OneOp_dir = os.path.join(frameworkDir,'R8_OneOption_enable_one')
apktool = 'java -jar '+os.path.join(libDir,'apktool_2.9.1.jar')+' '
keystore = os.path.join(libDir,'guoguo.keystore')
androidJar = os.path.join(libDir,'android.jar')
allatori = os.path.join(libDir,'allatori.jar')
dx = os.path.join(libDir,'dx.jar')
proguard = os.path.join(libDir,'proguard.jar')
if 'win' in sys.platform:
    dex2jar = os.path.join(libDir,'dex2jar-2.1', 'd2j-dex2jar.bat')
else:
    dex2jar = os.path.join(libDir,'dex2jar-2.1', 'd2j-dex2jar.sh')
errorFile = os.path.join(frameworkDir,'logs',errorFileName+'.csv')

error_file_opened = False

def print_error(msg):
    print('error')
    print (msg)

def handleException():
    pass

def obfuscateapk(unarchivedPath, workingDir, fileNames, apktool_output ,postfix, r8_path): 
    '''
    rawJar = 'output_dex2jar.jar'
    rawDex = i
    obfJar = 'r8-obf-classes.jar'
    obfDex = 'r8-classes.dex'
    obfMap = 'r8-obf-classes.map'
    
    if i != 'classes.dex':
        rawJar = 'output_dex2jar' + str(i[-5]) + '.jar'
        #rawDex = 'classes' + str(i+1) + '.dex'
        obfJar = 'r8-obf-classes' + str(i[-5]) + '.jar'
        obfDex = 'r8-classes' + str(i[-5]) + '.dex'
        obfMap = 'r8-obf-classes' + str(i[-5]) + '.map'
    '''
    jarList = ''
    for rawDex in fileNames:
        rawJar = 'output_dex2jar' + str(rawDex[-5]) + '.jar'
        jarList = jarList + '-injars ' + rawJar + '\n'
        
        #Dex2Jar: convert the file.dex to a file.jar
        jarFile = str(os.path.join(workingDir, rawJar))
        dexFile = str(os.path.join(unarchivedPath, rawDex))
        print(jarFile,dexFile)
        if os.path.exists(jarFile): 
            os.remove(jarFile)
        if not os.path.exists(dexFile):
            print_error('missingDexFile,'+dexFile+','+str(sys.exc_info())+'\n')
            return   
        Dex2JarCmd = dex2jar +' -o '+ jarFile+' '+dexFile
        print (Dex2JarCmd)
        os.system(Dex2JarCmd)
        if not os.path.exists(jarFile):
            print_error('missingJarFile,'+jarFile+','+str(sys.exc_info())+'\n')
            # return
            sys.exit(1)
        os.remove(dexFile)
        
    if jarList == '':
        for d in os.listdir(workingDir):
            if d.endswith('jar'):
                jarList = jarList + '-injars ' + d + '\n'
    
    # R8 obfuscation: 
    # R8 is a free Java class file shrinker, optimizer, obfuscator, and preverifier 
    configFile = os.path.join(workingDir,'R8-android.pro')    
    shutil.copyfile(os.path.join(libDir,'R8-android.pro'), configFile)

    with open(configFile, 'r') as f:
        configContext = f.read()

    configContext = configContext.replace('-injars xxx', jarList)

    # todo refine this
    ['opt', 'opt-obf' , 'obf']
    if postfix == 'opt-srk':
        # 优化+缩减。如果不开缩减，有些优化无法启用。so disable obf。
        configContext = configContext.replace('#-dontobfuscate', '-dontobfuscate')
    elif postfix == 'opt-obf-srk':
        pass
    elif postfix == 'obf':
        # 只开混淆。
        configContext = configContext.replace('#-dontoptimize', '-dontoptimize').replace('#-dontshrink', '-dontshrink')
    elif postfix == 'srk':
        # 只开srk
        configContext = configContext.replace('#-dontoptimize', '-dontoptimize').replace('#-dontobfuscate', '-dontobfuscate')
    elif postfix == 'opt':
        # 只开优化
        configContext = configContext.replace('#-dontshrink', '-dontshrink').replace('#-dontobfuscate', '-dontobfuscate')
    elif postfix == 'opt-srk':
        # 优化 + srk
        configContext = configContext.replace('#-dontobfuscate', '-dontobfuscate')
    elif postfix == 'disableAll':
        # 全部关闭
        configContext = configContext.replace('#-dontoptimize', '-dontoptimize').replace('#-dontshrink', '-dontshrink').replace('#-dontobfuscate', '-dontobfuscate')
    
    # fix aapt rules
    aapt_rules = parse_xmls(apktool_output)
    configContext = configContext.replace('#-todo_aapt_rules', aapt_rules)
    
    with open(configFile, 'w') as f:
        f.write(configContext)    
    
    
    maindex = os.path.join(libDir,'R8-android-maindex.pro')
    r8Cmd = f'java -Xms128m -Xmx2048m -cp {r8_path} com.android.tools.r8.R8 --lib {androidJar} --pg-conf {configFile} --release --main-dex-rules {maindex} --output {unarchivedPath}'
    print (r8Cmd)
    os.system(r8Cmd)

    if not os.path.exists(os.path.join(unarchivedPath,'classes.dex')):
        # retry without release, this may be buggy sometimes
        r8Cmd = f'java -Xms128m -Xmx2048m -cp {r8_path} com.android.tools.r8.R8 --lib {androidJar} --pg-conf {configFile} --debug --main-dex-rules {maindex} --output {unarchivedPath}'
        print (r8Cmd)
        os.system(r8Cmd)

    if not os.path.exists(os.path.join(unarchivedPath,'classes.dex')):
        # retry without main-dex-rules, this may be buggy sometimes
        r8Cmd = f'java -Xms128m -Xmx2048m -cp {r8_path} com.android.tools.r8.R8 --lib {androidJar} --pg-conf {configFile} --release --output {unarchivedPath}'
        print (r8Cmd)
        os.system(r8Cmd)

    

    if not os.path.exists(os.path.join(unarchivedPath,'classes.dex')):
        print_error('Run R8 failed '+str(sys.exc_info())+'\n')
        print(r8Cmd)
        sys.exit(1)
        # return


def R8_process_app(app, mode = 'default'):
    print('process obfuscator '+app)
    appDir=os.path.join(dataset,app)
    apkFile = os.path.join(appDir, (app+'.apk'))
    apktool_output = os.path.join(appDir, 'apktool-output')
    apktool_yml = os.path.join(apktool_output,'apktool.yml')
        #run apktool if not exists from previous run or from running Allattori obfuscator     
    apktoolCmd = '{0} d {1} -f -output {2}'.format(apktool, apkFile, apktool_output)   
    if not os.path.exists(apktool_output) or not os.path.exists(apktool_yml):
        print(apktoolCmd)
        os.system(apktoolCmd)

    if not os.path.exists(apktool_yml):
        print_error('apktool failed\n '+ apktoolCmd)
        sys.exit(1)
        # return
    if mode =='default':
        r8 = os.path.join(libDir,'r8-8.2.33.jar')
        for postfix in ['opt-obf-srk', 'opt-srk', 'obf' , 'srk']:
            target_apkFile = os.path.join(appDir,app+'_'+postfix+'.apk')
            do_process(appDir,app, target_apkFile, apkFile, apktool_output, postfix, r8)
    elif mode == 'opt-OneOption':
        for R8_postfix in ['enableInlining', 'enableClassInlining', 'enableDevirtualization',
                           'enableEnumUnboxing', 'outline','enableEnumValueOptimization','enableSideEffectAnalysis',
                        'enableInitializedClassesAnalysis','callSiteOptimizationOptions',
                        'enableNameReflectionOptimization','enableStringConcatenationOptimization',
                        'horizontalClassMergerOptions','verticalClassMergerOptions']:
            target_apkFile = os.path.join(appDir,app+'_opt-srk_'+R8_postfix+'.apk')
            r8 = os.path.join(R8_OneOp_dir,f'r8_{R8_postfix}.jar')
            do_process(appDir,app, target_apkFile, apkFile, apktool_output, 'opt-srk', r8, '_'+R8_postfix)
    
def check_for_skip(workingDir,app ,obf_apkFile):
    # check apktool output
    if not os.path.exists(os.path.join(os.path.dirname(workingDir),'apktool-output','apktool.yml')):
        return False
    # check apk exist
    if not os.path.exists(obf_apkFile):
        return False

    size_criteria = 100 * 1024  # 300 KB in bytes
    dex_file_found = False
    dex_file_size = -1
    with zipfile.ZipFile(obf_apkFile, 'r') as zip_ref:
        for file_info in zip_ref.infolist():
            if file_info.filename == 'classes.dex':
                dex_file_found = True
                dex_file_size = file_info.file_size
                break
    if not dex_file_found or dex_file_size < size_criteria:
        print('dex file not found or too small: ' + obf_apkFile)
        # return False

    # check the jar exists
    if not os.path.exists(os.path.join(workingDir,'output_dex2jars.jar')):
        return False
    # check the dex exists
    if not os.path.exists(os.path.join(workingDir,app,'classes.dex')):
        return False
    return True


def do_process(appDir,app, obf_apkFile ,apkFile, apktool_output, postfix, r8_path, R8_postfix=''):
    workingDir =os.path.join(appDir,'working-dir-' + postfix + R8_postfix)
    if check_for_skip(workingDir,app,obf_apkFile):
        print ('skip ' + app +'_'+ postfix + R8_postfix)
        return

    unarchivedPath = os.path.join(workingDir,app)
    #unarchive the apk file
    if not zipfile.is_zipfile(apkFile):
        print_error('invalid-apk,'+app+','+apkFile+','+str(sys.exc_info())+'\n')
        return
    if os.path.exists(unarchivedPath):
        shutil.rmtree(unarchivedPath)
    zApk = zipfile.ZipFile(apkFile)   
    zApk.extractall(unarchivedPath)
    if os.path.exists(unarchivedPath):
        fileNames = [d for d in os.listdir(unarchivedPath) if d.endswith('dex')]
        print('Unarchived '+apkFile)

        obfuscateapk(unarchivedPath, workingDir, fileNames, apktool_output, postfix, r8_path)

        shutil.copyfile(os.path.join(apktool_output,'apktool.yml'), os.path.join(unarchivedPath,'apktool.yml'))
        if os.path.exists(os.path.join(apktool_output,'unknown')):
            shutil.copytree(apktool_output + '/unknown',unarchivedPath + '/unknown', dirs_exist_ok=True)


        obf_apkFile = os.path.join(appDir,app+'_'+postfix+R8_postfix+'.apk')
        buildCmd = '{0} b {1} -output {2}'.format(apktool, unarchivedPath, obf_apkFile)
        print (buildCmd)
        os.system(buildCmd)
        if not os.path.exists(obf_apkFile):
            #try build an apk file after moving the AndroidManifest file                        
            shutil.copyfile(os.path.join(apktool_output,'AndroidManifest.xml'), os.path.join(unarchivedPath,'AndroidManifest.xml'))
            print ('Build again: '+buildCmd)
            os.system(buildCmd)

        if not os.path.exists(obf_apkFile):
            print ('Build Failed: '+buildCmd)
            # return
            sys.exit(1)

        if os.path.exists(obf_apkFile):
            # signApkCmd = '{0} {1}'.format(sign_apk_with_mahmoud, obf_apkFile)
            signApkCmd = 'jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore {0} -storepass guoguo -keypass guoguo {1} guoguo.keystore'.format(keystore,obf_apkFile)
            print (signApkCmd)
            os.system(signApkCmd)                    
        else:
            print ('file not found to sign: '+obf_apkFile)
            sys.exit(1)    

            #aapt remove -f ./original-test.apk ./classes.dex
            #aapt add -f ./original-test.apk ./classes.dex
        
        print('R8 finished '+apkFile)
        
            
################################################################################################################
def check_androguard_config(file):
    f = open(file, 'r')
    print ('check if '+file+' exists.')
    for l in f:
        if l.startswith('-libraryjars'):
            print ('check this line '+l)
            jar = (l.replace('\n','').split()[1]).strip()
            if not (os.path.exists(jar) and jar.endswith('.jar')):
                print ('JAR file '+jar+' is not exists. Update '+file+' accordingly.')
                sys.exit(1)
            break   
    return True

# Define a function to extract class names
def extract_class_names(package,element):
    class_names = []
    for elem in element.iter():
        for attrib, value in elem.attrib.items():
            # Look for attributes that likely contain class names
            if attrib.endswith("name") or attrib.endswith("Name"):
                if value.startswith('.') and package:
                    value = package + value
                # Check if the value looks like a fully qualified class name
                if "." in value and not value.startswith(('@', '?', '#')) and not ' ' in value and '/' not in value:
                    if ':' in value:
                        value = value[value.index(':') + 1:]
                    class_names.append(value)
    return class_names

def parse_xml(file_path:str):
    # Parse the XML file
    tree = ElementTree.parse(file_path)
    root = tree.getroot()
    package_name = root.attrib.get('package')

    # Extract class names from the root element
    class_names = extract_class_names(package_name,root)
    return class_names


def parse_xmls(apktool_output:str):
    class_names = []
    for root, _, files in os.walk(os.path.join(apktool_output, 'res')):
        for file in files:
            if file.endswith(".xml"):
                class_names += parse_xml(os.path.join(root, file))
    class_names += parse_xml(os.path.join(apktool_output, 'AndroidManifest.xml'))

    class_names = list(set(class_names))  # Removing duplicates
    aapt_rules = ''
    for name in class_names:
        # -keep class androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy { <init>(); }
        aapt_rules = aapt_rules + '-keep class ' + name + ' { <init>(); }\n'
    return aapt_rules


def process_app(app):
    mode = 'opt-OneOption'  # 或者根据需要设置
    R8_process_app(app, mode)

################### Main ###################

# stuff to run always here such as class/def
if __name__ == "__main__":

    # R8_process_app('me.murks.feedwatcher')

    apps = [name for name in os.listdir(dataset) if os.path.isdir(os.path.join(dataset, name))]

    mode = 'default'
    # mode = 'opt-OneOption'
    
    # for app in apps:
    #     if app in skips:
    #         continue
    #     R8_process_app(app, mode)
    
    with Pool(4) as pool:
        pool.map(process_app, apps)

