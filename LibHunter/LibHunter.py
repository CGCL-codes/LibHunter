# Program entry point
import argparse
import os
import sys
import zipfile

from module.config import setup_logger, clear_log

sys.path.append(os.getcwd() + "/module")
from module.analyzer import search_lib_in_app,search_libs_in_app

# Parsing user command line input parameters
def parse_arguments():
    parser = argparse.ArgumentParser(description='Process some integers')
    subparsers = parser.add_subparsers(
        help='sub-command help', dest='subparser_name')

    parser_one = subparsers.add_parser(
        'detect_one', help='Detection mode (Single): detect if multiple apps contain a specific TPL version')
    parser_one.add_argument(
        '-o',
        metavar='FOLDER',
        type=str,
        default='outputs',
        help='Specify directory of detection results (containing result in .TXT per app)')
    parser_one.add_argument(
        '-p',
        metavar='num_processes',
        type=int,
        default=None,
        help='Specify maximum number of processes used in detection (default=#CPU_cores)'
    )
    parser_one.add_argument(
        '-af',
        metavar='FOLDER',
        type=str,
        help='Specify directory of apps'
    )
    parser_one.add_argument(
        '-lf',
        metavar='FOLDER',
        type=str,
        help='Specify directory of TPL versions'
    )
    parser_one.add_argument(
        '-ld',
        metavar='FOLDER',
        type=str,
        help='Specify directory of TPL versions in DEX files'
    )

    parser_specific = subparsers.add_parser(
        'detect_all', help='Detection mode (Multiple): detect if multiple apps contain multiple TPL versions')
    parser_specific.add_argument(
        '-o',
        metavar='FOLDER',
        type=str,
        default='outputs',
        help='Specify directory of detection results (containing result in .TXT per app)')
    parser_specific.add_argument(
        '-p',
        metavar='num_processes',
        type=int,
        default=None,
        help='Specify maximum number of processes used in detection (default=#CPU_cores)'
    )
    parser_specific.add_argument(
        '-af',
        metavar='FOLDER',
        type=str,
        help='Specify directory of apps')
    parser_specific.add_argument(
        '-lf',
        metavar='FOLDER',
        type=str,
        help='Specify directory of TPL versions'
    )
    parser_specific.add_argument(
        '-ld',
        metavar='FOLDER',
        type=str,
        help='Specify directory of TPL versions in DEX files'
    )

    return parser.parse_args()

# Use dex2jar tool to convert the jar file to be detected into dex file
def jar_to_dex(libs_folder, lib_dex_folder):
    for file in os.listdir(libs_folder):
        target_dex = lib_dex_folder + '/' + file[:file.rfind(".")] + ".dex"
        if os.path.exists(target_dex):
            continue
        file_name = file[:file.rfind(".")]
        input_file = libs_folder + '/' + file
        
        tmp_file = "lib_dex_folder/classes.dex"
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        
        cmd = f"java -cp libs/r8.jar com.android.tools.r8.D8 --lib libs/android.jar --output {lib_dex_folder} {input_file}"
        print(cmd)
        os.system(cmd)
        tmp_file = f"{lib_dex_folder}/classes.dex"
        if os.path.exists(tmp_file):
            os.rename(tmp_file, target_dex)
        else:
            raise Exception("Dex file not convert!")
        

# Convert aar file to jar file
def arr_to_jar(libs_folder):
    
    for file in os.listdir(libs_folder):
        if file.endswith(".aar"):
            os.rename(libs_folder + "/" + file, libs_folder + "/" + file[:file.rfind(".")] + ".zip")

    for file in os.listdir(libs_folder):
        target_name = libs_folder + "/" + file[:file.rfind(".")] + ".jar"
        if os.path.exists(target_name):
            return
        if file.endswith(".zip"):
            zip_file = zipfile.ZipFile(libs_folder + "/" + file)
            zip_file.extract("classes.jar", ".")
            for f in os.listdir(libs_folder):
                if f == "classes.jar":
                    os.rename(libs_folder + "/" + f, target_name)
            zip_file.close()
            os.remove(libs_folder+ "/" + file)

def main(lib_folder = 'libs',
         lib_dex_folder = 'libs_dex',
         apk_folder = 'apks',
         output_folder = 'outputs',
         processes = None,
         model = 'multiple'):
    # Convert all arr, jar files in the library directory to dex files and put them in the libs_dex directory
    # if len(os.listdir(lib_dex_folder)) < len(os.listdir(lib_folder)) :
    #     arr_to_jar(lib_folder)
    #     jar_to_dex(lib_folder, lib_dex_folder)
        
    if model == "multiple": # Parallel analysis at the library level
        search_libs_in_app(os.path.abspath(lib_dex_folder),
                          os.path.abspath(apk_folder),
                          os.path.abspath(output_folder),
                          processes)
    elif model == "one": # Parallel analysis at the apk level
        search_lib_in_app(os.path.abspath(lib_dex_folder),
                           os.path.abspath(apk_folder),
                           os.path.abspath(output_folder),
                           processes)

if __name__ == '__main__':
    args = parse_arguments()

    clear_log()
    LOGGER = setup_logger()

    LOGGER.debug("args: %s", args)
    
    if not os.path.exists(args.o):
        os.makedirs(args.o)

    if args.subparser_name == 'detect_one':
        main(lib_folder = args.lf, lib_dex_folder = args.ld, apk_folder=args.af, output_folder= args.o, processes=args.p, model="one")
    elif args.subparser_name == 'detect_all':
        main(lib_folder = args.lf, lib_dex_folder = args.ld, apk_folder=args.af, output_folder= args.o, processes=args.p, model="multiple")
    else:
        LOGGER.debug("Detection mode input error!")
