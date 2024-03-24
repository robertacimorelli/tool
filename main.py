import sys

from arbac2vac import *
from vac_cleaner import *
from aegrbac2arbac import *


def main():
    if sys.argv[1] == 'help':
        print_help()
        sys.exit(1)

    input_file_path = sys.argv[1]
    method = sys.argv[2]
    arbac_file_path = input_file_path.replace('.txt', '_2_') + 'arbac_policy.txt'
    vac_file_path = input_file_path.replace('.txt', '_2_') + 'vac_policy.txt'
    clean_vac_file_path = input_file_path.replace('.txt', '_2_') + 'clean_vac_policy.txt'

    flag_2 = False
    flag_3 = False
    if method == '0':
        aegrbac2arbac(input_file_path, arbac_file_path)
        arbac2vac(arbac_file_path, vac_file_path)
        vac_cleaner(vac_file_path, clean_vac_file_path)
    if method == '1':
        aegrbac2arbac(input_file_path, arbac_file_path)
    if method == '2':
        flag_2 = True
        if flag_2:
            arbac_file_path = input_file_path
        arbac2vac(arbac_file_path, vac_file_path)
    if method == '3':
        flag_3 = True
        if flag_3:
            vac_file_path = input_file_path
        vac_cleaner(vac_file_path, clean_vac_file_path)


if __name__ == "__main__":
    main()
