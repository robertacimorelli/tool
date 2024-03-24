from functions import *


def aegrbac2arbac(input_file_path, output_file_path):
    input_policy = read_aegrbac_policy(input_file_path)
    prova = input_policy.get_all_attributes()
    output_policy = transform_to_arbac(prova)

    save_arbac_policy(output_policy, output_file_path)
