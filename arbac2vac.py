from functions import *


def arbac2vac(input_file_path, output_file_path):
    input_content = read_input_file(input_file_path)
    sections = {
        'ADMIN': transform_admin,
        'R': transform_roles,
        'U': transform_users,
        'UA': transform_ua,
        'can_revoke': transform_cr,
        'can_assign': transform_ca,
        'SPEC': transform_spec
    }

    output_content = ''
    for section_name, transform_function in sections.items():
        if section_name in input_content:
            section_content = input_content.split(section_name + ':')[1].split('\n\n')[0]
            transformed_section = transform_function(section_content)
            output_content += transformed_section + '\n'
        elif section_name == 'ADMIN':
            output_content += section_name + '\n     ' + transform_admin() + '\n;\n\n'
        elif section_name == 'SPEC':
            output_content += section_name + ' ' + transform_spec() + ';'

    save_vac_policy(output_content.strip(), output_file_path)
