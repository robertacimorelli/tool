from functions import *


def vac_cleaner(input_file_path, output_file_path):
    input_content = read_input_file(input_file_path)
    parsed_sections = parse_policy_string(input_content)

    admin = parsed_sections['ADMIN']
    roles = parsed_sections['ROLES']
    users = parsed_sections['USERS']
    ua = parsed_sections['UA']
    cr = parsed_sections['CR']
    ca = parsed_sections['CA']
    spec = parsed_sections['SPEC']

    user_to_keep = None
    for i, elem in enumerate(ca.split('\n')[:-2]):
        if elem.split(',')[2] == ' target>':
            user_to_keep = elem.split(',')[1].split('&')[0].replace(' ', '').replace('r_', 'u_')

    users_list = users.split(' ')
    new_users_list = filter_list_by_sublist(users_list, ['admin', user_to_keep])

    split_list = ua.split()[:-1]
    ua_list = [f"{split_list[i]} {split_list[i + 1]}" for i in range(0, len(split_list), 2)]
    new_ua_list = []
    for i, item in enumerate(ua_list):
        if ((item.split(', ')[0].replace('<', '') == user_to_keep or
                item.split(', ')[0].replace('<', '') == 'admin')):
            new_ua_list.append(item)

    sections = {
        'ADMIN': admin,
        'ROLES': roles,
        'USERS': ' '.join(new_users_list),
        'UA': ' '.join(new_ua_list),
        'CR': cr,
        'CA': ca,
        'SPEC': spec
    }

    admin = 'ADMIN\n    ' + sections['ADMIN']
    roles = 'ROLES\n    ' + sections['ROLES']
    users = 'USERS\n    ' + sections['USERS'] + '\n;\n\n'
    ua = 'UA\n    ' + sections['UA'] + '\n;\n\n'
    cr = 'CR\n    ' + sections['CR'].replace('>\n', '>\n    ').replace('\n    ;', '\n;')
    ca = 'CA\n    ' + sections['CA'].replace('>\n', '>\n    ').replace('\n    ;', '\n;')
    spec = '\nSPEC target;'

    save_vac_policy(admin + roles + users + ua + cr + ca + spec, output_file_path)
