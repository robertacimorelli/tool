import re
from classes import *


def read_aegrbac_policy(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(f'File not found: {file_path}')

    aegrbac_policy = AEGRBACPolicy()

    rp_found = False
    dr_found = False
    rpdra_found = False
    assign_found = False
    revoke_found = False
    query_found = False
    for line in lines:
        line = line.strip()
        if line:
            if re.search(r'\bAUser\b', line):
                aegrbac_policy.set_auser('admin')
            if re.search(r'\bAR\b', line):
                aegrbac_policy.set_ar('Admin')
            if re.search(r'\bAUA\b', line):
                aegrbac_policy.set_aua('admin, Admin')
            if re.search(r'\bRP\b', line):
                rp_found = True
            elif rp_found:
                aegrbac_policy.set_rp(str(line.strip()))
                rp_found = False
            if re.search(r'\bDR\b', line):
                dr_found = True
            elif dr_found:
                aegrbac_policy.set_dr(str(line.strip()))
                dr_found = False
            if re.search(r'\bRPDRA\b', line):
                rpdra_found = True
            elif rpdra_found:
                aegrbac_policy.set_rpdra(str(line.strip()))
                rpdra_found = False
            if re.search(r'\bAssignRPDR\b', line):
                assign_found = True
            elif assign_found:
                aegrbac_policy.set_assign_rpdr(str(line.strip()))
                assign_found = False
            if re.search(r'\bRevokeRPDR\b', line):
                revoke_found = True
            elif revoke_found:
                aegrbac_policy.set_revoke_rpdr(str(line.strip()))
                revoke_found = False
            if re.search(r'\bQUERY\b', line):
                query_found = True
            elif query_found:
                aegrbac_policy.set_query(str(line.strip()))
                query_found = False

    return aegrbac_policy


def clean_text(text):
    cleaned_text = text.replace('{', '').replace('}', '').replace('(', '').replace(')', '').replace(',', '')
    return cleaned_text


def split_on_comma(text, chunk_size):
    items = text.split(',')
    result = [','.join(items[i:i + chunk_size]) for i in range(0, len(items), chunk_size)]

    return result


def extract_words_between(text):
    start_pattern = '(admin,'
    end_pattern = '}))'
    start_match = re.search(re.escape(start_pattern) + r'\s*([^,]+)', text)
    end_match = re.search(r'([^,]+)\s*' + re.escape(end_pattern), text)

    if start_match and end_match:
        start_pos = start_match.start()
        end_pos = end_match.end()
        extracted_text = text[start_pos:end_pos]
        words = extracted_text.split(',')
        return [word.strip() for word in words]

    return []


def transform_to_arbac(aegrbac_policy):
    arbac_policy = ARBACPolicy()

    # Rule 1
    arbac_policy.U.add(aegrbac_policy['AUser'])
    arbac_policy.R.add('Admin')
    arbac_policy.U.add('target')

    # Rule 2
    string = aegrbac_policy['AUA']
    first = string.split(',')[0]
    second = string.split(',')[1].replace(' ', '')
    arbac_policy.UA.add((first, second))

    # Rule 3 and Rule 6
    rps = aegrbac_policy['RP']
    pattern = r'\([^)]+\)'
    substrings = re.findall(pattern, rps)

    for i, substring in enumerate(substrings, start=1):
        clean_substring = ''.join(c for c in substring if c.isalnum() or c == '_')
        user_name = f'u_{clean_substring}'
        dummy_role_name = f'r_{clean_substring}'
        arbac_policy.U.add(user_name)
        arbac_policy.R.add(dummy_role_name)
        arbac_policy.UA.add((user_name, dummy_role_name))

    # Rule 4
    drs = aegrbac_policy['DR']
    substrings1 = re.findall(r'\b\w+\b', drs)

    for i, substring1 in enumerate(substrings1, start=1):
        device_role_name = f'r_{substring1}'
        arbac_policy.R.add(device_role_name)

    # Rule 5
    rpdras = aegrbac_policy['RPDRA']
    first_split = split_on_comma(rpdras, 3)

    second_split = []
    for r in first_split:
        second_split.append(split_on_comma(r, 2))

    for r1 in second_split:
        r10_clean = clean_text(r1[0])
        r11_clean = clean_text(r1[1])
        user_name = f'u_{r10_clean}'
        device_role_name = f'r_{r11_clean}'
        arbac_policy.UA.add((user_name, device_role_name))

    # Rule 7
    assign = aegrbac_policy['AssignRPDR']
    assign_list = []

    for split in assign.split('assignRPDR'):
        if split != '{':
            assign_list.append(split)

    for elem in assign_list:
        result = extract_words_between(elem)
        assigner = result[1]
        assignee = ('r_' + clean_text(result[2]) + clean_text(result[3]) + '&r_' + result[4].replace('∧', '&r_') + ', '
                    + 'r_' + clean_text(result[5]))
        arbac_policy.can_assign.add('(' + assigner + ', ' + assignee + ')')

    # Rule 8
    revoke = aegrbac_policy['RevokeRPDR']
    revoke_list = []

    for split in revoke.split('revokeRPDR'):
        if split != '{':
            revoke_list.append(split)

    for elem in revoke_list:
        result = extract_words_between(elem)
        revoker = result[1]
        revoked = 'r_' + clean_text(result[4])
        arbac_policy.can_revoke.add('(' + revoker + ', ' + revoked + ')')

    # Query rule
    query = aegrbac_policy['Query']
    query_list = []

    for split in query.split():
        if split != '{':
            query_list.append(clean_text(split))

    arbac_policy.can_assign.add('(Admin, ' + 'r_' + query_list[0] + '&r_' + query_list[1] + ', target)')

    return arbac_policy


def save_arbac_policy(arbac_policy, output_file_path):
    with open(output_file_path, 'w') as file:
        file.write('U:\n')
        users = arbac_policy.get_u()
        for user in users:
            file.write(user + ',' + '\n')
        file.write('\n')

        file.write('UA:\n')
        for user_role_pair in arbac_policy.UA:
            file.write(f'({user_role_pair[0]}, {user_role_pair[1]})\n')
        file.write('\n')

        file.write('R:\n')
        roles = arbac_policy.get_r()
        for role in roles:
            file.write(role + ',' + '\n')
        file.write('\n')

        file.write('can_assign:\n')
        for assign in arbac_policy.can_assign:
            file.write(f'{assign}\n')
        file.write('\n')

        file.write('can_revoke:\n')
        for revoke in arbac_policy.can_revoke:
            file.write(f'{revoke}\n')
        file.write('\n')


def read_input_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    return content


def transform_admin():
    return 'admin'


def transform_roles(content):
    transformed_content = ('ROLES\n    ' + 'target '
                           + ' '.join([role.strip(',') for role in content.split('\n')[1:]]) + '\n;\n')
    return transformed_content


def transform_users(content):
    transformed_content = 'USERS\n    ' + ' '.join([user.strip(',') for user in content.split('\n')[1:]]) + '\n;\n'
    return transformed_content


def transform_ua(content):
    elements = [ua.strip(',').replace('(', '<').replace(')', '>') for ua in content.split('\n')[1:]]
    transformed_content = 'UA\n    ' + ' '.join(elements) + '\n;\n'
    return transformed_content


def transform_cr(content):
    elements = [cr.strip(",").replace('(', '<').replace(')', '>') for cr in content.split('\n')[1:]]
    transformed_content = 'CR\n    ' + '\n    '.join(elements) + '\n;\n'
    return transformed_content


def transform_ca(content):
    elements = [ca.strip(",").replace('(', '<').replace(')', '>') for ca in content.split('\n')[1:]]
    transformed_content = 'CA\n    ' + '\n    '.join(elements) + '\n;\n'
    return transformed_content


def transform_spec():
    return 'target'


def save_vac_policy(output_content, output_file_path):
    with open(output_file_path, 'w') as file:
        file.write(output_content)


def parse_policy_string(policy_string):
    sections = {'ADMIN': '', 'ROLES': '', 'USERS': '', 'UA': '', 'CR': '', 'CA': '', 'SPEC': ''}
    current_section = None

    for line in policy_string.split('\n'):
        line = line.strip()

        if line in sections:
            current_section = line
        elif current_section is not None:
            if current_section == 'CA' and line.endswith(';'):
                sections[current_section] += line + '\n'
                current_section = None
            elif current_section == 'CA' and line == 'SPEC target;':
                current_section = 'SPEC'
            else:
                sections[current_section] += line + '\n'

    return sections


def filter_list_by_sublist(full_list, sublist):
    return [item for item in full_list if item in sublist]


def print_help():
    print("Usage: python script.py <input_file_path> <method>")
    print("Methods:")
    print("  0: Perform all transformations [aegrbac -> arbac -> vac -> clean_vac]")
    print("  1: Perform [aegrbac -> arbac] only")
    print("  2: Perform [arbac -> vac] only")
    print("  3: Perform [vac -> clean_vac] only")
