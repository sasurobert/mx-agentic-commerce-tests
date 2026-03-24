import os
import re

TEST_DIR = 'tests'

def fix_imports(content):
    def filter_brackets(m):
        inner = m.group(1)
        inner = inner.replace('GATEWAY_URL, ', '').replace('GATEWAY_URL', '')
        inner = inner.replace('SIM_URL, ', '').replace('SIM_URL', '')
        inner = re.sub(r',\s*,', ',', inner)
        inner = re.sub(r',\s*$', '', inner)
        inner = re.sub(r'^\s*,', '', inner)
        if not inner.strip():
            return ''
        return '{' + inner + '}'

    lines = content.split('\n')
    for i, line in enumerate(lines):
        if line.lstrip().startswith('use '):
            if '{' in line and '}' in line:
                lines[i] = re.sub(r'\{(.*?)\}', filter_brackets, line)
                lines[i] = re.sub(r'use\s+[a-zA-Z0-9_:]+::;\s*', '', lines[i])
            else:
                if 'GATEWAY_URL' in line or 'SIM_URL' in line:
                    lines[i] = ''
    return '\n'.join([l for l in lines if l is not None])

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    original_content = content

    content = fix_imports(content)
    
    content = content.replace('use mx_agentic_commerce_tests::common::find_available_port;\n', '')
    content = content.replace('use mx_agentic_commerce_tests::common::find_available_port;', '')

    def do_import(m):
        prefix = m.group(1)
        inner = m.group(2)
        inner = re.sub(r'\bGATEWAY_URL\b,?\s*', '', inner)
        inner = re.sub(r'\bSIM_URL\b,?\s*', '', inner)
        inner = re.sub(r',\s*,', ',', inner)
        inner = re.sub(r',\s*$', '', inner)
        inner = re.sub(r'^\s*,', '', inner)
        if not inner.strip():
            return '' 
        return prefix + '{ ' + inner.strip() + ' }'

    content = re.sub(r'(use\s+.*?::\s*)\{([^}]+)\}', do_import, content, flags=re.DOTALL)
    content = re.sub(r'use\s+.*?::\s*;\s*', '', content)
    content = re.sub(r'use\s+.*?::\s*GATEWAY_URL\s*;\s*', '', content)
    content = re.sub(r'use\s+.*?::\s*SIM_URL\s*;\s*', '', content)


    form1 = r'(let\s+mut\s+[a-zA-Z0-9_]+\s*=\s*start_chain_simulator\()(8085|CHAIN_SIM_PORT|808\d|8090)(,)'
    form2 = r'(let\s+mut\s+([a-zA-Z0-9_]+)\s*=\s*ProcessManager::new\(\);[\s\S]*?\2\s*\.\s*start_chain_simulator\()(8085|CHAIN_SIM_PORT|808\d|8090)(\))'

    needs_port = False
    if re.search(form1, content) or re.search(form2, content):
        needs_port = True

    if needs_port:
        content = re.sub(
            form1,
            r'let port = find_available_port();\n    let gateway_url = format!("http://localhost:{}", port);\n    \1port\3',
            content
        )
        content = re.sub(
            form2,
            r'let port = find_available_port();\n    let gateway_url = format!("http://localhost:{}", port);\n    \1port\4',
            content
        )

        if 'find_available_port' not in content.split('let port')[0]:
            if re.search(r'use\s+crate::common::\s*\{', content):
                content = re.sub(r'(use\s+crate::common::\s*\{)', r'\1find_available_port, ', content, count=1)
            elif re.search(r'use\s+common::\s*\{', content):
                content = re.sub(r'(use\s+common::\s*\{)', r'\1find_available_port, ', content, count=1)
            else:
                content = 'use crate::common::find_available_port;\n' + content


    content = re.sub(r'\bGATEWAY_URL\b', '&gateway_url', content)
    content = re.sub(r'\bSIM_URL\b', '&gateway_url', content)
    
    content = re.sub(r'const\s+&gateway_url[^;]+;\n', '', content)
    content = re.sub(r'const\s+&gateway_url[^;]+;\r\n', '', content)

    def replace_fund(m):
        raw_args = m.group(1)
        args = raw_args.split(',')
        args = [a.strip() for a in args]
        if len(args) == 3:
            return f'fund_address_on_simulator_custom({args[0]}, {args[1]}, {args[2]}, &gateway_url)'
        elif len(args) == 4 and '&gateway_url' not in args[3]:
            return f'fund_address_on_simulator_custom({args[0]}, {args[1]}, {args[2]}, &gateway_url)'
        elif len(args) == 4:
            return f'fund_address_on_simulator_custom({args[0]}, {args[1]}, {args[2]}, {args[3]})'
        return m.group(0)

    content = re.sub(r'fund_address_on_simulator\(([^)]+)\)', replace_fund, content)

    # Manual fixes for vm_query local definitions
    if 'async fn vm_query(sc_address_bech32: &str, func_name: &str, args_hex: Vec<&str>)' in content:
        content = content.replace(
            'async fn vm_query(sc_address_bech32: &str, func_name: &str, args_hex: Vec<&str>)',
            'async fn vm_query(sc_address_bech32: &str, func_name: &str, args_hex: Vec<&str>, gateway_url: &str)'
        )
        content = content.replace('vm_query(&reputation_bech32, "get_reputation_score", vec![&nonce_hex])', 'vm_query(&reputation_bech32, "get_reputation_score", vec![&nonce_hex], &gateway_url)')
        content = content.replace('vm_query(&alice_bech32', 'vm_query(&alice_bech32, &gateway_url') # hypothetical
        # Also suite_l might have different vm_query calls
        content = content.replace('vm_query(&identity_bech32, "get_agents", vec![])', 'vm_query(&identity_bech32, "get_agents", vec![], &gateway_url)')

    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)

for root, _, files in os.walk(TEST_DIR):
    for file in files:
        if file.endswith('.rs') and file != 'mod.rs':
            process_file(os.path.join(root, file))
