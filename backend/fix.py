import glob; 
for f in glob.glob('generate_rules_*.py'):
    with open(f, 'r') as file:
        c = file.read()
    c = c.replace('Type Confusion', 'Code Injection').replace('Log Forging', 'Log Injection')
    with open(f, 'w') as file:
        file.write(c)
