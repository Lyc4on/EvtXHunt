# evtxIOC
- Built using python2.7

# Usage
Has to be complied in Windows environment.

```bash
pip install -r requirements.txt
```

Compile into exe (to be refined)
```cmd
pyinstaller evtxIOCHunter_python.py -F --hidden-import="pyevtx" --hidden-import="yaml" --hidden-import="sqlalchemy.sql.default_comparator"
```

Run python script (to be refined)
```cmd
python evtxIOC_prototypev6_sigma.py -f evtx_samples -r rules\\rules_windows_generic.json -o C:\Users\nic\Desktop\SIT_Local\evtxIOC\temp\sub

python evtxIOC_prototypev6_sigma.py -f evtx_samples -r rules\\test.json -o C:\Users\nic\Desktop\SIT_Local\evtxIOC\temp\sub


python evtxIOCHunter_python.py -f evtx_samples -r single_rule_test -o C:\Users\nic\Desktop\SIT_Local\evtxIOC
```

Run exe (to be refined)
```cmd
evtxIOC_prototypev6_sigma.exe -f evtx_samples -r rules\\rules_windows_generic.json -o C:\Users\nic\Desktop\SIT_Local\evtxIOC\temp\sub
```

```bash
# whole folder
sigmac -I -t sqlite -c config/generic/sysmon.yml -r ../rules/windows/ -oF json -o test.json -of title,description

# single file
sigmac -I -t sqlite -c config/generic/sysmon.yml ../rules/windows/create_remote_thread/sysm
on_suspicious_remote_thread.yml -oF json -o single.json -of title,description
```